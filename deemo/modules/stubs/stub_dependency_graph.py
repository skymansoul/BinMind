# stub_dependency_graph.py — 跨模块依赖图 + 拓扑约束调度
# 从 stub 模块源码的 import/call 关系构造有向依赖图，
# 为 ImplementationPrioritizer 提供约束感知排序。
# 设计依据:
#   1. 桩模块实现隐含拓扑序 — A 依赖 B 则 B 必须先于 A 可用。
#   2. 优先级信号（调用量、缺口度）在拓扑可行集内以加权排位生效，
#      而非无视依赖硬排全局序。
#   3. 增量更新：仅重算受变更影响节点的下游传递闭包。
# 区别于已有工作:
#   SYNFlx (ACL 2025) 的 RelationGraph 面向跨文件协同修复，
#   本模块的图结构额外编码 stub→compat 的"已转发/待实现"语义，
#   调度目标非修复完成度而是实现可行集的逐层扩展。
import ast as _ast
import os as _os
from collections import defaultdict as _dd, deque as _dq
from dataclasses import dataclass as _dc, field as _field
from typing import Optional as _Opt

from modules.stubs.stub_contract import (
    StubContractor as _StubContractor,
    StubContract as _StubContract,
    ImplementationStatus as _Status,
)


@_dc
class DepNode:
    """依赖图中单个模块节点。"""
    module_name: str
    status: str = ''
    # 该模块直接依赖的模块名集合（含 compat 转发目标）
    imports_from: set = _field(default_factory=set)
    # 依赖该模块的模块名集合（反向边，惰性填充）
    depended_by: set = _field(default_factory=set)
    # 拓扑深度: 0 = 无依赖, k = 最长依赖链长度
    topo_depth: int = 0
    # 下游传递闭包大小（影响面）
    downstream_closure_size: int = 0

    def is_leaf(self) -> bool:
        return len(self.imports_from) == 0

    def is_root(self) -> bool:
        return len(self.depended_by) == 0


class ModuleDependencyGraph:
    """从 stubs/ 目录构造跨模块依赖有向图。

    依赖关系来源:
      1. AST import 语句 — from modules.xxx import ... 或 import modules.xxx
      2. compat 转发目标 — stub 文件内 from modules.core.compat.xxx import *
      3. 函数体内的跨模块调用 — 通过 AST Call + Name/Attribute 推断

    图不变量: 自环忽略（模块不应依赖自身）；重复边合并。
    """

    def __init__(self, stubs_dir: str = None):
        if stubs_dir is None:
            stubs_dir = _os.path.dirname(_os.path.abspath(__file__))
        self.stubs_dir = stubs_dir
        self.nodes: dict[str, DepNode] = {}
        self._contractor = _StubContractor(stubs_dir=stubs_dir)
        # 已失效标记 — 节点被移除或源码变更时置位
        self._dirty: set[str] = set()

    # ---- 图构造 ----
    def build(self) -> 'ModuleDependencyGraph':
        """扫描 stubs/ 下全部 .py 文件，构造完整依赖图。"""
        self.nodes.clear()
        self._dirty.clear()
        contracts = self._contractor.scan_all()

        for name, contract in contracts.items():
            node = self.nodes.setdefault(name, DepNode(module_name=name))
            node.status = contract.status

        for name in self.nodes:
            self._extract_deps(name)

        self._compute_topo_depths()
        self._fill_reverse_edges()
        self._compute_downstream_closures()
        return self

    def _extract_deps(self, module_name: str) -> None:
        """解析单个模块源码，提取其依赖集合。"""
        node = self.nodes[module_name]
        path = _os.path.join(self.stubs_dir, f'{module_name}.py')
        if not _os.path.isfile(path):
            return

        try:
            src = open(path, encoding='utf-8').read()
        except (OSError, UnicodeDecodeError):
            return
        try:
            tree = _ast.parse(src, filename=path)
        except SyntaxError:
            return

        for stmt in _ast.walk(tree):
            # import modules.xxx.yyy → 提取 xxx 为依赖模块
            if isinstance(stmt, _ast.Import):
                for alias in stmt.names:
                    target = self._resolve_module_name(alias.name)
                    if target and target != module_name and target in self.nodes:
                        node.imports_from.add(target)
            elif isinstance(stmt, _ast.ImportFrom):
                if stmt.module:
                    target = self._resolve_module_name(stmt.module)
                    if target and target != module_name and target in self.nodes:
                        node.imports_from.add(target)

    @staticmethod
    def _resolve_module_name(full_dotted: str) -> _Opt[str]:
        """modules.stubs.xxx 或 modules.core.compat.xxx → xxx。
        抽取最右段并检查是否对应已知 stub 模块。
        非 modules.* 路径的 import（如 os, json）返回 None。"""
        parts = full_dotted.split('.')
        if len(parts) >= 2 and parts[0] == 'modules':
            return parts[-1]
        # 非框架内 import，不纳入依赖图
        return None

    # ---- 拓扑深度 ----
    def _compute_topo_depths(self) -> None:
        """BFS 计算各节点的拓扑深度（最长依赖链长度）。

        采用 Kahn 变体: 从无依赖节点（深度 0）出发，
        每处理一条边松弛目标深度 = max(当前, 源深度+1)。
        处理顺序用队列保证每个节点在其所有前驱被处理后才传播。"""
        in_degree = {name: len(node.imports_from) for name, node in self.nodes.items()}
        queue = _dq([name for name, deg in in_degree.items() if deg == 0])
        depths = {name: 0 for name in queue}

        while queue:
            cur = queue.popleft()
            cur_depth = depths[cur]
            # 传播到依赖当前节点的模块（在填充反向边后使用）
            for dependent in self.nodes[cur].depended_by:
                new_depth = cur_depth + 1
                if depths.get(dependent, 0) < new_depth:
                    depths[dependent] = new_depth
                in_degree[dependent] -= 1
                if in_degree[dependent] == 0:
                    queue.append(dependent)

        for name, node in self.nodes.items():
            node.topo_depth = depths.get(name, 0)

    def _fill_reverse_edges(self) -> None:
        """为每个节点的 imports_from 建立反向边 depended_by。"""
        for name, node in self.nodes.items():
            node.depended_by.clear()
        for name, node in self.nodes.items():
            for dep in node.imports_from:
                if dep in self.nodes:
                    self.nodes[dep].depended_by.add(name)

    def _compute_downstream_closures(self) -> None:
        """DFS 计算每个节点的下游传递闭包大小。

        用于影响面评估: 修改该模块会波及多少依赖方。
        缓存中间结果避免重复遍历。"""
        memo: dict[str, int] = {}

        def closure_size(name: str, visited: set) -> int:
            if name in memo:
                return memo[name]
            visited.add(name)
            total = 0
            for dep_by in self.nodes[name].depended_by:
                if dep_by not in visited:
                    total += 1 + closure_size(dep_by, visited | {dep_by})
            memo[name] = total
            return total

        for name in self.nodes:
            if name not in memo:
                self.nodes[name].downstream_closure_size = closure_size(name, {name})
            else:
                self.nodes[name].downstream_closure_size = memo[name]

    # ---- 增量更新 ----
    def mark_dirty(self, module_name: str) -> None:
        """标记节点为脏（源码变更后调用）。下次查询时惰性重算。"""
        self._dirty.add(module_name)
        # 将所有下游依赖方也标记为脏，因其拓扑深度可能变化
        node = self.nodes.get(module_name)
        if node is None:
            return
        stack = list(node.depended_by)
        while stack:
            dep = stack.pop()
            if dep not in self._dirty:
                self._dirty.add(dep)
                stack.extend(self.nodes[dep].depended_by)

    def refresh(self) -> None:
        """重算所有脏节点的依赖边与拓扑深度。"""
        if not self._dirty:
            return
        for name in self._dirty:
            if name in self.nodes:
                self.nodes[name].imports_from.clear()
                self._extract_deps(name)
        self._fill_reverse_edges()
        self._compute_topo_depths()
        self._compute_downstream_closures()
        self._dirty.clear()

    # ---- 查询接口 ----
    def dependency_chain(self, module_name: str) -> list[str]:
        """返回该模块的完整依赖链（按拓扑序，最底层依赖在前）。"""
        if module_name not in self.nodes:
            return []
        result = []
        visited = set()

        def dfs(name: str):
            if name in visited:
                return
            visited.add(name)
            for dep in sorted(self.nodes[name].imports_from):
                dfs(dep)
            result.append(name)

        dfs(module_name)
        return result

    def impact_set(self, module_name: str) -> set[str]:
        """返回受该模块变更影响的下游模块集合（传递闭包）。"""
        if module_name not in self.nodes:
            return set()
        result = set()
        stack = list(self.nodes[module_name].depended_by)
        while stack:
            dep = stack.pop()
            if dep not in result:
                result.add(dep)
                stack.extend(self.nodes[dep].depended_by)
        return result

    def leaf_modules(self) -> list[str]:
        """无依赖的叶子模块（可从任意顺序实现）。"""
        return sorted(name for name, node in self.nodes.items() if node.is_leaf())

    def root_modules(self) -> list[str]:
        """无被依赖的根模块（变更不影响其他模块）。"""
        return sorted(name for name, node in self.nodes.items() if node.is_root())

    def to_dict(self) -> dict:
        return {
            name: {
                'imports_from': sorted(node.imports_from),
                'depended_by': sorted(node.depended_by),
                'topo_depth': node.topo_depth,
                'downstream_closure': node.downstream_closure_size,
                'status': node.status,
            }
            for name, node in sorted(self.nodes.items())
        }


# ---- 拓扑约束调度器 ----
# 核心思想:
#   在任意时刻，只有"全部依赖均已实现（或可直接转发 compat）"的模块
#   才进入可行集。调度器在可行集内按优先级权重排序，选出下一批实现目标。
#   每完成一轮实现后，重新计算可行集（新实现的模块释放其下游依赖）。
class TopologicalScheduler:
    """依赖拓扑约束下的渐进实现调度。

    与纯优先级排序的区别:
      - 高优先级但依赖未满足 → 延迟到依赖实现后
      - 低优先级但依赖已满足 → 可能提前（因无阻塞）
      - 最终执行序列总能满足: 任意模块在其依赖之后被实现
    """

    def __init__(self, dep_graph: ModuleDependencyGraph):
        self.graph = dep_graph
        # 追踪已实现/可用的模块（含 compat 转发即有实现的模块）
        self._available: set[str] = set()
        self._init_available()

    def _init_available(self) -> None:
        """初始化可用集: compat 转发已存在或已实现的模块视为可用。"""
        for name, node in self.graph.nodes.items():
            if node.status in (_Status.RE_EXPORT.value, _Status.IMPLEMENTED.value,
                              _Status.MIXED.value):
                self._available.add(name)

    def mark_available(self, module_name: str) -> None:
        """标记模块为已可用（实现或 compat 转发后调用）。"""
        self._available.add(module_name)

    def feasible_set(self) -> set[str]:
        """当前可行集: 所有依赖均已可用的待实现模块。

        可行条件:
          1. 模块自身非已可用状态
          2. 其所有直接依赖均在可用集中
        """
        feasible = set()
        for name, node in self.graph.nodes.items():
            if name in self._available:
                continue
            if node.imports_from.issubset(self._available):
                feasible.add(name)
        return feasible

    def scheduled_order(self, priorities: dict[str, float]) -> list[str]:
        """在可行集内按优先级权重降序返回调度序列。

        priorities: {module_name: total_score}，由 ImplementationPrioritizer 提供。
        返回: 满足拓扑约束的优先级降序模块名列表。
        """
        feasible = self.feasible_set()
        # 稳定排序: 优先级降序，同分按模块名字典序
        ordered = sorted(feasible, key=lambda n: (-priorities.get(n, 0.0), n))
        return ordered

    def next_batch(self, priorities: dict[str, float], n: int = 5) -> list[str]:
        """返回下一批应实现的模块（最多 n 个），按拓扑可行+优先级排序。"""
        return self.scheduled_order(priorities)[:n]


# ---- 依赖感知优先级包装 ----
class DependencyAwarePrioritizer:
    """包装 ImplementationPrioritizer，在其优先级评分上叠加依赖约束。

    输出排序 = 拓扑可行过滤 × 优先级评分。
    额外计算依赖密度因子: 被依赖越多的模块，其实现价值越高
    （因实现一个可解除多个下游阻塞），该因子作为优先级调制项。
    """

    def __init__(self, base_prioritizer, dep_graph: ModuleDependencyGraph,
                 dependency_bonus_weight: float = 0.12):
        self.base = base_prioritizer
        self.graph = dep_graph
        self.dep_bonus_weight = dependency_bonus_weight
        self.scheduler = TopologicalScheduler(dep_graph)

    def rank_with_deps(self) -> list[dict]:
        """输出依赖感知排序结果，每项含原始分、依赖调制分与综合分。"""
        base_ranking = self.base.rank()
        # {module_name: StubPriority}
        base_scores = {p.module_name: p.total_score for p in base_ranking}
        feasible = self.scheduler.feasible_set()

        result = []
        for p in base_ranking:
            node = self.graph.nodes.get(p.module_name)
            dep_bonus = 0.0
            if node is not None:
                # 依赖密度调制: 被依赖数 / 总模块数归一化
                total = max(len(self.graph.nodes), 1)
                dep_bonus = (len(node.depended_by) / total) * self.dep_bonus_weight

            # 不可行模块的综合分大幅降低，但保留原始分供参考
            in_feasible = p.module_name in feasible
            adjusted = (p.total_score + dep_bonus) if in_feasible else p.total_score * 0.15

            result.append({
                'module_name': p.module_name,
                'status': p.status,
                'base_score': round(p.total_score, 4),
                'dep_bonus': round(dep_bonus, 4),
                'feasible': in_feasible,
                'adjusted_score': round(adjusted, 4),
                'topo_depth': node.topo_depth if node else -1,
                'blocked_by': sorted(node.imports_from - self.scheduler._available)
                if node and not in_feasible else [],
                'reason': p.reason,
            })

        result.sort(key=lambda r: (-r['adjusted_score'], r['module_name']))
        for i, r in enumerate(result, start=1):
            r['rank'] = i
        return result

    def implementation_backlog(self, n: int = None) -> list[str]:
        """返回拓扑可行的实现积压清单（模块名）。"""
        feasible = self.scheduler.feasible_set()
        base_ranking = self.base.rank()
        ordered = [p.module_name for p in base_ranking if p.module_name in feasible]
        if n is not None:
            ordered = ordered[:n]
        return ordered


__all__ = [
    'DepNode', 'ModuleDependencyGraph',
    'TopologicalScheduler', 'DependencyAwarePrioritizer',
]
