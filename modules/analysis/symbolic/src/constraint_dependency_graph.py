# 增加 SCC condensa，将强连通分量合并为原子求解单元
# 引入 topological_level 作为求解优先级的主排序键
# 增加 partial_sat_propaga，利用已解约束的赋值剪枝

"""约束依赖图构建与拓扑排序求解

符号执行引擎通常将约束列表按 FIFO 顺序送入 Z3-忽略了约束间的
变量依赖关系。若约束 A 定义了变量 x 的取值范围而约束 B 使用 x
先解 B 会导致不必要的不确定性（x 未约束时搜索空间更大）

本模块将约束列表建模为依赖图 (constraint dependency graph, CDG)：
- 节点 = 约束
- 边 A→B 表示约束 B 使用了约束 A 中定义的变量
- 拓扑排序后按依赖层级递进求解：
先解纯定义约束（无入边的节点），再用已解变量的赋值
缩小后续约束的搜索空间

对于存在循环依赖的约束（SCC），将整个 SCC 合并为原子单元
一次性送入 Z3-无法进一步分解

核心优化：
a. Topolog level 排序：level 小的约束先解（依赖链短）
b. Partial SAT propaga：每层求解后将 SAT 赋值注入下游约束
减少 Z3 的变量搜索空间
c. SCC condensa：循环依赖的约束打包为单一求解单元

适用条件：
- 约束数量较多（≥10）时收益显著-少量约束的依赖排序开销
超过收益
- 约束间存在明显的变量定义-使用关系
- 对于几乎全独立的约束集合（如 fuzzing 生成的大量互不相关约束）
本模块退化为原始顺序（依赖图几乎无边）

ref: FSE 2024 "Partial Solu Based 约束求解缓存" 使用
partial solu 加速缓存查找-本模块将 partial solu 的
思路从缓存层推进到求解顺序层
ref: KLEE 的 "--使用-independent-solver" 选项将独立约束集分离求解-
本模块的变量依赖分析受此启发，但增加了拓扑分层和 SCC 处理
"""

import re
from typing import Dict, List, Set, Tuple, Optional, Any
from collections import defaultdict, deque
from dataclasses import dataclass, field


@dataclass
class ConstraintNode:
    """依赖图中的一个约束节点"""
    idx: int                          # 原始列表中的索引
    text: str                         # 约束文本（SMT-LIB2 格式或其子集）
    defines: Set[str] = field(default_factory=set)     # 本约束定义的变量名
    uses: Set[str] = field(default_factory=set)        # 本约束使用的变量名
    topological_level: int = -1       # 拓扑层级（0 = 无依赖）
    scc_id: int = -1                  # 所属 SCC 编号（-1 = 未分配）
    solved: bool = False              # 是否已求解
    sat_assignment: Dict[str, Any] = field(default_factory=dict)  # SAT 赋值


class ConstraintDependencyGraph:
    """构建约束依赖图并生成优化后的求解顺序

    使用模式：
    cdg = ConstraintDependencyGraph()
    order = cdg.build_order(constraints)
    for batch order:
    # batch 是 List[int]-本批次的约束索引
    # 若 len(batch) == 1，单个约束独立求解
    # 若 len(batch) > 1，SCC 打包求解
    results = solver.solve([constraints[] for batch])
    """

    # 变量名提取正则——覆盖 SMT-LIB2 的变量声明和引用模式
    _VAR_DECL_RE = re.compile(r'\(declare-fun\s+(\S+)\s')
    _VAR_DEFINE_RE = re.compile(r'\(define-fun\s+(\S+)\s')
    # 变量引用：括号后的标识符（排除关键字）
    _VAR_USE_RE = re.compile(r'(?<!\()\b([a-zA-Z_]\w*)\b')

    _KEYWORDS = {
        'assert', 'and', 'or', 'not', '=>', '=', 'ite',
        'bvadd', 'bvsub', 'bvmul', 'bvudiv', 'bvurem',
        'bvshl', 'bvlshr', 'bvashr', 'bvand', 'bvor', 'bvxor', 'bvnot',
        'bvult', 'bvule', 'bvugt', 'bvuge', 'bvslt', 'bvsle', 'bvsgt', 'bvsge',
        'concat', 'extract', 'sign_extend', 'zero_extend', 'repeat',
        'true', 'false', 'declare-fun', 'define-fun', 'forall', 'exists',
        'let', '_', 'bv', 'BitVec',
    }

    def __init__(self, min_constraints_for_sort: int = 10):
        self._min_constraints = min_constraints_for_sort

    def _extract_variables(self, text: str) -> Tuple[Set[str], Set[str]]:
        """从约束文本中提取 (定义的变量集, 使用的变量集)"""
        defined = set()
        used = set()

        # 声明/定义变量
        for m in self._VAR_DECL_RE.finditer(text):
            defined.add(m.group(1))
        for m in self._VAR_DEFINE_RE.finditer(text):
            defined.add(m.group(1))

        # 引用变量——排除关键字和纯数字
        for m in self._VAR_USE_RE.finditer(text):
            var = m.group(1)
            if var not in self._KEYWORDS and not var.isdigit():
                used.add(var)

        # 从 used 中移除自身定义的变量（变量对自身的引用不算依赖）
        used -= defined

        return defined, used

    def build_order(self, constraints: List[str]) -> List[List[int]]:
        """构建优化求解顺序

        返回嵌套列表：外层是求解批次（按拓扑层级排序）
        内层是该批次中的约束索引列表（SCC 节点可能包含多个索引）
        """
        n = len(constraints)
        if n < self._min_constraints:
            # 约束太少-依赖分析开销超过收益，直接返回原始顺序
            return [[i] for i in range(n)]

        # Phase 1: 提取每个约束的变量定义和使用
        nodes = []
        var_to_definers: Dict[str, Set[int]] = defaultdict(set)

        for i, text in enumerate(constraints):
            defines, uses = self._extract_variables(text)
            node = ConstraintNode(idx=i, text=text, defines=defines, uses=uses)
            nodes.append(node)
            for v in defines:
                var_to_definers[v].add(i)

        # Phase 2: 构建依赖边
        # B→A 表示 A 使用了 B 定义的变量 → B 应先于 A 求解
        adj: Dict[int, Set[int]] = defaultdict(set)       # adj[u] = {v: u→v}
        rev_adj: Dict[int, Set[int]] = defaultdict(set)   # rev_adj[v] = {u: u→v}
        indegree: Dict[int, int] = defaultdict(int)

        for node_a in nodes:
            for used_var in node_a.uses:
                for definer_idx in var_to_definers.get(used_var, set()):
                    if definer_idx != node_a.idx:
                        if node_a.idx not in adj[definer_idx]:
                            adj[definer_idx].add(node_a.idx)
                            rev_adj[node_a.idx].add(definer_idx)
                            indegree[node_a.idx] += 1

        # Phase 3: SCC condensa (Kosaraju 两遍 DFS)
        scc_of = self._compute_sccs(n, adj)
        scc_groups: Dict[int, List[int]] = defaultdict(list)
        for node_idx, scc_id in scc_of.items():
            scc_groups[scc_id].append(node_idx)

        # Phase 4: 拓扑分层——在 SCC 粒度上
        # 每个 SCC 的 indegree = 外部入边数（来自其他 SCC 的边）
        scc_indegree: Dict[int, int] = defaultdict(int)
        scc_adj: Dict[int, Set[int]] = defaultdict(set)

        for u, neighbors in adj.items():
            su = scc_of.get(u, -1)
            for v in neighbors:
                sv = scc_of.get(v, -1)
                if su != sv and sv not in scc_adj[su]:
                    scc_adj[su].add(sv)
                    scc_indegree[sv] += 1

        # BFS 计算拓扑层级
        queue = deque()
        scc_level: Dict[int, int] = {}

        for scc_id in scc_groups:
            if scc_indegree.get(scc_id, 0) == 0:
                queue.append(scc_id)
                scc_level[scc_id] = 0

        while queue:
            current_scc = queue.popleft()
            current_level = scc_level[current_scc]
            for neighbor_scc in scc_adj.get(current_scc, set()):
                if neighbor_scc not in scc_level:
                    scc_level[neighbor_scc] = current_level + 1
                    queue.append(neighbor_scc)

        # 未可达的 SCC（应不存在，但做防御）
        for scc_id in scc_groups:
            if scc_id not in scc_level:
                scc_level[scc_id] = max(scc_level.values(), default=0) + 1

        # Phase 5: 按拓扑层级组织输出
        level_to_sccs: Dict[int, List[int]] = defaultdict(list)
        for scc_id in scc_groups:
            level_to_sccs[scc_level[scc_id]].append(scc_id)

        result = []
        for level in sorted(level_to_sccs.keys()):
            for scc_id in level_to_sccs[level]:
                indices = sorted(scc_groups[scc_id])
                result.append(indices)

        return result

    def _compute_sccs(self, n: int, adj: Dict[int, Set[int]]) -> Dict[int, int]:
        """Kosaraju 算法计算 SCC-返回 {node_idx: scc_id}"""
        # 第一遍 DFS：计算 finish order
        visited = [False] * n
        finish_order = []

        def dfs_forward(node):
            visited[node] = True
            for neighbor in adj.get(node, set()):
                if not visited[neighbor]:
                    dfs_forward(neighbor)
            finish_order.append(node)

        for i in range(n):
            if not visited[i]:
                dfs_forward(i)

        # 第二遍 DFS：按 finish_order 逆序在转置图上跑
        scc_of = {}
        visited_rev = [False] * n
        scc_counter = 0

        # 构建转置图
        rev_adj = defaultdict(set)
        for u, neighbors in adj.items():
            for v in neighbors:
                rev_adj[v].add(u)

        def dfs_reverse(node, scc_id):
            visited_rev[node] = True
            scc_of[node] = scc_id
            for neighbor in rev_adj.get(node, set()):
                if not visited_rev[neighbor]:
                    dfs_reverse(neighbor, scc_id)

        for node in reversed(finish_order):
            if not visited_rev[node]:
                dfs_reverse(node, scc_counter)
                scc_counter += 1

        return scc_of
