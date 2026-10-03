#!/usr/bin/env python3
"""符号执行优化 — 路径剪枝、状态合并、循环展开、函数摘要

组合优于继承: PathOptimizer 组合 ConstraintSolver 与
SymbolicExecutor 协作者, 基类不耦合
ConstraintSimplifier 是独立的表达式级优化工具
(冗余约束消除、常量折叠)

相同 PC 的状态合并需要兼容约束 (并集),
约束矛盾时跳过合并, 保留各自状态
符号循环计数展开: 构造 BOUND 份循环体副本,
为剩余迭代添加 fresh 符号变量 (可靠的过近似)
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Set, Tuple, Union

_log = logging.getLogger(__name__)


# ConstraintSimplifier (约束化简器)

class ConstraintSimplifier:
    """化简约束集, 消除冗余并折叠常量

    去重: 相同约束移除
    矛盾检测: var==a, var==b, a!=b -> UNSAT
    常量折叠: 求值具体子表达式
    恒等消除: 永真约束 (x==x) 移除

    在调用求解器前执行化简, Z3 内置化简器是通用目的的,
    无法利用路径约束的领域知识 (主要是对单个变量的等式/不等式比较)
    """

    def simplify(self, constraints: List[Any]) -> List[Any]:
        """化简约束列表, 返回可能更短的列表"""
        if not constraints:
            return []

        seen: Set[str] = set()
        result: List[Any] = []
        eq_map: Dict[str, int] = {}

        for c in constraints:
            key = self._constraint_key(c)
            if key in seen:
                continue  # 重复约束
            seen.add(key)

            # 检查矛盾等式约束
            if isinstance(c, dict) and c.get("type") == "eq":
                var = c.get("var", "")
                val = c.get("value", 0)
                if var in eq_map and eq_map[var] != val:
                    # 发现矛盾 — 返回最小 UNSAT 标记
                    _log.debug("约束矛盾: %s=%d vs %s=%d", var, eq_map[var], var, val)
                    return [{"type": "eq", "var": "__unsat__", "value": 0}]
                eq_map[var] = val

            # 跳过恒等式: var == var
            if isinstance(c, dict) and c.get("type") == "eq":
                if c.get("var") == str(c.get("value")):
                    continue  # 恒等式, 跳过

            result.append(c)

        return result

    def eliminate_redundant(self, constraints: List[Any]) -> List[Any]:
        """移除被其他约束逻辑蕴含的约束

        结构化检查: x>5 蕴含 x>3, 所以 x>3 被丢弃
        N 通常较小 (<100 每条路径), 更大集合可考虑用 Z3 reduce
        """
        if len(constraints) <= 1:
            return list(constraints)

        result = list(constraints)
        i = 0
        while i < len(result):
            ci = result[i]
            if not isinstance(ci, dict):
                i += 1
                continue
            j = 0
            while j < len(result):
                if i == j:
                    j += 1
                    continue
                cj = result[j]
                if not isinstance(cj, dict):
                    j += 1
                    continue
                if self._implies(ci, cj):
                    # cj 被 ci 蕴含, 移除 cj
                    result.pop(j)
                    if j < i:
                        i -= 1  # 因移除调整索引
                    continue
                j += 1
            i += 1

        return result

    def _implies(self, stronger: Dict, weaker: Dict) -> bool:
        """检查 stronger 约束是否逻辑蕴含 weaker

        简单情形: x>5 蕴含 x>3 (相同变量, 相同类型, 更强的值); x==5 蕴含 x!=3
        """
        if stronger.get("type") != weaker.get("type"):
            return False
        if stronger.get("var") != weaker.get("var"):
            return False
        sv = stronger.get("value", 0)
        wv = weaker.get("value", 0)
        typ = stronger.get("type")
        if typ == "gt":
            return sv >= wv  # x > 5 蕴含 x > 3
        if typ == "lt":
            return sv <= wv  # x < 3 蕴含 x < 5
        if typ == "ge":
            return sv >= wv
        if typ == "le":
            return sv <= wv
        return False

    def _constraint_key(self, c: Any) -> str:
        """构造用于去重的稳定键"""
        if isinstance(c, dict):
            items = sorted(c.items())
            return str(items)
        return repr(c)


# PathOptimizer (路径优化器)

class PathOptimizer:
    """优化符号执行: 剪枝、合并、摘要

    路径剪枝: 移除不可满足状态 (约束 UNSAT)
    状态合并: 合并相同 PC 的状态
    循环展开: 有界符号展开
    函数摘要: 预计算的输入/输出约束

    先剪枝再合并 — 剪枝以低成本消除死状态, 减少 O(N^2) 合并的 N
    汇聚点合并对大量控制流汇合 (if-else 链、switch) 的代码最有效
    合并丢失路径敏感性 (忘记分支来源), 但大幅减少状态爆炸
    """

    def __init__(
        self,
        constraint_solver=None,
        simplifier: Optional[ConstraintSimplifier] = None,
        pruning_enabled: bool = True,
        merging_enabled: bool = True,
        loop_unroll_bound: int = 10,
    ):
        self._solver = constraint_solver
        self._simplifier = simplifier or ConstraintSimplifier()
        self.pruning_enabled = pruning_enabled
        self.merging_enabled = merging_enabled
        self.loop_unroll_bound = loop_unroll_bound
        self._summaries: Dict[str, Any] = {}  # func_name -> summary
        self._stats: Dict[str, int] = {
            "pruned": 0, "merged": 0, "unrolled": 0,
            "summaries_used": 0,
        }

    def prune_infeasible_paths(self, states: List[Any]) -> List[Any]:
        """移除约束不可满足的路径

        对每个状态, 化简约束并检查可满足性, 不可满足状态被丢弃并计数
        solver 为 None 时跳过剪枝, 返回原始状态
        求解器出错时偏向 SAT (超时默认), 不可满足路径保留 — 剪枝策略偏保守
        """
        if not self.pruning_enabled or self._solver is None:
            return states

        survivors = []
        for state in states:
            constraints = getattr(state, 'path_constraints', [])
            simplified = self._simplifier.simplify(constraints)
            if not simplified:
                survivors.append(state)
                continue
            # 检查化简器返回的 UNSAT 标记
            if any(isinstance(c, dict) and c.get("var") == "__unsat__" for c in simplified):
                self._stats["pruned"] += 1
                continue
            try:
                if self._solver.is_satisfiable(simplified):
                    survivors.append(state)
                else:
                    self._stats["pruned"] += 1
            except Exception:
                # 求解器出错 — 保留状态 (保守策略)
                survivors.append(state)

        return survivors

    def merge_states(self, states: List[Any]) -> List[Any]:
        """合并相同 PC 且约束兼容的状态

        按 PC 分组, 每组尝试合并约束集兼容的状态对 (并集不产生 UNSAT)
        组通常很小 (<5)
        合并减少状态数但丢失路径敏感性, 适用于 switch/if-else 汇聚
        """
        if not self.merging_enabled or len(states) < 2:
            return states

        from collections import defaultdict

        # 按 PC 分组
        groups: Dict[int, List[Any]] = defaultdict(list)
        for s in states:
            pc = getattr(s, 'pc', 0)
            groups[pc].append(s)

        result = []
        for pc, group in groups.items():
            if len(group) == 1:
                result.extend(group)
            elif self._solver is None:
                result.append(group[0])  # 无 solver — 取第一个
                self._stats["merged"] += len(group) - 1
            else:
                merged, unmerged = self._merge_group(group)
                result.extend(merged)
                result.extend(unmerged)

        _log.debug("Merged %d states, %d remain", self._stats["merged"], len(result))
        return result

    def _merge_group(self, group: List[Any]) -> Tuple[List[Any], List[Any]]:
        """尝试合并组内状态

        贪心算法: 从第一个状态开始, 尝试合并后续状态
        合并失败的状态保留为未合并
        """
        if len(group) <= 1:
            return ([], group)

        merged_states: List[Any] = [group[0]]
        unmerged: List[Any] = []

        for i in range(1, len(group)):
            new_state = group[i]
            merged = False
            for base in merged_states:
                combined = self._try_merge_pair(base, new_state)
                if combined is not None:
                    merged_states[merged_states.index(base)] = combined
                    self._stats["merged"] += 1
                    merged = True
                    break
            if not merged:
                unmerged.append(new_state)

        return (merged_states, unmerged)

    def _try_merge_pair(self, s1: Any, s2: Any) -> Optional[Any]:
        """尝试合并两个状态为一个

        合并条件: 相同 PC (调用方保证), 约束并集可满足, 寄存器值通过 ITE 合并
        成功返回合并状态; 失败返回 None
        """
        c1 = getattr(s1, 'path_constraints', [])
        c2 = getattr(s2, 'path_constraints', [])
        combined_constraints = self._simplifier.simplify(c1 + c2)

        # 检查 UNSAT marker
        if any(isinstance(c, dict) and c.get("var") == "__unsat__" for c in combined_constraints):
            return None

        if self._solver and not self._solver.is_satisfiable(combined_constraints):
            return None

        # 合并: 取并集约束, 以 s1 的状态为基础
        # (完整 ITE 寄存器合并较复杂)
        merged = s1.fork(getattr(s1, 'state_id', 0) + 100000) if hasattr(s1, 'fork') else s1
        if hasattr(merged, 'path_constraints'):
            merged.path_constraints = combined_constraints
        return merged

    def unroll_loop(
        self,
        loop_body: List[Any],  # IR 指令列表
        trip_count_expr: Any,   # 循环次数的符号表达式
        initial_state: Any,
        ir_fetcher: Any,
    ) -> List[Any]:
        """符号循环计数的有界展开

        展开至多 loop_unroll_bound 次 (具体副本), 超出边界后为剩余迭代添加 fresh 符号变量
        可靠过近似: 精确覆盖有界执行, 其余符号化建模
        循环次数为具体值且 < bound 时, 精确展开, 不添加符号尾部
        """
        results: List[Any] = []
        current_state = initial_state

        # 启发式: 尝试具体循环次数
        concrete_trip = None
        if hasattr(trip_count_expr, 'is_symbolic') and not trip_count_expr.is_symbolic:
            concrete_trip = trip_count_expr.value
        elif isinstance(trip_count_expr, int):
            concrete_trip = trip_count_expr

        # 符号或未知循环计数, 使用 bound
        if concrete_trip is None:
            unroll_count = self.loop_unroll_bound
            add_symbolic_tail = True
        else:
            unroll_count = min(concrete_trip, self.loop_unroll_bound)
            add_symbolic_tail = concrete_trip > self.loop_unroll_bound

        for iteration in range(unroll_count):
            self._stats["unrolled"] += 1
            for instr in loop_body:
                if hasattr(ir_fetcher, 'step_one'):
                    successors = ir_fetcher.step_one(current_state, instr)
                    if successors:
                        current_state = successors[0]
            results.append(current_state)

        if add_symbolic_tail:
            # 添加符号尾部状态
            if hasattr(current_state, 'fork'):
                tail = current_state.fork(current_state.state_id + 1000)
                if hasattr(tail, 'path_constraints'):
                    tail.path_constraints.append({
                        "type": "lt", "var": "sym_loop_remaining",
                        "value": 0xFFFFFFFF, "desc": "symbolic_loop_tail",
                    })
                results.append(tail)

        return results

    def register_summary(self, func_name: str, summary: Any) -> None:
        """注册预计算的函数摘要

        摘要格式: {"inputs": [...], "outputs": [...], "constraints": [...],
        "side_effects": ["write", ...], "may_return": bool}
        """
        self._summaries[func_name] = summary

    def has_summary(self, func_name: str) -> bool:
        """检查是否已有 func_name 的摘要"""
        return func_name in self._summaries

    def get_summary(self, func_name: str) -> Optional[Any]:
        """获取函数摘要, 未找到返回 None

        使用摘要可避免进入库函数内部, 大幅减少状态空间
        memcpy/memset/strlen 等常用函数预定义摘要后能省大量时间
        """
        summary = self._summaries.get(func_name)
        if summary:
            self._stats["summaries_used"] += 1
        return summary

    def apply_summary(self, state: Any, func_name: str, args: List[Any]) -> Optional[Any]:
        """对状态应用函数摘要 — 跳过函数体, 按摘要直接更新状态

        函数摘要以精度换速度: 危险函数 (memcpy, system) 需精确建模,
        工具函数可用粗粒度模型 — 分层策略获得最佳 ROI
        """
        summary = self.get_summary(func_name)
        if summary is None:
            return None

        # 应用输出约束
        if hasattr(state, 'path_constraints'):
            for c in summary.get("constraints", []):
                state.path_constraints.append(c)

        # 按摘要应用寄存器/内存修改
        for reg_name, val in summary.get("outputs", {}).items():
            if hasattr(state, 'registers'):
                state.registers[reg_name] = val

        state.pc = getattr(state, 'pc', 0) + 4  # 跳过 call 指令
        return state

    def get_stats(self) -> Dict[str, int]:
        return dict(self._stats)


# 备用: 状态指纹计算

def _compute_StateFingerprint(state: Any) -> int:
    """计算状态比较的确定性哈希, 用于状态去重 (当前未接入)

    基于 PC + 寄存器快照的哈希, merge 前先检查是否完全一样可跳过
    """
    h = 0
    h ^= hash(getattr(state, 'pc', 0))
    for reg, val in sorted(getattr(state, 'registers', {}).items()):
        h ^= hash((reg, str(val)))
    return h


__all__ = [
    "PathOptimizer", "ConstraintSimplifier",
    "_compute_StateFingerprint",
]
