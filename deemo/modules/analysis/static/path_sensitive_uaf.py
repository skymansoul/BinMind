# 路径敏感的UAF检测 (Path-Sensitive UAF Detection)
#
# 核心决策:
#   标准UAF检测在free后的所有使用都报UAF, 但free本身可能在
#   条件分支内(如错误处理路径), 而后续use在另一条路径上.
#   在不分析路径可行性时, 这种"伪UAF"产生大量误报.
#
#   本模块在free/use之间提取路径约束, 判定两者是否在同一
#   可行路径上. 若free和use被互斥的分支条件分隔,
# 则该UAF不可达 - 过滤此告警.
#
from typing import Dict, List, Optional, Set, Tuple

from .path_condition import PathConstraint, CondOp, JCC_TO_COND, PathConditionTracker
from .disasm_util import norm_reg, extract_func_name


# free系列函数
_FREE_FUNCS = {"free", "_ZdlPv", "_ZdaPv", "operator_delete", "g_free",
               "ExFreePool", "kfree", "vfree", "__builtin_free"}

# jcc指令对应的"跳转方向"
# taken=true时条件成立, fallthrough时条件不成立


class PathSensitiveUAF:
    """路径敏感的UAF检测增强.

    在现有UAF检测器基础上, 增加路径可行性验证:
    - free() 所在路径的条件约束
    - use() 所在路径的条件约束
    - 判定两条路径是否互斥

    仅过滤可证明不可达的free-use对 (sound filtering).
    """

    def __init__(self):
        self._path_tracker = PathConditionTracker()
        # free记录: addr → [(obj_reg, constraint_set_id)]
        self._free_sites: Dict[int, List[Tuple[str, int]]] = {}
        # 每个分支点的约束ID序列
        self._branch_seq = 0
        # 地址上的活跃约束快照: addr → set of constraint hashes
        self._addr_constraint_snap: Dict[int, Set[int]] = {}

    def feed_instruction(self, ins: dict):
        """逐指令馈入, 维护路径条件追踪."""
        mnem = ins.get("mnemonic", "").lower()
        ops = ins.get("operands", [])
        addr = ins.get("address", 0)

        # 检测 free() 调用
        if mnem == "call" and ops:
            func = extract_func_name(ops[0])
            if func in _FREE_FUNCS:
                # 记录当前路径约束快照
                self._free_sites.setdefault(addr, []).append(
                    (self._get_arg_reg(ops), self._branch_seq))

        # 路径条件追踪
        result = self._path_tracker.feed_instruction(ins)
        if result:
            taken, fallthrough = result
            self._branch_seq += 1
            # 记录两个分支的约束
            target = self._extract_jump_target(ins)
            if target:
                self._path_tracker.record_constraint_at(target, taken)

    def is_same_feasible_path(self, free_addr: int,
                               use_addr: int) -> bool:
        """检查free和use是否在同一可行路径上.

        返回 True 表示两者可达 (应保留告警).
        返回 False 表示路径互斥 (可安全过滤).
        """
        free_constraints = self._path_tracker.get_constraints(free_addr)
        use_constraints = self._path_tracker.get_constraints(use_addr)

        if not free_constraints and not use_constraints:
            return True  # 无约束信息, 保守保留

        # 合并检查矛盾: 若free的约束与use的约束互斥
        all_constraints = free_constraints + use_constraints
        by_reg: Dict[str, List[PathConstraint]] = {}
        for c in all_constraints:
            by_reg.setdefault(c.reg, []).append(c)

        for reg, cs in by_reg.items():
            lo_upper = 2**63
            hi_lower = -1
            for c in cs:
                narrowed = c.narrow(0, 2**31 - 1)
                lo_upper = min(lo_upper, narrowed[1])
                hi_lower = max(hi_lower, narrowed[0])
            if hi_lower > lo_upper:
                return False  # 矛盾: free和use不可能同时可达

        return True

    def free_on_conditional_path(self, free_addr: int) -> bool:
        """检查free是否在条件分支内 (非无条件路径)."""
        constraints = self._path_tracker.get_constraints(free_addr)
        return len(constraints) > 0

    def use_on_disjoint_path(self, free_addr: int,
                              use_addr: int) -> bool:
        """检查use是否在free的互斥路径上.

        返回 True 表示互斥 (可以过滤).
        """
        return not self.is_same_feasible_path(free_addr, use_addr)

    def get_constraint_summary(self, addr: int) -> str:
        """获取地址处的约束摘要 (调试用)."""
        cs = self._path_tracker.get_constraints(addr)
        if not cs:
            return "no constraints"
        return " ∧ ".join(str(c) for c in cs)

    @staticmethod
    def _get_arg_reg(ops: List[str]) -> str:
        if len(ops) >= 2:
            return norm_reg(ops[1])
        return "unknown"

    @staticmethod
    def _extract_jump_target(ins: dict) -> Optional[int]:
        ops = ins.get("operands", [])
        if not ops:
            return None
        target = ops[0].strip().lower().lstrip("%").replace("$", "")
        try:
            if target.startswith("0x"):
                return int(target, 16)
            return int(target)
        except ValueError:
            return None

    def reset(self):
        self._path_tracker.reset()
        self._free_sites.clear()
        self._branch_seq = 0
        self._addr_constraint_snap.clear()


__all__ = ["PathSensitiveUAF"]
