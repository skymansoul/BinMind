# UAF路径可行性验证 — guard条件区间交 → 消除不可达路径UAF误报
"""UAF路径可行性验证器。

free路径的守卫条件(如 ptr!=NULL)与use路径守卫条件
(如 ptr==NULL)若矛盾(交集为空), 则free和use不可能在同一执行路径共存
→ 过滤此UAF。基于cmp+jcc→区间约束→交集检查, 与heap_path_sensitivity.py
共用GuardKind/区间交运算。
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from enum import Enum, auto

_log = logging.getLogger(__name__)


class GuardKind(str, Enum):
    """条件跳转的语义类型。"""
    CMP_JA = "cmp_ja"       # 无符号大于 (above)
    CMP_JBE = "cmp_jbe"     # 无符号小于等于
    CMP_JG = "cmp_jg"       # 有符号大于
    CMP_JLE = "cmp_jle"     # 有符号小于等于
    CMP_JE = "cmp_je"       # 等于/零
    CMP_JNE = "cmp_jne"     # 不等于/非零
    TEST_JZ = "test_jz"     # test结果为0
    TEST_JNZ = "test_jnz"   # test结果非0
    CMP_JS = "cmp_js"       # 符号位 (negative)
    CMP_JNS = "cmp_jns"     # 无符号位
    UNKNOWN = "unknown"


@dataclass
class GuardConstraint:
    """从cmp+jcc提取的约束。"""
    kind: GuardKind = GuardKind.UNKNOWN
    reg: str = ""            # 被比较的寄存器
    bound: int = 0           # 比较值
    line: int = -1           # 所在行
    # 此约束对寄存器的区间效应
    lower: int = 0           # 约束施加的下界 (含)
    upper: int = 2**63 - 1   # 约束施加的上界 (含)
    # 约束来自的方向 (在free路径上 → 'free', 在use路径上 → 'use')
    direction: str = ""


@dataclass
class PathFeasibilityVerdict:
    """UAF路径可行性判定。"""
    feasible: bool = True
    reason: str = ""
    # 区间交运算的中间结果
    free_interval: Tuple[int, int] = (0, 0)
    use_interval: Tuple[int, int] = (0, 0)
    intersection_empty: bool = False
    contradiction_source: str = ""


# cmp+jcc → GuardConstraint

# 匹配: cmp reg, N 或 cmp reg, N (objdump中逗号可能在也可能不在)
_CMP_REG_IMM = re.compile(r'\bcmp\s+(\w+),?\s*(0x[0-9a-f]+|\d+)', re.I)
# 匹配: test reg, reg
_TEST_REG = re.compile(r'\btest\s+(\w+),?\s*\w+', re.I)
# 匹配后续的 jcc
_JCC = re.compile(r'\b(j[a-z]{1,3})\s+', re.I)


def _extract_guard_kind(cmp_line: str, jcc_line: str) -> GuardKind:
    """从cmp和jcc指令中提取guard类型。"""
    jcc_m = _JCC.search(jcc_line)
    if not jcc_m:
        return GuardKind.UNKNOWN
    jcc = jcc_m.group(1).lower()
    if 'cmp' in cmp_line.lower():
        return {
            'ja': GuardKind.CMP_JA, 'jb': GuardKind.CMP_JA,
            'jbe': GuardKind.CMP_JBE, 'jna': GuardKind.CMP_JBE,
            'jg': GuardKind.CMP_JG, 'jge': GuardKind.CMP_JG,
            'jle': GuardKind.CMP_JLE, 'jl': GuardKind.CMP_JLE,
            'je': GuardKind.CMP_JE, 'jz': GuardKind.CMP_JE,
            'jne': GuardKind.CMP_JNE, 'jnz': GuardKind.CMP_JNE,
            'js': GuardKind.CMP_JS, 'jns': GuardKind.CMP_JNS,
        }.get(jcc, GuardKind.UNKNOWN)
    if 'test' in cmp_line.lower():
        return {
            'je': GuardKind.TEST_JZ, 'jz': GuardKind.TEST_JZ,
            'jne': GuardKind.TEST_JNZ, 'jnz': GuardKind.TEST_JNZ,
        }.get(jcc, GuardKind.UNKNOWN)
    return GuardKind.UNKNOWN


def _constraint_to_interval(c: GuardConstraint) -> Tuple[int, int]:
    """将约束映射到该寄存器值的存活区间。"""
    N = c.bound
    kind = c.kind
    if kind == GuardKind.CMP_JA:
        # 无符号大于N → 区间 (N, ∞)
        return (N + 1, 2**63 - 1)
    elif kind == GuardKind.CMP_JBE:
        # 无符号小于等于N → 区间 [0, N]
        return (0, N)
    elif kind == GuardKind.CMP_JG:
        return (N + 1, 2**63 - 1)
    elif kind == GuardKind.CMP_JLE:
        return (0, N)
    elif kind == GuardKind.CMP_JE or kind == GuardKind.TEST_JZ:
        return (N, N)  # 等于N → 精确值
    elif kind == GuardKind.CMP_JNE or kind == GuardKind.TEST_JNZ:
        # 不等于N → 排除N
        return (N + 1, 2**63 - 1) if N == 0 else (0, N - 1)
    elif kind == GuardKind.CMP_JS:
        return (0, 0)  # 符号位=1 → 负数, 对无符号指针无意义
    elif kind == GuardKind.CMP_JNS:
        return (0, 2**63 - 1)
    return (0, 2**63 - 1)


def _interval_intersect(a: Tuple[int, int], b: Tuple[int, int]) -> Optional[Tuple[int, int]]:
    """两个区间的交集, 若为空返回None。"""
    lo = max(a[0], b[0])
    hi = min(a[1], b[1])
    return (lo, hi) if lo <= hi else None


# UAFPathVerifier

class UAFPathVerifier:
    """UAF路径可行性验证器 — guard约束交集判定free→use路径是否可达。"""

    def verify(self, path) -> PathFeasibilityVerdict:
        """验证单条FreeUsePath的可行性。
        path: FreeUsePath (from uaf_demand_driven)
        """
        verdict = PathFeasibilityVerdict()

        # 提取free路径上的约束 (alloc→free)
        free_constraints = self._parse_constraints(
            path.alloc_to_free_guards, direction='free')

        # 提取use路径上的约束 (free→use)
        use_constraints = self._parse_constraints(
            path.free_to_use_guards, direction='use')

        if not free_constraints and not use_constraints:
            # 无约束 → 无法判定不可行 → 保守保留
            verdict.feasible = True
            verdict.reason = "无guard约束, 保守保留"
            return verdict

        # 计算两个方向约束的交集
        free_interval = self._merge_constraints(free_constraints)
        use_interval = self._merge_constraints(use_constraints)

        verdict.free_interval = free_interval
        verdict.use_interval = use_interval

        # 交集检查
        intersection = _interval_intersect(free_interval, use_interval)
        if intersection is None:
            verdict.feasible = False
            verdict.intersection_empty = True
            verdict.contradiction_source = (
                f"free约束区间{free_interval} 与 use约束区间{use_interval} 交集为空")
            verdict.reason = "路径不可达: free和use路径互斥"
        else:
            verdict.feasible = True
            verdict.reason = f"交集{intersection}非空 → 路径可达"

        return verdict

    def _parse_constraints(self, guard_lines: List[str],
                           direction: str) -> List[GuardConstraint]:
        constraints = []
        for i, line in enumerate(guard_lines):
            ll = line.lower()
            cmp_m = _CMP_REG_IMM.search(ll)
            if cmp_m:
                reg = cmp_m.group(1)
                b = cmp_m.group(2)
                bound = int(b, 16) if b.lower().startswith('0x') else int(b)
                # 在后续行找jcc
                next_line = guard_lines[i + 1] if i + 1 < len(guard_lines) else line
                kind = _extract_guard_kind(line, next_line)
                if kind != GuardKind.UNKNOWN:
                    lo, hi = _constraint_to_interval(GuardConstraint(
                        kind=kind, reg=reg, bound=bound))
                    constraints.append(GuardConstraint(
                        kind=kind, reg=reg, bound=bound,
                        lower=lo, upper=hi, direction=direction))
                continue
            test_m = _TEST_REG.search(ll)
            if test_m:
                reg = test_m.group(1)
                next_line = guard_lines[i + 1] if i + 1 < len(guard_lines) else line
                kind = _extract_guard_kind(line, next_line)
                if kind != GuardKind.UNKNOWN:
                    lo, hi = _constraint_to_interval(GuardConstraint(
                        kind=kind, reg=reg, bound=0))
                    constraints.append(GuardConstraint(
                        kind=kind, reg=reg, bound=0,
                        lower=lo, upper=hi, direction=direction))
        return constraints

    def _merge_constraints(self, constraints: List[GuardConstraint]
                           ) -> Tuple[int, int]:
        """合并多个约束 → 最紧的区间。"""
        if not constraints:
            return (0, 2**63 - 1)

        lo, hi = 0, 2**63 - 1
        for c in constraints:
            lo = max(lo, c.lower)
            hi = min(hi, c.upper)
        return (lo, hi)


# 路径验证聚合

def filter_uaf_paths(dd_report, asm_lines=None) -> Tuple[List, float]:
    """对demand-driven报告的所有UAF路径执行可行性验证。
    返回: (verified_paths, fp_reduction_pct)
    """
    verifier = UAFPathVerifier()
    verified, filtered = 0, 0
    for path in dd_report.uaf_paths:
        v = verifier.verify(path)
        path.path_feasible = v.feasible
        path.feasibility_score = 1.0 if v.feasible else 0.0
        if v.feasible and not path.realloc_on_path:
            verified += 1
        else:
            filtered += 1
    total = len(dd_report.uaf_paths)
    return dd_report.uaf_paths, (filtered / total * 100) if total > 0 else 0.0
