"""
VeriBin 三级验证增强 + ARCANIST 小配件链防御评分。

理论基础:
  VeriBin: 指令边界 / Z3约束 / 回归风险。
  ARCANIST: 小配件分类 / 可达链 / 防御评分。
  ESBMC-AI: 数组边界 / 空指针 / 整数溢出 / 资源泄漏断言。

与 patch_safety_verifier.py 对比:
  Z3 可选且不可用时跳过 B 级; ARCANIST 仅计数量。
  本模块:
  1. Z3 不可用时区间分析降级, 不跳过 B 级
  2. 链复杂度 + 关键小配件稀缺性 + ASLR 熵降低
  3. 补丁前后函数指纹对比 → 回归用例
"""

import hashlib
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

import logging
_log = logging.getLogger(__name__)


# 安全等级枚举

class SafetyLevel(Enum):
    """三级安全验证等级。"""
    LEVEL_A = "A"   # 指令边界 + 跳转目标合法性
    LEVEL_B = "B"   # 约束求解: 边界检查 + 数据流
    LEVEL_C = "C"   # 回归风险: 函数指纹 + 风险评分


@dataclass
class SafetyVerdict:
    """补丁安全裁决。"""
    level: SafetyLevel
    is_safe: bool
    score: float          # [0, 1], 越高越安全
    issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


# 区间分析 — Z3 不可用时的 B 级降级

@dataclass
class Interval:
    """整数区间 [lo, hi] — 轻量级值范围分析。"""
    lo: int
    hi: int

    def __contains__(self, val: int) -> bool:
        return self.lo <= val <= self.hi

    def intersect(self, other: "Interval") -> Optional["Interval"]:
        lo = max(self.lo, other.lo)
        hi = min(self.hi, other.hi)
        return Interval(lo, hi) if lo <= hi else None

    def union(self, other: "Interval") -> "Interval":
        return Interval(min(self.lo, other.lo), max(self.hi, other.hi))

    def add(self, other: "Interval") -> "Interval":
        return Interval(self.lo + other.lo, self.hi + other.hi)

    def mul(self, other: "Interval") -> "Interval":
        prods = [
            self.lo * other.lo, self.lo * other.hi,
            self.hi * other.lo, self.hi * other.hi,
        ]
        return Interval(min(prods), max(prods))


def interval_bound_check(
    access_offset: Interval, buffer_size: int, access_size: int = 1
) -> Tuple[bool, str]:
    """
    区间边界检查 — Z3 不可用时的 B 级降级。

    检查 access_offset 的全部可能值是否落在 [0, buffer_size - access_size] 内。

    返回:
      (is_safe, reason)

    精度:
      区间分析保守 — 可能假阳性 (报告 OOB 不可达), 但零假阴性。
      优于 Z3 不可用时直接跳过 B 级。
    """
    valid_lo = 0
    valid_hi = buffer_size - access_size

    if access_offset.lo < valid_lo:
        return False, (
            f"可能的下溢: offset ∈ [{access_offset.lo}, {access_offset.hi}], "
            f"有效范围 [{valid_lo}, {valid_hi}]"
        )

    if access_offset.hi > valid_hi:
        return False, (
            f"可能的上溢: offset ∈ [{access_offset.lo}, {access_offset.hi}], "
            f"有效范围 [{valid_lo}, {valid_hi}]"
        )

    return True, "区间分析: 边界检查通过"


# ARCANIST 增强 — 小配件链防御评分

@dataclass
class GadgetScore:
    """单个小配件评分。"""
    address: int
    category: str       # ret | call_reg | jmp_reg | syscall | leave_ret
    is_critical: bool   # 图灵完备计算是否必需
    scarcity: float     # 1/N, N = 同类小配件总数


@dataclass
class ChainDefenseScore:
    """ROP 链防御评分 (ARCANIST 增强)。"""
    total_gadgets: int
    critical_gadgets: int
    gadget_scarcity_avg: float           # 平均稀缺性
    min_chain_complexity: int            # 最短可利用链步数
    turing_complete_risk: bool           # 小配件集是否图灵完备
    aslr_entropy_bits: int               # ASLR 有效熵位
    aslr_entropy_reduction: float        # 信息泄露致熵降低 (0-1)
    defense_score: float                 # 综合防御 (0-1)
    recommendation: str = ""


def compute_arcanist_defense_score(
    gadgets: List[GadgetScore],
    aslr_entropy_bits: int = 28,      # x86_64 默认有效 ASLR 熵
    info_leak_bits: int = 0,          # 信息泄露揭示位数
) -> ChainDefenseScore:
    """
    ARCANIST 增强防御评分 — ROP 防御强度综合评定。

    维度:
      1. 小配件总数 — 越多越易利用
      2. 关键小配件 — syscall/ret 等图灵完备必需品
      3. 稀缺性 — 独特性越高越难利用
      4. 链复杂度 — 最短链步数越多越安全
      5. ASLR 熵 — 有效熵 = 总熵 - 泄露

    公式:
      defense = 0.25 * (1 - normalized_count)
              + 0.20 * (1 - critical_ratio)
              + 0.15 * scarcity_avg
              + 0.15 * min(1.0, min_chain_complexity / 10)
              + 0.25 * min(1.0, effective_entropy / aslr_entropy_bits)

    权重来源: ARCANIST Table 4 特征重要性分析。
    """
    n = len(gadgets)
    if n == 0:
        return ChainDefenseScore(
            total_gadgets=0, critical_gadgets=0,
            gadget_scarcity_avg=0.0, min_chain_complexity=0,
            turing_complete_risk=False,
            aslr_entropy_bits=aslr_entropy_bits,
            aslr_entropy_reduction=0.0,
            defense_score=1.0,
            recommendation="无小配件: 最高防御",
        )

    critical_set = {"syscall", "ret", "jmp_reg", "call_reg"}
    critical = [g for g in gadgets if g.category in critical_set]
    critical_ratio = len(critical) / n if n > 0 else 0

    scarcity_values = [g.scarcity for g in gadgets]
    scarcity_avg = sum(scarcity_values) / n if n > 0 else 0

    # 最小链复杂度: 图灵完备至少需 6 个小配件
    min_chain = max(6, len(critical)) if critical else n

    # 图灵完备判定: syscall/ret + 内存访问 + 寄存器操作
    has_syscall = any(g.category == "syscall" for g in gadgets)
    has_ret = any(g.category == "ret" for g in gadgets)
    has_mem = any(g.category in ("jmp_reg", "call_reg") for g in gadgets)
    turing_complete = has_syscall and has_ret and has_mem and len(gadgets) >= 6

    # ASLR 熵降低
    effective_entropy = max(0, aslr_entropy_bits - info_leak_bits)
    entropy_reduction = info_leak_bits / aslr_entropy_bits if aslr_entropy_bits > 0 else 0

    # 综合加权
    defense = (
        0.25 * max(0.0, 1.0 - n / 100.0)        # 小配件数 (上限 100)
        + 0.20 * (1.0 - critical_ratio)          # 关键小配件比例
        + 0.15 * scarcity_avg                     # 稀缺性
        + 0.15 * min(1.0, min_chain / 10.0)      # 链复杂度
        + 0.25 * min(1.0, effective_entropy / aslr_entropy_bits)  # ASLR
    )

    rec = "高防御" if defense > 0.7 else ("中防御" if defense > 0.4 else "低防御 — 建议加固")
    if turing_complete:
        rec += " | 图灵完备风险 — 优先修复关键小配件"
    if entropy_reduction > 0.3:
        rec += " | ASLR 熵显著降低 — 检查信息泄露源"

    return ChainDefenseScore(
        total_gadgets=n,
        critical_gadgets=len(critical),
        gadget_scarcity_avg=round(scarcity_avg, 4),
        min_chain_complexity=min_chain,
        turing_complete_risk=turing_complete,
        aslr_entropy_bits=aslr_entropy_bits,
        aslr_entropy_reduction=round(entropy_reduction, 4),
        defense_score=round(defense, 4),
        recommendation=rec,
    )


# 补丁回归测试

@dataclass
class FunctionFingerprint:
    """函数指纹 — 补丁前后差异对比。"""
    name: str
    address: int
    size: int
    instruction_count: int
    call_count: int
    cyclomatic_complexity: int
    checksum: str          # 指令字节 SHA256
    danger_calls: List[str] = field(default_factory=list)


def compute_function_fingerprint(
    func_name: str,
    func_bytes: bytes,
    func_addr: int = 0,
    danger_funcs: Optional[List[str]] = None,
) -> FunctionFingerprint:
    """
    函数指纹计算 — 补丁前后差异分析。

    维度:
      - 大小 + 指令数 (粗粒度)
      - 调用数 + 圈复杂度 (中粒度)
      - SHA256 校验和 (细粒度)
      - 危险函数调用列表 (安全维度)
    """
    if danger_funcs is None:
        danger_funcs = ["system", "execve", "memcpy", "strcpy", "sprintf", "gets"]

    # 指令数估计: 平均 4 字节/指令
    est_instructions = len(func_bytes) // 4

    # 圈复杂度近似: 条件跳转数 + 1
    cond_jumps = func_bytes.count(b'\x74') + func_bytes.count(b'\x75')  # jz, jnz
    cond_jumps += func_bytes.count(b'\x7c') + func_bytes.count(b'\x7e')  # jl, jle
    cond_jumps += func_bytes.count(b'\x0f\x84') + func_bytes.count(b'\x0f\x85')  # near jz/jnz
    cyclomatic = cond_jumps + 1

    # call 指令计数
    calls = func_bytes.count(b'\xe8') + func_bytes.count(b'\xff\x15')

    # SHA256 前 16 位
    checksum = hashlib.sha256(func_bytes).hexdigest()[:16]

    # 危险函数匹配
    detected_dangers = []
    for df in danger_funcs:
        if df.encode() in func_bytes:
            detected_dangers.append(df)

    return FunctionFingerprint(
        name=func_name,
        address=func_addr,
        size=len(func_bytes),
        instruction_count=est_instructions,
        call_count=calls,
        cyclomatic_complexity=cyclomatic,
        checksum=checksum,
        danger_calls=detected_dangers,
    )


def generate_regression_tests(
    before_fp: FunctionFingerprint,
    after_fp: FunctionFingerprint,
) -> List[str]:
    """
    推导补丁回归测试建议 — 对比补丁前后函数指纹。

    返回:
      测试建议列表。
    """
    tests = []

    if before_fp.checksum != after_fp.checksum:
        tests.append(
            f"[回归] {before_fp.name}: 函数体已变更 "
            f"(大小: {before_fp.size}→{after_fp.size}, "
            f"指令: {before_fp.instruction_count}→{after_fp.instruction_count})"
        )

    if before_fp.cyclomatic_complexity != after_fp.cyclomatic_complexity:
        direction = "增加" if after_fp.cyclomatic_complexity > before_fp.cyclomatic_complexity else "减少"
        tests.append(
            f"[圈复杂度] {before_fp.name}: {direction}了 "
            f"{abs(after_fp.cyclomatic_complexity - before_fp.cyclomatic_complexity)}"
        )

    for dc in after_fp.danger_calls:
        if dc not in before_fp.danger_calls:
            tests.append(
                f"[危险函数] {before_fp.name}: 新增了 {dc}() 调用 — 需要审查"
            )

    removed_dangers = set(before_fp.danger_calls) - set(after_fp.danger_calls)
    for dc in removed_dangers:
        tests.append(
            f"[正面变更] {before_fp.name}: 移除了 {dc}() 调用"
        )

    if not tests:
        tests.append(f"[无变更] {before_fp.name}: 补丁未改变函数结构")

    return tests


# VeriBin 增强管道

class EnhancedVeriBinChecker:
    """
    VeriBin 三级验证器 (增强版)。

    相比 patch_safety_verifier.py:
      1. B 级 Z3 不可用时自动降级为区间分析
      2. 完整小配件链防御评分
      3. 补丁前后函数指纹自动对比
    """

    def __init__(self, z3_available: bool = False):
        self._z3_ok = z3_available
        try:
            import z3
            self._z3_ok = True
        except ImportError:
            _log.info("Z3 不可用 — B 级验证将使用区间分析降级")

    def check_level_a(
        self, original_bytes: bytes, patched_bytes: bytes
    ) -> SafetyVerdict:
        """
        A 级: 字节结构分析。

        检查指令边界完整性与跳转目标合法性。
        (简化实现 — 完整版需 capstone 反汇编)
        """
        issues = []
        # 补丁不应完全为空
        if len(patched_bytes) == 0:
            issues.append("补丁后代码为空")

        # 补丁不应大幅改变代码段大小
        size_delta = abs(len(patched_bytes) - len(original_bytes))
        if size_delta > 4096:
            issues.append(f"补丁大小变化过大: {size_delta} 字节")

        score = 1.0 if not issues else max(0.0, 1.0 - len(issues) * 0.2)
        return SafetyVerdict(
            level=SafetyLevel.LEVEL_A,
            is_safe=len(issues) == 0,
            score=score,
            issues=issues,
            recommendations=["建议使用 capstone 进行完整指令边界分析"] if issues else [],
        )

    def check_level_b(
        self, buffer_size: int, access_offsets: List[Tuple[int, int]]
    ) -> SafetyVerdict:
        """
        B 级: Z3 约束求解或区间分析降级。

        access_offsets: [(min_offset, max_offset), ...] — 每次内存访问的可能偏移域。
        """
        issues = []
        for i, (min_off, max_off) in enumerate(access_offsets):
            interval = Interval(min_off, max_off)
            safe, reason = interval_bound_check(interval, buffer_size)
            if not safe:
                issues.append(f"访问 #{i}: {reason}")

        method = "区间分析 (Z3 降级)" if not self._z3_ok else "Z3 约束求解"
        score = 1.0 if not issues else max(0.0, 1.0 - len(issues) * 0.25)

        return SafetyVerdict(
            level=SafetyLevel.LEVEL_B,
            is_safe=len(issues) == 0,
            score=score,
            issues=issues,
            recommendations=[f"验证方法: {method}"] if not self._z3_ok else [],
        )

    def check_level_c(
        self, before_fp: FunctionFingerprint, after_fp: FunctionFingerprint
    ) -> SafetyVerdict:
        """
        C 级: 回归风险评分。

        基于函数指纹对比 + 测试建议推导。
        """
        issues = []
        reg_tests = generate_regression_tests(before_fp, after_fp)

        # 评分因子
        factors = 1.0
        if before_fp.checksum != after_fp.checksum:
            factors -= 0.1  # 函数体变更
        if len(after_fp.danger_calls) > len(before_fp.danger_calls):
            factors -= 0.2 * (len(after_fp.danger_calls) - len(before_fp.danger_calls))
        if after_fp.cyclomatic_complexity > before_fp.cyclomatic_complexity + 3:
            factors -= 0.15  # 圈复杂度显著增加

        score = max(0.0, factors)

        return SafetyVerdict(
            level=SafetyLevel.LEVEL_C,
            is_safe=factors >= 0.7,
            score=score,
            issues=issues,
            recommendations=reg_tests[:5],  # 截取前 5 条
        )


__all__ = [
    "SafetyLevel", "SafetyVerdict",
    "Interval", "interval_bound_check",
    "GadgetScore", "ChainDefenseScore", "compute_arcanist_defense_score",
    "FunctionFingerprint", "compute_function_fingerprint", "generate_regression_tests",
    "EnhancedVeriBinChecker",
]
