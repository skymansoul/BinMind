"""
约束简化器 — 将数据流追踪的约束转化为可判定的区间问题。

底层原理:
  数据流追踪得到 Register A = value, Register B 受限于 [lo, hi]。
  简化器将这些事实转化为区间约束, 供 fp_filter 做判定。

  例如: mov rdi, 64; call malloc; ... mov rdx, 128; call memcpy
  简化器推导: rdi=64, rdx=128, alloc_size(rdi)=64, write_size(rdx)=128
  判据: 64 < 128 → 不可证明安全 → 保留告警

  但若 rdx 的来源是 rdi+0 → rdx=64 → 64 >= 64 → 可证明安全 → 过滤。

修改记录:
  创建 2025-03-28
"""
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass
class Interval:
    lo: Optional[int] = None
    hi: Optional[int] = None

    def contains(self, v: int) -> bool:
        if self.lo is not None and v < self.lo: return False
        if self.hi is not None and v > self.hi: return False
        return True

    def is_definitely_less_than(self, other: 'Interval') -> bool:
        """self.hi < other.lo → self 完全小于 other"""
        return (self.hi is not None and other.lo is not None and self.hi < other.lo)


def simplify_constraints(
    reg_values: Dict[str, int],
    alloc_reg: str,
    write_len_reg: str,
) -> Tuple[Interval, Interval]:
    """
    将寄存器值简化为分配大小区间和写入长度区间。

    若寄存器值已知→精确定点区间; 未知→无界区间(None, None)。
    """
    alloc_val = reg_values.get(alloc_reg)
    write_val = reg_values.get(write_len_reg)

    alloc_iv = Interval(alloc_val, alloc_val) if alloc_val is not None else Interval()
    write_iv = Interval(write_val, write_val) if write_val is not None else Interval()

    return alloc_iv, write_iv


def can_prove_safe(alloc_iv: Interval, write_iv: Interval) -> bool:
    """
    判定: 分配大小区间 ≥ 写入长度区间 → 可证明安全。
    仅当两个区间都有界时才做判定; 否则保守返回 False (不冒险过滤)。
    """
    if alloc_iv.lo is None or write_iv.hi is None:
        return False  # 信息不足, 保守不滤
    return alloc_iv.lo >= write_iv.hi


def generate_evidence(alloc_iv: Interval, write_iv: Interval) -> str:
    """生成约束证据描述字符串"""
    if alloc_iv.lo is not None and write_iv.hi is not None:
        if alloc_iv.lo >= write_iv.hi:
            return f"已证明: alloc ≥ {alloc_iv.lo} ≥ write ≤ {write_iv.hi}"
        else:
            return f"溢出证据: alloc ≤ {alloc_iv.lo} < write ≥ {write_iv.hi}"
    return "约束信息不足, 保留告警"
