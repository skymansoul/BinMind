# coding: utf-8
"""
同余域 — 整数区间域的精化 (refinement) 组件.

核心洞察: glibc 分配器约束 eff % 16 == 0 是整除约束, 区间域 [32,35]
无法表达。加入同余信息后: eff∈[32,35] ∧ eff≡0(mod 16) → eff=32 (唯一解).
这种精化在 Granger "Static Analysis of Congruence Properties" 中
称为简化积 (reduced product) — 两个域的交换信息循环收缩边界.

方法:
  - Congruence: (residue, modulus) 表示 {x | x ≡ residue (mod modulus)}
  - meet(c1, c2): 两个同余约束的交 (中国剩余定理的简化版)
  - reduce(interval, congruence): 用同余约束收缩区间
  - expand(congruence, interval): 用区间约束收缩同余 (取区间内最小解)

  - Granger, "Static Analysis of Congruence Properties"
  - Miné, "The Octagon Abstract Domain"
    — 同余域与区间域的组合与 Octagon 域同属数值抽象域的泛化
"""

from dataclasses import dataclass
from math import gcd
from typing import Optional, Tuple

@dataclass
class Congruence:
    """同余约束: x ≡ residue (mod modulus), 即 x = residue + k*modulus.

    特例:
      - modulus=0: 无约束 (⊥ 在余数格中)
      - modulus=1: 无信息 (⊤, residue 任意)
    """
    residue: int
    modulus: int

    def __post_init__(self):
        if self.modulus < 0:
            self.modulus = -self.modulus
        if self.modulus > 1:
            self.residue = self.residue % self.modulus

    def is_top(self) -> bool:
        return self.modulus <= 1

    def is_bottom(self) -> bool:
        return self.modulus == 0

    def contains(self, value: int) -> bool:
        if self.is_top():
            return True
        return value % self.modulus == self.residue

    def meet(self, other: 'Congruence') -> 'Congruence':
        """两个同余约束的交 (信息合并).

        x≡a(mod m) ∧ x≡b(mod n):
        若 a≡b(mod gcd(m,n)): 由 CRT, 模数为 lcm(m,n), 余数为唯一解
        否则: 无解 (⊥)
        """
        if self.is_top():
            return other
        if other.is_top():
            return self

        g = gcd(self.modulus, other.modulus)

        # 检查一致性: a ≡ b (mod g)
        if (self.residue - other.residue) % g != 0:
            return Congruence(0, 0)  # 无解 → bottom

        # 中国剩余定理求合并后的 residue
        if self.modulus == other.modulus:
            return self if self.residue == other.residue else Congruence(0, 0)

        # 简并情况: 一个模数能整除另一个
        if self.modulus % other.modulus == 0:
            if self.residue % other.modulus == other.residue:
                return self
            return Congruence(0, 0)
        if other.modulus % self.modulus == 0:
            if other.residue % self.modulus == self.residue:
                return other
            return Congruence(0, 0)

        # 一般 CRT — 扩展欧几里得 O(log min(m,n))
        lcm = (self.modulus // g) * other.modulus
        if lcm > 2**20:  # 避免模数膨胀, 回退保守近似
            return Congruence(self.residue, self.modulus)

        # 扩展欧几里得: 求 s, t 使 s*m + t*n = g
        def _egcd(a: int, b: int):
            if b == 0:
                return (1, 0, a)
            x1, y1, d = _egcd(b, a % b)
            return (y1, x1 - (a // b) * y1, d)

        s, t, _ = _egcd(self.modulus, other.modulus)
        # CRT 合并: x = a * t * n/g + b * s * m/g (mod lcm)
        merged = (self.residue * t * (other.modulus // g) +
                  other.residue * s * (self.modulus // g)) % lcm
        return Congruence(merged, lcm)

    @staticmethod
    def from_divisibility(modulus: int, residue: int = 0) -> 'Congruence':
        """快捷构造: x 能被 modulus 整除 (或余 residue).

        例如: Congruence.from_divisibility(16) → x ≡ 0 (mod 16)
        """
        return Congruence(residue, modulus)

def reduce_interval_with_congruence(
    lo: int, hi: int, c: Congruence,
) -> Tuple[int, int]:
    """用同余约束收缩区间 — Granger 简化积的核心操作.

    给定 x∈[lo,hi] ∧ x≡r(mod m), 收缩区间两端到满足同余约束的最近点.
    若区间内无满足约束的值 → 返回空区间 (lo > hi).
    """
    if c.is_top() or lo > hi:
        return lo, hi

    m = c.modulus
    r = c.residue

    # 收缩下界: 第一个 >= lo 且 ≡ r (mod m) 的值
    rem = lo % m
    if rem <= r:
        new_lo = lo + (r - rem)
    else:
        new_lo = lo + (m - rem + r)
    if new_lo < lo:
        new_lo += m

    # 收缩上界: 第一个 <= hi 且 ≡ r (mod m) 的值
    rem = hi % m
    if rem >= r:
        new_hi = hi - (rem - r)
    else:
        new_hi = hi - (m - r + rem)
    if new_hi > hi:
        new_hi -= m

    return new_lo, new_hi

def extract_congruence_from_interval(
    lo: int, hi: int, modulus: int,
) -> Optional[Congruence]:
    """从区间中提取同余信息.

    若区间内所有值 ≡ r (mod m) → 返回 Congruence(r, m).
    否则返回 None (无法提取整除信息).
    """
    if hi - lo + 1 >= modulus:
        # 区间宽度 >= modulus, 覆盖了所有余数类 → 无整除信息
        return None

    residues = {x % modulus for x in range(lo, min(hi + 1, lo + modulus + 1))}
    if len(residues) == 1:
        return Congruence(residues.pop(), modulus)
    return None

class CongruenceDomain:
    """同余域的简化积运算 — 区间与同余信息的双向精化.

    使用场景: allocator constraint encoding 中,
    eff ∈ [32, 35] (区间) + eff ≡ 0 (mod 16) (对齐) → eff = 32 (精确值).
    """

    def __init__(self):
        self._congruences: dict = {}  # var_name → Congruence

    def set(self, var: str, c: Congruence):
        if not c.is_top():
            self._congruences[var] = c

    def get(self, var: str) -> Congruence:
        return self._congruences.get(var, Congruence(0, 1))

    def add_divisibility(self, var: str, modulus: int, residue: int = 0):
        """记录变量满足整除约束: var ≡ residue (mod modulus)."""
        existing = self.get(var)
        new_c = Congruence(residue, modulus)
        self._congruences[var] = existing.meet(new_c)

    def reduce(self, var: str, lo: int, hi: int) -> Tuple[int, int]:
        """使用同余信息收缩区间边界."""
        c = self.get(var)
        return reduce_interval_with_congruence(lo, hi, c)

    def extract(self, var: str, lo: int, hi: int, modulus: int):
        """从已知区间尝试提取同余信息."""
        c = extract_congruence_from_interval(lo, hi, modulus)
        if c:
            existing = self.get(var)
            self._congruences[var] = existing.meet(c)

def prove_with_congruence(
    alloc_request: int, write_size: int,
    alignment: int = 16, min_chunk: int = 32, metadata: int = 16,
) -> Tuple[bool, str]:
    """使用同余精化域证明堆溢出不可行.

    演示简化积的效果:
    eff ∈ [alloc+meta, alloc+meta+align-1] ∧ eff≥min_chunk ∧ eff≡0(mod align)
    → 精确 eff 值 → usable = eff - meta → 与 write 比较.
    """
    cd = CongruenceDomain()
    cd.add_divisibility('eff', alignment)  # eff % 16 == 0

    # 计算区间边界
    eff_lo = max(alloc_request + metadata, min_chunk)
    eff_hi = alloc_request + metadata + alignment - 1

    # 同余精化
    eff_lo, eff_hi = cd.reduce('eff', eff_lo, eff_hi)

    if eff_lo > eff_hi:
        return True, (f'alignment+interval 冲突: eff∈∅, '
                      f'malloc({alloc_request}) 无法满足对齐约束')

    # 精化后的 usable
    usable_lo = eff_lo - metadata
    usable_hi = eff_hi - metadata

    if write_size <= usable_lo:
        return True, (
            f'同余精化: eff∈[{eff_lo},{eff_hi}] ∧ eff≡0(mod {alignment}), '
            f'usable={usable_lo} ≥ write({write_size})')

    if write_size > usable_hi:
        return False, (
            f'同余精化: eff∈[{eff_lo},{eff_hi}], '
            f'usable={usable_hi} < write({write_size})')

    return False, (
        f'同余精化不确定: eff∈[{eff_lo},{eff_hi}], '
        f'usable∈[{usable_lo},{usable_hi}] vs write({write_size})')
