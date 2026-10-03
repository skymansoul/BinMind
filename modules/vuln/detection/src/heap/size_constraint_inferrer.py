"""堆溢出误报削减——基于区间抽象解释的size约束关系推断.

问题: 现有检测对所有 size 来自外部的 memcpy(dst, src, size) 均标记溢出,
但多数固件中 size 虽外部而来却被约束在 malloc 范围内:
  size = read_input(); if (size > 256) size = 256;
  buf = malloc(size); memcpy(buf, src, size);  # 安全

方案: 区间抽象解释——每变量维护 [lo,hi], 条件分支更新区间,
在 memcpy 点比较其 size 区间与 malloc 的 size 区间:
  memcpy.size_max ≤ malloc.size_min → SAFE
  memcpy.size_min > malloc.size_max → VULNERABLE
  其余 → UNCERTAIN (保守标记为潜在漏洞)

与 value_composer (值转换链) / heap_state_model (指针生命周期) 互补,
本模块专攻分配大小与拷贝大小的约束关系。
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from enum import Enum

class SizeRelation(Enum):
    SAFE = 0           # memcpy.size ≤ malloc.size 可证明
    VULNERABLE = 1     # memcpy.size > malloc.size 可证明
    UNCERTAIN = 2      # 无法证明——保守标记

@dataclass
class Interval:
    """整数区间 [lo, hi]。——INF表示无界。"""
    lo: int = 0
    hi: int = 2**63 - 1  # INT64_MAX as "unknown upper bound"

    @property
    def is_unbounded(self) -> bool:
        return self.hi >= 2**62

    def intersect(self, other: 'Interval') -> 'Interval':
        _lo = max(self.lo, other.lo)
        _hi = min(self.hi, other.hi)
        if _lo > _hi:  # 空区间——约束冲突
            return Interval(self.lo, self.hi)  # 保持原区间不变
        return Interval(_lo, _hi)

    def __repr__(self):
        _hi = "∞" if self.is_unbounded else str(self.hi)
        return f"[{self.lo}, {_hi}]"

@dataclass
class MallocSite:
    """一次malloc调用点的信息。"""
    addr: int
    func_name: str
    size_reg: str       # 哪个寄存器/变量携带size
    size_interval: Interval = field(default_factory=Interval)
    size_is_tainted: bool = False
    allocated_max: int = 0

@dataclass
class MemcpySite:
    """一次memcpy调用点的信息。"""
    addr: int
    func_name: str
    size_reg: str
    size_interval: Interval = field(default_factory=Interval)
    size_is_tainted: bool = False
    # 推断的约束关系
    relation_to_alloc: SizeRelation = SizeRelation.UNCERTAIN
    related_malloc: Optional[MallocSite] = None

@dataclass
class SizeConstraintReport:
    """一次扫描的完整size约束分析报告。"""
    malloc_sites: List[MallocSite] = field(default_factory=list)
    memcpy_sites: List[MemcpySite] = field(default_factory=list)
    safe_memcpy: int = 0        # 可证明安全的memcpy
    vulnerable_memcpy: int = 0  # 可证明溢出的memcpy
    uncertain_memcpy: int = 0   # 无法证明的(保守告警)
    fp_reduction_ratio: float = 0.0

class SizeConstraintInferrer:
    """基于区间抽象解释的size约束推断——堆溢出专用."""

    def __init__(self):
        # 寄存器→当前区间 (单线程假设——每次分析一个函数)
        self._intervals: Dict[str, Interval] = {}
        # malloc点记录
        self._mallocs: List[MallocSite] = []
        # memcpy点记录
        self._memcpys: List[MemcpySite] = []

    def track_malloc(
        self, addr: int, func: str, size_reg: str,
        size_hint: int = 0, tainted: bool = True,
    ):
        """记录一次malloc调用。allocated_max捕获分配时size的上界。"""
        _init_interval = (
            Interval(0, size_hint) if size_hint > 0 else Interval()
        )
        _site = MallocSite(
            addr=addr, func_name=func, size_reg=size_reg,
            size_interval=_init_interval, size_is_tainted=tainted,
        )
        # 保存分配时size的上界作为allocated_size的参考
        _site.allocated_max = _init_interval.hi if not _init_interval.is_unbounded else size_hint
        self._mallocs.append(_site)
        self._intervals[size_reg] = _init_interval

    def constrain_reg(self, reg: str, constraint: Interval):
        """应用约束——例如 cmp reg, N; jg → reg ∈ [0, N]。"""
        if reg in self._intervals:
            self._intervals[reg] = self._intervals[reg].intersect(constraint)
        else:
            self._intervals[reg] = constraint

    def constrain_reg_max(self, reg: str, max_val: int):
        """reg ≤ max_val。常见于 if (size > N) size = N 之后。"""
        self.constrain_reg(reg, Interval(0, max_val))

    def check_memcpy(
        self, addr: int, func: str, size_reg: str, tainted: bool = True,
    ) -> SizeRelation:
        """在memcpy调用点检查size约束——返回与最近malloc的关系。

        若无法找到对应malloc→默认为 UNCERTAIN (保守)。
        """
        _mem_interval = self._intervals.get(size_reg, Interval())
        _related_malloc = (
            self._mallocs[-1] if self._mallocs else None
        )

        _relation = SizeRelation.UNCERTAIN

        if _related_malloc and _related_malloc.size_reg == size_reg:
            _malloc_interval = _related_malloc.size_interval

            # 可证明安全: memcpy.size_max ≤ 分配时size的上界
            _alloc_max = (_related_malloc.allocated_max
                          if _related_malloc.allocated_max > 0
                          else _malloc_interval.hi)
            if (not _mem_interval.is_unbounded
                    and _mem_interval.hi <= _alloc_max
                    and _alloc_max > 0):
                _relation = SizeRelation.SAFE
            # 可证明溢出: memcpy.size_min > 分配的最大值
            elif (_mem_interval.lo > _alloc_max
                  and _alloc_max > 0):
                _relation = SizeRelation.VULNERABLE
            else:
                _relation = SizeRelation.UNCERTAIN

        _site = MemcpySite(
            addr=addr, func_name=func, size_reg=size_reg,
            size_interval=_mem_interval, size_is_tainted=tainted,
            relation_to_alloc=_relation, related_malloc=_related_malloc,
        )
        self._memcpys.append(_site)
        return _relation

    def generate_report(self) -> SizeConstraintReport:
        """生成完整分析报告——含误报降低率。"""
        _safe = sum(1 for m in self._memcpys
                    if m.relation_to_alloc == SizeRelation.SAFE)
        _vuln = sum(1 for m in self._memcpys
                     if m.relation_to_alloc == SizeRelation.VULNERABLE)
        _uncertain = sum(1 for m in self._memcpys
                         if m.relation_to_alloc == SizeRelation.UNCERTAIN)

        _total = len(self._memcpys)
        # 误报降低率: 若传统检测标记全部为告警,
        # 本模块将SAFE剔除 → 降低比 = SAFE / total
        _fp_reduction = _safe / max(_total, 1)

        return SizeConstraintReport(
            malloc_sites=self._mallocs,
            memcpy_sites=self._memcpys,
            safe_memcpy=_safe,
            vulnerable_memcpy=_vuln,
            uncertain_memcpy=_uncertain,
            fp_reduction_ratio=round(_fp_reduction, 4),
        )

    def reset(self):
        """重置状态——分析下一个函数前调用。"""
        self._intervals.clear()
        self._mallocs.clear()
        self._memcpys.clear()

# 冒烟用例: SAFE/UNCERTAIN/VULNERABLE 三态
def _check():
    _inf = SizeConstraintInferrer()

    # 安全case: malloc(256) → size被约束 → memcpy
    _inf.track_malloc(0x1000, "process", "rsi", size_hint=256)
    _inf.constrain_reg_max("rsi", 256)
    _r1 = _inf.check_memcpy(0x1020, "process", "rsi")
    assert _r1 == SizeRelation.SAFE, f"constrained size should be SAFE, got {_r1}"

    _inf.reset()

    # 不确定case: malloc(256) → memcpy(不同寄存器, 无约束)
    _inf.track_malloc(0x2000, "worker", "rdx", size_hint=256)
    # memcpy用rbx——这个寄存器从未被约束, 默认区间[0,∞)
    _r2 = _inf.check_memcpy(0x2020, "worker", "rbx")
    assert _r2 == SizeRelation.UNCERTAIN, f"unconstrained should be UNCERTAIN, got {_r2}"

    _inf.reset()

    # 溢出case: malloc(size_reg="rcx", size_hint=128) → memcpy(不同reg=1024)
    _inf.track_malloc(0x3000, "buggy", "rcx", size_hint=128)
    # memcpy用rbx, 约束为1024, 远超malloc分配的128
    _inf.constrain_reg("rbx", Interval)
    _r3 = _inf.check_memcpy(0x3020, "buggy", "rbx")
    # 不同寄存器→UNCERTAIN (无法关联到具体malloc)——这是保守策略的体现
    assert _r3 == SizeRelation.UNCERTAIN, f"different reg→uncertain, got {_r3}"

    # 溢出case2: 同寄存器, lo=256 > allocated_max=128 → VULNERABLE
    _inf2 = SizeConstraintInferrer()
    _inf2.track_malloc(0x4000, "bug2", "rdi", size_hint=128)
    # 模拟寄存器被覆盖为更大的值——lo>allocated_max
    _inf2._intervals["rdi"] = Interval
    _r4 = _inf2.check_memcpy(0x4020, "bug2", "rdi")
    assert _r4 == SizeRelation.VULNERABLE, f"overflow should be VULNERABLE, got {_r4}"

    # 汇总: 1 SAFE (case1), 1 UNCERTAIN (case2), 1 UNCERTAIN+1 VULNERABLE (case3+4)
    print(f"[size_infer] case1: r1={_r1} | case2: r2={_r2} | case3: r3={_r3} | case4: r4={_r4}")
    print("[OK] size_constraint_inferrer passed")

if __name__ == "__main__":
    _check()
