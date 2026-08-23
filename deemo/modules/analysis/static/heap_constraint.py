# 堆分配约束简化器
# 追踪 malloc(N) 与 memcpy(dst, src, M) 的参数同源关系和对齐约束

from typing import Dict, List, Optional, Tuple


class Interval:
    __slots__ = ("lo","hi")
    def __init__(self, lo: int, hi: int):
        self.lo = lo; self.hi = hi

    def join(self, other: "Interval") -> "Interval":
        return Interval(min(self.lo, other.lo), max(self.hi, other.hi))

    def add(self, delta: int) -> "Interval":
        return Interval(self.lo + delta, self.hi + delta)

    def contains(self, val: int) -> bool:
        return self.lo <= val <= self.hi

    @property
    def is_singleton(self) -> bool:
        return self.lo == self.hi

    def __repr__(self):
        return f"[{self.lo},{self.hi}]"


class HeapConstraint:
    """单个堆操作的约束信息."""
    __slots__ = ("alloc_site","alloc_size","raw_alloc_size",
                 "free_site","write_sites")
    def __init__(self, alloc_site: int, alloc_size: Interval,
                 raw_alloc_size: Optional[Interval] = None):
        self.alloc_site = alloc_site
        self.alloc_size = alloc_size            # 对齐后区间
        self.raw_alloc_size = raw_alloc_size    # 原始请求区间
        self.free_site: Optional[int] = None
        self.write_sites: List[Tuple[int, Interval]] = []  # (addr, write_size)


class HeapConstraintTracker:
    """堆约束追踪器.

    追踪每个 malloc 调用点的分配大小,
    以及后续 memcpy/strcpy 写入的 size 参数,
    判断是否存在溢出.
    """

    # glibc malloc 最小 chunk 大小 (含元数据)
    MIN_CHUNK_SIZE = 32  # x86-64, 含 16B 元数据 + 16B 最小数据区

    def __init__(self):
        self._allocations: Dict[int, HeapConstraint] = {}  # alloc_addr → constraint
        self._ptr_to_alloc: Dict[str, int] = {}            # reg→alloc_addr 映射
        self._findings: List[dict] = []

    def track_alloc(self, alloc_addr: int, size_interval: Interval,
                     result_reg: str = "rax"):
        """记录 malloc(size) 的分配信息."""
        # 原始请求区间单独保留, 供 allocator usable 精确计算
        # (对齐后区间无法可靠逆推请求值).
        raw_lo = max(0, size_interval.lo)
        raw_hi = size_interval.hi if size_interval.hi < 2**30 else 2**30 - 1
        raw_iv = Interval(raw_lo, raw_hi)
        # 对齐修正: glibc 实际分配 ≥ MIN_CHUNK_SIZE 且 16 字节对齐
        aligned_lo = max(self.MIN_CHUNK_SIZE,
                          (size_interval.lo + 15) & ~15)
        aligned_hi = max(aligned_lo,
                          (size_interval.hi + 15) & ~15) if size_interval.hi < 2**30 else size_interval.hi

        constraint = HeapConstraint(alloc_addr,
                                     Interval(aligned_lo, aligned_hi),
                                     raw_alloc_size=raw_iv)
        self._allocations[alloc_addr] = constraint
        self._ptr_to_alloc[result_reg] = alloc_addr

    def track_write(self, write_addr: int, write_size: Interval,
                     ptr_reg: str) -> Optional[dict]:
        """检查对某指针的写入是否可能溢出.

        ptr_reg: 指针所在的寄存器名. 若该寄存器指向已知的堆分配,
        比较写入大小与分配大小.
        """
        alloc_addr = self._ptr_to_alloc.get(ptr_reg)
        if alloc_addr is None:
            return None

        alloc = self._allocations.get(alloc_addr)
        if alloc is None:
            return None

        alloc.write_sites.append((write_addr, write_size))

        # 安全性判定: 写入大小的上界 ≤ 分配大小的下界 → 安全.
        # alloc.alloc_size 是对齐后区间; 写量落在 (aligned_lo-15, aligned_lo]
        # 的 padding 区域时不能在此判安全, 交由 allocator 层精确判定
        # (usable 基于原始请求), 避免小请求下真实溢出被误吞.
        if write_size.is_singleton and \
                write_size.hi + 15 <= alloc.alloc_size.lo:
            return None  # 确定安全, 不报告

        # 写入下界 > 分配上界 → 确定溢出
        if write_size.lo > alloc.alloc_size.hi:
            overflow = write_size.lo - alloc.alloc_size.hi
            return {
                "type": "heap_overflow",
                "alloc_addr": alloc.alloc_site,
                "alloc_size": alloc.alloc_size.hi,
                "write_addr": write_addr,
                "write_size": write_size.hi,
                "overflow_bytes": overflow,
                "severity": "critical" if overflow > 64 else "high",
            }

        # 区间重叠: 可能溢出 (需精确分析)
        return {
            "type": "heap_overflow_possible",
            "alloc_addr": alloc.alloc_site,
            "alloc_size_range": f"{alloc.alloc_size}",
            "write_addr": write_addr,
            "write_size_range": f"{write_size}",
            "severity": "medium",
            "note": "intervals_overlap_need_precise_analysis",
        }

    def check_correlation(self, alloc_addr: int,
                           write_size_reg: str,
                           instructions: Optional[List[dict]] = None,
                           write_addr: int = 0,
                           alloc_size_reg: Optional[str] = None,
                           use_win64_abi: bool = False) -> bool:
        """检查分配大小与写入大小是否来自同一变量 (allocation-site correlation).

        malloc(X) 和 memcpy(ptr, src, X) 的 X 为同一数据流根来源
        (同栈槽/同参数/同返回值) → 返回 True 表示安全.

        实现: 委托 AWSC 引擎做寄存器级后向 def-use 根来源追踪.
        instructions 缺失时返回 False (保守, 不冒险过滤).
        """
        if not instructions or not write_size_reg:
            return False
        from .co_source_engine import AWSCEngine
        engine = AWSCEngine(use_win64_abi=use_win64_abi)
        alloc_root = engine.trace_size_root(
            instructions, alloc_addr, alloc_size_reg or "rdi")
        write_root = engine.trace_size_root(
            instructions, write_addr, write_size_reg)
        verdict, _, _ = engine.correlate(alloc_root, write_root)
        return verdict == "safe"

    def get_or_create_size_interval(self, operand: str,
                                     known_constants: Dict[str, int]
                                     ) -> Interval:
        """从操作数推导区间.

        立即数 → 精确值 (按32/64位宽度符号扩展).
        寄存器 → 查已知常量表, 否则返回 [0, 2^31-1].
        """
        from .disasm_util import is_32bit_reg
        op = operand.strip().lower().lstrip("%").replace("$", "")
        if op.startswith("0x"):
            v = int(op, 16)
            if is_32bit_reg(operand) and v >= 0x80000000:
                v -= 0x100000000
            return Interval(v, v)
        if op.isdigit():
            v = int(op)
            if is_32bit_reg(operand) and v >= 0x80000000:
                v -= 0x100000000
            return Interval(v, v)
        if op in known_constants:
            v = known_constants[op]
            return Interval(v, v)
        return Interval(0, 2**31 - 1)  # 未知: 最宽区间

    @property
    def findings(self) -> List[dict]:
        return list(self._findings)

    def stats(self) -> dict:
        return {
            "allocations_tracked": len(self._allocations),
            "heap_writes_checked": sum(
                len(a.write_sites) for a in self._allocations.values()),
            "findings": len(self._findings),
        }


__all__ = ["HeapConstraintTracker", "Interval", "HeapConstraint"]
