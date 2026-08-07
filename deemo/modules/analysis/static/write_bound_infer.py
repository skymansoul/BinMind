# 写界推断器 (Write-Bound Inferer) — PcWBI来源约束写界推断.
#
# 决策逻辑:
#   将检测器产生的原始堆写入告警按来源重新分级, 输出三级判定:
#     CONFIRMED — 可证明存在使写入越过分配可用边界的路径
#     BENIGN    — 可证明所有路径上写入均不越过分配可用边界
#     SUSPECTED — 信息不足, 保守保留但不计入确认告警
#   分级依据优先级从高到低:
#     1. 数值边界: 写入来源为常量且 bound ≤ usable_size(alloc) → BENIGN.
#     2. 守卫边界: 来源为 GUARDED 且 guard_upper ≤ usable_size(alloc) → BENIGN.
#     3. 分配同源: 来源为 ALLOC_LINKED, 依据符号表达式与分配来源的
#        系数/常量差判定安全或溢出 (复用 correlate_sizes 的线性规则).
#     4. 输入不可控: 分配为固定常量且写入来源为 INPUT_TAINTED
#        且无有效守卫 → CONFIRMED (经典固定buffer+攻击者输入型溢出).
#     5. 无法定界: 其余一律 SUSPECTED.
#   只有 CONFIRMED 计入检出统计, SUSPECTED 单独汇报, 从而在保持
#   "真溢出必被确认" 的前提下, 将区间重叠类系统性误报剔除出报告.
#
# 创建: 2026-07-02

from dataclasses import dataclass
from typing import List, Optional

from .heap_alloc_model import HeapAllocModel
from .provenance_domain import ProvClass, ProvValue
from .sym_size_correlator import correlate_sizes


class WbVerdict:
    CONFIRMED = "confirmed"
    BENIGN = "benign"
    SUSPECTED = "suspected"


@dataclass
class WriteBoundResult:
    """单条告警的写界判定结果."""
    finding: dict
    verdict: str
    reason: str
    provenance: str = ""

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "reason": self.reason,
            "provenance": self.provenance,
            **{k: v for k, v in self.finding.items()},
        }


class WriteBoundInferer:
    """写界推断器 — 将原始告警映射到三级判定."""

    def __init__(self, alloc_model: Optional[HeapAllocModel] = None):
        self._alloc_model = alloc_model or HeapAllocModel()
        self._stats = {"confirmed": 0, "benign": 0, "suspected": 0}

    def infer(self, findings: List[dict],
              get_write_prov, get_alloc_prov) -> List[WriteBoundResult]:
        """对告警集合执行写界推断.

        get_write_prov(write_addr, size_reg) -> ProvValue|None
        get_alloc_prov(alloc_addr) -> ProvValue|None (分配size参数来源)
        """
        results = []
        for f in findings:
            alloc_sz = f.get("alloc_size", 0) or 0
            write_sz = f.get("write_size")
            size_op = f.get("size_operand", "")
            write_addr = f.get("write_addr", 0)
            alloc_addr = f.get("_snapshot_alloc_addr", f.get("alloc_addr", 0))

            wprov = None
            if size_op:
                wprov = get_write_prov(write_addr, size_op)

            alloc_prov = get_alloc_prov(alloc_addr)

            res = self._decide(f, alloc_sz, write_sz, wprov, alloc_prov)
            self._stats[res.verdict] += 1
            results.append(res)
        return results

    def _decide(self, f: dict, alloc_sz: int, write_sz,
                wprov: Optional[ProvValue],
                alloc_prov: Optional[ProvValue]) -> WriteBoundResult:
        """单条告警的三级判定."""

        # 0. 符号相关性优先: 分配与写入共享符号变量且线性可比时,
        #    符号证据强于数值区间, 先于一切数值分支判定.
        sym = self._symbolic_compare(f, wprov, alloc_prov)
        if sym is not None:
            return sym

        # 0.5 静态写终点优先: 内联存储的写终点是编译时确定的数值,
        #    直接与分配(对齐后)比较, 不依赖寄存器来源传播.
        wb_num = f.get("wb_numeric")
        if wb_num is not None and isinstance(wb_num, int) \
                and alloc_sz is not None and 0 < alloc_sz < 2**31 - 1:
            if wb_num > alloc_sz:
                return WriteBoundResult(
                    f, WbVerdict.CONFIRMED,
                    f"static write_end {wb_num} > alloc {alloc_sz}",
                    "inline-store")
            return WriteBoundResult(
                f, WbVerdict.BENIGN,
                f"static write_end {wb_num} ≤ alloc {alloc_sz} "
                f"(alignment padding)", "inline-store")

        # 分配大小缺失或无界: 无法证明安全, 保守确认.
        if alloc_sz is None or alloc_sz <= 0 or alloc_sz >= 2**31 - 1:
            if wprov is None or wprov.cls in (
                    ProvClass.CONSTANT, ProvClass.GUARDED,
                    ProvClass.ALLOC_LINKED):
                return WriteBoundResult(f, WbVerdict.SUSPECTED,
                                        "alloc size unbounded",
                                        wprov.describe() if wprov else "?")
            return WriteBoundResult(f, WbVerdict.CONFIRMED,
                                    "unbounded alloc + tainted write",
                                    wprov.describe())

        usable = self._alloc_model.usable_size(alloc_sz)

        if wprov is None:
            # 无来源信息: 数值写大小已知则直接比较, 否则保守.
            if isinstance(write_sz, int) and write_sz > usable:
                return WriteBoundResult(f, WbVerdict.CONFIRMED,
                                        f"write {write_sz} > usable {usable}",
                                        "numeric")
            return WriteBoundResult(f, WbVerdict.SUSPECTED,
                                    "no provenance info", "?")

        cls = wprov.cls

        if cls == ProvClass.CONSTANT:
            w = wprov.bound if wprov.bound is not None else (
                write_sz if isinstance(write_sz, int) else None)
            if w is None:
                return WriteBoundResult(f, WbVerdict.SUSPECTED,
                                        "constant without value", "const")
            if w <= usable:
                return WriteBoundResult(
                    f, WbVerdict.BENIGN,
                    f"const write {w} ≤ usable {usable} "
                    f"(allocator padding)", wprov.describe())
            return WriteBoundResult(f, WbVerdict.CONFIRMED,
                                    f"const write {w} > usable {usable}",
                                    wprov.describe())

        if cls == ProvClass.GUARDED:
            g = wprov.guard_upper if wprov.guard_upper is not None \
                else wprov.bound
            # 守卫上界必须为正数才是真正的上界; 0/None 表示无有效上界
            # (零值比较仅约束下界), 此时不能证明写量有界 → 保守保留.
            if g is not None and g > 0 and g <= usable:
                return WriteBoundResult(
                    f, WbVerdict.BENIGN,
                    f"bounds-checked write ≤ {g} ≤ usable {usable}",
                    wprov.describe())
            return WriteBoundResult(f, WbVerdict.SUSPECTED,
                                    "guard upper exceeds usable or unknown",
                                    wprov.describe())

        if cls == ProvClass.ALLOC_LINKED:
            return self._decide_alloc_linked(f, alloc_sz, usable, wprov,
                                             alloc_prov)

        if cls == ProvClass.INPUT_TAINTED:
            # TODO: 分配参数自身的整数回绕未建模 (count*16 收缩为小分配
            # 后写入 count 仍超限), 该模式依赖整数溢出检测器补充.
            # 分配为固定常量 + 输入写入: 若写入数值已知且>usable, 确认;
            # 否则视为存在未约束输入路径, 确认.
            if isinstance(write_sz, int) and write_sz <= usable:
                return WriteBoundResult(f, WbVerdict.BENIGN,
                                        f"bounded write {write_sz}",
                                        wprov.describe())
            alloc_const = self._alloc_is_constant(alloc_prov)
            if alloc_const is not None and alloc_const < usable + 1:
                return WriteBoundResult(
                    f, WbVerdict.CONFIRMED,
                    f"fixed alloc {alloc_const} + tainted write",
                    wprov.describe())
            return WriteBoundResult(f, WbVerdict.CONFIRMED,
                                    "tainted write, unbounded upper",
                                    wprov.describe())

        return WriteBoundResult(f, WbVerdict.SUSPECTED,
                                "unknown provenance", wprov.describe())

    def _symbolic_compare(self, f: dict, wprov: Optional[ProvValue],
                          alloc_prov: Optional[ProvValue]) -> Optional[WriteBoundResult]:
        """基于线性符号表达式比较分配与写入.

        两者均有可比较表达式且共享符号变量时返回判定, 否则None.
        """
        if wprov is None or alloc_prov is None:
            return None
        w_expr = wprov.expr
        a_expr = alloc_prov.expr
        if w_expr is None or a_expr is None:
            return None
        # 纯常量对: 数值路径用 usable_size 判定 (含分配器padding),
        # 符号比较只负责共享符号变量的线性关系.
        if a_expr.is_const() and w_expr.is_const():
            return None
        verdict, overflow = correlate_sizes(a_expr, w_expr)
        # AWSC 已确认溢出 (含目标偏移) 时, 符号等价不可覆盖该结论.
        # 符号比较忽略目标指针偏移 (memcpy(buf+0x10,...)), 等价判定
        # 在存在正向偏移时并不安全, 必须交由数值/偏移路径裁决.
        if f.get("awsc_confirmed"):
            return None
        if verdict == "safe_equal":
            return WriteBoundResult(f, WbVerdict.BENIGN,
                                    "write ≡ alloc (shared symbol)",
                                    wprov.describe())
        if verdict == "safe_dominates":
            return WriteBoundResult(f, WbVerdict.BENIGN,
                                    "alloc dominates write (symbolic)",
                                    wprov.describe())
        if verdict == "overflow":
            return WriteBoundResult(f, WbVerdict.CONFIRMED,
                                    f"write grows beyond alloc (+{overflow}B)",
                                    wprov.describe())
        return None

    def _decide_alloc_linked(self, f: dict, alloc_sz: int, usable: int,
                             wprov: ProvValue,
                             alloc_prov: Optional[ProvValue]) -> WriteBoundResult:
        """分配同源写入的符号判定."""
        w_expr = wprov.expr
        a_expr = alloc_prov.expr if alloc_prov is not None else None

        if w_expr is not None and a_expr is not None:
            verdict, overflow = correlate_sizes(a_expr, w_expr)
            if verdict == "safe_equal":
                return WriteBoundResult(
                    f, WbVerdict.BENIGN,
                    f"write ≡ alloc (shared symbol)", wprov.describe())
            if verdict == "safe_dominates":
                return WriteBoundResult(
                    f, WbVerdict.BENIGN,
                    f"alloc dominates write (symbolic)", wprov.describe())
            if verdict == "overflow":
                return WriteBoundResult(
                    f, WbVerdict.CONFIRMED,
                    f"write grows beyond alloc (+{overflow}B)", wprov.describe())

        # 符号不可比时回退到数值: 写入上界已知且≤usable → 安全.
        if wprov.bound is not None and wprov.bound <= usable:
            return WriteBoundResult(f, WbVerdict.BENIGN,
                                    f"linked write bound {wprov.bound} ≤ usable",
                                    wprov.describe())
        return WriteBoundResult(f, WbVerdict.SUSPECTED,
                                "alloc-linked but incomparable",
                                wprov.describe())

    @staticmethod
    def _alloc_is_constant(alloc_prov: Optional[ProvValue]) -> Optional[int]:
        """提取分配 size 参数的常量值 (非常量返回None)."""
        if alloc_prov is None:
            return None
        if alloc_prov.cls == ProvClass.CONSTANT:
            return alloc_prov.bound
        if alloc_prov.expr is not None and alloc_prov.expr.is_const():
            return alloc_prov.expr.const
        return None

    @property
    def stats(self) -> dict:
        return dict(self._stats)


__all__ = ["WriteBoundInferer", "WriteBoundResult", "WbVerdict"]
