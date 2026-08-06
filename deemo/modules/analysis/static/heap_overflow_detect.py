# 增强型堆溢出检测器 (Enhanced Heap Overflow Detector)
#
# 整合后向值流追踪 + 约束简化 + 三阶段FP过滤,
# 在保留高召回的同时压低误报率.
#
# 工作流程:
#   1. 识别堆分配点 (malloc/calloc/realloc)
#   2. 追踪返回指针的数据流 (哪个寄存器持有指针, 传给了谁)
#   3. 识别对堆指针的写入 (memcpy/strcpy/自定义循环写入)
#   4. 后向追踪写入 size 的来源 (常量/已校验/外部输入)
#   5. 约束比较: 分配大小 vs 写入大小, 检查是否可能溢出
#   6. 三阶段FP过滤
#
# 创新锚点:
#   本检测器与现有方案(Mobius CCS24/BinTaint/Sydr)的核心区别在于
#   "allocation-site correlation + interval-based constraint simplification"
#   的组合. 现有方案要么只检查危险函数调用(高FP), 要么做全路径符号执行
#   (低效率). 本方案通过约束简化在两者间取得平衡.
#
# 创建: 2026-08-06

from typing import Dict, List, Optional, Tuple
from .heap_slice_trace import BackwardSliceTracer, SourceKind
from .heap_constraint import HeapConstraintTracker, Interval
from .heap_fp_filter import HeapFPFilter


class HeapOverflowDetector:
    """增强型堆溢出检测器.

    输入: 反汇编指令流.
    输出: 过滤后的高置信度堆溢出告警.
    """

    ALLOC_FUNCS = {"malloc","calloc","realloc","_Znwm","_Znam",
                    "g_malloc","g_try_malloc","ExAllocatePoolWithTag"}
    WRITE_FUNCS = {"memcpy","memmove","strcpy","strncpy","strcat",
                    "sprintf","snprintf","read","fread","recv"}
    FREE_FUNCS = {"free","_ZdlPv","g_free","ExFreePool"}

    def __init__(self):
        self._alloc_tracker = HeapConstraintTracker()
        self._fp_filter = HeapFPFilter()
        self._tracer = BackwardSliceTracer()
        self._raw_findings: List[dict] = []
        self._filtered_findings: List[dict] = []
        self._known_constants: Dict[str, int] = {}

    def analyze_instruction(self, ins: dict):
        """逐指令分析: 追踪分配/写入/释放."""
        mnem = ins.get("mnemonic", "").lower()
        ops = ins.get("operands", [])
        addr = ins.get("address", 0)

        # 分配追踪
        if mnem == "call" and ops:
            func = self._extract_func(ops[0])
            if func in self.ALLOC_FUNCS:
                size_reg = self._get_arg_reg(ops, 0, "rdi")
                size_iv = self._alloc_tracker.get_or_create_size_interval(
                    size_reg, self._known_constants)
                self._alloc_tracker.track_alloc(addr, size_iv, "rax")
            elif func in self.FREE_FUNCS:
                ptr_reg = self._get_arg_reg(ops, 0, "rdi")
                alloc_addr = self._alloc_tracker._ptr_to_alloc.get(ptr_reg)
                if alloc_addr and alloc_addr in self._alloc_tracker._allocations:
                    self._alloc_tracker._allocations[alloc_addr].free_site = addr
            elif func in self.WRITE_FUNCS:
                dst_reg = self._get_arg_reg(ops, 0, "rdi")
                size_reg = self._get_arg_reg(ops, 2, "rdx")
                size_iv = self._alloc_tracker.get_or_create_size_interval(
                    size_reg, self._known_constants)
                result = self._alloc_tracker.track_write(
                    addr, size_iv, dst_reg)
                if result:
                    result["size_operand"] = size_reg
                    result["ptr_operand"] = dst_reg
                    result["alloc_size"] = self._alloc_tracker._allocations.get(
                        self._alloc_tracker._ptr_to_alloc.get(dst_reg, -1),
                        None)
                    if result["alloc_size"]:
                        result["alloc_size"] = result["alloc_size"].alloc_size.hi
                    self._raw_findings.append(result)

        # 寄存器常量追踪: mov reg, imm
        if mnem == "mov" and len(ops) >= 2:
            src = ops[1].strip().lstrip("$")
            if src.startswith("0x") or src.isdigit():
                dst_reg = ops[0].strip().lower().lstrip("%")
                self._known_constants[dst_reg] = (
                    int(src, 16) if src.startswith("0x") else int(src))

    def finalize(self, instructions: List[dict]) -> List[dict]:
        """所有指令分析完毕后, 运行三阶段FP过滤."""
        self._filtered_findings = self._fp_filter.filter(
            self._raw_findings, instructions, self._alloc_tracker)
        return self._filtered_findings

    @property
    def raw_findings(self) -> List[dict]:
        return list(self._raw_findings)

    @property
    def findings(self) -> List[dict]:
        return list(self._filtered_findings)

    @property
    def stats(self) -> dict:
        return {
            "raw_findings": len(self._raw_findings),
            "filtered_findings": len(self._filtered_findings),
            "alloc_tracker": self._alloc_tracker.stats(),
            "fp_filter": self._fp_filter.stats,
        }

    @staticmethod
    def _extract_func(target: str) -> str:
        t = target.strip().lower()
        for p in ("call ","callq "):
            if t.startswith(p): t = t[len(p):]
        return t.split("@")[0].split("(")[0].split(".")[-1]

    @staticmethod
    def _get_arg_reg(ops: List[str], idx: int, default: str) -> str:
        if idx + 1 < len(ops):
            return ops[idx + 1].strip().lower().lstrip("%")
        return default


__all__ = ["HeapOverflowDetector"]
