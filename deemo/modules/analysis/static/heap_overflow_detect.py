# 增强型堆溢出检测器 (Enhanced Heap Overflow Detector)
#
# 整合后向值流追踪 + 约束简化 + 多阶段FP过滤,
# 在保留高召回的同时压低误报率.
#
# 创建: 2026-06-21

from typing import Dict, List, Optional, Tuple

from .heap_constraint import HeapConstraintTracker, Interval
from .heap_alloc_model import AllocatorFamily, HeapAllocModel
from .heap_fp_filter import HeapFPFilter
from .heap_slice_trace import BackwardSliceTracer
from .heap_struct_infer import HeapStructInference
from .path_sensitive_vra import PathSensitiveVRA
from .value_range_analyzer import ValueRangeAnalyzer
from .value_range import ValueRange
from .sym_propagator import SymbolicPropagator
from .sym_size_correlator import SymbolicSizeTracker as _SymCorrTracker
from .symbolic_size_expr import SymbolicSizeTracker
from .symbolic_correlator import SymbolicCorrelator
from .ddssc_coordinator import DDSSCCoordinator
from .ddssc_fp_filter import DDSSCFPFilter
from .octagon_filter import OctagonFPFilter
from .co_source_filter import AWSCFPFilter
from .loop_write_accumulator import LoopWriteAccumulator
from .octagon_filter import OctagonFPFilter
from .disasm_util import extract_func_name

from ._heap_insn_handlers import HeapInsnHandlerMixin
from ._heap_call_handlers import HeapCallHandlerMixin
from ._heap_finalize import HeapFinalizeMixin
from ._heap_provenance import HeapProvenanceMixin
from ._heap_precision_stages import HeapPrecisionStagesMixin
from .bounded_write_recovery import BoundedWriteRecovery


class HeapOverflowDetector(
    HeapPrecisionStagesMixin,
    HeapInsnHandlerMixin, HeapCallHandlerMixin, HeapFinalizeMixin,
    HeapProvenanceMixin,
):
    """增强型堆溢出检测器.

    输入: 反汇编指令流.
    输出: 过滤后的高置信度堆溢出告警.
    """

    ALLOC_FUNCS = {"malloc", "calloc", "realloc", "_Znwm", "_Znam",
                   "g_malloc", "g_try_malloc", "ExAllocatePoolWithTag"}
    WRITE_FUNCS = {"memcpy", "memmove", "memset", "strcpy", "strncpy",
                   "strcat", "sprintf", "snprintf", "read", "fread", "recv"}
    FREE_FUNCS = {"free", "_ZdlPv", "g_free", "ExFreePool"}

    _UNSIZED_WRITES = {"strcpy", "strcat", "gets", "sprintf"}

    _WIN64_ARGS = ["rcx", "rdx", "r8", "r9"]
    _SYSV_ARGS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]

    def __init__(
        self,
        allocator: Optional[AllocatorFamily] = None,
        allocator_family: AllocatorFamily = AllocatorFamily.GLIBC,
        use_win64_abi: bool = False,
        enable_bwr: bool = True,
        enable_pcst: bool = True,
    ):
        family = allocator if allocator is not None else allocator_family
        self._alloc_tracker = HeapConstraintTracker()
        self._fp_filter = HeapFPFilter()
        self._tracer = BackwardSliceTracer()
        self._raw_findings: List[dict] = []
        self._filtered_findings: List[dict] = []
        self._known_constants: Dict[str, int] = {}
        self._stack_constants: Dict[str, int] = {}
        self._instructions: List[dict] = []

        self._win64 = use_win64_abi
        self._args = self._WIN64_ARGS if use_win64_abi else self._SYSV_ARGS
        self._alloc_model = HeapAllocModel(family)
        self._sym_tracker = _SymCorrTracker()
        self._sym_propagator = SymbolicPropagator(self._sym_tracker)
        self._sym_snapshots: Dict[int, dict] = {}
        self._struct_infer = HeapStructInference()
        self._ps_vra = PathSensitiveVRA()
        self._vra = ValueRangeAnalyzer()
        self._ddssc_coordinator = DDSSCCoordinator(enable_smt=True)
        self._ddssc_filter = DDSSCFPFilter(self._ddssc_coordinator)
        self._symbolic_correlator = SymbolicCorrelator()
        self._struct_size_tracker = SymbolicSizeTracker(
            arg_regs=tuple(self._args))
        self._loop_accumulator = LoopWriteAccumulator(
            use_win64_abi=use_win64_abi)
        self._init_provenance()
        self._octagon_filter = OctagonFPFilter()
        self._awsc_filter = AWSCFPFilter(
            use_win64_abi=use_win64_abi, alloc_model=self._alloc_model)

        # PCST+BWR精度阶段
        self._enable_pcst = enable_pcst
        self._bwr_enabled = enable_bwr and enable_pcst
        self._bwr = BoundedWriteRecovery(self._alloc_model)
        self._bwr_safe_suppressed = 0
        self._bwr_unknown_skipped = 0
        self._addr_to_idx: Dict[int, int] = {}

        self._min_user_addr: int = 0
        self._user_func_ranges: List[Tuple[int, int]] = []

    def set_min_user_addr(self, addr: int):
        self._min_user_addr = addr

    def set_rodata_bytes(self, rodata: dict):
        """注入 .rdata/.rodata 节字节映射, 供BWR读取字符串字面量."""
        if rodata:
            self._bwr.set_rodata(rodata)

    def set_user_func_ranges(self, ranges: List[Tuple[int, int]]):
        self._user_func_ranges = ranges

    def pre_analyze(self, instructions: List[dict]):
        """预分析: 值域分析 + 符号传播参数初始化."""
        self._instructions = instructions
        self._vra.analyze(instructions)
        self._sym_propagator.init_function_params(self._args)

    def analyze_instruction(self, ins: dict):
        """逐指令分析: 追踪分配/写入/释放."""
        mnem = ins.get("mnemonic", "").lower()
        ops = ins.get("operands", [])
        addr = ins.get("address", 0)

        self._sym_propagator.handle_instruction(ins, self._known_constants)

        if mnem == "call" and ops:
            self._handle_call(ins, ops, addr)
        elif mnem == "rep" or (mnem.startswith("rep") and ops):
            self._handle_rep_movs(ins, ops, addr)
        elif mnem in ("mov", "movsxd", "movzx", "movsx") and len(ops) >= 2:
            self._handle_mov(ins, ops, addr)
        elif mnem == "lea" and len(ops) >= 2:
            self._handle_lea(ins, ops, addr)
        elif mnem in ("shl", "sal", "shr", "sar") and len(ops) >= 2:
            self._handle_shift_const(ins, ops, addr)
        elif mnem in ("add", "sub") and len(ops) >= 2:
            self._handle_arith_const(ins, ops, addr)
        elif mnem in ("movaps", "movups", "movdqa", "movdqu",
                       "movapd", "movupd") and len(ops) >= 2:
            self._handle_inline_sse_store(ins, ops, addr)

    def _is_user_code(self, addr: int) -> bool:
        """判断地址是否属于用户代码区(非CRT库).

        _user_func_ranges非空时检查地址是否在任一函数范围内;
        _min_user_addr作为辅助过滤, 但不单独拒绝(分配可能在main之前).
        """
        if self._user_func_ranges:
            for lo, hi in self._user_func_ranges:
                if lo <= addr < hi:
                    return True
            if self._min_user_addr and addr < self._min_user_addr:
                return False
            return False
        return True

    def _get_precise_range(self, addr: int, reg: str) -> Optional[ValueRange]:
        """获取寄存器在指定地址的精确值域."""
        return self._vra.get_range_at(addr, reg)

    def _get_arg_reg(self, ops: List[str], idx: int, default: str) -> str:
        if idx + 1 < len(ops):
            return ops[idx + 1].strip().lower().lstrip("%")
        return default

    @property
    def raw_findings(self) -> List[dict]:
        return list(self._raw_findings)

    @property
    def findings(self) -> List[dict]:
        return list(self._filtered_findings)

    @property
    def stats(self) -> dict:
        s = {
            "raw_findings": len(self._raw_findings),
            "filtered_findings": len(self._filtered_findings),
            "alloc_tracker": self._alloc_tracker.stats(),
        }
        if getattr(self, "_bwr", None) is not None:
            s["bwr"] = {
                "enabled": self._bwr_enabled,
                "safe_suppressed": self._bwr_safe_suppressed,
                "unknown_skipped": self._bwr_unknown_skipped,
                **self._bwr.stats,
            }
        return s


__all__ = ["HeapOverflowDetector"]
