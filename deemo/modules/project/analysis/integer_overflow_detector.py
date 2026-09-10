# 整数溢出静态检测器 — 基于ASA-VRA值域框架
# 复用堆溢出检测的值域基础设施,
#   但不检测堆分配边界, 而是检测算术操作中的整数溢出/回绕
# 八模式检测管道 + 栈变量追踪:
#   Mode 1: UADD_WRAP  Mode 2: UMUL_OVF  Mode 3: USHL_OVF
#   Mode 4: SADD_OVF   Mode 5: SEXT_TRUNC Mode 6: USUB_WRAP
#   Mode 7: ALLOC_SIZE_MUL  Mode 8: LOOP_COUNTER_WRAP
# 设计原则: 与HeapOverflowDetector共享ValueRangeDomain, 正交检测
# 理论来源:
#   Dietz et al. "Understanding Integer Overflow in C/C++" (ICSE 2012/2015)
#   Wang et al. "Int Overflow Detection with Abstract Interpretation" (ISSTA 2023)
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple

from .value_range import ValueRange
from .value_range import ValueRangeDomain
from .instruction_parser import InstructionParser

class IntOverflowMode(Enum):
    UADD_WRAP = auto(); UMUL_OVF = auto(); USHL_OVF = auto()
    SADD_OVF = auto(); SEXT_TRUNC = auto(); USUB_WRAP = auto()
    ALLOC_SIZE_MUL = auto(); LOOP_COUNTER_WRAP = auto()


class IntOverflowSeverity(Enum):
    CRITICAL = auto(); HIGH = auto(); MEDIUM = auto(); LOW = auto(); INFO = auto()

@dataclass
class IntOverflowFinding:
    finding_id: str; mode: IntOverflowMode; severity: IntOverflowSeverity
    confidence: float; operation: str; operands: str
    value_before: str; value_after: str
    instruction_idx: int; instruction_text: str; function_name: str
    detail: str; recommendation: str = ""
    dst_reg: str = ""
    is_false_positive: bool = False
    false_positive_reason: str = ""
class IntegerOverflowDetector:
    """整数溢出静态检测器 — 八模式管道.
    复用 ValueRangeDomain + 栈变量追踪.
    """

    _MALLOC_FUNCS = {'malloc', 'calloc', 'realloc', '_malloc',
                     'HeapAlloc', 'GlobalAlloc'}
    _CRT_NOISE_FUNCS = {'__tmainCRTStartup', 'WinMainCRTStartup',
        'mainCRTStartup', '__mingw_invalidParameterHandler', 'safe_flush',
        '__do_global_dtors', '__do_global_ctors', '__gcc_register_frame',
        '__gcc_deregister_frame', 'check_managed_app', 'atexit',
        'register_frame_ctor', 'wcsnlen', 'strnlen', '_lock_file',
        '_unlock_file', '_set_invalid_parameter_handler',
        '_get_invalid_parameter_handler', '_configthreadlocale',
        '__acrt_iob_func', 'wcrtomb', 'mbrtowc', '__mingw_wcrtomb_cp',
        '__mingw_mbrtowc_cp', 'fallback_IsDBCSLeadByteEx',
        '__mingw_isleadbyte_cp', '__p__fmode', '__p__commode',
        '__p___initenv', '_initterm_e', '_initterm', '__mingw_glob',
        '__mingw_dirname', '__mingw_basename', '_fpreset',
        '__report_error', '__write_memory', 'restore_modified_sections',
        'do_pseudo_reloc', '__mingw_printf', '__mingw_pformat',
        '__pformat_putc', '__pformat_puts', '__pformat_int'}
    def __init__(self, wrap_sanitize_validation: bool = True):
        """wrap_sanitize_validation: 回绕结果被掩码/截断/右移净化
        后不再构成实际溢出 → 标记可抑制. 关闭时恢复逐算术点判定."""
        self._wrap_sanitize_validation = wrap_sanitize_validation
        self._vd = ValueRangeDomain()
        self._parser = InstructionParser()
        self._current_func = "_entry_"
        self._call_ctr = 0
        self._findings: List[IntOverflowFinding] = []
        self._stack_slots: Dict[str, ValueRange] = {}
        self._last_mul_dst: Dict[str, ValueRange] = {}

    def analyze(self, instructions: List[str],
                func_map: Optional[Dict[str, Tuple[int, int]]] = None,
                instr_addrs: Optional[List[int]] = None
                ) -> List[IntOverflowFinding]:
        self._vd = ValueRangeDomain()
        self._current_func = "_entry_"
        self._call_ctr = 0
        self._findings = []
        self._stack_slots = {}
        self._last_mul_dst = {}
        func_map = func_map or {}

        for idx, line in enumerate(instructions):
            result = InstructionParser.parse_line(line)
            if result is None:
                continue
            op, operands = result
            if not op:
                continue
            # 函数边界
            if func_map:
                for fname, (s, e) in func_map.items():
                    if s <= idx <= e and self._current_func != fname:
                        self._vd.clear_registers()
                        self._stack_slots.clear()
                        self._current_func = fname
                        break
            # CRT噪声过滤
            if self._current_func in self._CRT_NOISE_FUNCS:
                continue
            if (self._current_func.startswith(('__', '_.', '<'))
                    or self._current_func.startswith(
                        ('_mingw', '_acrt', '_p_', 'fallback_'))
                    or re.match(r'^func_\d+$', self._current_func)
                    or '_D2A' in self._current_func
                    or 'dtoa' in self._current_func.lower()
                    or self._current_func == 'bitstob'):
                continue
            # 传播 + 检测
            self._propagate_vr(op, operands, idx, line)
            self._check_overflow(op, operands, idx, line, instructions)
            if op == 'call':
                self._check_alloc_mul_chain(idx, operands, line)
        from .int_sanitization import apply_sanitization
        apply_sanitization(self._findings, instructions,
                           self._wrap_sanitize_validation)
        return self._findings

# 值域传播
    def _get_stack_offset(self, text: str) -> Optional[int]:
        m = re.search(r'\[rbp\s*([-+])\s*(0x[0-9a-fA-F]+|\d+)\]',
                      text, re.IGNORECASE)
        if m:
            off = int(m.group(2), 16) if m.group(2).startswith(
                '0x') else int(m.group(2))
            return -off if m.group(1) == '-' else off
        return None

    def _propagate_vr(self, op: str, operands: List[str],
                      idx: int, line: str):
        """值域传播: 委托模块函数 (动态访问自身状态)."""
        from .int_vr_propagation import propagate_vr
        propagate_vr(self, op, operands, idx, line)

# 溢出检测
    def _emit(self, mode, severity, confidence, op, dst, src, idx, line,
              val_before, val_after, detail, rec=""):
        """统一发射溢出发现."""
        self._findings.append(IntOverflowFinding(
            finding_id=f"INT-{mode.name[:4]}-{self._call_ctr}@{idx}",
            mode=mode, severity=severity, confidence=confidence,
            operation=op, operands=f'{dst}, {src}',
            value_before=val_before, value_after=val_after,
            instruction_idx=idx, instruction_text=line,
            function_name=self._current_func, detail=detail,
            recommendation=rec, dst_reg=dst))
        self._call_ctr += 1

    def _check_overflow(self, op: str, operands: List[str],
                        idx: int, line: str, instructions: List[str]):
        if len(operands) < 2 and op != 'cdqe':
            return
        raw_dst = operands[0] if operands else 'rax'
        dst = InstructionParser.clean_reg(raw_dst)
        dst64 = InstructionParser.normalize_reg64(dst)
        raw_src = operands[1] if len(operands) > 1 else ''
        src = InstructionParser.clean_reg(raw_src)
        src64 = InstructionParser.normalize_reg64(src) if src else ''
        # 内存槽目标支持: add [rbp-0x4], imm 形式的回绕检测
        is_mem_dst = '[' in raw_dst and ']' in raw_dst
        slot_key = None
        if is_mem_dst:
            off = self._get_stack_offset(raw_dst)
            if off is not None:
                slot_key = f'rbp{off:+d}'
            dst_vr = (self._stack_slots.get(slot_key, ValueRange.top())
                      if slot_key else ValueRange.top())
            dst_label = raw_dst
        else:
            dst_vr = self._vd.get(dst64)
            dst_label = dst
        if not (InstructionParser.is_reg(dst) or is_mem_dst):
            return
        if op in ('add', 'sub'):
            if dst_vr.is_top:
                return
            imm = InstructionParser.parse_immediate(src)
            delta = 0
            if imm is not None:
                delta = imm * (-1 if op == 'sub' else 1)
            elif InstructionParser.is_reg(src):
                src_vr = self._vd.get(src64)
                if not src_vr.is_top:
                    delta = src_vr.umax if op == 'add' else -src_vr.umin
            if delta == 0:
                return
            vb = dst_vr.summarize()
            # 操作位宽: 内存目标从 SIZE PTR 前缀提取, 寄存器按位宽表
            bw = 64
            if is_mem_dst:
                wm = re.search(r'\b(DWORD|QWORD|WORD|BYTE)\s+PTR', line, re.I)
                if wm:
                    bw = {'BYTE': 8, 'WORD': 16, 'DWORD': 32,
                          'QWORD': 64}[wm.group(1).upper()]
            else:
                bw = InstructionParser.reg_bit_width(dst) or 64
            max_u = (1 << bw) - 1
            # Mode 1: 无符号加法回绕 (位宽感知, 32 位回绕同检)
            if delta > 0 and dst_vr.umax + delta > max_u:
                self._emit(IntOverflowMode.UADD_WRAP,
                    IntOverflowSeverity.MEDIUM, 0.65, op, dst_label, src,
                    idx, line, vb, f'+{delta}: 回绕可能',
                    f"{op} {dst_label}, {delta:+d}: "
                    f"umax={dst_vr.umax:#x}+{delta:#x}>U64_MAX")
            # Mode 4: 有符号溢出 — 位宽感知阈值
            bw = InstructionParser.reg_bit_width(dst)
            if bw and bw <= 64:
                smax_bound = (1 << (bw - 1)) - 1
                smin_bound = -(1 << (bw - 1))
                delta_s = delta
                if imm is None and InstructionParser.is_reg(src):
                    s_vr = self._vd.get(src64)
                    if not s_vr.is_top:
                        delta_s = (s_vr.smax if op == 'add'
                                   else -s_vr.smin)
                r_smax = dst_vr.smax + delta_s
                r_smin = dst_vr.smin + delta_s
                if r_smax > smax_bound or r_smin < smin_bound:
                    self._emit(IntOverflowMode.SADD_OVF,
                        IntOverflowSeverity.MEDIUM, 0.55, op, dst_label, src,
                        idx, line, vb, f'+{delta_s}: {bw}位有符号溢出',
                        f"{bw}位smax={dst_vr.smax}+{delta_s}"
                        f"={r_smax:#x}>{smax_bound:#x}")
            # Mode 6: 减法下溢
            if op == 'sub' and dst_vr.umin < abs(delta):
                self._emit(IntOverflowMode.USUB_WRAP,
                    IntOverflowSeverity.LOW, 0.50, op, dst_label, src,
                    idx, line, vb, f'-{abs(delta)}: 下溢回绕',
                    f"umin={dst_vr.umin}<|{delta}|→回绕")

        elif op in ('imul', 'mul') and len(operands) >= 2:
            if not InstructionParser.is_reg(dst):
                return
            dst_label = dst
            imm = InstructionParser.parse_immediate(src)
            if imm is None and '[' in raw_src and ']' in raw_src:
                off = self._get_stack_offset(raw_src)
                if off is not None:
                    slot_key = f'rbp{off:+d}'
                    if slot_key in self._stack_slots:
                        slot_vr = self._stack_slots[slot_key]
                        if slot_vr.is_constant:
                            imm = slot_vr.constant_value
            if imm is not None and not dst_vr.is_top:
                product = dst_vr.umax * abs(imm)
                if product > 0xFFFFFFFF:
                    self._emit(IntOverflowMode.UMUL_OVF,
                        IntOverflowSeverity.HIGH, 0.75, op, dst_label, src,
                        idx, line, dst_vr.summarize(),
                        f'x{imm}: 溢出DWORD',
                        f"umax={dst_vr.umax:#x}*{imm}={product:#x}>DWORD_MAX")
                self._last_mul_dst[dst64] = dst_vr.mul(
                    ValueRange.constant(imm))

        elif op in ('shl', 'sal'):
            if not (InstructionParser.is_reg(dst) or is_mem_dst):
                return
            imm = InstructionParser.parse_immediate(src)
            if imm is not None and imm > 0 and not dst_vr.is_top:
                if dst_vr.umin > 0:
                    shifted = dst_vr.umax << imm
                    if shifted > 0xFFFFFFFF:
                        self._emit(IntOverflowMode.USHL_OVF,
                            IntOverflowSeverity.HIGH, 0.70, 'shl', dst_label, src,
                            idx, line, dst_vr.summarize(),
                            f'<<{imm}: 溢出可能',
                            f"shl {dst_label},{imm}: umin={dst_vr.umin}>0, "
                            f"max={shifted:#x}>DWORD_MAX")
        elif op in ('movsxd', 'cdqe'):
            # Mode 5: SEXT_TRUNC — 32 位负值符号扩展到 64 位产生巨值
            # movsxd rax, eax / cdqe: 源为 eax, 符号位为 1 时高位全 1
            if op == 'cdqe':
                ext_src = 'eax'
                ext_dst = dst_label
            else:
                if len(operands) < 2:
                    return
                ext_src = src
                ext_dst = dst_label
            src_vr = self._vd.get(
                InstructionParser.normalize_reg64(ext_src))
            # 符号判定按源寄存器位宽: 32 位源 eax 的符号位为 bit31
            src_bw = InstructionParser.reg_bit_width(ext_src) or 32
            sign_bit = 1 << (src_bw - 1)
            is_neg = (not src_vr.is_top
                      and (src_vr.umin & sign_bit) != 0)
            if is_neg:
                self._emit(IntOverflowMode.SEXT_TRUNC,
                    IntOverflowSeverity.LOW, 0.50, op, ext_dst, ext_src,
                    idx, line, src_vr.summarize(),
                    f'smin={src_vr.smin}: 符号扩展为巨值',
                    f"{op}: smin={src_vr.smin}<0 → 高位全1")
    def _check_alloc_mul_chain(self, idx: int, operands: List[str],
                               line: str):
        """Mode 7: 检测乘法结果→malloc溢出链."""
        if not operands:
            return
        callee = operands[0]
        if callee not in self._MALLOC_FUNCS:
            return
        if 'rcx' in self._last_mul_dst:
            mul_vr = self._last_mul_dst['rcx']
            if not mul_vr.is_top:
                self._emit(IntOverflowMode.ALLOC_SIZE_MUL,
                    IntOverflowSeverity.CRITICAL, 0.80,
                    f'{callee}(imul_result)', 'rcx', '',
                    idx, line, mul_vr.summarize(),
                    f'->{callee}: 截断分配',
                    f"乘法结果{mul_vr.summarize()}->{callee}: "
                    f"溢出导致分配远小于预期")

    def summary(self) -> Dict:
        modes = {}
        for f in self._findings:
            m = f.mode.name
            modes[m] = modes.get(m, 0) + 1
        return {'total_int_overflow': len(self._findings), 'by_mode': modes}
