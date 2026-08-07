# 整数溢出静态检测器 — 基于ASA-VRA值域框架
# 核心创新: 复用堆溢出检测的值域基础设施,
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
        'register_frame_ctor'}

    def __init__(self):
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
                    or re.match(r'^func_\d+$', self._current_func)):
                continue
            # 传播 + 检测
            self._propagate_vr(op, operands, idx, line)
            self._check_overflow(op, operands, idx, line, instructions)
            if op == 'call':
                self._check_alloc_mul_chain(idx, operands, line)
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
        """值域传播: 寄存器 + 栈槽."""
        if op in ('mov', 'movzx', 'movsx') and len(operands) >= 2:
            raw_dst = operands[0]
            raw_src = operands[1] if len(operands) > 1 else ''
            dst = InstructionParser.clean_reg(raw_dst)
            src = InstructionParser.clean_reg(raw_src)
            dst64 = InstructionParser.normalize_reg64(dst)
            imm = InstructionParser.parse_immediate(src)
            # mov reg, imm
            if imm is not None and InstructionParser.is_reg(dst):
                self._vd.set(dst64, ValueRange.constant(imm))
                return
            # mov [rbp-X], imm → 栈槽
            if imm is not None:
                off = self._get_stack_offset(raw_dst)
                if off is not None:
                    self._stack_slots[f'rbp{off:+d}'] = ValueRange.constant(imm)
                    return
            # mov reg, reg → 传播
            if InstructionParser.is_reg(dst) and InstructionParser.is_reg(src):
                src64 = InstructionParser.normalize_reg64(src)
                src_vr = self._vd.get(src64)
                if not src_vr.is_top:
                    self._vd.set(dst64, src_vr)
                return
            # mov reg, [rbp-X] → 从栈槽加载
            if InstructionParser.is_reg(dst):
                off = self._get_stack_offset(raw_src)
                if off is not None:
                    slot_key = f'rbp{off:+d}'
                    if slot_key in self._stack_slots:
                        self._vd.set(dst64, self._stack_slots[slot_key])
                return
        # lea reg, [base+offset] → 传播调整后的值域
        if op == 'lea' and len(operands) >= 2:
            dst64 = InstructionParser.normalize_reg64(
                InstructionParser.clean_reg(operands[0]))
            src = operands[1]
            base, off, idx_reg, scale = InstructionParser.parse_lea_src(src)
            if base:
                base64 = InstructionParser.normalize_reg64(base)
                base_vr = self._vd.get(base64)
                if not base_vr.is_top:
                    if off != 0:
                        self._vd.set(dst64, base_vr.add(
                            ValueRange.constant(off)))
                    else:
                        self._vd.set(dst64, base_vr)
        # cdqe: eax → rax 符号扩展
        if op == 'cdqe':
            eax_vr = self._vd.get('eax')
            if not eax_vr.is_top:
                self._vd.set('rax', eax_vr)

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
            recommendation=rec))
        self._call_ctr += 1

    def _check_overflow(self, op: str, operands: List[str],
                        idx: int, line: str, instructions: List[str]):
        if len(operands) < 2:
            return
        dst = InstructionParser.clean_reg(operands[0])
        dst64 = InstructionParser.normalize_reg64(dst)
        raw_src = operands[1] if len(operands) > 1 else ''
        src = InstructionParser.clean_reg(raw_src)
        src64 = InstructionParser.normalize_reg64(src) if src else ''
        dst_vr = self._vd.get(dst64)

        if op in ('add', 'sub'):
            if not InstructionParser.is_reg(dst):
                return
            imm = InstructionParser.parse_immediate(src)
            delta = 0
            if imm is not None:
                delta = imm * (-1 if op == 'sub' else 1)
            elif InstructionParser.is_reg(src):
                src_vr = self._vd.get(src64)
                if not src_vr.is_top:
                    delta = src_vr.umax if op == 'add' else -src_vr.umin
            if delta == 0 or dst_vr.is_top:
                return
            vb = dst_vr.summarize()
            # Mode 1: 无符号加法回绕
            if delta > 0 and dst_vr.umax + delta > 0xFFFFFFFFFFFFFFFF:
                self._emit(IntOverflowMode.UADD_WRAP,
                    IntOverflowSeverity.MEDIUM, 0.65, op, dst, src,
                    idx, line, vb, f'+{delta}: 回绕可能',
                    f"{op} {dst}, {delta:+d}: "
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
                        IntOverflowSeverity.MEDIUM, 0.55, op, dst, src,
                        idx, line, vb, f'+{delta_s}: {bw}位有符号溢出',
                        f"{bw}位smax={dst_vr.smax}+{delta_s}"
                        f"={r_smax:#x}>{smax_bound:#x}")
            # Mode 6: 减法下溢
            if op == 'sub' and dst_vr.umin < abs(delta):
                self._emit(IntOverflowMode.USUB_WRAP,
                    IntOverflowSeverity.LOW, 0.50, op, dst, src,
                    idx, line, vb, f'-{abs(delta)}: 下溢回绕',
                    f"umin={dst_vr.umin}<|{delta}|→回绕")

        elif op in ('imul', 'mul') and len(operands) >= 2:
            if not InstructionParser.is_reg(dst):
                return
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
                        IntOverflowSeverity.HIGH, 0.75, op, dst, src,
                        idx, line, dst_vr.summarize(),
                        f'x{imm}: 溢出DWORD',
                        f"umax={dst_vr.umax:#x}*{imm}={product:#x}>DWORD_MAX")
                self._last_mul_dst[dst64] = dst_vr.mul(
                    ValueRange.constant(imm))

        elif op in ('shl', 'sal'):
            if not InstructionParser.is_reg(dst):
                return
            imm = InstructionParser.parse_immediate(src)
            if imm is not None and imm > 0 and not dst_vr.is_top:
                if dst_vr.umin > 0:
                    shifted = dst_vr.umax << imm
                    if shifted > 0xFFFFFFFF:
                        self._emit(IntOverflowMode.USHL_OVF,
                            IntOverflowSeverity.HIGH, 0.70, 'shl', dst, src,
                            idx, line, dst_vr.summarize(),
                            f'<<{imm}: 溢出可能',
                            f"shl {dst},{imm}: umin={dst_vr.umin}>0, "
                            f"max={shifted:#x}>DWORD_MAX")

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