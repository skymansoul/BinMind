"""整数溢出区间分析引擎 — 区间传播 + 溢出检测.

替代已标记 DEPRECATED 的 int_range_analyzer.py。
指令分派在 insn_dispatch.py, 转移函数在本模块, 仅做状态管理+转移+输出。
方法: Cousot & Cousot, Mine 抽象解释框架。
"""

from dataclasses import dataclass
from typing import Dict, List, Set, Tuple

try:
    from .interval_domain import (
        Interval, interval_add, interval_sub, interval_mul,
        interval_shl, interval_and_const, interval_meet,
        interval_can_overflow, interval_sign_extend,
    )
    from .insn_to_interval import (
        RegisterState, _GPRS, _parse_immediate, _ARITH_HANDLERS,
    )
    from .insn_dispatch import dispatch_instruction
except ImportError:
    from interval_domain import (  # type: ignore[no-redef]
        Interval, interval_add, interval_sub, interval_mul,
        interval_shl, interval_and_const, interval_meet,
        interval_can_overflow, interval_sign_extend,
    )
    from insn_to_interval import (  # type: ignore[no-redef]
        RegisterState, _GPRS, _parse_immediate, _ARITH_HANDLERS,
    )
    from insn_dispatch import dispatch_instruction  # type: ignore[no-redef]


@dataclass
class OverflowCandidate:
    """一个整数溢出候选 — 由区间分析判定."""
    insn_addr: int
    insn_text: str
    operation: str
    width_bits: int
    left_interval: Interval
    right_interval: Interval
    result_interval: Interval
    overflow_possible: bool
    overflow_type: str
    used_in_alloc: bool = False
    risk_level: str = 'low'


class IntervalPropagationEngine:
    """基于抽象解释的整数区间传播引擎.

    在每个函数内做正向区间传播.
    不构建完整的 CFG — 用指令间的前向线性扫描.
    """

    def __init__(self):
        self._state = RegisterState()
        self._candidates: List[OverflowCandidate] = []
        self._alloc_regs: Set[str] = set()
        self._insn_count: int = 0
        self._back_edges: Set[int] = set()
        self._stack: Dict[int, Interval] = {}
        self._last_cmp = None  # (left_op, right_op) | None
        self._guards: Dict[int, list] = {}  # addr → [(left, right, cond)]
        self._post_check_reg: str = None  # test reg,reg → reg name for js suppression

    # 转移函数 (被 insn_dispatch 调用)

    def _transfer_mov_imm(self, dst: str, imm: int) -> None:
        """mov reg, imm → reg := [imm, imm]."""
        self._state.set(dst, Interval.const(imm))

    def _transfer_mov_reg(self, dst: str, src: str) -> None:
        """mov reg1, reg2 → reg1 := state(reg2)."""
        self._state.set(dst, self._state.get(src))

    def _transfer_mov_load(self, dst: str, base: str, offset: int) -> None:
        """mov reg, [base + offset] → 查栈内存, 无则 TOP."""
        if base.lower() in ('rbp', 'ebp', 'rsp', 'esp'):
            self._state.set(dst, self._stack.get(offset, Interval.top()))
        else:
            self._state.set(dst, Interval.top())

    def _transfer_mov_store(self, base: str, offset: int,
                            src_iv: Interval) -> None:
        """mov [base + offset], reg/imm → 记录栈值."""
        if base.lower() in ('rbp', 'ebp', 'rsp', 'esp'):
            self._stack[offset] = src_iv

    def _transfer_arithmetic(self, op: str, dst: str,
                             left: Interval, right: Interval,
                             insn_addr: int, insn_text: str,
                             width_bits: int = 32) -> None:
        """算术指令的抽象传递 — 含溢出检测与噪声过滤."""
        handler = _ARITH_HANDLERS.get(op)
        if handler is None:
            return
        result = handler(left, right)
        self._state.set(dst, result)

        # 噪声过滤: rsp/esp 目标是栈帧管理
        if dst.lower() in ('rsp', 'esp'):
            return
        # 噪声过滤: 仅当dst是alloc指针寄存器时跳过TOP+小常量加法
        if (op in ('add', 'sub')
            and left.is_top
            and right.is_constant()
            and abs(right.lo) < 0x10000
            and dst.lower() in self._alloc_regs):
            return

        ovf = interval_can_overflow(left, right, op, width_bits)
        if ovf or (not result.is_top and not result.is_bottom
                   and result.hi >= (1 << width_bits)):
            risk = ('critical' if dst.lower() in self._alloc_regs
                    else 'high')
            self._candidates.append(OverflowCandidate(
                insn_addr=insn_addr, insn_text=insn_text,
                operation=op, width_bits=width_bits,
                left_interval=left, right_interval=right,
                result_interval=result,
                overflow_possible=True, overflow_type='wrap',
                used_in_alloc=dst.lower() in self._alloc_regs,
                risk_level=risk))

    @staticmethod
    def _width_from_reg(reg_name: str) -> int:
        """从寄存器名推断位宽: r64→64, e32→32, 16位→16."""
        r = reg_name.lower()
        if r in ('rax','rbx','rcx','rdx','rsi','rdi','rbp','rsp',
                 'r8','r9','r10','r11','r12','r13','r14','r15'):
            return 64
        if r in ('eax','ebx','ecx','edx','esi','edi','ebp','esp',
                 'r8d','r9d','r10d','r11d','r12d','r13d','r14d','r15d'):
            return 32
        if r in ('ax','bx','cx','dx','si','di','bp','sp'):
            return 16
        return 32

    def _transfer_shl(self, dst: str, src: str, shift_imm: int,
                      insn_addr: int, insn_text: str,
                      width_bits: int = 0) -> None:
        """shl dst, N — 左移. width_bits=0时按dst寄存器名推断."""
        if width_bits <= 0:
            width_bits = self._width_from_reg(dst)
        src_iv = self._state.get(src)
        result = interval_shl(src_iv, shift_imm)
        self._state.set(dst, result)
        limit = (1 << width_bits) - 1
        if not result.is_top and not result.is_bottom and result.hi > limit:
            self._candidates.append(OverflowCandidate(
                insn_addr=insn_addr, insn_text=insn_text,
                operation='shl', width_bits=width_bits,
                left_interval=src_iv,
                right_interval=Interval.const(shift_imm),
                result_interval=result,
                overflow_possible=True, overflow_type='wrap',
                risk_level='medium'))

    def _transfer_and(self, dst: str, src_reg: str, mask: int) -> None:
        """and reg, mask — 位与约束收紧."""
        src_iv = self._state.get(src_reg)
        result = interval_and_const(src_iv, mask)
        self._state.set(dst, result)

    def _transfer_sign_extend(self, dst: str, src: str,
                               from_bits: int, to_bits: int) -> None:
        """cdqe / movsxd — 符号扩展: src → dst (from_bits → to_bits)."""
        src_iv = self._state.get(src)
        if src_iv.is_top or src_iv.is_bottom:
            self._state.set(dst, src_iv)
            return
        result = interval_sign_extend(src_iv, from_bits, to_bits)
        self._state.set(dst, result)

    # 指令分派 (委托给 insn_dispatch)

    def feed_instruction(self, mnemonic: str, op_str: str,
                         insn_addr: int = 0,
                         mark_alloc_args: bool = False) -> None:
        """单条指令分派 — 委托给 insn_dispatch.dispatch_instruction."""
        dispatch_instruction(self, mnemonic, op_str, insn_addr,
                            mark_alloc_args)
        # Post-check pattern: test reg,reg + js → __builtin_add_overflow 模式
        mnem = mnemonic.lower()
        ops = [o.strip() for o in op_str.split(',') if o.strip()]
        if mnem == 'test' and len(ops) == 2 and ops[0].lower() == ops[1].lower():
            self._post_check_reg = ops[0]
        elif mnem == 'js' and self._post_check_reg and self._candidates:
            last = self._candidates[-1]
            parts = last.insn_text.split()
            if len(parts) >= 2:
                last_dst = parts[1].split(',')[0].strip().lower()
                if (parts[0].lower() in ('add', 'sub', 'mul', 'imul')
                    and last_dst == self._post_check_reg.lower()):
                    # 仅确认跳向错误处理路径时才抑制, 否则保留候选
                    js_target = op_str.strip().lower()
                    is_err_path = any(
                        kw in js_target for kw in
                        ('err', 'fail', 'cleanup', 'overflow', 'abort',
                         '.LBB_', 'trap'))
                    if is_err_path:
                        self._candidates.pop()
            self._post_check_reg = None
        elif mnem not in ('test',):
            self._post_check_reg = None

    def feed_instructions(self,
                          instructions: List[Tuple[str, str, int]],
                          mark_alloc_args: bool = True) -> None:
        """批量处理指令序列."""
        for mnem, op_str, addr in instructions:
            self.feed_instruction(mnem, op_str, addr, mark_alloc_args)

    # 分析输出

    def detect_overflows(self, width_bits: int = 32,
                         min_risk: str = 'medium') -> List[OverflowCandidate]:
        """返回所有检测到的溢出候选."""
        risk_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        min_idx = risk_order.get(min_risk, 99)
        filtered = [c for c in self._candidates
                    if c.overflow_possible
                    and risk_order.get(c.risk_level, 99) <= min_idx]
        return sorted(filtered,
                     key=lambda c: risk_order.get(c.risk_level, 99))

    def state_summary(self) -> dict:
        reg_count = sum(1 for iv in self._state.regs.values()
                       if not iv.is_top and not iv.is_bottom)
        return {
            'insns_processed': self._insn_count,
            'regs_tracked': len(self._state.regs),
            'regs_constrained': reg_count,
            'overflow_candidates': len(self._candidates),
            'alloc_regs': sorted(self._alloc_regs),
        }

    def clear(self) -> None:
        self._state = RegisterState()
        self._candidates.clear()
        self._alloc_regs.clear()
        self._insn_count = 0
        self._back_edges.clear()
        self._stack.clear()
        self._last_cmp = None
        self._guards.clear()
        self._post_check_reg = None


# 便捷入口

def analyze_int_overflow(
    instructions: List[Tuple[str, str, int]],
    width_bits: int = 32,
) -> Tuple[List[OverflowCandidate], dict]:
    """便捷入口: 指令序列 → 溢出候选列表 + 统计信息."""
    engine = IntervalPropagationEngine()
    engine.feed_instructions(instructions)
    cands = engine.detect_overflows(width_bits)
    return cands, engine.state_summary()
