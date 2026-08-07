"""指令分派模块 — mov/lea/arithmetic/call + 截断检测 + 守卫追踪. ≤300行."""

import re
try:
    from .interval_domain import Interval, interval_mul, interval_can_overflow
    from .insn_to_interval import _GPRS, _ARITH_HANDLERS, _parse_immediate
except ImportError:
    from interval_domain import Interval, interval_mul, interval_can_overflow  # type: ignore[no-redef]
    from insn_to_interval import _GPRS, _ARITH_HANDLERS, _parse_immediate  # type: ignore[no-redef]

_JC = {'jle':'le','jge':'ge','jl':'lt','jg':'gt','jbe':'be','jae':'ae','jb':'b','ja':'a'}

def _parse_mem_offset(op_str: str):
    """[base +/- offset] → (base, offset) | None."""
    m = re.search(r'\[(\w+)\s*([-+])\s*(0x[0-9a-fA-F]+|\d+)\]', op_str)
    if not m or 'rip' in op_str:
        return None
    base = m.group(1)
    sign = -1 if m.group(2) == '-' else 1
    off = sign * int(m.group(3), 0)
    return base, off


def _resolve_operand(engine: "IntervalPropagationEngine", op_str: str):
    """操作数 → Interval (寄存器/立即数/栈)."""
    op_lower = op_str.lower()
    imm = _parse_immediate(op_str)
    if imm is not None:
        return Interval.const(imm)
    if op_lower in _GPRS:
        return engine._state.get(op_str)
    parsed = _parse_mem_offset(op_lower)
    if parsed:
        base, off = parsed
        if base in ('rbp', 'ebp', 'rsp', 'esp') and off in engine._stack:
            return engine._stack[off]
    return Interval.top()


def _handle_lea(engine: "IntervalPropagationEngine",
                dst: str, lea_src: str, insn_addr: int,
                insn_label: str) -> None:
    """lea [base+off] / [base*scale±off] — 含溢出检测."""
    m_scale = re.search(
        r'\[(\w+)\s*\*\s*(\d+)\s*([-+])\s*(0x[0-9a-fA-F]+|\d+)\]', lea_src)
    if m_scale:
        return _do_lea_scale(engine, dst, m_scale, True, insn_addr, insn_label)
    m_s = re.search(r'\[(\w+)\s*\*\s*(\d+)\]', lea_src)
    if m_s:
        return _do_lea_scale(engine, dst, m_s, False, insn_addr, insn_label)
    m = re.search(r'\[(\w+)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\]', lea_src)
    if m:
        base_iv = engine._state.get(m.group(1))
        off = int(m.group(2), 0)
        if not base_iv.is_top:
            engine._state.set(dst, Interval(
                lo=base_iv.lo + off, hi=base_iv.hi + off))


def _do_lea_scale(engine: "IntervalPropagationEngine",
                  dst: str, match, has_offset: bool,
                  insn_addr: int, insn_label: str) -> None:
    """lea [reg*scale +/- offset] → 乘法溢出检测."""
    base = match.group(1)
    scale = int(match.group(2))
    off = 0
    if has_offset:
        sign = -1 if match.group(3) == '-' else 1
        off = sign * int(match.group(4), 0)
    base_iv = engine._state.get(base)
    if base_iv.is_top or base_iv.is_bottom:
        return
    lo = base_iv.lo * scale + off
    hi = base_iv.hi * scale + off
    new_iv = Interval(lo=min(lo, hi), hi=max(lo, hi))
    engine._state.set(dst, new_iv)
    if (scale > 1 and not base_iv.is_top
        and interval_can_overflow(base_iv, Interval.const(scale), 'mul', 32)):
        engine._candidates.append(type('OverflowCandidate', (), {
            'insn_addr': insn_addr, 'insn_text': insn_label,
            'operation': 'mul', 'width_bits': 32,
            'left_interval': base_iv,
            'right_interval': Interval.const(scale),
            'result_interval': new_iv,
            'overflow_possible': True, 'overflow_type': 'wrap',
            'used_in_alloc': False, 'risk_level': 'high',
        })())


def _handle_arith_mem(engine: "IntervalPropagationEngine",
                      mnem: str, ops: list,
                      insn_addr: int, insn_label: str) -> bool:
    """内存目标算术指令. 返回 True=已处理."""
    dst_lower = ops[0].lower()
    m_dst = _parse_mem_offset(dst_lower)
    if not m_dst:
        return False
    base, off = m_dst
    left = (engine._stack.get(off, Interval.top())
            if base in ('rbp', 'ebp', 'rsp', 'esp')
            else Interval.top())
    right = _resolve_operand(engine, ops[1])
    handler = _ARITH_HANDLERS.get(mnem)
    if not handler or left.is_top:
        return True
    result = handler(left, right)
    if base in ('rbp', 'ebp', 'rsp', 'esp'):
        engine._stack[off] = result
    ovf = interval_can_overflow(left, right, mnem, 32)
    if ovf or (not result.is_top and not result.is_bottom
               and result.hi >= (1 << 32)):
        engine._candidates.append(type('OverflowCandidate', (), {
            'insn_addr': insn_addr, 'insn_text': insn_label,
            'operation': mnem, 'width_bits': 32,
            'left_interval': left, 'right_interval': right,
            'result_interval': result,
            'overflow_possible': True, 'overflow_type': 'wrap',
            'used_in_alloc': False, 'risk_level': 'high',
        })())
    return True

def _check_alloc_overflow(engine: "IntervalPropagationEngine",
                          mnem: str, op_str: str,
                          ops: list, insn_addr: int) -> None:
    """alloc 调用点: arg1*arg2 溢出检测."""
    from int_interval_engine import OverflowCandidate
    arg1 = arg2 = None
    for reg in ('rcx', 'rdi', 'ecx', 'edi'):
        iv = engine._state.get(reg)
        if not iv.is_top and not iv.is_bottom:
            arg1 = iv; break
    for reg in ('rdx', 'rsi', 'edx', 'esi'):
        iv = engine._state.get(reg)
        if not iv.is_top and not iv.is_bottom:
            arg2 = iv; break
    insn_text = f'{mnem} {op_str}'
    cand = lambda **kw: OverflowCandidate(insn_addr=insn_addr,
        insn_text=insn_text, overflow_possible=True, **kw)
    if arg1 and arg2 and not arg1.is_top and not arg2.is_top:
        mul_result = interval_mul(arg1, arg2)
        if interval_can_overflow(arg1, arg2, 'mul', 32):
            engine._candidates.append(cand(
                operation='mul', width_bits=32, left_interval=arg1,
                right_interval=arg2, result_interval=mul_result,
                overflow_type='wrap', used_in_alloc=True, risk_level='critical'))
        elif not mul_result.is_top and mul_result.hi > (1 << 31) - 1:
            engine._candidates.append(cand(
                operation='mul', width_bits=32, left_interval=arg1,
                right_interval=arg2, result_interval=mul_result,
                overflow_type='near_wrap', used_in_alloc=True, risk_level='medium'))
    elif arg1 and not arg1.is_top:
        if arg1.lo > (1 << 31) or arg1.hi > (1 << 32):
            engine._candidates.append(cand(
                operation='alloc', width_bits=32, left_interval=arg1,
                right_interval=Interval.const(0), result_interval=arg1,
                overflow_type='alloc_size', used_in_alloc=True, risk_level='critical'))

def _check_store_trunc(engine: "IntervalPropagationEngine",
                       dst_lower: str, src_iv, insn_addr: int,
                       insn_label: str) -> None:
    """WORD/BYTE PTR 存储截断 → 溢出候选."""
    if src_iv.is_top or src_iv.is_bottom:
        return
    w = 16 if ('word' in dst_lower and 'dword' not in dst_lower and 'qword' not in dst_lower) else 8 if 'byte' in dst_lower else 0
    if w and src_iv.hi >= (1 << w):
        from int_interval_engine import OverflowCandidate
        m = (1 << w) - 1
        engine._candidates.append(OverflowCandidate(
            insn_addr=insn_addr, insn_text=insn_label,
            operation='trunc', width_bits=w,
            left_interval=src_iv, right_interval=Interval.const(1 << w),
            result_interval=Interval(lo=src_iv.lo & m, hi=src_iv.hi & m),
            overflow_possible=True, overflow_type='truncation',
            used_in_alloc=False, risk_level='high'))

def dispatch_instruction(engine: "IntervalPropagationEngine",
                         mnemonic: str, op_str: str,
                         insn_addr: int = 0,
                         mark_alloc_args: bool = False) -> None:
    """单条指令分派 — 状态更新 + 溢出候选 + 守卫约束."""
    engine._insn_count += 1
    mnem = mnemonic.lower()
    ops = [o.strip() for o in op_str.split(',')]

    # 守卫约束: cmp+jcc → 路径条件精化
    for left, right, cond in engine._guards.pop(insn_addr, []):
        lv = _resolve_operand(engine, left)
        rv = _resolve_operand(engine, right)
        if not (lv.is_top or lv.is_bottom or rv.is_top or rv.is_bottom):
            if cond in ('le', 'be'):
                lv = Interval(lo=lv.lo, hi=min(lv.hi, rv.hi))
            elif cond in ('lt', 'b'):
                lv = Interval(lo=lv.lo, hi=min(lv.hi, rv.hi - 1))
            elif cond in ('ge', 'ae'):
                lv = Interval(lo=max(lv.lo, rv.lo), hi=lv.hi)
            elif cond in ('gt', 'a'):
                lv = Interval(lo=max(lv.lo, rv.lo + 1), hi=lv.hi)
            if lv.lo > lv.hi:
                lv = Interval.bottom()
            parsed = _parse_mem_offset(left.lower())
            if parsed:
                base, off = parsed
                if base in ('rbp', 'ebp', 'rsp', 'esp'):
                    engine._stack[off] = lv
            elif left.lower() in _GPRS:
                engine._state.set(left, lv)

    # mov
    if mnem == 'mov' and len(ops) == 2:
        dst, src = ops
        m_store = _parse_mem_offset(dst.lower())
        if m_store:
            base, off = m_store
            src_iv = None
            imm = _parse_immediate(src)
            if imm is not None:
                src_iv = Interval.const(imm)
            elif src.lower() in _GPRS:
                src_iv = engine._state.get(src)
            if src_iv:
                engine._transfer_mov_store(base, off, src_iv)
                _check_store_trunc(engine, dst.lower(), src_iv, insn_addr,
                                  f'{mnem} {op_str}')
        else:
            m_load = _parse_mem_offset(src.lower())
            if m_load:
                base, off = m_load
                engine._transfer_mov_load(dst, base, off)
            else:
                imm = _parse_immediate(src)
                if imm is not None:
                    engine._transfer_mov_imm(dst, imm)
                elif src.lower() in _GPRS:
                    engine._transfer_mov_reg(dst, src)

    elif mnem == 'movabs' and len(ops) == 2:
        imm = _parse_immediate(ops[1])
        if imm is not None:
            engine._transfer_mov_imm(ops[0], imm)

    elif mnem == 'lea' and len(ops) == 2:
        _handle_lea(engine, ops[0], ops[1].lower(), insn_addr,
                    f'{mnem} {op_str}')

    elif mnem in _ARITH_HANDLERS and len(ops) == 2:
        dst, src = ops
        insn_label = f'{mnem} {op_str}'
        if not _handle_arith_mem(engine, mnem, ops, insn_addr, insn_label):
            if dst.lower() in _GPRS:
                left = engine._state.get(dst)
                right = _resolve_operand(engine, src)
                engine._transfer_arithmetic(mnem, dst, left, right,
                                           insn_addr, insn_label)

    elif mnem in ('shl', 'sal') and len(ops) == 2:
        shift = _parse_immediate(ops[1])
        if shift is not None:
            engine._transfer_shl(ops[0], ops[0], shift, insn_addr,
                                f'{mnem} {op_str}')

    elif mnem == 'and' and len(ops) == 2:
        mask = _parse_immediate(ops[1])
        if mask is not None:
            engine._transfer_and(ops[0], ops[0], mask)

    elif mnem == 'xor' and len(ops) == 2:
        if ops[0].lower() == ops[1].lower():
            engine._state.set(ops[0], Interval.const(0))

    elif mnem in ('cdqe', 'cdq'):
        engine._transfer_sign_extend('rax', 'eax', 32, 64)
    elif mnem == 'cwde':
        engine._transfer_sign_extend('eax', 'ax', 16, 32)
    elif mnem == 'cqo':
        engine._transfer_sign_extend('rdx', 'rax', 64, 128)
    elif mnem == 'movsxd' and len(ops) == 2:
        engine._transfer_sign_extend(ops[0], ops[1], 32, 64)
    elif (mnem == 'movzx' and len(ops) == 2
          and ops[1].lower() in _GPRS):
        engine._state.set(ops[0], engine._state.get(ops[1]))

    # cmp/jcc → 守卫注册
    if mnem == 'cmp' and len(ops) == 2:
        engine._last_cmp = (ops[0], ops[1])
    elif mnem.startswith('j') and mnem != 'jmp' and engine._last_cmp and ops:
        tgt = re.match(r'([0-9a-fA-F]+)', ops[0])
        if tgt and mnem in _JC:
            engine._guards.setdefault(int(tgt.group(1), 16), []).append(
                (engine._last_cmp[0], engine._last_cmp[1], _JC[mnem]))
        engine._last_cmp = None
    elif mnem == 'jmp':
        engine._last_cmp = None

    if mark_alloc_args and mnem == 'call':
        call_target = ops[0].lower() if ops else ''
        if any(a in call_target
               for a in ('malloc', 'calloc', 'realloc', '_Znwm')):
            for r in ('rcx', 'rdi', 'ecx', 'edi'):
                engine._alloc_regs.add(r)
            _check_alloc_overflow(engine, mnem, op_str, ops, insn_addr)
