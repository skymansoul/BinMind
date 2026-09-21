"""
汇编翻译器 — 指令 handler 组.

每条指令的寄存器/槽位状态更新独立成函数, 由 translate 循环
调度. 语义要点:
  - mov: 立即数/寄存器/栈槽/寄存器基址四类装载, 栈槽存储
  - lea: 帧基址与寄存器基址 (堆别名偏移) 两类
  - add/sub/shl: 常量折叠, 指针别名保持不变 (偏移不改变身份)
  - cdqe/movzx 等扩展: 别名/常量保持
  - cmp+jcc: 输出 guard 伪 IR (上界/下界/相等)
  - call: ABI 参数收集 + alloc/copy/strlen 语义
"""

from __future__ import annotations

import re
from typing import Optional

from .asm_regex import (_ALLOC_FUNCS, _COPY_FUNCS, _FMT_FUNCS, _LEN_FUNCS,
                        _RE_ADD_IMM, _RE_ADD_REG, _RE_CMP_IMM, _RE_JCC_EQ,
                        _RE_JCC_GT, _RE_JCC_LT, _RE_LEA, _RE_LEA_INDEX,
                        _RE_LEA_REG, _RE_LEA_SCALE, _RE_LOAD_REG_BASE,
                        _RE_LOAD_STACK, _RE_MOV_IMM, _RE_MOV_MEM,
                        _RE_MOV_REG, _RE_SHL_IMM, _RE_STORE_REG_BASE,
                        _RE_STORE_REG_IMM, norm_reg)
from .asm_cond import handle_cmp, handle_extend, handle_jcc  # noqa: E402,F401


def handle_mov(self, operands: str) -> None:
    m = _RE_MOV_IMM.match(operands)
    if m:
        dst = norm_reg(m.group(1))
        self.regs[dst] = int(m.group(2), 0)
        return
    m = _RE_MOV_REG.match(operands)
    if m:
        dst, src = norm_reg(m.group(1)), norm_reg(m.group(2))
        self.regs[dst] = self.regs.get(src)
        return
    m = _RE_MOV_MEM.match(operands)
    if m:
        base, sign, off, src_reg = (m.group(1), m.group(2), m.group(3),
                                    m.group(4))
        slot = self._slot_name(base, sign, off)
        val = self.regs.get(norm_reg(src_reg))
        if val is not None:
            self.slots[slot] = str(val)
        return
    m = _RE_LOAD_STACK.match(operands)
    if m:
        dst, base, sign, off = (norm_reg(m.group(1)), m.group(2),
                                m.group(3), m.group(4))
        slot = self._slot_name(base, sign, off)
        val = self.slots.get(slot)
        if val is not None:
            try:
                self.regs[dst] = int(val, 0)
            except (ValueError, TypeError):
                # 槽值可能是栈地址元组 repr (lea 产物) — 还原类型
                if isinstance(val, str) and val.startswith("('"):
                    try:
                        self.regs[dst] = eval(val)
                    except Exception:
                        self.regs[dst] = val
                else:
                    self.regs[dst] = val
        return
    m = _RE_LOAD_REG_BASE.match(operands)
    if m:
        dst, base_reg, off_str = (norm_reg(m.group(1)),
                                  norm_reg(m.group(2)), m.group(3))
        base_val = self.regs.get(base_reg)
        if isinstance(base_val, str) and base_val.startswith('v'):
            # [vN+off] 装载: 字段地址视为指向该堆缓冲的指针
            self.regs[dst] = base_val
            self.ir.append(f'use {base_val} + 0')
            return
        if isinstance(base_val, tuple) and len(base_val) == 3:
            # 栈基址元组 (rbp, sign, off): [栈地址+delta] 是栈槽
            # 内容间接读 — struct 指针的字段装载 (b->elems 等),
            # 槽内容若是堆别名则继承
            slot_base, sign, slot_off = base_val
            if slot_base == 'argv':
                # argv 基址: [argv + delta] = argv[i] — 外部输入
                ext = self._new_var()
                self.ir.append(f'{ext} = ext_input()')
                self.regs[dst] = ext
                return
            try:
                delta = int(off_str, 0) if off_str else 0
            except (ValueError, TypeError):
                delta = 0
            cur = int(slot_off, 0) if str(slot_off).startswith('0x') \
                else int(slot_off)
            total = cur + delta if sign == '+' else cur - delta
            slot = self._slot_name(slot_base, '+', hex(total))
            val = self.slots.get(slot)
            if val is not None:
                try:
                    self.regs[dst] = int(val, 0)
                except (ValueError, TypeError):
                    self.regs[dst] = val
            elif str(slot_off) in ('0x18', '0x10') and slot_base == 'rbp':
                # argv 参数槽间接: [argv + delta] = argv[i] — 外部
                # 输入. 生成外部污点变量, fmt 检测据此判用户可控
                ext = self._new_var()
                self.ir.append(f'{ext} = ext_input()')
                self.regs[dst] = ext
            else:
                self.regs[dst] = None
            return
        self.regs[dst] = None
        return
    m = _RE_STORE_REG_BASE.match(operands)
    if m:
        # 寄存器基址存储: [rax] 或 [rax+off], rax 为堆别名时
        # 视为对该堆缓冲的偏移写
        base_reg = norm_reg(m.group(1))
        off_str = m.group(2)
        base_val = self.regs.get(base_reg)
        if isinstance(base_val, str) and base_val.startswith('v'):
            off = 0
            if off_str:
                try:
                    off = int(off_str, 0)
                except ValueError:
                    off = 0
            self.ir.append(f'store {base_val} + {off}')
            self.ir.append(f'use {base_val} + {off}')
        return
    # 立即数存储: mov BYTE PTR [rax],0x1b — 同寄存器基址语义
    m = _RE_STORE_REG_IMM.match(operands)
    if m:
        base_reg = norm_reg(m.group(1))
        off_str = m.group(2)
        base_val = self.regs.get(base_reg)
        if isinstance(base_val, str) and base_val.startswith('v'):
            off = 0
            if off_str:
                try:
                    off = int(off_str, 0)
                except ValueError:
                    off = 0
            imm = int(m.group(3), 0)
            self.ir.append(f'store {base_val} + {off} = {imm}')
            if imm != 0:
                self.ir.append(f'use {base_val} + {off}')


def handle_lea(self, operands: str) -> None:
    m = _RE_LEA.match(operands)
    if m:
        dst, base, sign, off = (norm_reg(m.group(1)), m.group(2),
                                m.group(3), m.group(4))
        self.regs[dst] = (base, sign, off)
        return
    m = _RE_LEA_REG.match(operands)
    if m:
        dst, base_reg, off_str = (norm_reg(m.group(1)),
                                  norm_reg(m.group(2)), m.group(3))
        base_val = self.regs.get(base_reg)
        if isinstance(base_val, str) and base_val.startswith('v'):
            # 堆别名 + 偏移: 字段地址视为指向该缓冲
            self.regs[dst] = base_val
        else:
            self.regs[dst] = None
        return
    # lea 缩放: dst = [src*k + imm] → 常量折叠
    m = _RE_LEA_SCALE.match(operands)
    if m:
        dst, src, k = norm_reg(m.group(1)), norm_reg(m.group(2)), int(m.group(3))
        val = self.regs.get(src)
        if isinstance(val, int):
            self.regs[dst] = val * k
        else:
            self.regs[dst] = None
        return
    # 双寄存器索引: lea rdx,[rcx+rax*1] — 基址或索引为堆别名时
    # 目标继承别名 (循环内元素寻址, 偏移由索引决定不可静态求值)
    m = _RE_LEA_INDEX.match(operands)
    if m:
        dst = norm_reg(m.group(1))
        base = norm_reg(m.group(2))
        idx = norm_reg(m.group(3)) if m.group(3) else ''
        bv = self.regs.get(base)
        iv = self.regs.get(idx) if idx else None
        if isinstance(bv, str) and bv.startswith('v'):
            self.regs[dst] = bv
        elif isinstance(iv, str) and iv.startswith('v'):
            self.regs[dst] = iv
        else:
            self.regs[dst] = None
        return


def handle_addsub(self, op: str, operands: str) -> None:
    m = _RE_ADD_IMM.match(operands)
    if m:
        dst = norm_reg(m.group(1))
        imm = int(m.group(2), 0)
        cur = self.regs.get(dst)
        if isinstance(cur, int):
            self.regs[dst] = cur + imm if op == 'add' else cur - imm
        elif isinstance(cur, (str, tuple)):
            # 指针别名/栈地址元组 + 偏移: 身份不变, 保持
            self.regs[dst] = cur
        else:
            self.regs[dst] = None
        return
    m = _RE_ADD_REG.match(operands)
    if m:
        dst, src = norm_reg(m.group(1)), norm_reg(m.group(2))
        a, b = self.regs.get(dst), self.regs.get(src)
        if isinstance(a, int) and isinstance(b, int):
            self.regs[dst] = a + b if op == 'add' else a - b
        elif isinstance(a, str):
            pass  # 指针 + 索引: 保持别名, 偏移不可解析
        else:
            self.regs[dst] = None


def handle_shl(self, operands: str) -> None:
    m = _RE_SHL_IMM.match(operands)
    if m:
        dst = norm_reg(m.group(1))
        sh = int(m.group(2), 0)
        cur = self.regs.get(dst)
        if isinstance(cur, int):
            self.regs[dst] = cur << sh
        else:
            self.regs[dst] = None


def handle_extend(self, mnem: str, operands: str) -> None:
    """符号/零扩展与 movzx: 常量保持, 变量保持, 未知置 None."""
    parts = [p.strip() for p in operands.split(',')]
    if not operands or not parts or not parts[0]:
        # cdqe/cdq 等零操作数指令: 低32位即rax本身 (别名统一)
        return
    if mnem == 'movsxd':
        if len(parts) == 2:
            dst, src = norm_reg(parts[0]), norm_reg(parts[1])
            self.regs[dst] = self.regs.get(src)
        return
    dst = norm_reg(parts[0])
    if len(parts) >= 2:
        src = norm_reg(parts[1])
        self.regs[dst] = self.regs.get(src)


def handle_cmp(self, operands: str) -> None:
    m = _RE_CMP_IMM.match(operands)
    if m:
        self._pending_cmp = (norm_reg(m.group(1)), int(m.group(2), 0))


def handle_jcc(self, mnem: str) -> None:
    """jcc 配对上一条 cmp, 输出 guard 伪 IR 行.

    Intel 语义: cmp reg, imm; jge target → reg >= imm 时跳转,
    fall-through 是 reg < imm → 上界收窄 (guard reg < imm).
    反之 jl 的 fall-through 是 reg >= imm → 无上界, 不下界
    抑制. reg 若绑定伪变量 (vN) 则输出变量名; 若为常量则无
    窄化价值, 跳过.
    """
    if self._pending_cmp is None:
        return
    reg, imm = self._pending_cmp
    self._pending_cmp = None
    val = self.regs.get(reg)
    var = val if isinstance(val, str) and val.startswith('v') else None
    if var is None:
        return
    if mnem in ('jge', 'jae', 'jg', 'ja'):
        self.ir.append(f'guard {var} < {imm}')
    elif mnem in ('jle', 'jbe', 'jl', 'jb'):
        self.ir.append(f'guard {var} > {imm}')
    elif mnem in ('je', 'jz'):
        self.ir.append(f'guard {var} == {imm}')


def handle_call(self, operands: str) -> None:
    sym = re.search(r'<([^>]+)>', operands)
    if sym:
        base_name = sym.group(1)
    else:
        first = operands.split()[0] if operands else ''
        base_name = first.split('.')[0]
    name = base_name.lower()
    for fn in (_ALLOC_FUNCS + _COPY_FUNCS):
        if fn in name:
            self._emit_call(fn)
            return
    for fn in _LEN_FUNCS:
        if fn in name:
            ret = self._new_var()
            self.ir.append(f'{ret} = {fn}()')
            self.regs['rax'] = ret
            return
    if any(f in name for f in _FMT_FUNCS):
        # printf 族: 委托 hfp_fmt 的提取函数 (避免本模块超行数),
        # 生成 fmt(格式化串, 参数...) 伪 IR 行
        from .alloc_aware_fmt import fmt_extract_call
        fmt_extract_call(self, name)
        return
    if 'free' in name:
        # free(vN): 释放语义, UAF 检测器据此追踪生命周期
        arg0 = self.regs.get(self.arg_regs[0])
        if isinstance(arg0, str) and arg0.startswith('v'):
            self.ir.append(f'free({arg0})')
        return