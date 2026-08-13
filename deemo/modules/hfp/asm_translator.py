"""
汇编语义提取 — 把 objdump 寄存器级指令翻译为伪 IR.

HFP 引擎的正则假定反编译器风格的行 (var = malloc(n),
memcpy(dst, src, size)). objdump 输出是寄存器级汇编, 两者
存在语义鸿沟. 本模块做有界的数据流模拟, 两遍执行:
  第一遍逐块收集调用点参数快照 (全局变量编号保证与第二遍
  别名一致); 第二遍按函数块翻译, 注入实参到参数槽, 输出
  伪 IR (分配/拷贝/守卫/存储行).
局限: 不模拟内存读值, 不处理间接调用.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from .asm_handlers import (handle_addsub, handle_call, handle_cmp,
                           handle_extend, handle_jcc, handle_lea,
                           handle_mov, handle_shl)
from .asm_regex import (_RE_INSN, split_into_functions)

_JCC_LT = ('jl', 'jb', 'jle', 'jbe')
_JCC_GT = ('jg', 'ja', 'jge', 'jae')
_JCC_EQ = ('je', 'jz', 'jne', 'jnz')


class AsmTranslator:
    """寄存器级数据流模拟器 → 伪 IR 行列表."""

    def __init__(self, abi: str = 'win64'):
        self._abi = abi
        from .asm_regex import _SYSV_ARGS, _WIN64_ARGS
        self.arg_regs = _WIN64_ARGS if abi == 'win64' else _SYSV_ARGS
        self.regs: Dict[str, object] = {}
        self.slots: Dict[str, str] = {}
        self.ir: List[str] = []
        self.var_counter = 0
        self.pending_args: Optional[list] = None
        self._pending_cmp: Optional[tuple] = None
        self._call_args: Dict[str, list] = {}
        self._blocks: Dict[str, list] = {}
        self._loop_ranges: List[tuple] = []

    def _new_var(self) -> str:
        self.var_counter += 1
        return f'v{self.var_counter}'

    def _slot_name(self, base: str, sign: str, off_str: str) -> str:
        return f'{base}{sign}{off_str}'

    def translate(self, lines: List[str]) -> List[str]:
        """两遍翻译: 先收集调用参数, 再按块注入并输出伪 IR."""
        blocks = split_into_functions(lines, _RE_INSN)
        call_args: Dict[str, list] = {}
        t0_counter = 0
        for fn_name, block in blocks:
            t0 = AsmTranslator(self._abi)
            t0.var_counter = t0_counter
            for line in block:
                self._simulate_line(t0, line, collect=True,
                                    call_args=call_args)
            t0_counter = t0.var_counter
        self._call_args = call_args
        self._blocks = {name: blk for name, blk in blocks}

        for fn_name, block in blocks:
            if fn_name in call_args:
                self.pending_args = list(call_args[fn_name])
            else:
                self.pending_args = None
            self.regs.clear()
            self.slots.clear()
            self._pending_cmp = None
            self._translate_block(block, fn_name)
        return self.ir

    def _simulate_line(self, t0, line: str, collect: bool,
                       call_args: Dict[str, list]) -> None:
        """单行模拟: 收集阶段只跟踪寄存器, 不输出伪 IR."""
        m = _RE_INSN.match(line)
        if not m:
            return
        mnem, operands = m.group(1).lower(), m.group(2)
        if mnem == 'mov':
            handle_mov(t0, operands)
        elif mnem == 'lea':
            handle_lea(t0, operands)
        elif mnem in ('add', 'sub'):
            handle_addsub(t0, mnem, operands)
        elif mnem in ('shl', 'sal'):
            handle_shl(t0, operands)
        elif mnem in ('cdqe', 'cdq', 'movsxd', 'movzx'):
            handle_extend(t0, mnem, operands)
        elif mnem == 'cmp':
            handle_cmp(t0, operands)
        elif mnem in _JCC_LT + _JCC_GT + _JCC_EQ:
            t0._pending_cmp = None
        elif mnem == 'call':
            target = self._call_target(operands)
            if target:
                call_args.setdefault(target, [None] * 4)
                for i, r in enumerate(self.arg_regs):
                    if call_args[target][i] is None:
                        call_args[target][i] = t0.regs.get(r)
            handle_call(t0, operands)
            self._clear_volatile(t0)

    def _translate_block(self, lines: List[str], fn_name: str = '') -> None:
        """翻译单个函数块 (不含函数头注入, 由 translate 预置)."""
        if fn_name:
            self.ir.append(f'# fn {fn_name}')
        # 回边检测: 块内 jmp/jcc 目标指向块内更早指令 → 循环结构.
        # 循环内 store 的写量可能随迭代累积, 标记供引擎判定
        self._loop_ranges = self._detect_loop_ranges(lines)
        # main 块 argv 语义: rbp+0x18 是 argv 参数槽 (Win64 第2参数),
        # 无调用者注入时预设 argv 基址元组 — LOAD_REG_BASE 据此
        # 识别 [argv+delta] 为外部输入 (argv[i])
        if fn_name == 'main':
            self.slots.setdefault('rbp+0x18', "('argv', '+', '0x0')")
        # 函数头参数注入: 调用点实参写入参数槽 [rbp+0x10..]
        if self.pending_args:
            for i, val in enumerate(self.pending_args):
                if val is None:
                    continue
                slot = self._slot_name('rbp', '+', hex(0x10 + i * 8))
                # 外部块别名 (vN) 沿用原名: var_counter 全局唯一,
                # 跨块同名即同一对象, 使 memcpy/store 与调用方
                # malloc 返回变量直接关联
                self.slots[slot] = str(val)
                if i < len(self.arg_regs):
                    self.regs[self.arg_regs[i]] = val
        for line_idx, line in enumerate(lines):
            m = _RE_INSN.match(line)
            if not m:
                continue
            mnem, operands = m.group(1).lower(), m.group(2)
            if mnem in ('push', 'pop', 'ret'):
                continue
            ir_before = len(self.ir)
            if mnem == 'mov':
                handle_mov(self, operands)
            elif mnem == 'lea':
                handle_lea(self, operands)
            elif mnem in ('add', 'sub'):
                handle_addsub(self, mnem, operands)
            elif mnem in ('shl', 'sal'):
                handle_shl(self, operands)
            elif mnem in ('cdqe', 'cdq', 'movsxd', 'movzx'):
                handle_extend(self, mnem, operands)
            elif mnem == 'cmp':
                handle_cmp(self, operands)
            elif mnem in _JCC_LT + _JCC_GT + _JCC_EQ:
                handle_jcc(self, mnem)
            elif mnem == 'call':
                target = self._call_target(operands)
                live_args = [self.regs.get(r) for r in self.arg_regs]
                # 实时参数优先: 第二遍寄存器状态比第一遍快照更准
                # (含当前块的 malloc 返回别名), 快照仅作回退
                if any(v is not None for v in live_args):
                    self.pending_args = live_args
                elif target and target in self._call_args:
                    self.pending_args = list(self._call_args[target])
                else:
                    self.pending_args = live_args
                handle_call(self, operands)
                # 调用点展开: 被调函数内对参数槽的 memcpy/free
                # 内联到当前块, 使跨函数堆操作与调用方变量关联
                self._emit_inlined_ops(target)
                self._clear_volatile(self)
            # 循环内 store 标记: 本行新增的 store 若位于循环体
            # 区间, 追加 '# loop' 供引擎识别累积写
            if any(lo <= line_idx <= hi for lo, hi in self._loop_ranges):
                for new_i in range(ir_before, len(self.ir)):
                    if self.ir[new_i].startswith('store '):
                        self.ir[new_i] += ' # loop'

    def _call_target(self, operands: str) -> Optional[str]:
        """提取 call 目标函数名 (无符号或间接调用返回 None)."""
        sym = re.search(r'<([^>]+)>', operands)
        if sym:
            return sym.group(1)
        return None

    def _detect_loop_ranges(self, lines: List[str]) -> List[tuple]:
        """检测块内循环: jmp/jcc 目标指向块内更早指令 → (头, 尾).

        循环内指令的 store 可能随迭代累积写量, 引擎据此禁止
        SAFE 抑制. 返回循环体行号区间列表.
        """
        ranges: List[tuple] = []
        line_addrs: List[str] = []
        for l in lines:
            m = re.match(r'^\s*([0-9a-fA-F]+):', l)
            line_addrs.append(m.group(1) if m else '')
        jmp_mnems = ('jmp', 'jne', 'je', 'jl', 'jb', 'jle', 'jbe',
                     'jg', 'ja', 'jge', 'jae', 'jz', 'jnz', 'loop')
        for i, l in enumerate(lines):
            m = _RE_INSN.match(l)
            if not m or m.group(1).lower() not in jmp_mnems:
                continue
            tgt = re.search(r'\b([0-9a-fA-F]{6,})\b', m.group(2))
            if not tgt:
                continue
            target = tgt.group(1)
            for j in range(i):
                if line_addrs[j] == target:
                    ranges.append((j, i))
                    break
        return ranges

    def _emit_inlined_ops(self, target: Optional[str]) -> None:
        """把被调函数内对参数槽的 memcpy/free 语义内联到当前块.

        扫描被调函数块的指令序列, 识别
          mov rax,[rbp+0x10]; mov rcx,rax; ...; call <memcpy|free>
        模式: dst 为参数槽 [rbp+0x10], 在调用点生成对应伪 IR,
        使跨函数堆操作与调用方 malloc 关联 (执行序正确).
        """
        if not target or not self._blocks:
            return
        block = self._blocks.get(target)
        if not block:
            return
        for li, line in enumerate(block):
            if not re.search(r'mov\s+rax,\s*QWORD PTR \[rbp\+0x10\]',
                             line, re.IGNORECASE):
                continue
            for j in range(li, min(li + 12, len(block))):
                if re.search(r'call\s+\S*\s*<memcpy>', block[j],
                             re.IGNORECASE):
                    arg0 = self.regs.get(self.arg_regs[0])
                    dst_name = arg0 if isinstance(arg0, str) else '?'
                    self.ir.append(f'memcpy({dst_name}, ?, ?)')
                    break
                if re.search(r'call\s+\S*\s*<free>', block[j],
                             re.IGNORECASE):
                    arg0 = self.regs.get(self.arg_regs[0])
                    fname = arg0 if isinstance(arg0, str) else '?'
                    self.ir.append(f'free({fname})')
                    break

    def _clear_volatile(self, t) -> None:
        """call 后清空易失寄存器 (参数 + rax), 防跨调用污染.

        rax 若为模拟变量 (malloc 返回) 保留, 供后续 mov [slot],rax
        绑定; 其余情况清空.
        """
        for r in self.arg_regs:
            t.regs.pop(r, None)
        rax_val = t.regs.get('rax')
        if not (isinstance(rax_val, str) and rax_val.startswith('v')):
            t.regs.pop('rax', None)

    def _emit_call(self, fn: str) -> None:
        """按 ABI 取实参生成伪 IR 行 (分配/拷贝), 绑定返回别名."""
        args = [self.regs.get(r) for r in self.arg_regs]
        if fn in ('malloc', 'calloc', 'realloc'):
            size = args[0]
            ret = self._new_var()
            if isinstance(size, (int, str)):
                self.ir.append(f'{ret} = {fn}({size})')
            else:
                self.ir.append(f'{ret} = {fn}(?)')
            self.regs['rax'] = ret
            return
        if fn in ('memcpy', 'memset', 'strcpy', 'strncpy', 'memmove'):
            dst, src, size = args[0], args[1], args[2]
            # dst/src 保留类型: 栈地址元组 repr 也是 str, 与 '?'
            # 区分 — fmt 检测需匹配拷贝目标与 printf 的 fmt 参数
            dst_name = dst if isinstance(dst, (str, tuple)) else '?'
            src_name = src if isinstance(src, (str, int, tuple)) else '?'
            if isinstance(size, (int, str)):
                self.ir.append(f'{fn}({dst_name}, {src_name}, {size})')
            else:
                self.ir.append(f'{fn}({dst_name}, {src_name}, ?)')