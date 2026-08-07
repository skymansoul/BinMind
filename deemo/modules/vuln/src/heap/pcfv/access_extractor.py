"""堆访问提取器 — 从函数指令流提取与 malloc 指针相关的所有访问点.

创建: 2026-06-15
修改: 2026-06-15 — store/copy 记录逻辑拆至 extract_ops.py, ≤300行.
设计决策:
  - 前向抽象寄存器追踪分配指针 (malloc@addr[+off] / arg-ptr 标签),
    同时解析访问指令的偏移操作数: 常量立即数 → 常量偏移;
    寄存器索引 → 值流解析; 栈槽保存/恢复 → 指针标签贯通.
  - memcpy 调用按 Windows x64 (rcx=dst, r8=size) 与 SysV (rdi=rsi=size)
    双 ABI 识别; jmp 尾调用 (O2 优化) 同样识别.
  - 入口参数标记为 arg-ptr: 交叉函数场景保守保留, 消除漏报族.
"""
import re
from typing import Dict, List

from .types import ValueInfo, Provenance
from .value_flow import ValueFlowTracer, norm_reg
from .extract_ops import (AccessOpsMixin, _slot_key, _label_offset)

_ALLOC_FUNCS = ('malloc', 'calloc', 'realloc', 'strdup', 'new')
_COPY_FUNCS = ('memcpy', 'memmove', 'memset', 'memcpy_s', 'strncpy')
_STR_FUNCS = ('strcpy', 'strcat', 'sprintf', 'gets')

_REG_RE = re.compile(r'\b(r[0-9a-d]+[bwd]?|[er]?[abcd]x|[er]?[sd]i|[er]?[sb]p)\b',
                     re.IGNORECASE)


class AccessExtractor(AccessOpsMixin):
    """单函数内的堆访问提取."""

    def __init__(self, fn_name: str, insns: list,
                 malloc_ret_summary: dict = None):
        self.fn_name = fn_name
        self.insns = insns
        self.tracer = ValueFlowTracer(insns)
        self.mallocs: List[dict] = []
        self.accesses: List[dict] = []
        self._reg_ptr: Dict[str, object] = {}
        self._mem_ptr: Dict[str, object] = {}
        # 调用点参数标签快照: [(addr, reg, label)] — 供跨函数事件提取
        self.call_arg_labels: List[tuple] = []
        # 被调函数 malloc 返回摘要: {fn_name: has_malloc} — 调用点返回标签
        self._malloc_ret_summary = malloc_ret_summary or {}
        # 入口参数标记为可能堆指针: 交叉函数场景 (main分配, 子函数写入)
        # 分配基址在调用方, 单函数分析无法解析 → 保守保留判定
        self._reg_ptr['rcx'] = 'arg-ptr-1'
        self._reg_ptr['rdi'] = 'arg-ptr-1'
        self._reg_ptr['rdx'] = 'arg-ptr-2'
        self._reg_ptr['rsi'] = 'arg-ptr-2'
        self._reg_ptr['r8'] = 'arg-ptr-3'
        self._reg_ptr['r9'] = 'arg-ptr-4'
        self._run()

    def _run(self) -> None:
        for insn in self.insns:
            mn = insn.mnemonic
            if mn in ('call', 'callq', 'jmp', 'jmpq'):
                # jmp 可能是尾调用 memcpy/strcpy (O2优化)
                self._handle_call(insn)
            elif mn in ('mov', 'movabs', 'movsxd', 'movzx', 'movsx'):
                self._handle_mov(insn)
            elif mn == 'lea':
                self._handle_lea(insn)
            elif mn in ('add', 'sub', 'imul', 'shl', 'sal', 'and',
                        'or', 'xor', 'inc', 'dec'):
                self._handle_arith(insn)

# 指令处理

    def _handle_call(self, insn) -> None:
        callee = insn.operands.lower()
        # 记录调用点参数标签 (供跨函数 free/use 事件提取)
        # rax 是返回值寄存器: 仅在间接调用 (call rax) 时作为候选
        cand_regs = ('rcx', 'rdi', 'rdx', 'rsi')
        if '<' not in callee:
            cand_regs = ('rcx', 'rdi', 'rdx', 'rsi', 'rax')
        for reg in cand_regs:
            v = self._reg_ptr.get(reg)
            if v is not None and str(v).startswith('malloc@'):
                self.call_arg_labels.append((insn.addr, reg, str(v)))
                break
        if any(f in callee for f in _ALLOC_FUNCS):
            size_reg = self._alloc_size_reg(insn, callee)
            size_info = (self.tracer.trace(size_reg, insn.addr)
                         if size_reg else ValueInfo(
                             provenance=Provenance.UNKNOWN))
            alloc = {'addr': insn.addr, 'callee': callee,
                     'size_reg': size_reg, 'size_info': size_info,
                     'size_value': size_info.constant_value}
            self.mallocs.append(alloc)
            # 先清 caller-saved 再设置 rax, 否则 malloc 指针被清掉
            self._clear_caller_saved()
            self._reg_ptr['rax'] = f"malloc@{insn.addr:x}"
        elif any(f in callee for f in _COPY_FUNCS):
            self._record_copy(insn, callee, strcpy_like=False)
        elif any(f in callee for f in _STR_FUNCS):
            self._record_copy(insn, callee, strcpy_like=True)
        else:
            # 其它调用: 只清 caller-saved (Windows: rcx,rdx,r8-r11)
            for r in ('rcx', 'rdx', 'r8', 'r9', 'r10', 'r11'):
                self._reg_ptr.pop(r, None)
            # 被调函数含 malloc 且返回 rax → 调用点返回标签 (跨函数分配)
            name = callee.split('<')[-1].split('>')[0].split('@')[0] \
                if '<' in callee else callee.strip()
            if self._malloc_ret_summary.get(name):
                self._reg_ptr['rax'] = f"malloc@{insn.addr:x}"

    def _alloc_size_reg(self, insn, callee: str) -> str:
        if 'realloc' in callee:
            return 'rdx'
        return 'rcx'

    def _handle_mov(self, insn) -> None:
        op = insn.operands
        dst = op.split(',')[0].strip() if ',' in op else ''
        src = op.split(',')[-1].strip() if ',' in op else ''
        if '[' in dst:
            # 内存槽保存: mov [rbp-8], rX → 记录指针到槽
            src_reg_m = _REG_RE.search(src)
            if src_reg_m:
                v = self._reg_ptr.get(norm_reg(src_reg_m.group(1)))
                if v is not None:
                    self._mem_ptr[_slot_key(dst)] = v
            self._handle_store(insn, dst)
            return
        dst_reg_m = _REG_RE.search(dst)
        if dst_reg_m is None:
            return
        dst_reg = norm_reg(dst_reg_m.group(1))
        src_reg_m = _REG_RE.search(src)
        if '[' in src:
            # 从内存槽恢复指针: mov rX, [rbp-8]
            v = self._mem_ptr.get(_slot_key(src))
            if v is not None:
                self._reg_ptr[dst_reg] = v
            else:
                # 堆对象加载: 读取源对象标签 (use 事件溯源)
                base_m = _REG_RE.search(src)
                if base_m:
                    bv = self._reg_ptr.get(norm_reg(base_m.group(1)))
                    if bv is not None and str(bv).startswith('malloc@'):
                        off = _label_offset(str(bv))
                        self._reg_ptr[dst_reg] = f'{bv}+{off}'
                    else:
                        self._reg_ptr[dst_reg] = None
                else:
                    self._reg_ptr[dst_reg] = None
            return
        if src_reg_m and norm_reg(src_reg_m.group(1)) in self._reg_ptr:
            self._reg_ptr[dst_reg] = self._reg_ptr[
                norm_reg(src_reg_m.group(1))]
        else:
            self._reg_ptr.pop(dst_reg, None)

    def _handle_lea(self, insn) -> None:
        op = insn.operands
        dst = op.split(',')[0].strip() if ',' in op else ''
        src = op.split(',')[-1].strip() if ',' in op else ''
        dst_reg_m = _REG_RE.search(dst)
        if dst_reg_m is None:
            return
        dst_reg = norm_reg(dst_reg_m.group(1))
        m = re.search(r'\[([^\]]+)\]', src)
        if not m:
            self._reg_ptr.pop(dst_reg, None)
            return
        inner = m.group(1)
        base_m = _REG_RE.search(inner)
        if base_m is None:
            self._reg_ptr.pop(dst_reg, None)
            return
        base_reg = norm_reg(base_m.group(1))
        disp = None
        im = re.search(r'[+]\s*(0x[0-9a-fA-F]+|\d+)', inner)
        if im:
            try:
                disp = int(im.group(1), 0)
            except ValueError:
                disp = None
        base = self._reg_ptr.get(base_reg)
        if base is None:
            self._reg_ptr.pop(dst_reg, None)
            return
        self._reg_ptr[dst_reg] = f'{base}+{disp}' if disp else base

    def _handle_arith(self, insn) -> None:
        op = insn.operands
        dst = op.split(',')[0].strip() if ',' in op else ''
        src = op.split(',')[-1].strip() if ',' in op else ''
        dst_reg_m = _REG_RE.search(dst)
        if dst_reg_m is None:
            return
        dst_reg = norm_reg(dst_reg_m.group(1))
        cur = self._reg_ptr.get(dst_reg)
        if cur is None:
            return
        imm = _parse_imm(src)
        if imm is None:
            return
        if insn.mnemonic in ('add', 'inc'):
            delta = imm if insn.mnemonic == 'add' else 1
            self._reg_ptr[dst_reg] = f'{cur}+{delta}'
        elif insn.mnemonic in ('sub', 'dec'):
            delta = imm if insn.mnemonic == 'sub' else 1
            self._reg_ptr[dst_reg] = f'{cur}-{delta}'

    def _ptr_info_of(self, reg: str, addr: int) -> object:
        return self._reg_ptr.get(reg)

    def _clear_caller_saved(self) -> None:
        for r in ('rcx', 'rdx', 'r8', 'r9', 'r10', 'r11', 'rax'):
            self._reg_ptr.pop(r, None)


def _parse_imm(op: str):
    """提取操作数中的立即数 (供标签偏移计算)."""
    if not op:
        return None
    m = re.search(r'0x[0-9a-fA-F]+', op)
    if m:
        try:
            return int(m.group(0), 16)
        except ValueError:
            return None
    m = re.search(r'\b\d+\b', op)
    if m:
        val = int(m.group(0))
        return val if val < 0x1000000 else None
    return None
