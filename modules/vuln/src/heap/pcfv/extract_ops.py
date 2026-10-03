"""堆访问记录操作 — store/copy 的提取与偏移解析.
"""
import re
from typing import Optional

from .types import ValueInfo, Provenance
from .value_flow import norm_reg

_REG_RE = re.compile(r'\b(r[0-9a-d]+[bwd]?|[er]?[abcd]x|[er]?[sd]i|[er]?[sb]p)\b',
                     re.IGNORECASE)


class AccessOpsMixin:
    """store/copy 记录 mixin — 由 AccessExtractor 继承."""

    def _record_copy(self, insn, callee: str, strcpy_like: bool) -> None:
        # Windows: rcx=dst, r8=size; SysV: rdi=dst, rdx=size
        # 优先选 malloc@ 标签寄存器, 其次 arg-ptr (交叉函数)
        dst_reg = None
        dst_info = None
        for reg in ('rcx', 'rdi', 'rsi', 'rdx'):
            v = self._ptr_info_of(reg, insn.addr)
            if v is not None:
                if str(v).startswith('malloc@'):
                    dst_reg, dst_info = reg, v
                    break
                if dst_info is None:
                    dst_reg, dst_info = reg, v
        if dst_info is None:
            return
        size_info = None
        size_reg = 'unknown'
        for sr in ('r8', 'rdx', 'rsi', 'rcx'):
            if sr == dst_reg:
                continue
            si = self.tracer.trace(sr, insn.addr)
            if si.is_constant or si.interval_hi is not None:
                size_info = si
                size_reg = sr
                break
            if size_info is None:
                size_info = si
                size_reg = sr
        # 目标指针标签中的常量偏移: 'malloc@140001772+64' → off 64
        label_off = _label_offset(str(dst_info)) if dst_info else 0
        if label_off:
            offset_info = ValueInfo(interval_lo=label_off,
                                    interval_hi=label_off,
                                    is_constant=True,
                                    constant_value=label_off,
                                    tainted=False, taint_confidence=0.98,
                                    provenance=Provenance.CONSTANT,
                                    summary=f'label:{label_off}')
        else:
            # 标签无偏移: 追踪目标寄存器值流, 捕获 add/lea 变量偏移模式
            traced = self.tracer.trace(dst_reg, insn.addr)
            if 'binop' in traced.summary:
                offset_info = traced
            else:
                offset_info = ValueInfo(interval_lo=0, interval_hi=0,
                                        is_constant=True, constant_value=0,
                                        tainted=False, taint_confidence=0.98,
                                        provenance=Provenance.CONSTANT,
                                        summary='copy:0')
        self.accesses.append({
            'kind': 'strcpy' if strcpy_like else 'memcpy',
            'addr': insn.addr, 'function': self.fn_name,
            'dst_info': dst_info, 'size_info': size_info,
            'offset_info': offset_info,
            'size_reg': 'unknown' if size_info is None else size_reg,
            'callee': callee,
        })
        self._clear_caller_saved()

    def _handle_store(self, insn, mem_operand: str) -> None:
        base_reg_m = _REG_RE.search(mem_operand)
        if base_reg_m is None:
            return
        base_reg = norm_reg(base_reg_m.group(1))
        ptr = self._reg_ptr.get(base_reg)
        if ptr is None or not (str(ptr).startswith('malloc@')
                               or str(ptr).startswith('arg-ptr')):
            return
        # 指针标签中累积的常量偏移: 'malloc@140001772+40+256'
        label_off = _label_offset(str(ptr))
        disp = None
        im = re.search(r'[+]\s*(0x[0-9a-fA-F]+|\d+)', mem_operand)
        if im:
            try:
                disp = int(im.group(1), 0)
            except ValueError:
                disp = None
        # 偏移寄存器索引: [base+idx*scale] 或 [base+idx]
        idx_m = re.search(r'\[[^\]]*[+]\s*(r[0-9a-d]+[bwd]?|[er]?[abcd]x)',
                          mem_operand, re.IGNORECASE)
        offset_info = None
        if idx_m and norm_reg(idx_m.group(1)) != base_reg:
            idx_info = self.tracer.trace(norm_reg(idx_m.group(1)),
                                         insn.addr)
            # 索引值 + 基指针标签偏移
            if label_off:
                if idx_info.interval_lo is not None:
                    idx_info.interval_lo += label_off
                if idx_info.interval_hi is not None:
                    idx_info.interval_hi += label_off
                if idx_info.is_constant and idx_info.constant_value is not None:
                    idx_info.constant_value += label_off
                    idx_info.interval_lo = idx_info.constant_value
                    idx_info.interval_hi = idx_info.constant_value
            offset_info = idx_info
        elif disp is not None:
            c = label_off + disp
            offset_info = ValueInfo(interval_lo=c, interval_hi=c,
                                    is_constant=True, constant_value=c,
                                    tainted=False, taint_confidence=0.98,
                                    provenance=Provenance.CONSTANT,
                                    summary=f'disp:{c}')
        elif label_off:
            offset_info = ValueInfo(interval_lo=label_off,
                                    interval_hi=label_off,
                                    is_constant=True,
                                    constant_value=label_off,
                                    tainted=False, taint_confidence=0.98,
                                    provenance=Provenance.CONSTANT,
                                    summary=f'label:{label_off}')
        else:
            # 无显式偏移: 追踪基寄存器值流
            # 1) binop-regreg (add rax, idx) → 保留区间, 由循环/守卫分析判定
            # 2) 其余 (指针传播/栈槽重载) → 偏移0
            traced = self.tracer.trace(base_reg, insn.addr)
            if 'binop' in traced.summary:
                offset_info = traced
            else:
                offset_info = ValueInfo(interval_lo=0, interval_hi=0,
                                        is_constant=True, constant_value=0,
                                        tainted=False, taint_confidence=0.98,
                                        provenance=Provenance.CONSTANT,
                                        summary='disp:0')
        size = _infer_store_size(insn.raw, insn.operands)
        self.accesses.append({
            'kind': 'store', 'addr': insn.addr,
            'function': self.fn_name, 'base_ptr': ptr,
            'offset_info': offset_info, 'access_size': size,
        })


def _label_offset(ptr_label: str) -> int:
    """从 'malloc@140001772+40+256' 提取累积偏移量."""
    total = 0
    for m in re.finditer(r'\+(\d+)', ptr_label):
        try:
            total += int(m.group(1))
        except ValueError:
            pass
    return total


def _slot_key(mem_operand: str) -> str:
    """内存槽规范化键: [rbp-8] / [rsp+0x10] 等."""
    m = re.search(r'\[([^\]]+)\]', mem_operand)
    if not m:
        return mem_operand
    inner = m.group(1).strip()
    reg_m = _REG_RE.search(inner)
    if reg_m is None:
        return inner
    reg = norm_reg(reg_m.group(1))
    disp_m = re.search(r'([+-])\s*(0x[0-9a-fA-F]+|\d+)', inner)
    disp = 0
    if disp_m:
        try:
            val = int(disp_m.group(2), 0)
        except ValueError:
            val = 0
        disp = val if disp_m.group(1) == '+' else -val
    return f'[{reg}{disp:+d}]'


def _infer_store_size(raw: str, operands: str) -> int:
    raw_l = raw.lower()
    if 'byte ptr' in raw_l:
        return 1
    if 'word ptr' in raw_l:
        return 2
    if 'dword ptr' in raw_l:
        return 4
    if 'qword ptr' in raw_l:
        return 8
    if 'xmmword' in raw_l:
        return 16
    if raw_l.startswith('movb'):
        return 1
    if raw_l.startswith('movw'):
        return 2
    if raw_l.startswith('movq'):
        return 8
    if raw_l.startswith('movd'):
        return 4
    return 4
