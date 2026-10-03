"""堆区间证据消歧 指针溯源引擎 — 流敏感 must-point-to 分析.

追踪每个寄存器和栈槽的指针来源: 哪个 malloc 分配的, 偏移多少.
与现有 heap_bound_infer 的关系: 它做边界检查, 我们做"同一缓冲区"判定,
两者互补 — 当两个访问指向同一 malloc 的不同偏移时, 可以精确判定越界.

  - 非源码级: 直接在 objdump 上工作, 不需要 LLVM IR
  - 非全程序: 函数内 per-instruction 前向扫描, O(n) 单 pass
  - 保守但实用: 不追求精确 aliasing, 只追踪"来自 rax=malloc()" 的指针派生链

方法参考:
  - MECA: 多维证据组合 — 借鉴其指针置信度评分
  - Cod: 堆不相交性 — 但我们是二进制级等价实现
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

# 数据模型

@dataclass
class PointerOrigin:
    """指针的分配来源."""
    alloc_addr: int          # malloc 调用地址
    alloc_size: int          # 已知/推断的分配大小 (0=未知)
    base_offset: int = 0     # 该指针距分配起始点的偏移
    is_derived: bool = False # 是否通过算术运算派生 (mov rax,rbx 不算派生)

@dataclass
class PointerState:
    """单点程序状态: 寄存器+栈槽的指针溯源."""
    # 64-bit 寄存器 → 指针来源
    reg_origin: Dict[str, PointerOrigin] = field(default_factory=dict)
    # [rbp+offset] → 指针来源
    stack_origin: Dict[int, PointerOrigin] = field(default_factory=dict)

    def get_reg(self, reg: str) -> Optional[PointerOrigin]:
        return self.reg_origin.get(reg)

    def set_reg(self, reg: str, origin: PointerOrigin):
        self.reg_origin[reg] = origin

    def kill_reg(self, reg: str):
        self.reg_origin.pop(reg, None)

    def get_stack(self, offset: int) -> Optional[PointerOrigin]:
        return self.stack_origin.get(offset)

    def set_stack(self, offset: int, origin: PointerOrigin):
        self.stack_origin[offset] = origin


# 引擎

class PointerProvenanceEngine:
    """逐指令追踪指针的来源 (must-point-to 分析).

    只追踪正向派生链:
      rax = malloc(N)       → rax → {alloc: call_addr, size: N, offset: 0}
      rbx = rax             → rbx → {alloc: call_addr, offset: 0} (拷贝)
      rcx = rax + 0x10      → rcx → {alloc: call_addr, offset: 16} (派生)
      rdx = rax + rsi       → rdx → {alloc: call_addr, offset: UNKNOWN} (动态偏移)

    设计决策:
      - 不追踪通过栈的间接路径: mov [rbp-8], rax → mov rcx, [rbp-8] 只追踪栈槽
        到寄存器这一步 (通过 get_reg 和 get_stack 联合查询).
        原因: per-instruction 前向扫描中, 栈读回寄存器发生在后序指令,
        mov ptr [rbp+N], rax 记录栈槽, 后续 mov rcx, ptr [rbp+N] 从中读取.
        正确做法是实现栈槽→寄存器的回读, 详见 _propagate_instruction 中的处理.
    """

    _MOV_RR = re.compile(r'mov\s+(\w+),\s*(\w+)\s*$', re.I)
    _MOV_RI = re.compile(r'mov\s+(\w+),\s*(0x[0-9a-f]+|\d+)\s*$', re.I)
    _LEA_SIMPLE = re.compile(
        r'lea\s+(\w+),\s*\[(\w+)\s*\+\s*(0x[0-9a-f]+|\d+)\]', re.I)
    _LEA_COMPLEX = re.compile(
        r'lea\s+(\w+),\s*\[(\w+)\s*\+\s*(\w+)\s*\*\s*(\d+)\]', re.I)
    _ADD_IMM = re.compile(r'add\s+(\w+),\s*(0x[0-9a-f]+|\d+)', re.I)
    _MOV_TO_MEM = re.compile(
        r'mov\s+(?:qword|dword)\s+ptr\s+\[(rbp|rsp)\s*([+\-])\s*(0x[0-9a-f]+|\d+)\]'
        r'\s*,\s*(\w+)', re.I)
    _MOV_FROM_MEM = re.compile(
        r'mov\s+(\w+),\s*(?:qword|dword)\s+ptr\s+\[(rbp|rsp)\s*([+\-])\s*(0x[0-9a-f]+|\d+)\]',
        re.I)
    _XOR_RR = re.compile(r'xor\s+(\w+),\s*\1\b', re.I)
    _CALL = re.compile(r'call\s+(?:[0-9a-f]+\s+<)?([^>\s]+)(?:@plt)?>?', re.I)
    _CDQE = re.compile(r'cdqe', re.I)
    _MOVSXD = re.compile(r'movsxd\s+(\w+),\s*(\w+)', re.I)

    _ALLOC_FNS = {'malloc', 'calloc', 'realloc', '_malloc', 'HeapAlloc'}

    def __init__(self):
        self._state = PointerState()
        # 已见 malloc 点 → (alloc_addr, known_size)
        self._alloc_sites: Dict[int, int] = {}

    def analyze(self, instructions: List[str],
                addrs: Optional[List[int]] = None) -> PointerState:
        self._state = PointerState()
        self._alloc_sites.clear()

        for i, insn in enumerate(instructions):
            il = insn.strip().lower()
            if not il:
                continue

            addr = addrs[i] if addrs and i < len(addrs) else i

            if 'call' in il:
                self._handle_call(il, addr)
                continue
            if 'ret' in il:
                continue
            self._propagate(il)

        return self._state

    def _propagate(self, il: str):
        # mov r64, r64 (拷贝 — 传递指针来源)
        m = self._MOV_RR.search(il)
        if m:
            dst, src = m.group(1), m.group(2)
            if src in ('rbp','rsp','rip'):
                self._state.kill_reg(dst); return
            origin = self._state.get_reg(src)
            if origin:
                self._state.set_reg(dst, origin)
            else:
                self._state.kill_reg(dst)
            return

        # movzx/movsxd: 32→64 扩展, 传递来源但不标记派生
        m = self._MOVSXD.search(il)
        if m:
            dst, src = m.group(1), m.group(2)
            origin = self._state.get_reg(src)
            if origin:
                self._state.set_reg(dst, origin)
            else:
                self._state.kill_reg(dst)
            return

        # cdqe: eax→rax 符号扩展
        if self._CDQE.search(il):
            origin = self._state.get_reg('eax')
            if origin:
                self._state.set_reg('rax', origin)
            else:
                self._state.kill_reg('rax')
            return

        # mov reg, imm (杀死指针来源 — imm 不是堆指针)
        m = self._MOV_RI.search(il)
        if m:
            self._state.kill_reg(m.group(1)); return

        # xor r,r (清零 — 不是堆指针)
        m = self._XOR_RR.search(il)
        if m:
            self._state.kill_reg(m.group(1)); return

        # lea dst, [base + offset] (派生指针)
        m = self._LEA_SIMPLE.search(il)
        if m:
            dst, base = m.group(1), m.group(2)
            off = int(m.group(3), 0)
            origin = self._state.get_reg(base)
            if origin:
                self._state.set_reg(dst, PointerOrigin(
                    alloc_addr=origin.alloc_addr,
                    alloc_size=origin.alloc_size,
                    base_offset=origin.base_offset + off,
                    is_derived=True))
            else:
                self._state.kill_reg(dst)
            return

        # lea dst, [base + idx*scale]
        m = self._LEA_COMPLEX.search(il)
        if m:
            dst = m.group(1); base = m.group(2)
            origin = self._state.get_reg(base)
            if origin:
                # 动态偏移 — 保留 alloc 来源但偏移未知
                self._state.set_reg(dst, PointerOrigin(
                    alloc_addr=origin.alloc_addr,
                    alloc_size=origin.alloc_size,
                    base_offset=-1,  # sentinel: 动态偏移
                    is_derived=True))
            else:
                self._state.kill_reg(dst)
            return

        # add reg, imm (偏移派生)
        m = self._ADD_IMM.search(il)
        if m:
            reg = m.group(1); off = int(m.group(2), 0)
            origin = self._state.get_reg(reg)
            if origin:
                self._state.set_reg(reg, PointerOrigin(
                    alloc_addr=origin.alloc_addr,
                    alloc_size=origin.alloc_size,
                    base_offset=origin.base_offset + off,
                    is_derived=True))
            return

        # mov [rbp+N], reg (栈存储 — 持久化指针来源)
        m = self._MOV_TO_MEM.search(il)
        if m:
            sign = -1 if m.group(2) == '-' else 1
            off = sign * int(m.group(3), 0)
            src_reg = m.group(4)
            origin = self._state.get_reg(src_reg)
            if origin:
                self._state.set_stack(off, origin)
            else:
                self._state.stack_origin.pop(off, None)
            return

        # mov reg, [rbp+N] (栈加载 — 恢复指针来源)
        m = self._MOV_FROM_MEM.search(il)
        if m:
            dst_reg = m.group(1)
            sign = -1 if m.group(3) == '-' else 1
            off = sign * int(m.group(4), 0)
            origin = self._state.get_stack(off)
            if origin:
                self._state.set_reg(dst_reg, origin)
            else:
                self._state.kill_reg(dst_reg)
            return

    def _handle_call(self, il: str, addr: int):
        m = self._CALL.search(il)
        if not m:
            return
        func = m.group(1).lower()

        # 检测 alloc 调用 — 记录分配点
        for af in self._ALLOC_FNS:
            if af in func:
                self._alloc_sites[addr] = 0
                # rax = malloc(N) — rax 指向新分配的堆块
                self._state.set_reg('rax', PointerOrigin(
                    alloc_addr=addr, alloc_size=0, base_offset=0))
                return

        # 非 alloc 调用: 杀 caller-saved 寄存器
        for r in ['rax','rcx','rdx','r8','r9','r10','r11']:
            self._state.kill_reg(r)

    @property
    def alloc_sites(self) -> Dict[int, int]:
        return dict(self._alloc_sites)


# smoke
def _check():
    eng = PointerProvenanceEngine()
    state = eng.analyze([
        "  401000:\tmov    ecx,0x100",
        "  401005:\tcall   401100 <malloc>",
        "  40100a:\tmov    rbx,rax",
        "  40100d:\tlea    rcx,[rax+0x10]",
        "  401011:\tadd    rbx,0x8",
    ])
    rax = state.get_reg('rax')
    rbx = state.get_reg('rbx')
    rcx = state.get_reg('rcx')
    assert rax is not None, "rax should have origin"
    assert rax.base_offset == 0, f"rax offset={rax.base_offset}, expected 0"
    assert rbx is not None and rbx.base_offset == 8, f"rbx offset={rbx.base_offset if rbx else 'None'}"
    assert rcx is not None and rcx.base_offset == 16, f"rcx offset={rcx.base_offset if rcx else 'None'}"
    print("[OK] pointer_provenance tests passed")

if __name__ == "__main__":
    _check()
