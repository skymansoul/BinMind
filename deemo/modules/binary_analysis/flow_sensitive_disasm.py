import os as _os
import logging as _logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple

logger = _logging.getLogger(__name__)

_HAS_UC = False
_HAS_CS = False
try:
    import unicorn as _uc
    import capstone as _cs
    _HAS_UC = True
    _HAS_CS = True
except ImportError:
    logger.warning('unicorn/capstone unavailable')


class Architecture(Enum):
    X86 = 'x86'
    X64 = 'x86_64'
    ARM = 'arm'
    ARM64 = 'arm64'
    MIPS = 'mips'
    PPC = 'ppc'


class DisasmMode(Enum):
    STATIC = 'static'
    DYNAMIC = 'dynamic'
    HYBRID = 'hybrid'


_MODE_MAP = {'static': DisasmMode.STATIC, 'dynamic': DisasmMode.DYNAMIC,
             'hybrid': DisasmMode.HYBRID}


@dataclass
class Instruction:
    address: int = 0
    mnemonic: str = ''
    operands: str = ''
    raw_bytes: bytes = b''
    is_conditional: bool = False
    is_indirect: bool = False
    targets: list = field(default_factory=list)


@dataclass
class DisasmResult:
    instructions: list = field(default_factory=list)
    functions: dict = field(default_factory=dict)
    unresolved: list = field(default_factory=list)
    warnings: list = field(default_factory=list)


class FlowSensitiveDisassembler:
    def __init__(self, arch=None):
        if arch is None:
            arch = Architecture.X64
        self._arch = Architecture(arch) if isinstance(arch, str) else arch
        self._cs = None
        self._uc = None
        self._mem = {}
        self._trace = []
        self._resolved = {}

        if _HAS_CS:
            self._init_cs()
        if _HAS_UC:
            self._init_uc()

    def _init_cs(self):
        a = self._arch
        if a == Architecture.X86:
            self._cs = _cs.Cs(_cs.CS_ARCH_X86, _cs.CS_MODE_32)
        elif a == Architecture.X64:
            self._cs = _cs.Cs(_cs.CS_ARCH_X86, _cs.CS_MODE_64)
        elif a == Architecture.ARM:
            self._cs = _cs.Cs(_cs.CS_ARCH_ARM, _cs.CS_MODE_ARM)
        elif a == Architecture.ARM64:
            self._cs = _cs.Cs(_cs.CS_ARCH_ARM64, _cs.CS_MODE_ARM64)
        if self._cs:
            self._cs.detail = True

    def _init_uc(self):
        a = self._arch
        if a == Architecture.X86:
            self._uc = _uc.Uc(_uc.UC_ARCH_X86, _uc.UC_MODE_32)
        elif a == Architecture.X64:
            self._uc = _uc.Uc(_uc.UC_ARCH_X86, _uc.UC_MODE_64)
        elif a == Architecture.ARM:
            self._uc = _uc.Uc(_uc.UC_ARCH_ARM, _uc.UC_MODE_ARM)
        elif a == Architecture.ARM64:
            self._uc = _uc.Uc(_uc.UC_ARCH_ARM64, _uc.UC_MODE_ARM64)

    def map_mem(self, addr, size, data=None):
        if self._uc is None:
            return
        buf = data if data else b'\x00' * size
        self._uc.mem_map(addr, size, _uc.UC_PROT_ALL)
        self._uc.mem_write(addr, buf)
        self._mem[addr] = (size, buf)

    def set_reg(self, reg_name, value):
        if self._uc is None:
            return
        _RMAP = {'rax': _uc.x86_const.UC_X86_REG_RAX, 'rbx': _uc.x86_const.UC_X86_REG_RBX,
                 'rcx': _uc.x86_const.UC_X86_REG_RCX, 'rdx': _uc.x86_const.UC_X86_REG_RDX,
                 'rsp': _uc.x86_const.UC_X86_REG_RSP, 'rbp': _uc.x86_const.UC_X86_REG_RBP,
                 'rip': _uc.x86_const.UC_X86_REG_RIP}
        rl = reg_name.lower()
        if rl in _RMAP:
            self._uc.reg_write(_RMAP[rl], value)

    def _trace_cb(self, uc, addr, sz, ud):
        insn = uc.mem_read(addr, sz)
        self._trace.append((addr, sz))
        if self._cs:
            for i in self._cs.disasm(insn, addr):
                if self._is_cf(i):
                    targs = self._get_targs(uc, i)
                    if addr not in self._resolved:
                        self._resolved[addr] = []
                    self._resolved[addr].extend(targs)

    def _is_cf(self, insn):
        _GRPS = (_cs.CS_GRP_CALL, _cs.CS_GRP_JUMP, _cs.CS_GRP_RET, _cs.CS_GRP_IRET)
        for grp in _GRPS:
            if insn.group(grp):
                return True
        return False

    def _get_targs(self, uc, insn):
        out = []
        iid = insn.id
        ops = insn.op_str
        _JMP = (_cs.x86.X86_INS_JMP, _cs.x86.X86_INS_JMPD)
        _CALL = (_cs.x86.X86_INS_CALL, _cs.x86.X86_INS_CALLD)
        _COND = (_cs.x86.X86_INS_JZ, _cs.x86.X86_INS_JNZ, _cs.x86.X86_INS_JE, _cs.x86.X86_INS_JNE,
                 _cs.x86.X86_INS_JS, _cs.x86.X86_INS_JNS, _cs.x86.X86_INS_JB, _cs.x86.X86_INS_JNB,
                 _cs.x86.X86_INS_JL, _cs.x86.X86_INS_JGE, _cs.x86.X86_INS_JLE, _cs.x86.X86_INS_JG)
        if iid in _JMP:
            if ops.startswith('0x'):
                try:
                    out.append(int(ops, 16))
                except ValueError:
                    pass
            elif ops.startswith('*'):
                try:
                    a = self._eval(uc, ops[1:])
                    if a:
                        out.append(a)
                except Exception:
                    pass
        elif iid in _CALL:
            if ops.startswith('0x'):
                try:
                    out.append(int(ops, 16))
                except ValueError:
                    pass
        elif iid in _COND:
            if ops.startswith('0x'):
                try:
                    out.append(int(ops, 16))
                except ValueError:
                    pass
            out.append(insn.address + insn.size)
        return out

    def _eval(self, uc, expr):
        try:
            e = expr
            _REGS = {'rax': _uc.x86_const.UC_X86_REG_RAX, 'rbx': _uc.x86_const.UC_X86_REG_RBX,
                     'rcx': _uc.x86_const.UC_X86_REG_RCX, 'rdx': _uc.x86_const.UC_X86_REG_RDX,
                     'rsi': _uc.x86_const.UC_X86_REG_RSI, 'rdi': _uc.x86_const.UC_X86_REG_RDI}
            for rn, rc in _REGS.items():
                e = e.replace(rn, str(uc.reg_read(rc)))
            e = e.replace('[', '(').replace(']', ')')
            return eval(e)
        except Exception:
            return None

    def run(self, start_addr, end_addr=None, max_steps=10000):
        if self._uc is None:
            logger.error('unicorn unavailable')
            return
        self._uc.hook_add(_uc.UC_HOOK_CODE, self._trace_cb)
        try:
            self._uc.emu_start(start_addr, end_addr or 0, count=max_steps)
        except _uc.UcError as e:
            logger.warning(f'emu stopped: {e}')

    def disasm(self, data, base_addr=0, mode=None):
        if mode is None:
            mode = DisasmMode.HYBRID
        insns = []
        unres = []
        warns = []

        if mode in (DisasmMode.STATIC, DisasmMode.HYBRID):
            sr = self._static(data, base_addr)
            insns.extend(sr.instructions)
            unres.extend(sr.unresolved)

        if mode in (DisasmMode.DYNAMIC, DisasmMode.HYBRID) and _HAS_UC:
            self._run_dyn(data, base_addr)
            insns = self._merge(insns)

        return DisasmResult(instructions=insns, unresolved=unres, warnings=warns)

    def _static(self, data, addr):
        insns = []
        unres = []
        if self._cs is None:
            return DisasmResult()
        for i in self._cs.disasm(data, addr):
            is_cond = (i.group(_cs.CS_GRP_JUMP) and not i.group(_cs.CS_GRP_CALL)) or \
                      i.id in (_cs.x86.X86_INS_JZ, _cs.x86.X86_INS_JNZ, _cs.x86.X86_INS_JE, _cs.x86.X86_INS_JNE)
            is_ind = i.op_str.startswith('*') or ('[' in i.op_str and '+' in i.op_str)
            insns.append(Instruction(address=i.address, mnemonic=i.mnemonic, operands=i.op_str,
                                     raw_bytes=i.bytes, is_conditional=is_cond, is_indirect=is_ind))
            if is_ind and i.group(_cs.CS_GRP_JUMP):
                unres.append(i.address)
        return DisasmResult(instructions=insns, unresolved=unres)

    def _run_dyn(self, data, addr):
        PS = 0x1000
        aa = addr & ~(PS - 1)
        off = addr - aa
        self.map_mem(aa, PS * 2, data)
        self.set_reg('rip', addr)
        self.set_reg('rsp', 0x7fffffff000)
        self.run(addr, max_steps=1000)

    def _merge(self, insns):
        for i in insns:
            if i.address in self._resolved:
                i.targets = self._resolved[i.address]
                if i.is_indirect:
                    logger.info(f'resolved indirect @ 0x{i.address:x}: {i.targets}')
        return insns

    def trace(self):
        return self._trace

    def resolved(self):
        return self._resolved


def create_disassembler(arch='x86_64'):
    if isinstance(arch, str):
        for a in Architecture:
            if a.value == arch:
                arch = a
                break
    return FlowSensitiveDisassembler(arch)


def disassemble(data, base_addr=0, arch='x86_64', mode='hybrid'):
    d = create_disassembler(arch)
    m = _MODE_MAP.get(mode, DisasmMode.HYBRID)
    return d.disasm(data, base_addr, m)
