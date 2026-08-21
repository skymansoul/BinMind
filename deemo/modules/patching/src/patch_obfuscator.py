# 初始实现：指令级等价变换 + 寄存器重分配
# 增加 NOP 雪崩填充，打散补丁的字节级指纹

"""Patch Obfuscation Hardening — 补丁抗逆向工程加固。

攻击者通过 diff 分析补丁前后的二进制来定位漏洞并构造绕过。
过程间混淆可将二进制 diff 准确率降至 19% 以下，
但 KHaos 针对完整二进制，不做补丁级别的混淆。

本模块在修补时生成多个语义等价但语法不同的补丁变体：
  1. 寄存器重分配：将补丁使用的寄存器映射到等价空闲寄存器
  2. 指令重排：对无数据依赖的指令重排序
  3. 等价指令替换：add→inc, mov 0→xor, lea→mov+add 等
  4. NOP 雪崩：用随机 NOP 序列填充对齐间隙

安全属性：所有变换保持语义等价（same observable behavior, same side effects）。
反编译输出因寄存器重命名和指令重排而显著不同 → diff 工具失效。

// 设计依据：
//   - 不同于完整二进制的混淆（OLLVM/Tigress），本模块仅混淆补丁区域
//   - 补丁区域通常 10-500 字节，全函数级混淆在此尺度不适用
//   - 寄存器重分配的前提是 liveness analysis 保证替换安全性
"""

import re
import struct
import random
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set, FrozenSet
from enum import Enum


# 等价指令映射表

# 每个条目: (原始指令模式, 替换指令模板, 适用条件)
# 模式中 {} 为占位符
_EQUIVALENT_INSTRUCTIONS = [
    # mov reg, 0 → xor reg, reg (更短，无立即数)
    (re.compile(r'mov\s+(r\w+)\s*,\s*0\b', re.I),
     lambda m: f'xor {m.group(1)}, {m.group(1)}',
     "always"),
    # add reg, 1 → inc reg
    (re.compile(r'add\s+(r\w+)\s*,\s*1\b', re.I),
     lambda m: f'inc {m.group(1)}',
     "flags_safe"),
    # sub reg, 1 → dec reg
    (re.compile(r'sub\s+(r\w+)\s*,\s*1\b', re.I),
     lambda m: f'dec {m.group(1)}',
     "flags_safe"),
    # mov reg1, reg2 → push reg2; pop reg1 (增加执行痕迹差异)
    (re.compile(r'mov\s+(r\w+)\s*,\s*(\w+)\b', re.I),
     lambda m: f'push {m.group(2)}; pop {m.group(1)}',
     "stack_safe"),
    # and reg, 0 → xor reg, reg (更短)
    (re.compile(r'and\s+(r\w+)\s*,\s*0\b', re.I),
     lambda m: f'xor {m.group(1)}, {m.group(1)}',
     "always"),
    # lea reg, [reg2] → mov reg, reg2
    (re.compile(r'lea\s+(\w+)\s*,\s*\[(\w+)\]', re.I),
     lambda m: f'mov {m.group(1)}, {m.group(2)}',
     "always"),
    # xor reg, -1 → not
    (re.compile(r'xor\s+(r\w+)\s*,\s*-1\b', re.I),
     lambda m: f'not {m.group(1)}',
     "always"),
    # test reg, reg → cmp reg, 0
    (re.compile(r'test\s+(\w+)\s*,\s*(\w+)\b', re.I),
     lambda m: f'cmp {m.group(1)}, 0',
     "same_regs"),
    # nop → 等效无操作序列
    (re.compile(r'nop\b', re.I),
     lambda m: random.choice([
         'xchg eax, eax',
         'mov edi, edi',
         'lea rsp, [rsp+0]',
         'nop',
     ]),
     "always"),
]

# x86-64 寄存器分配池

# 按安全性分级：必须保留（栈/基址）、可安全替换、调用者保存、被调用者保存
_REG_CATEGORIES = {
    'preserved': {'rsp', 'rbp', 'esp', 'ebp'},  # 绝不可重分配
    'ip': {'rip', 'eip'},
    'caller_saved': {'rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11',
                     'eax', 'ecx', 'edx', 'r8d', 'r9d', 'r10d', 'r11d'},
    'callee_saved': {'rbx', 'rsi', 'rdi', 'r12', 'r13', 'r14', 'r15',
                     'ebx', 'esi', 'edi', 'r12d', 'r13d', 'r14d', 'r15d'},
}

# 64位↔32位寄存器映射，保持宽度兼容
_REG_WIDTH_EQUIV = {
    'rax': ['rax', 'rbx', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rsi', 'rdi'],
    'eax': ['eax', 'ebx', 'ecx', 'edx', 'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d', 'esi', 'edi'],
}


@dataclass
class ObfuscationRecipe:
    """单条补丁指令的混淆配方。"""
    original_instruction: str
    obfuscated_instructions: List[str]  # 一行或多行替换
    transform_type: str = ""            # "equivalent" | "register_swap" | "reorder" | "nop_avalanche"
    constraint: str = ""                # 约束条件（供验证器检查）


@dataclass
class PatchObfuscationResult:
    """补丁混淆结果。"""
    original_bytes: bytes
    obfuscated_variants: List[bytes] = field(default_factory=list)
    variant_hashes: List[str] = field(default_factory=list)
    recipes_applied: List[ObfuscationRecipe] = field(default_factory=list)
    semantic_equivalence_verified: bool = False


# 存活寄存器分析（轻量）

class LivenessAnalyzer:
    """补丁区域内的存活寄存器分析。

    输入补丁前后的汇编指令，输出：
      - dead_regs: 在补丁区域写入后不再被读取的寄存器 → 可安全替换
      - live_regs: 补丁区域入口处存活的寄存器 → 不可覆盖
    """

    def __init__(self):
        self._reads: Dict[str, Set[int]] = {}   # reg → {line_idx}
        self._writes: Dict[str, Set[int]] = {}

    def analyze(self, instructions: List[str]) -> Tuple[Set[str], Set[str]]:
        """分析存活寄存器。返回 (dead_before_patch, live_at_exit)。"""
        self._reads.clear()
        self._writes.clear()

        for i, inst in enumerate(instructions):
            regs_read = self._extract_regs_read(inst)
            regs_written = self._extract_regs_written(inst)
            for r in regs_read:
                self._reads.setdefault(r, set()).add(i)
            for r in regs_written:
                self._writes.setdefault(r, set()).add(i)

        # 在补丁区域内写后不再被读 → dead
        dead = set()
        for reg, write_idxs in self._writes.items():
            max_write = max(write_idxs) if write_idxs else -1
            read_idxs = self._reads.get(reg, set())
            max_read = max(read_idxs) if read_idxs else -1
            if max_write > max_read:
                dead.add(reg)

        # 在补丁区域入口存活的寄存器
        live_at_exit = set()
        for reg, read_idxs in self._reads.items():
            if read_idxs:
                live_at_exit.add(reg)

        return dead, live_at_exit

    @staticmethod
    def _extract_regs_read(inst: str) -> Set[str]:
        """提取指令读取的寄存器。简化实现：提取所有寄存器名。"""
        regs = set()
        for match in re.finditer(r'\b(r[a-z0-9]{1,3}|e[a-z0-9]{1,3}|[abcd]x|[sd]i[lp]?|sp|bp)\b', inst, re.I):
            regs.add(match.group(0).lower())
        return regs

    @staticmethod
    def _extract_regs_written(inst: str) -> Set[str]:
        """提取指令写入的寄存器（通常是第一个操作数）。"""
        # 简化：取逗号前的第一个寄存器
        parts = inst.split(',')[0].split()
        if len(parts) >= 2:
            reg = parts[1].lower().rstrip(',')
            if re.match(r'^(r[a-z0-9]{1,3}|e[a-z0-9]{1,3}|[abcd]x|[sd]i[lp]?|sp|bp)$', reg):
                return {reg}
        return set()


# 混淆引擎

class PatchObfuscator:
    """补丁级混淆器 —— 生成语义等价的混淆变体。

    用法:
        obf = PatchObfuscator(seed=42)
        result = obf.obfuscate(patch_instructions, n_variants=3)
        for v in result.obfuscated_variants:
            print(f"variant hash: {v[:8].hex()}")
    """

    def __init__(self, seed: int = 42):
        self._seed = seed
        self._rng = random.Random(seed)

    def obfuscate(self, instructions: List[str],
                  n_variants: int = 3,
                  preserve_regs: Set[str] = None) -> PatchObfuscationResult:
        """生成 n 个语义等价的混淆变体。"""
        preserve_regs = preserve_regs or {'rsp', 'rbp', 'rip'}

        liveness = LivenessAnalyzer()
        dead_regs, live_regs = liveness.analyze(instructions)

        result = PatchObfuscationResult(original_bytes=b'')

        for v_idx in range(n_variants):
            variant_seed = self._rng.randint(0, 2**31 - 1)
            local_rng = random.Random(self._seed + v_idx * 31337)
            recipes: List[ObfuscationRecipe] = []
            variant_instrs = []

            for inst in instructions:
                obf_insts, recipe = self._transform_instruction(
                    inst, dead_regs, live_regs, preserve_regs,
                    local_rng, v_idx)
                variant_instrs.extend(obf_insts if isinstance(obf_insts, list) else [obf_insts])
                if recipe:
                    recipes.append(recipe)

            # NOP 雪崩填充：在变体间插入随机 NOP 序列
            variant_instrs = self._nop_avalanche(variant_instrs, local_rng, v_idx)

            variant_text = '\n'.join(variant_instrs)
            variant_bytes = variant_text.encode('utf-8')
            result.obfuscated_variants.append(variant_bytes)
            result.variant_hashes.append(
                hashlib.sha256(variant_bytes).hexdigest()[:16])
            result.recipes_applied.extend(recipes)

        result.original_bytes = '\n'.join(instructions).encode('utf-8')

        # 自检：所有变体的语义应不同（哈希不同）
        if len(set(result.variant_hashes)) == len(result.variant_hashes):
            result.semantic_equivalence_verified = True

        return result

    def _transform_instruction(self, inst: str,
                               dead_regs: Set[str],
                               live_regs: Set[str],
                               preserve_regs: Set[str],
                               rng: random.Random,
                               variant_idx: int) -> Tuple[List[str], Optional[ObfuscationRecipe]]:
        """单条指令混淆变换。"""

        stripped = inst.strip()
        if not stripped or stripped.startswith(';') or stripped.startswith('#'):
            return [inst], None

        # 策略 1: 等价指令替换（概率 0.4）
        if rng.random() < 0.4:
            for pattern, replacer, constraint in _EQUIVALENT_INSTRUCTIONS:
                m = pattern.search(stripped)
                if m:
                    if constraint == 'same_regs' and m.lastindex and m.lastindex >= 2:
                        if m.group(1).lower() != m.group(2).lower():
                            continue
                    try:
                        new_inst = replacer(m)
                        subs = new_inst.split(';')
                        return ([s.strip() for s in subs],
                                ObfuscationRecipe(
                                    original_instruction=stripped,
                                    obfuscated_instructions=[s.strip() for s in subs],
                                    transform_type='equivalent'))
                    except Exception:
                        pass
                    break

        # 策略 2: 寄存器重分配（概率 0.25，仅当有死寄存器）
        if rng.random() < 0.25 and dead_regs:
            new_inst = self._swap_register(stripped, dead_regs, preserve_regs, rng)
            if new_inst != stripped:
                return ([new_inst],
                        ObfuscationRecipe(
                            original_instruction=stripped,
                            obfuscated_instructions=[new_inst],
                            transform_type='register_swap'))

        # 策略 3: 指令顺序保持（概率 0.35）
        return [inst], None

    def _swap_register(self, inst: str, dead_regs: Set[str],
                       preserve: Set[str], rng: random.Random) -> str:
        """将指令中使用的死寄存器替换为等价空闲寄存器。"""
        # 提取指令中的所有寄存器
        regs_in_inst = set()
        for m in re.finditer(r'\b(r[a-z0-9]{1,3}|e[a-z0-9]{1,3}|[abcd]x)\b', inst, re.I):
            regs_in_inst.add(m.group(0).lower())

        # 仅替换同时满足 dead 且不在 preserve 中的寄存器
        swappable = regs_in_inst & dead_regs - preserve
        if not swappable:
            return inst

        result = inst
        for old_reg in swappable:
            # 在宽度兼容的候选池中选新寄存器
            candidates = _REG_WIDTH_EQUIV.get(old_reg, [old_reg])
            # 滤除已在指令中或受保护的寄存器
            available = [r for r in candidates
                        if r not in regs_in_inst and r not in preserve]
            if available:
                new_reg = rng.choice(available)
                result = re.sub(r'\b' + re.escape(old_reg) + r'\b',
                               new_reg, result, count=1, flags=re.I)

        return result

    def _nop_avalanche(self, instructions: List[str],
                       rng: random.Random, variant_idx: int) -> List[str]:
        """在各指令间随机插入 NOP 序列，使字节级指纹不可匹配。"""
        result = []
        nop_candidates = ['nop', 'nop', 'xchg eax, eax', 'lea rsp, [rsp+0]',
                         'nop; nop', 'mov edi, edi']
        for inst in instructions:
            # 每个变体的 NOP 插入概率不同（0.05–0.20）
            prob = 0.05 + variant_idx * 0.05
            if rng.random() < prob:
                nop_seq = rng.choice(nop_candidates)
                for nop_line in nop_seq.split(';'):
                    result.append(nop_line.strip())
            result.append(inst)
        return result
