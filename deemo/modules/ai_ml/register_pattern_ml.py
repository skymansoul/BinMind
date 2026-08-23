from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class RegisterUsage:
    reg: str
    read_count: int = 0
    write_count: int = 0
    usage_purpose: str = "general"


@dataclass
class CompilerSignature:
    name: str
    confidence: float
    features: Dict[str, float]
    evidence: List[str] = field(default_factory=list)


@dataclass
class OptimizationProfile:
    """优化等级推断结果 — 每个决策都应有数据背书。"""
    level: str
    confidence: float
    indicators: Dict[str, float] = field(default_factory=dict)
    rationale: List[str] = field(default_factory=list)


@dataclass
class ArchitectureHint:
    """架构指纹：指令集特征 → CPU 架构。歧义即噪声，必须消除。"""
    arch: str
    bitness: int
    confidence: float
    dominant_opcodes: List[str] = field(default_factory=list)


REGISTER_PATTERNS: Dict[str, List[str]] = {
    'msvc_debug': [
        'mov edi, edi',
        'push ebp',
        'mov ebp, esp',
        'sub esp,',
        'push ebx',
        'push esi',
        'push edi',
        'pop edi',
        'pop esi',
        'pop ebx',
        'mov esp, ebp',
        'pop ebp',
        'ret',
    ],
    'msvc_release': [
        'push ebp',
        'mov ebp, esp',
        'sub esp,',
        'mov esp, ebp',
        'pop ebp',
        'ret',
    ],
    'gcc_o0': [
        'push rbp',
        'mov rbp, rsp',
        'sub rsp,',
        'leave',
        'ret',
    ],
    'gcc_o2': [
        'endbr64',
        'push r',
        'mov r',
        'lea r',
        'ret',
    ],
    'clang_o0': [
        'push rbp',
        'mov rbp, rsp',
        'sub rsp,',
        'pop rbp',
        'ret',
    ],
    'clang_o2': [
        'endbr64',
        'xor eax, eax',
        'ret',
    ],
}

X86_REGISTERS: Dict[str, str] = {
    'eax': 'accumulator',
    'ebx': 'base',
    'ecx': 'counter',
    'edx': 'data',
    'esi': 'source_index',
    'edi': 'dest_index',
    'ebp': 'base_pointer',
    'esp': 'stack_pointer',
    'eip': 'instruction_pointer',
}

X64_REGISTERS: Dict[str, str] = {
    'rax': 'accumulator',
    'rbx': 'base',
    'rcx': 'counter',
    'rdx': 'data',
    'rsi': 'source_index',
    'rdi': 'dest_index',
    'rbp': 'base_pointer',
    'rsp': 'stack_pointer',
    'rip': 'instruction_pointer',
    'r8': 'general_1',
    'r9': 'general_2',
    'r10': 'general_3',
    'r11': 'general_4',
    'r12': 'general_5',
    'r13': 'general_6',
    'r14': 'general_7',
    'r15': 'general_8',
}

ARM_REGISTERS: Dict[str, str] = {
    'r0': 'arg/result',
    'r1': 'arg',
    'r2': 'arg',
    'r3': 'arg',
    'r4': 'callee_saved',
    'r5': 'callee_saved',
    'r6': 'callee_saved',
    'r7': 'frame_pointer',
    'r8': 'callee_saved',
    'r9': 'platform',
    'r10': 'callee_saved',
    'r11': 'callee_saved',
    'r12': 'intra_procedure',
    'sp': 'stack_pointer',
    'lr': 'link_register',
    'pc': 'program_counter',
}

# 优化等级特征指纹 — 每条规则来源于真实编译器行为的逆向归纳。
OPT_LEVEL_INDICATORS: Dict[str, Dict[str, Any]] = {
    'O0': {
        'stack_frame_density': (0.6, 1.0),
        'redundant_moves': (0.3, 1.0),
        'loop_unroll_hint': (0.0, 0.05),
        'inline_hint': (0.0, 0.02),
        'dead_store_density': (0.01, 1.0),
    },
    'O1': {
        'stack_frame_density': (0.3, 0.7),
        'redundant_moves': (0.1, 0.4),
        'loop_unroll_hint': (0.0, 0.1),
        'inline_hint': (0.0, 0.05),
        'dead_store_density': (0.0, 0.05),
    },
    'O2': {
        'stack_frame_density': (0.0, 0.3),
        'redundant_moves': (0.0, 0.15),
        'loop_unroll_hint': (0.0, 0.3),
        'inline_hint': (0.0, 0.2),
        'dead_store_density': (0.0, 0.02),
    },
    'O3': {
        'stack_frame_density': (0.0, 0.25),
        'redundant_moves': (0.0, 0.1),
        'loop_unroll_hint': (0.02, 0.5),
        'inline_hint': (0.02, 0.4),
        'dead_store_density': (0.0, 0.01),
    },
    'Os': {
        'stack_frame_density': (0.0, 0.25),
        'redundant_moves': (0.0, 0.1),
        'loop_unroll_hint': (0.0, 0.1),
        'inline_hint': (0.0, 0.05),
        'dead_store_density': (0.0, 0.01),
    },
}

# 架构检测启发式 — 指令前缀 + 寄存器命名约定，不依赖元数据。
ARCH_HEURISTICS: Dict[str, Dict[str, Any]] = {
    'x86': {
        'bitness': 32,
        'reg_pattern': re.compile(r'\b(eax|ebx|ecx|edx|esi|edi|ebp|esp|eip)\b', re.IGNORECASE),
        'opcodes': ['push', 'pop', 'mov', 'add', 'sub', 'cmp', 'jmp', 'call', 'ret', 'lea', 'int'],
        'prefix_hint': None,
    },
    'x64': {
        'bitness': 64,
        'reg_pattern': re.compile(r'\b(r[89]|r1[0-5]|rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|rip)\b', re.IGNORECASE),
        'opcodes': ['push', 'pop', 'mov', 'add', 'sub', 'cmp', 'jmp', 'call', 'ret', 'lea', 'syscall'],
        'prefix_hint': re.compile(r'\bendbr64\b|\b0x[0-9a-f]{8,16}\b', re.IGNORECASE),
    },
    'arm': {
        'bitness': 32,
        'reg_pattern': re.compile(r'\b(r[0-9]|r1[0-2]|sp|lr|pc)\b', re.IGNORECASE),
        'opcodes': ['ldr', 'str', 'b', 'bl', 'bx', 'add', 'sub', 'cmp', 'mov', 'push', 'pop'],
        'prefix_hint': None,
    },
    'arm64': {
        'bitness': 64,
        'reg_pattern': re.compile(r'\b(x[0-9]|x1[0-9]|x2[0-8]|x29|x30|sp|w[0-9]|w1[0-9]|w2[0-8]|w29|w30)\b', re.IGNORECASE),
        'opcodes': ['ldr', 'str', 'b', 'bl', 'blr', 'ret', 'add', 'sub', 'cmp', 'stp', 'ldp'],
        'prefix_hint': None,
    },
}


class RegisterPatternExtractor:

    def __init__(self) -> None:
        self._all_registers = {
            **X86_REGISTERS,
            **X64_REGISTERS,
            **ARM_REGISTERS,
        }

    def extract_from_disasm(
        self,
        disassembly: str,
    ) -> List[RegisterUsage]:
        usage: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {'read': 0, 'write': 0}
        )

        lines = disassembly.split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                continue

            line_lower = line.lower()

            for reg_name in self._all_registers:
                reg_lower = reg_name.lower()
                if reg_lower not in line_lower:
                    continue

                if re.search(
                    rf'\b(?:mov|lea|pop|ldr)\s+{reg_lower}',
                    line_lower,
                ):
                    usage[reg_name]['write'] += 1
                elif re.search(
                    rf'\b(?:add|sub|inc|dec|and|or|xor|mul|imul|div|idiv|shl|shr)\s+{reg_lower}',
                    line_lower,
                ):
                    usage[reg_name]['write'] += 1
                    usage[reg_name]['read'] += 1
                else:
                    usage[reg_name]['read'] += 1

        return [
            RegisterUsage(
                reg=reg,
                read_count=stats['read'],
                write_count=stats['write'],
                usage_purpose=self._all_registers.get(reg, 'general'),
            )
            for reg, stats in usage.items()
        ]

    def detect_architecture(self, disassembly: str) -> ArchitectureHint:
        """从反汇编指令流自动推断 CPU 架构和位宽。
        不依赖外部元数据 — 仅凭指令形态 + 寄存器命名空间做判断。
        歧义场景（如 x86↔x64 混合）给出最低置信度，不猜测。"""
        # 归一化：只取助记符和寄存器名，忽略地址和立即数
        mnemonics: List[str] = []
        for line in disassembly.split('\n'):
            stripped = line.strip().lower()
            if not stripped or stripped.startswith(';') or stripped.startswith('#'):
                continue
            # 拆出第一个 token 作为助记符
            tok = stripped.split()[0] if stripped.split() else ''
            if tok:
                mnemonics.append(tok)

        total_instr = max(len(mnemonics), 1)
        arch_scores: Dict[str, float] = {}

        for arch_name, heuristics in ARCH_HEURISTICS.items():
            reg_hits = len(heuristics['reg_pattern'].findall(disassembly.lower()))
            opcode_hits = sum(
                1 for m in mnemonics if m in heuristics['opcodes']
            )
            prefix_score = 0.0
            if heuristics['prefix_hint'] is not None:
                prefix_score = 1.0 if heuristics['prefix_hint'].search(disassembly.lower()) else 0.0

            # 综合得分：寄存器的存在性是强信号，助记符是弱信号
            if total_instr == 0 or reg_hits == 0:
                arch_scores[arch_name] = 0.0
            else:
                reg_density = min(reg_hits / total_instr, 1.0) * 0.5
                opcode_density = min(opcode_hits / total_instr, 1.0) * 0.3
                prefix_bonus = prefix_score * 0.2
                arch_scores[arch_name] = reg_density + opcode_density + prefix_bonus

        if not arch_scores or max(arch_scores.values()) == 0.0:
            return ArchitectureHint(
                arch='unknown',
                bitness=0,
                confidence=0.0,
                dominant_opcodes=list(set(mnemonics))[:5],
            )

        best_arch = max(arch_scores, key=lambda k: arch_scores[k])
        best_score = arch_scores[best_arch]
        second_score = sorted(arch_scores.values(), reverse=True)[1] if len(arch_scores) > 1 else 0.0

        # 当第一和第二得分接近时降低置信度 — 不强行选择
        margin = best_score - second_score
        confidence = min(best_score, margin * 2.0)

        return ArchitectureHint(
            arch=best_arch,
            bitness=ARCH_HEURISTICS[best_arch]['bitness'],
            confidence=round(confidence, 4),
            dominant_opcodes=list(set(mnemonics))[:8],
        )

    def compute_feature_vector(
        self,
        usage: List[RegisterUsage],
    ) -> Dict[str, float]:
        total_reads = sum(u.read_count for u in usage)
        total_writes = sum(u.write_count for u in usage)
        total_ops = max(total_reads + total_writes, 1)

        features: Dict[str, float] = {
            'total_registers': len(usage),
            'read_write_ratio': (
                total_reads / max(total_writes, 1)
            ),
            'avg_reads_per_reg': total_reads / max(len(usage), 1),
            'avg_writes_per_reg': total_writes / max(len(usage), 1),
        }

        for u in usage:
            features[f'{u.reg}_read_ratio'] = u.read_count / total_ops
            features[f'{u.reg}_write_ratio'] = u.write_count / total_ops

        for category in set(self._all_registers.values()):
            cat_regs = [
                u for u in usage
                if self._all_registers.get(u.reg, 'general') == category
            ]
            if cat_regs:
                features[f'{category}_reads'] = sum(r.read_count for r in cat_regs) / total_ops
                features[f'{category}_writes'] = sum(r.write_count for r in cat_regs) / total_ops

        return features

    def extract_calling_convention(
        self,
        usage: List[RegisterUsage],
    ) -> str:
        used_regs = {u.reg.lower() for u in usage if u.write_count > 0 or u.read_count > 0}

        if {'rcx', 'rdx', 'r8', 'r9'} & used_regs:
            return 'x64_fastcall'

        if {'rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'} & used_regs:
            return 'system_v_amd64'

        if 'esp' in used_regs and 'ebp' in used_regs:
            return 'cdecl'

        if 'esp' in used_regs:
            return 'stdcall'

        if {'ecx', 'edx'} & used_regs:
            return 'fastcall_x86'

        if {'r0', 'r1', 'r2', 'r3'} & used_regs:
            return 'arm_aapcs'

        return 'unknown'


class CompilerRegisterClassifier:

    COMPILER_FEATURES: Dict[str, Dict[str, float]] = {
        'msvc_debug': {
            'stack_frame_ratio': 0.9,
            'push_pop_density': 0.7,
            'ebp_usage': 0.9,
            'leave_instruction': 0.0,
        },
        'msvc_release': {
            'stack_frame_ratio': 0.8,
            'push_pop_density': 0.3,
            'ebp_usage': 0.8,
            'leave_instruction': 0.0,
        },
        'gcc_o0': {
            'stack_frame_ratio': 0.8,
            'push_pop_density': 0.5,
            'ebp_usage': 0.0,
            'leave_instruction': 0.9,
        },
        'gcc_o2': {
            'stack_frame_ratio': 0.2,
            'push_pop_density': 0.3,
            'ebp_usage': 0.0,
            'leave_instruction': 0.3,
        },
        'clang_o0': {
            'stack_frame_ratio': 0.8,
            'push_pop_density': 0.4,
            'ebp_usage': 0.0,
            'leave_instruction': 0.0,
        },
        'clang_o2': {
            'stack_frame_ratio': 0.1,
            'push_pop_density': 0.2,
            'ebp_usage': 0.0,
            'leave_instruction': 0.1,
        },
    }

    def __init__(self) -> None:
        self.extractor = RegisterPatternExtractor()
        self._trained: bool = True
        # 特征权重缓存 — 一次性计算，多次复用。空间换时间。
        self._feature_weights: Optional[Dict[str, float]] = None

    def classify(
        self,
        disassembly: str,
    ) -> CompilerSignature:
        features = self._extract_features(disassembly)
        return self._match_compiler(features)

    def _extract_features(self, disassembly: str) -> Dict[str, float]:
        lines = disassembly.split('\n')
        total_lines = max(len(lines), 1)

        features: Dict[str, float] = {}

        push_count = sum(1 for l in lines if re.search(r'\bpush\b', l.lower()))
        pop_count = sum(1 for l in lines if re.search(r'\bpop\b', l.lower()))
        features['push_pop_density'] = (push_count + pop_count) / total_lines

        ebp_count = sum(1 for l in lines if re.search(r'\bebp\b', l.lower()))
        rbp_count = sum(1 for l in lines if re.search(r'\brbp\b', l.lower()))
        features['ebp_usage'] = (ebp_count + rbp_count) / total_lines

        stack_setup = sum(
            1 for l in lines
            if re.search(r'(mov\s+(ebp|rbp)\,\s*(esp|rsp))|(push\s+(ebp|rbp))', l.lower())
        )
        features['stack_frame_ratio'] = stack_setup / max(total_lines, 1)

        leave_count = sum(1 for l in lines if re.search(r'\bleave\b', l.lower()))
        features['leave_instruction'] = leave_count / max(total_lines, 1)

        features['xor_zeroing'] = sum(
            1 for l in lines
            if re.search(r'\bxor\s+(eax|rax|ecx|rcx)\,\s*(eax|rax|ecx|rcx)\b', l.lower())
        ) / max(total_lines, 1)

        features['cet_present'] = 1.0 if any(
            'endbr64' in l.lower() for l in lines
        ) else 0.0

        return features

    def _compute_feature_weights(self) -> Dict[str, float]:
        """计算每个特征的区分度权重 — 使用逆方差加权。
        特征在编译器间波动越大 → 区分能力越强 → 权重越高。
        方差为 0 的特征（所有编译器一致）不参与分类决策。"""
        if self._feature_weights is not None:
            return self._feature_weights

        feature_values: Dict[str, List[float]] = defaultdict(list)
        for profile in self.COMPILER_FEATURES.values():
            for fname, fval in profile.items():
                feature_values[fname].append(fval)

        weights: Dict[str, float] = {}
        for fname, values in feature_values.items():
            n = len(values)
            if n < 2:
                weights[fname] = 0.5  # 单一样本 → 中性权重
                continue
            mean = sum(values) / n
            variance = sum((v - mean) ** 2 for v in values) / n
            # 方差归一化：方差越大权重越高，cap 在 1.0
            weights[fname] = min(variance * 3.0, 1.0) if variance > 0 else 0.0

        self._feature_weights = weights
        return weights

    def _match_compiler(
        self,
        features: Dict[str, float],
    ) -> CompilerSignature:
        # 获取特征区分度权重，提升匹配精度
        weights = self._compute_feature_weights()

        best_match = 'unknown'
        best_score = -1.0
        evidence: List[str] = []

        for name, profile in self.COMPILER_FEATURES.items():
            score = self._weighted_cosine_similarity(features, profile, weights)
            if score > best_score:
                best_score = score
                best_match = name
                evidence = [
                    f"Matched {k}: observed {features.get(k, 0):.2f} vs expected {v:.2f} (weight={weights.get(k, 0):.3f})"
                    for k, v in profile.items()
                    if k in features
                ]

        confidence = min(best_score * 1.2, 0.99)

        return CompilerSignature(
            name=best_match,
            confidence=confidence,
            features=features,
            evidence=evidence,
        )

    @staticmethod
    def _cosine_similarity(
        a: Dict[str, float],
        b: Dict[str, float],
    ) -> float:
        keys = set(a.keys()) | set(b.keys())
        if not keys:
            return 0.0

        dot = sum(a.get(k, 0) * b.get(k, 0) for k in keys)
        norm_a = sum(v ** 2 for v in a.values()) ** 0.5
        norm_b = sum(v ** 2 for v in b.values()) ** 0.5

        if norm_a == 0 or norm_b == 0:
            return 0.0

        return dot / (norm_a * norm_b)

    @staticmethod
    def _weighted_cosine_similarity(
        a: Dict[str, float],
        b: Dict[str, float],
        weights: Dict[str, float],
    ) -> float:
        """加权余弦相似度 — 区分度高的特征在匹配中更有话语权。
        这是对朴素 cosine 的改良：权重来自特征在各编译器间的方差。"""
        keys = set(a.keys()) | set(b.keys())
        if not keys:
            return 0.0

        dot = sum(
            a.get(k, 0) * b.get(k, 0) * weights.get(k, 1.0)
            for k in keys
        )
        norm_a = sum(
            (a.get(k, 0) * weights.get(k, 1.0)) ** 2
            for k in keys
        ) ** 0.5
        norm_b = sum(
            (b.get(k, 0) * weights.get(k, 1.0)) ** 2
            for k in keys
        ) ** 0.5

        if norm_a == 0 or norm_b == 0:
            return 0.0

        return dot / (norm_a * norm_b)

    def infer_optimization_level(self, disassembly: str) -> OptimizationProfile:
        """独立推断优化等级 — 不依赖编译器识别结果。
        通过指令模式密度分析来判断 O0/O1/O2/O3/Os：
        - O0: 冗余 mov 多、栈帧完整、循环不展开
        - O1: 基本优化已应用但未激进
        - O2: 循环展开痕迹、内联迹象
        - O3: 激进展开 + 向量化痕迹
        - Os: 紧凑代码、无展开、无内联"""
        lines = disassembly.split('\n')
        total_lines = max(len(lines), 1)
        line_lower = [l.lower().strip() for l in lines if l.strip()]

# 提取启发式指标
        # 栈帧密度：push rbp/mov rbp, rsp/sub rsp 等
        stack_frame_lines = sum(
            1 for l in line_lower
            if re.search(r'(push\s+(ebp|rbp))|(mov\s+(ebp|rbp)\,\s*(esp|rsp))|(sub\s+(esp|rsp))', l)
        )
        stack_frame_density = stack_frame_lines / total_lines

        # 冗余移动：连续的 mov reg, reg 且无中间算术操作
        redundant_moves = 0
        prev_was_move = False
        for l in line_lower:
            is_move = bool(re.search(r'^\s*mov\s+\w+\,\s*\w+\s*$', l))
            if is_move and prev_was_move:
                redundant_moves += 1
            prev_was_move = is_move
        redundant_move_density = redundant_moves / total_lines

        # 循环展开痕迹：相同模式的指令块重复出现（简化版：检测重复的 opcode 序列）
        opcodes = [l.split()[0] for l in line_lower if l.split()]
        loop_hint = 0.0
        if len(opcodes) >= 6:
            for window_size in [3, 4]:
                seen: Dict[Tuple[str, ...], int] = {}
                for i in range(len(opcodes) - window_size + 1):
                    pat = tuple(opcodes[i:i + window_size])
                    seen[pat] = seen.get(pat, 0) + 1
                repeats = sum(1 for c in seen.values() if c >= 3)
                loop_hint = max(loop_hint, min(repeats / max(len(seen), 1), 1.0))

        # 内联迹象：多个 ret 或 多个独立的栈帧 setup
        inline_hint = min(
            (sum(1 for l in line_lower if l.strip() == 'ret') + 1) / max(total_lines, 1) * 4.0,
            1.0,
        )

        # 死存储密度：写后未读就被覆盖的 store 模式
        dead_store_hint = 0.0
        for i in range(len(line_lower) - 1):
            curr = line_lower[i]
            next_ = line_lower[i + 1]
            if re.search(r'mov\s+\[', curr) and re.search(r'mov\s+\[', next_):
                dead_store_hint += 1
        dead_store_density = dead_store_hint / total_lines

        observed = {
            'stack_frame_density': stack_frame_density,
            'redundant_moves': redundant_move_density,
            'loop_unroll_hint': loop_hint,
            'inline_hint': inline_hint,
            'dead_store_density': dead_store_density,
        }

# 与优化等级指纹匹配
        best_level = 'unknown'
        best_score = -1.0
        best_rationale: List[str] = []

        for level, indicators in OPT_LEVEL_INDICATORS.items():
            fits = 0
            total_checks = 0
            level_rationale: List[str] = []
            for indicator_name, (lo, hi) in indicators.items():
                val = observed.get(indicator_name, 0)
                total_checks += 1
                if lo <= val <= hi:
                    fits += 1
                    level_rationale.append(
                        f"✓ {indicator_name}: {val:.3f} ∈ [{lo:.2f}, {hi:.2f}]"
                    )
                else:
                    level_rationale.append(
                        f"✗ {indicator_name}: {val:.3f} ∉ [{lo:.2f}, {hi:.2f}]"
                    )

            score = fits / max(total_checks, 1)
            if score > best_score:
                best_score = score
                best_level = level
                best_rationale = level_rationale

        confidence = min(best_score * 1.15, 0.99) if best_score > 0 else 0.0

        return OptimizationProfile(
            level=best_level,
            confidence=round(confidence, 4),
            indicators=observed,
            rationale=best_rationale,
        )

    def batch_classify(
        self,
        functions: Dict[str, str],
    ) -> Dict[str, CompilerSignature]:
        return {
            name: self.classify(disasm)
            for name, disasm in functions.items()
        }

    def majority_vote(
        self,
        results: Dict[str, CompilerSignature],
    ) -> CompilerSignature:
        counter: Counter[str] = Counter()
        total_confidence: Dict[str, float] = defaultdict(float)

        for sig in results.values():
            counter[sig.name] += 1
            total_confidence[sig.name] += sig.confidence

        if not counter:
            return CompilerSignature(name='unknown', confidence=0.0, features={})

        most_common = counter.most_common(1)[0][0]
        avg_confidence = total_confidence[most_common] / counter[most_common]

        all_features: Dict[str, float] = {}
        count = 0
        for sig in results.values():
            if sig.name == most_common:
                for k, v in sig.features.items():
                    all_features[k] = all_features.get(k, 0) + v
                count += 1

        if count > 0:
            all_features = {k: v / count for k, v in all_features.items()}

        return CompilerSignature(
            name=most_common,
            confidence=avg_confidence,
            features=all_features,
            evidence=[
                f"Majority vote: {most_common} ({counter[most_common]}/{len(results)} functions)"
            ],
        )


def create_compiler_classifier() -> CompilerRegisterClassifier:
    return CompilerRegisterClassifier()
