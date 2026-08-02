# 2026-07-21 16:08
# obfuscation_resilience.py
# 混淆韧性模块 — 检测/归一化/绕过常见代码混淆技术
# 依据: "Identifying Obfuscated Code through Graph-Based Semantic Analysis"
#       [Applied Network Science 2025] 对比了GCN/GAT/GIN/SAGE/UNet在混淆检测上的表现
# 核心: 结合语义特征(Pcode IR风格的特征提取)和图结构特征来抵抗混淆

from __future__ import annotations
import re
import math
import hashlib
import logging
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import Counter, defaultdict
from enum import IntEnum, Enum
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 混淆技术枚举 (11类, 与Applied Network Science 2025一致)
# ---------------------------------------------------------------------------

class ObfuscationKind(IntEnum):
    NONE = 0
    CONTROL_FLOW_FLATTENING = 1    # OLLVM -fla
    OPAQUE_PREDICATE = 2           # 不透明谓词插入
    STRING_ENCRYPTION = 3          # 字符串加密
    MBA_EXPRESSION = 4             # 混合布尔算术
    INSTRUCTION_SUBSTITUTION = 5   # 指令替换 (如 x*2 -> x+x)
    BOGUS_CONTROL_FLOW = 6         # 虚假控制流
    CODE_VIRTUALIZATION = 7        # 代码虚拟化 (VMProtect/Themida风格)
    ANTI_DEBUG = 8                 # 反调试
    DEAD_CODE_INSERTION = 9        # 死代码插入
    CONSTANT_OBFUSCATION = 10     # 常量混淆 (如xor-encode立即数)
    METAMORPHIC = 11               # 变形代码 (等同功能不同实现)

    @classmethod
    def names(cls):
        return [k.name for k in cls]


# ---------------------------------------------------------------------------
# 检测结果
# ---------------------------------------------------------------------------

@dataclass
class ObfuscationReport:
    function_name: str
    detected_kinds: Dict[ObfuscationKind, float]  # kind -> confidence
    primary_kind: Optional[ObfuscationKind] = None
    primary_confidence: float = 0.0
    estimated_complexity_increase: float = 1.0
    semantic_features: Dict[str, float] = field(default_factory=dict)
    graph_features: Dict[str, float] = field(default_factory=dict)

    @property
    def is_obfuscated(self) -> bool:
        return self.primary_confidence >= 0.5

    @property
    def resilience_score(self) -> float:
        """韧性分数: 越高越难分析 [0, 10]"""
        if not self.detected_kinds:
            return 0.0
        weights = {
            ObfuscationKind.CODE_VIRTUALIZATION: 10.0,
            ObfuscationKind.METAMORPHIC: 9.0,
            ObfuscationKind.CONTROL_FLOW_FLATTENING: 7.0,
            ObfuscationKind.MBA_EXPRESSION: 6.5,
            ObfuscationKind.OPAQUE_PREDICATE: 5.0,
            ObfuscationKind.BOGUS_CONTROL_FLOW: 4.5,
            ObfuscationKind.INSTRUCTION_SUBSTITUTION: 3.0,
            ObfuscationKind.STRING_ENCRYPTION: 2.5,
            ObfuscationKind.CONSTANT_OBFUSCATION: 2.5,
            ObfuscationKind.DEAD_CODE_INSERTION: 1.5,
            ObfuscationKind.ANTI_DEBUG: 1.0,
        }
        total = 0.0
        for kind, conf in self.detected_kinds.items():
            total += weights.get(kind, 2.0) * conf
        return min(total, 10.0)

    def to_dict(self) -> dict:
        return {
            'function_name': self.function_name,
            'detected_kinds': {k.name: v for k, v in self.detected_kinds.items()},
            'primary_kind': self.primary_kind.name if self.primary_kind else None,
            'primary_confidence': self.primary_confidence,
            'is_obfuscated': self.is_obfuscated,
            'resilience_score': self.resilience_score,
            'complexity_increase': self.estimated_complexity_increase,
        }


# ---------------------------------------------------------------------------
# 混淆特征检测器
# ---------------------------------------------------------------------------

class ObfuscationDetector:
    """多策略混淆检测器

    同时使用指令序列特征和图结构特征进行检测。
    Applied Network Science 2025的关键发现: GNN需要有意义的语义特征才能胜过传统ML。
    因此本实现优先使用Pcode IR风格的归一化语义特征。
    """

    # 控制流平坦化特征: 大量间接跳转 + switch-like分发器模式
    _CFL_PATTERNS = [
        (re.compile(r'jmp\s+\[.*rax|jmp\s+\*(%|r|e)[a-d]x', re.I), 0.85),
        (re.compile(r'indirect\s+jump|switch.*dispatch|jmp\s+QWORD', re.I), 0.70),
    ]

    # 不透明谓词的常见模式
    _OPAQUE_PATTERNS = [
        (re.compile(r'(?:xor|and|or)\s+.*,\s*\1', re.I), 0.60),
        (re.compile(r'mov\s+\w+,\s*0\s*\n.*cmp\s+\w+,\s*0', re.I), 0.50),
        (re.compile(r'(?:add|sub)\s+\w+,\s*1\s*\n.*(?:cmp|test)\s+\w+', re.I), 0.45),
    ]

    # MBA表达式的特征: 大量算术/逻辑操作的复杂组合
    _MBA_PATTERNS = [
        (re.compile(r'(?:xor|and|or|not|neg)\s+\w+,\s*\w+\s*\n\s*(?:xor|and|or|not|neg)\s+\w+,\s*\w+', re.I), 0.65),
        (re.compile(r'(?:add|sub|shl|shr|sar)\s+\w+,\s*0x[0-9a-f]+\s*\n\s*(?:add|sub)\s+\w+,\s*0x[0-9a-f]+', re.I), 0.60),
    ]

    # 字符串加密: 高熵数据 + 重复的解密循环模式
    _STR_ENC_PATTERNS = [
        (re.compile(r'(?:xor|add|sub)\s+\[.*\],\s*0x[0-9a-f]+', re.I), 0.55),
        (re.compile(r'mov\s+\w+,\s*0x[0-9a-f]{8,}', re.I), 0.40),
    ]

    def __init__(self, min_confidence: float = 0.3):
        self.min_confidence = min_confidence

    def analyze(self, pseudo_code: str, disasm: str = "",
                graph_stats: Optional[Dict[str, float]] = None,
                func_name: str = "") -> ObfuscationReport:
        """执行全维度混淆检测"""
        report = ObfuscationReport(function_name=func_name)

        # 1. 指令序列特征
        report.semantic_features = self._extract_semantic_features(pseudo_code, disasm)

        # 2. 图结构特征 (如果提供)
        if graph_stats:
            report.graph_features = graph_stats

        # 3. 逐类型检测
        confidences = {}
        confidences[ObfuscationKind.CONTROL_FLOW_FLATTENING] = self._detect_cfl(pseudo_code, disasm)
        confidences[ObfuscationKind.OPAQUE_PREDICATE] = self._detect_opaque_predicates(pseudo_code)
        confidences[ObfuscationKind.STRING_ENCRYPTION] = self._detect_string_encryption(pseudo_code, disasm)
        confidences[ObfuscationKind.MBA_EXPRESSION] = self._detect_mba(pseudo_code)
        confidences[ObfuscationKind.BOGUS_CONTROL_FLOW] = self._detect_bogus_cf(pseudo_code, graph_stats)
        confidences[ObfuscationKind.INSTRUCTION_SUBSTITUTION] = self._detect_instr_substitution(disasm)
        confidences[ObfuscationKind.DEAD_CODE_INSERTION] = self._detect_dead_code(pseudo_code, graph_stats)
        confidences[ObfuscationKind.CONSTANT_OBFUSCATION] = self._detect_constant_obfuscation(disasm)
        confidences[ObfuscationKind.ANTI_DEBUG] = self._detect_anti_debug(pseudo_code, disasm)
        confidences[ObfuscationKind.CODE_VIRTUALIZATION] = self._detect_virtualization(pseudo_code, disasm)
        confidences[ObfuscationKind.METAMORPHIC] = self._detect_metamorphic(pseudo_code, graph_stats)

        # 过滤低置信度
        report.detected_kinds = {k: v for k, v in confidences.items()
                                 if v >= self.min_confidence}

        if report.detected_kinds:
            best = max(report.detected_kinds, key=lambda k: report.detected_kinds[k])
            report.primary_kind = best
            report.primary_confidence = report.detected_kinds[best]

        report.estimated_complexity_increase = self._estimate_complexity(report)
        return report

    def _extract_semantic_features(self, pseudo: str, disasm: str) -> Dict[str, float]:
        """提取Pcode IR风格的语义特征"""
        combined = pseudo + "\n" + disasm
        lines = combined.split('\n')

        total_ops = max(len(lines), 1)
        jmp_count = sum(1 for l in lines if re.search(r'jmp|j\w+\s|goto', l, re.I))
        call_count = sum(1 for l in lines if re.search(r'call\s', l, re.I))
        indirect_count = sum(1 for l in lines
                            if re.search(r'jmp\s+\[|jmp\s+\*|call\s+\[|call\s+\*', l, re.I))
        logical_count = sum(1 for l in lines
                           if re.search(r'xor|and|or|not|neg|shl|shr|sar|rol|ror', l, re.I))
        arith_count = sum(1 for l in lines
                         if re.search(r'add|sub|mul|div|imul|idiv', l, re.I))

        return {
            'jump_density': jmp_count / total_ops,
            'call_density': call_count / total_ops,
            'indirect_jmp_ratio': indirect_count / max(jmp_count, 1),
            'logical_to_arith': logical_count / max(arith_count, 1),
            'unique_mnemonics': len(set(re.findall(r'\b(mov|xor|add|sub|jmp|call|ret|push|pop|cmp|test|lea|and|or|not|neg|shl|shr|mul|div|nop|int3)\b', combined, re.I))) / 19.0,
        }

    def _detect_cfl(self, pseudo: str, disasm: str) -> float:
        """控制流平坦化检测"""
        combined = pseudo + "\n" + disasm
        score = 0.0
        weight_total = 0.0

        for pattern, weight in self._CFL_PATTERNS:
            matches = pattern.findall(combined)
            if matches:
                score += weight * min(len(matches), 5) / 5.0
                weight_total += weight

        # 检测大型switch-like分发器 (CFL的核心特征)
        switch_vars = re.findall(r'switch\s*\(|case\s+0x[0-9a-f]+:', pseudo, re.I)
        if len(switch_vars) >= 3:
            score += 0.80
            weight_total += 0.80

        if weight_total == 0:
            return 0.0
        return min(score / weight_total, 1.0)

    def _detect_opaque_predicates(self, code: str) -> float:
        score = 0.0
        total_w = 0.0
        for pattern, weight in self._OPAQUE_PATTERNS:
            if pattern.search(code):
                score += weight
                total_w += weight
        return score / max(total_w, 1.0) if total_w > 0 else 0.0

    def _detect_string_encryption(self, pseudo: str, disasm: str) -> float:
        """字符串加密检测 — 高熵数据段和解密循环"""
        combined = pseudo + "\n" + disasm
        score = 0.0

        for pattern, weight in self._STR_ENC_PATTERNS:
            if pattern.search(combined):
                score += weight

        # 检查是否存在xor解密循环特征
        xor_loops = re.findall(r'(?:loop|while|for).*xor.*byte', combined, re.I)
        if xor_loops:
            score += 0.30

        return min(score, 1.0)

    def _detect_mba(self, code: str) -> float:
        score = 0.0
        total_w = 0.0
        for pattern, weight in self._MBA_PATTERNS:
            if pattern.search(code):
                score += weight
                total_w += weight

        # 连续逻辑指令密度
        logical_density = len(re.findall(r'(?:xor|and|or|not|neg)\s+\w+,\s*\w+', code, re.I))
        if logical_density >= 8:
            score += 0.35

        return min(score / max(total_w, 1.0), 1.0) if total_w > 0 else 0.0

    def _detect_bogus_cf(self, code: str, graph_stats=None) -> float:
        score = 0.0
        if graph_stats:
            # 虚假控制流会增加大量不可达或不执行的基本块
            # 高节点数/低平均度的图可能是虚假CF的结果
            avg_degree = graph_stats.get('avg_degree', 0)
            cyclomatic = graph_stats.get('cyclomatic_complexity', 0)
            if avg_degree < 1.5 and cyclomatic > 20:
                score += 0.55
            elif cyclomatic > 15:
                score += 0.30

        # 检测不可达代码模式
        dead_blocks = len(re.findall(r'(?:unreachable|dead\s*code|bogus)', code, re.I))
        score += min(dead_blocks * 0.15, 0.40)

        return min(score, 1.0)

    def _detect_instr_substitution(self, disasm: str) -> float:
        """指令替换检测 — 常见替换模式"""
        subs = [
            (r'lea\s+\w+,\s*\[\w+\s*\*\s*2\]', r'(?:shl|add\s+\w+,\s*\w+)'),  # x*2
            (r'lea\s+\w+,\s*\[\w+\s*\*\s*4\]', r'(?:shl\s+\w+,\s*2)'),
            (r'xor\s+\w+,\s*\w+', r'mov\s+\w+,\s*0'),  # xor self -> mov 0
        ]
        scored = 0
        for orig, repl in subs:
            if re.search(repl, disasm, re.I) and not re.search(orig, disasm, re.I):
                scored += 1
        return min(scored / 3.0, 1.0)

    def _detect_dead_code(self, code: str, graph_stats=None) -> float:
        score = 0.0
        # nop序列
        nop_chains = len(re.findall(r'(?:nop\s*\n\s*){3,}', code, re.I))
        score += min(nop_chains * 0.20, 0.50)

        # 写入但永不读取的变量 (近似)
        dead_stores = len(re.findall(r'mov\s+\w+,\s*\w+\s*\n(?!.*\1)', code, re.I))
        score += min(dead_stores * 0.05, 0.30)

        if graph_stats:
            # 高比例的叶节点 (出度为0的非返回节点)
            leaf_ratio = graph_stats.get('leaf_ratio', 0)
            if leaf_ratio > 0.3:
                score += 0.25

        return min(score, 1.0)

    def _detect_constant_obfuscation(self, disasm: str) -> float:
        """常量混淆 — 立即数的xor/add/sub链"""
        xor_imm_chains = re.findall(
            r'(?:xor|add|sub)\s+\w+,\s*0x([0-9a-f]+)\s*\n\s*(?:xor|add|sub)\s+\w+,\s*0x([0-9a-f]+)',
            disasm, re.I)
        score = min(len(xor_imm_chains) * 0.25, 0.80)

        # 高位立即数 (大于16位) 频繁出现
        high_consts = len(re.findall(r'0x[0-9a-f]{5,}', disasm, re.I))
        if high_consts >= 5:
            score += 0.20

        return min(score, 1.0)

    def _detect_anti_debug(self, pseudo: str, disasm: str) -> float:
        combined = pseudo + "\n" + disasm
        indicators = [
            (r'isDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess', 0.90),
            (r'int\s*3|int3|__debugbreak', 0.60),
            (r'(?:rdtsc|cpuid).*\n.*(?:cmp|test|sub)', 0.50),
            (r'PEB|BeingDebugged|NtGlobalFlag', 0.75),
            (r'OutputDebugString|DbgBreakPoint|DebugActiveProcess', 0.85),
        ]
        score = 0.0
        for pattern, weight in indicators:
            if re.search(pattern, combined, re.I):
                score = max(score, weight)
        return score

    def _detect_virtualization(self, pseudo: str, disasm: str) -> float:
        """代码虚拟化检测 — VM入口/调度器模式"""
        combined = pseudo + "\n" + disasm
        score = 0.0

        # VM调度器: 大型switch-case + 间接跳转 + 寄存器上下文保存/恢复
        has_dispatch = bool(re.search(r'switch.*case|jmp\s+\*|indirect\s+jump', combined, re.I))
        has_context_save = len(re.findall(r'pusha|pushad|push\s+(?:r|e)?[a-d]x.*push\s+(?:r|e)?[a-d]x.*push\s+(?:r|e)?[a-d]x', combined, re.I)) >= 1
        has_vm_loop = bool(re.search(r'(?:while|loop).*(?:dispatch|decode|handler)', combined, re.I))

        if has_dispatch:
            score += 0.30
        if has_context_save:
            score += 0.30
        if has_vm_loop:
            score += 0.40

        # VMProtect/Themida特征字符串
        vm_signatures = ['VMProtect', 'vmp_begin', 'vmp_end', 'themida', 'enigma', 'code_virtualization']
        for sig in vm_signatures:
            if sig.lower() in combined.lower():
                score = max(score, 0.95)

        return min(score, 1.0)

    def _detect_metamorphic(self, code: str, graph_stats=None) -> float:
        """变形代码检测 — 功能等价的多样化实现"""
        score = 0.0

        # 相同功能的不同指令模式 (如: 多种清零方式)
        zero_methods = len(re.findall(r'(?:xor\s+\w+,\s*\w+|mov\s+\w+,\s*0|sub\s+\w+,\s*\w+|and\s+\w+,\s*0|lea\s+\w+,\s*\[0\])',
                                       code, re.I))
        if zero_methods >= 3:
            score += 0.40

        # 高指令种类密度 (变形代码使用大量不同的等效模式)
        mnemonics = set(re.findall(r'\b(mov|xor|add|sub|shl|shr|and|or|not|neg|mul|imul|div|idiv|lea|xchg|bswap|test|cmp)\b',
                                    code, re.I))
        if len(mnemonics) >= 10:
            score += 0.30

        if graph_stats:
            # 变形代码: 功能相同但图结构可能不同; 高cyclomatic但低语义变化
            cyclomatic = graph_stats.get('cyclomatic_complexity', 0)
            node_count = graph_stats.get('node_count', 0)
            if cyclomatic > 15 and node_count < 5:
                score += 0.30

        return min(score, 1.0)

    def _estimate_complexity(self, report: ObfuscationReport) -> float:
        """估算混淆导致的分析复杂度增长倍数"""
        factor = 1.0
        multipliers = {
            ObfuscationKind.CODE_VIRTUALIZATION: 8.0,
            ObfuscationKind.CONTROL_FLOW_FLATTENING: 4.0,
            ObfuscationKind.MBA_EXPRESSION: 3.0,
            ObfuscationKind.OPAQUE_PREDICATE: 2.5,
            ObfuscationKind.METAMORPHIC: 3.5,
            ObfuscationKind.STRING_ENCRYPTION: 1.5,
            ObfuscationKind.BOGUS_CONTROL_FLOW: 1.8,
            ObfuscationKind.INSTRUCTION_SUBSTITUTION: 1.3,
            ObfuscationKind.CONSTANT_OBFUSCATION: 1.2,
            ObfuscationKind.DEAD_CODE_INSERTION: 1.1,
            ObfuscationKind.ANTI_DEBUG: 1.05,
        }
        for kind, conf in report.detected_kinds.items():
            factor *= 1.0 + (multipliers.get(kind, 1.0) - 1.0) * conf
        return factor


# ---------------------------------------------------------------------------
# 混淆归一化器
# ---------------------------------------------------------------------------

class ObfuscationNormalizer:
    """混淆归一化 — 尝试将混淆代码还原为可分析形式

    不是完整的反混淆器, 而是进行轻量级归一化以改善下游分析:
      1. 指令标准化 (移除 立即数 -> <IMM>, 地址 -> <ADDR>)
      2. NOP移除
      3. 死代码标记
      4. 控制流简化提示生成
    """

    def __init__(self):
        self.op_re = re.compile(
            r'\b(mov|lea|xor|add|sub|and|or|not|neg|shl|shr|sar|rol|ror|mul|imul|div|idiv|jmp|je|jne|jg|jl|jge|jle|jb|ja|jbe|jae|jz|jnz|call|ret|push|pop|cmp|test|xchg|bswap|nop|int3|syscall|int)\b',
            re.I)

    def normalize(self, disasm: str) -> str:
        """归一化汇编代码"""
        lines = disasm.split('\n')
        normalized = []

        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith(';') or stripped.startswith('#'):
                normalized.append(stripped)
                continue

            # 移除NOP
            if re.match(r'^\s*nop\b', stripped, re.I):
                continue

            # 归一化立即数
            cleaned = re.sub(r'0x[0-9a-fA-F]+', '<IMM>', stripped)
            # 归一化内存地址
            cleaned = re.sub(r'\[0x[0-9a-fA-F]+\]', '[<ADDR>]', cleaned)
            cleaned = re.sub(r'\[(?:rip|eip)\s*[+\-]\s*0x[0-9a-fA-F]+\]', '[<RIPREL>]', cleaned, flags=re.I)
            # 归一化偏移
            cleaned = re.sub(r'\+0x[0-9a-fA-F]+', '+<OFF>', cleaned)
            cleaned = re.sub(r'-0x[0-9a-fA-F]+', '-<OFF>', cleaned)

            normalized.append(cleaned)

        return '\n'.join(normalized)

    def extract_semantic_skeleton(self, disasm: str) -> str:
        """提取语义骨架: 只保留操作码和操作数类型, 去掉具体值"""
        lines = disasm.split('\n')
        skeleton = []

        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue

            # 提取操作码
            m = self.op_re.search(stripped)
            if not m:
                continue

            opcode = m.group(1).lower()

            # 统计操作数
            operands = stripped[m.end():]
            op_count = len([o for o in operands.split(',') if o.strip()])

            skeleton.append(f"{opcode}({op_count})")

        return ' '.join(skeleton)


# ---------------------------------------------------------------------------
# 工厂函数
# ---------------------------------------------------------------------------

def create_obfuscation_detector(min_confidence: float = 0.3) -> ObfuscationDetector:
    return ObfuscationDetector(min_confidence=min_confidence)


def detect_obfuscation(pseudo_code: str, disasm: str = "",
                       graph_stats: Optional[Dict] = None,
                       func_name: str = "") -> ObfuscationReport:
    det = ObfuscationDetector()
    return det.analyze(pseudo_code, disasm, graph_stats, func_name)
