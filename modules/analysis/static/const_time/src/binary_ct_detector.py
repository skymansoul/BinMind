# 编译器模式数据库: GCC/Clang/MSVC 的已知优化模式, 用于假阳性抑制
# 秘密依赖度评分: 从二值 (CT-violation/not) 升级为连续值 [0,1]
# 二进制级常量时间违规检测 - 编译器感知的侧信道分析.

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple


# 编译器模式, 用于假阳性抑制

# 编译器生成的"伪 CT 违规"模式, 这些是编译器优化产生的
# 非秘密依赖的分支/访存, 不应标记为侧信道
_COMPILER_CT_SAFE_PATTERNS = {
    # GCC
    'GCC': [
        # cmov 类, 常量时间条件移动, 非分支
        (r'cmov(?:ne|e|a|ae|b|be|g|ge|l|le|s|ns|o|no|p|np)\s', 'cmov'),
        # setcc 类, 条件设置, 结果可用于常量时间 select
        (r'set(?:ne|e|a|ae|b|be|g|ge|l|le)\s', 'setcc'),
        # endbr64, Intel CET, 非秘密依赖
        (r'endbr64', 'cet'),
    ],
    # Clang
    'Clang': [
        (r'cmov(?:ne|e|a|ae|b|be|g|ge|l|le|s|ns|o|no|p|np)\s', 'cmov'),
        (r'set(?:ne|e|a|ae|b|be|g|ge|l|le)\s', 'setcc'),
        # ud2, Clang unreachable 标记
        (r'ud2', 'unreachable'),
    ],
    # MSVC
    'MSVC': [
        (r'cmov(?:ne|e|a|ae|b|be|g|ge|l|le)\s', 'cmov'),
# security_check_cookie, 栈保护, 非秘密依赖
        (r'__security_check_cookie', 'stack_guard'),
        (r'int\s*3', 'debug_break'),
    ],
}


# 编译器可能引入的 CT 违规模式, 这些需要注意
_COMPILER_CT_RISK_PATTERNS = {
    'GCC': [
        # if-conversion 回退, 当 cmov 不可用时使用分支
        # 模式: cmp/test + jcc + mov 的两条路径 (无 cmov)
        (r'(?:cmp|test)\s.*\n\s*(?:j(?:ne|e|a|ae|b|be|g|ge|l|le))\s',
         'if_conversion_fallback'),
    ],
    'Clang': [
        # select 回退, Clang 的 ?: 在某些条件下生成分支
        (r'(?:cmp|test)\s.*\n\s*(?:j(?:ne|e))\s.*\n\s*mov\s',
         'select_fallback'),
    ],
    'MSVC': [
        # MSVC 对某些模式不支持 cmov, 总是使用分支
        (r'(?:cmp|test)\s.*\n\s*(?:j(?:ne|e))\s.*\n\s*(?:mov|lea)\s',
         'msvc_branch_select'),
    ],
}


# 侧信道违规数据结构

class CTViolationType(Enum):
    SECRET_DEPENDENT_BRANCH = auto()    # 秘密值影响分支方向
    SECRET_DEPENDENT_LOAD = auto()      # 秘密值影响加载地址
    SECRET_DEPENDENT_STORE = auto()     # 秘密值影响存储地址
    SECRET_DEPENDENT_EXEC_TIME = auto() # 秘密值影响执行时间 (div, variable-shift)


@dataclass
class CTViolation:
    """单个 CT 违规的详细信息"""
    violation_type: CTViolationType
    address: int
    instruction_text: str
    confidence: float                    # [0,1] - 1=确认违规, <1=可能
    # 秘密信息
    secret_dependency: str = ''          # 哪个秘密变量
    dependency_distance: int = 0         # 离秘密源的指令距离
    # 编译器信息
    detected_compiler: str = 'unknown'
    compiler_pattern_match: str = ''     # 匹配的编译器模式 (假阳性抑制用)
    is_likely_false_positive: bool = False
    # 利用评估
    exploitability_score: float = 0.0    # [0,1] 被利用的难度
    estimated_leakage_bits: float = 0.0  # 每次执行可能泄漏的 bit 数


@dataclass
class CTDetectionReport:
    """二进制 CT 检测的完整报告"""
    function_name: str
    total_instructions: int
    total_violations: int
    violations: List[CTViolation]
    # 编译器信息
    detected_compiler: str
    false_positives_suppressed: int
    # 评分
    ct_safety_score: float              # [0,1] - 1=完全常量时间, 0=严重泄漏
    worst_leakage: float                # 最大泄漏 bit 数


# 检测器

class BinaryCTDetector:
    """二进制级常量时间违规检测器

    用法:
    detector = BinaryCTDetector()
    report = detector.detect(
        instructions=[(0x401000, 'cmp rax, 0', {'secret_dep': True}), ...],
        secret_vars={'rax'},
        compiler_hint='auto',  # auto | GCC | Clang | MSVC
    )
    """

    def __init__(self):
        # 秘密依赖寄存器集合, 动态更新
        self._secret_regs: Set[str] = set()
        self._violations: List[CTViolation] = []
        self._fp_suppressed = 0
        self._detected_compiler = 'unknown'

    def detect(
        self,
        instructions: List[Tuple[int, str, Dict[str, Any]]],
        secret_vars: Optional[Set[str]] = None,
        compiler_hint: str = 'auto',
        function_name: str = '',
    ) -> CTDetectionReport:
        """检测二进制指令序列中的 CT 违规

        instructions: [(address, disasm, metadata), ...]
           metadata: {'secret_dep': bool, 'regs_read': [...], 'regs_written': [...]}
        secret_vars: 初始秘密变量集合 (函数参数或全局变量)
        compiler_hint: 编译器提示, 若 'auto' 则自动检测
        """
        self._secret_regs = secret_vars or set()
        self._violations = []
        self._fp_suppressed = 0

        # 自动检测编译器
        if compiler_hint == 'auto':
            self._detected_compiler = self._detect_compiler(instructions)
        else:
            self._detected_compiler = compiler_hint

        safe_patterns = _COMPILER_CT_SAFE_PATTERNS.get(
            self._detected_compiler, []
        )
        risk_patterns = _COMPILER_CT_RISK_PATTERNS.get(
            self._detected_compiler, []
        )

        for addr, text, meta in instructions:
            # 更新秘密寄存器集合, 从数据流
            regs_written = meta.get('regs_written', [])
            regs_read = meta.get('regs_read', [])

            # 若读取了秘密寄存器 -> 写入的寄存器也变为秘密
            any_secret_read = any(
                r.lower() in self._secret_regs for r in regs_read
            )
            if any_secret_read:
                for w in regs_written:
                    self._secret_regs.add(w.lower())

            # 检测 CT 违规
            violation = self._check_instruction(
                addr, text, any_secret_read,
                safe_patterns, risk_patterns,
            )
            if violation:
                self._violations.append(violation)

        # 计算评分
        ct_score = self._compute_ct_score(len(instructions))

        return CTDetectionReport(
            function_name=function_name,
            total_instructions=len(instructions),
            total_violations=len(self._violations),
            violations=sorted(self._violations, key=lambda v: -v.confidence),
            detected_compiler=self._detected_compiler,
            false_positives_suppressed=self._fp_suppressed,
            ct_safety_score=round(ct_score, 4),
            worst_leakage=max(
                (v.estimated_leakage_bits for v in self._violations),
                default=0.0,
            ),
        )

    def _check_instruction(
        self,
        addr: int,
        text: str,
        is_secret_dependent: bool,
        safe_patterns: List[Tuple[str, str]],
        risk_patterns: List[Tuple[str, str]],
    ) -> Optional[CTViolation]:
        """检查单条指令是否为 CT 违规"""
        if not is_secret_dependent:
            return None

        text_lower = text.lower().strip()
        parts = text_lower.split()
        if not parts:
            return None
        mnemonic = parts[0]

        # 检查编译器安全模式 (假阳性抑制)
        for pattern, pattern_name in safe_patterns:
            if re.search(pattern, text_lower):
                self._fp_suppressed += 1
                return None  # 编译器优化, 抑制假阳性

        # 检查编译器风险模式
        compiler_risk = ''
        for pattern, pattern_name in risk_patterns:
            if re.search(pattern, text_lower):
                compiler_risk = pattern_name
                break

        # 检测: 秘密依赖的条件分支
        if mnemonic.startswith('j') and mnemonic not in ('jmp',):
            leakage = self._estimate_branch_leakage(text_lower)
            return CTViolation(
                violation_type=CTViolationType.SECRET_DEPENDENT_BRANCH,
                address=addr, instruction_text=text,
                confidence=0.90 if not compiler_risk else 0.65,
                estimated_leakage_bits=leakage,
                exploitability_score=0.7 if leakage > 0.5 else 0.3,
                compiler_pattern_match=compiler_risk,
                detected_compiler=self._detected_compiler,
            )

        # 检测: 秘密依赖的内存加载
        if mnemonic in ('mov', 'lea') and '[' in text_lower:
            # 加载地址取决于秘密 -> cache 侧信道
            leakage = 0.5  # 每字节地址空间的信息
            return CTViolation(
                violation_type=CTViolationType.SECRET_DEPENDENT_LOAD,
                address=addr, instruction_text=text,
                confidence=0.80,
                estimated_leakage_bits=leakage,
                exploitability_score=0.5,
                detected_compiler=self._detected_compiler,
            )

        # 检测: 秘密依赖的执行时间变化 (div, variable shift)
        if mnemonic in ('div', 'idiv'):
            return CTViolation(
                violation_type=CTViolationType.SECRET_DEPENDENT_EXEC_TIME,
                address=addr, instruction_text=text,
                confidence=0.85,
                estimated_leakage_bits=3.0,  # div 延迟可泄漏多个 bit
                exploitability_score=0.4,
                detected_compiler=self._detected_compiler,
            )

        return None

    def _estimate_branch_leakage(self, text: str) -> float:
        """估算条件分支的潜在信息泄漏量 (bit)"""
        # 直接比较, 泄漏 1 bit (条件成立/不成立)
        if any(op in text for op in ('je', 'jne', 'jz', 'jnz')):
            return 1.0
        # 大小比较, 泄漏 > 1 bit (结合多次执行可推断值)
        if any(op in text for op in ('jb', 'jae', 'ja', 'jbe', 'jl', 'jge', 'jg', 'jle')):
            return 2.0
        return 0.5

    def _compute_ct_score(self, total_insns: int) -> float:
        """计算整体 CT 安全评分, 违规越少/置信度越低 -> 评分越高"""
        if not self._violations:
            return 1.0

        total_penalty = sum(
            v.confidence * v.estimated_leakage_bits
            for v in self._violations
        )
        # 归一化: 每 100 条指令 max_penalty ≈ 100
        normalized = total_penalty / max(1, total_insns / 100)
        return max(0.0, 1.0 - normalized)

    @staticmethod
    def _detect_compiler(
        instructions: List[Tuple[int, str, Dict[str, Any]]],
    ) -> str:
        """从指令模式检测编译器"""
        text = '\n'.join(
            t for _, t, _ in instructions[:200]  # 前 200 条足够
        ).lower()

        scores = {'GCC': 0, 'Clang': 0, 'MSVC': 0}
        if 'endbr64' in text:
            scores['GCC'] += 2
        if 'ud2' in text:
            scores['Clang'] += 2
        if '__security_cookie' in text or 'int3' in text:
            scores['MSVC'] += 2
        if 'xor' in text and 'mov' in text:
            scores['GCC'] += 1    # GCC 偏好 xor 清零
        if 'mov' in text and 'xor' not in text[:500]:
            scores['Clang'] += 1  # Clang 偏好 mov 清零

        best = max(scores, key=scores.get)
        if scores[best] == 0:
            return 'unknown'
        return best
