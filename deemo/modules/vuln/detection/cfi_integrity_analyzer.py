# CFI完整性分析器-从二进制字符串检测CFI保护机制的存在性与完整性。
# 支持Clang CFI/kCFI/MSVC CFG/Spectre缓解四种CFI类型。
# 完整性评分：基础50pt + 每项启用CFI +15pt + 影子栈 +10pt - 每项violation扣分。

import logging
from enum import Enum
from typing import Dict, List, Any
from dataclasses import dataclass, field


logger = logging.getLogger(__name__)


class CFIStatus(str, Enum):
    ENABLED = "enabled"
    PARTIAL = "partial"
    DISABLED = "disabled"
    UNKNOWN = "unknown"


class CFIType(str, Enum):
    CLANG_CFI = "clang_cfi"
    KCFI = "kcfi"
    MSVC_CFI = "msvc_cfi"
    SPECTRE_CFI = "spectre_cfi"


@dataclass
class CFIProtection:
    protection_type: CFIType
    status: CFIStatus
    bypassable: bool
    confidence: float
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            'protection_type': self.protection_type.value,
            'status': self.status.value,
            'bypassable': self.bypassable,
            'confidence': self.confidence,
            'description': self.description}


@dataclass
class CFIViolation:
    violation_type: str
    address: int
    expected_target: int
    actual_target: int
    severity: str
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            'violation_type': self.violation_type,
            'address': hex(self.address),
            'expected_target': hex(self.expected_target),
            'actual_target': hex(self.actual_target),
            'severity': self.severity,
            'description': self.description}


@dataclass
class CFIIntegrityResult:
    cfi_protections: List[CFIProtection]
    violations: List[CFIViolation]
    shadow_stack_enabled: bool
    integrity_score: int
    recommendations: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'cfi_protections': [p.to_dict() for p in self.cfi_protections],
            'violations': [v.to_dict() for v in self.violations],
            'shadow_stack_enabled': self.shadow_stack_enabled,
            'integrity_score': self.integrity_score,
            'recommendations': self.recommendations}


class CFIIntegrityAnalyzer:
    """检测二进制中的CFI保护机制-特征字符串匹配识别四种CFI类型。
    Clang CFI与MSVC CFG判定为可绕过-两者均存在公开绕过技术。"""

    def __init__(self):
        self.cfi_patterns = {
            CFIType.CLANG_CFI: [
                r'__cfi_check', r'__cfi_slowpath', r'__cfi_fastpath',
                r'clang.*cfi', r'CFI.*enabled'],
            CFIType.KCFI: [
                r'kcfi_check', r'__kcfi', r'kernel_cfi', r'KCFI.*enabled'],
            CFIType.MSVC_CFI: [
                r'__guard_check_icall', r'__guard_', r'CFG.*enabled', r'msvc.*cfi'],
            CFIType.SPECTRE_CFI: [
                r'spectre', r'SPECTRE_V2', r'IBRS', r'IBPB']}

        self.shadow_stack_patterns = [
            r'shadow_stack', r'__shadow_stack', r'SHADOW_STACK', r'SSP']

    def analyze(self, binary_info: Dict[str, Any]) -> CFIIntegrityResult:
        cfi_protections = []
        violations = []
        shadow_stack_enabled = False
        strings = binary_info.get('strings', '')

        for cfi_type, patterns in self.cfi_patterns.items():
            detected = False
            matches = 0
            for pattern in patterns:
                if pattern.lower() in strings.lower():
                    matches += 1
                    detected = True
            if detected:
                cfi_protection = CFIProtection(
                    protection_type=cfi_type,
                    status=CFIStatus.ENABLED if matches >= 2 else CFIStatus.PARTIAL,
                    bypassable=self._is_bypassable(cfi_type),
                    confidence=matches / len(patterns),
                    description=self._fetch_description(cfi_type))
                cfi_protections.append(cfi_protection)

        for pattern in self.shadow_stack_patterns:
            if pattern.lower() in strings.lower():
                shadow_stack_enabled = True
                break

        violations = self._detect_violations(binary_info)
        integrity_score = self._calculate_score(
            cfi_protections, violations, shadow_stack_enabled)
        recommendations = self._generate_recommendations(cfi_protections, violations)
        return CFIIntegrityResult(
            cfi_protections=cfi_protections, violations=violations,
            shadow_stack_enabled=shadow_stack_enabled,
            integrity_score=integrity_score, recommendations=recommendations)

    def _is_bypassable(self, cfi_type: CFIType) -> bool:
        return cfi_type in (CFIType.CLANG_CFI, CFIType.MSVC_CFI)

    def _fetch_description(self, cfi_type: CFIType) -> str:
        descriptions = {
            CFIType.CLANG_CFI: 'Clang CFI - LLVM-based control flow integrity protection',
            CFIType.KCFI: 'kCFI - Kernel control flow integrity protection',
            CFIType.MSVC_CFI: 'MSVC CFI - Microsoft Visual Studio CFI protection',
            CFIType.SPECTRE_CFI: 'Spectre CFI - Spectre vulnerability mitigation'}
        return descriptions.get(cfi_type, 'Unknown CFI type')

    def _detect_violations(self, binary_info: Dict[str, Any]) -> List[CFIViolation]:
        violations = []
        if binary_info.get('has_jump_table'):
            violations.append(CFIViolation(
                violation_type='indirect_jump', address=0,
                expected_target=0, actual_target=0, severity='medium',
                description='Indirect jump table detected, may bypass CFI'))
        if binary_info.get('has_function_pointer'):
            violations.append(CFIViolation(
                violation_type='function_pointer', address=0,
                expected_target=0, actual_target=0, severity='high',
                description='Function pointer detected, may be exploited to bypass CFI'))
        return violations

    def _calculate_score(self, protections: List[CFIProtection],
                           violations: List[CFIViolation],
                           shadow_stack: bool) -> int:
        score = 50
        for protection in protections:
            if protection.status == CFIStatus.ENABLED:
                score += 15
            elif protection.status == CFIStatus.PARTIAL:
                score += 5
        if shadow_stack:
            score += 10
        for violation in violations:
            if violation.severity == 'high':
                score -= 20
            elif violation.severity == 'medium':
                score -= 10
        return max(0, min(100, score))

    def _generate_recommendations(self, protections: List[CFIProtection],
                                    violations: List[CFIViolation]) -> List[str]:
        recommendations = []
        clang_cfi = [p for p in protections if p.protection_type == CFIType.CLANG_CFI]
        if not clang_cfi:
            recommendations.append("Consider enabling Clang CFI protection")
        if violations:
            recommendations.append("CFI bypass risk detected, security review recommended")
        return recommendations


def analyze_cfi_integrity(binary_info: Dict[str, Any]) -> CFIIntegrityResult:
    analyzer = CFIIntegrityAnalyzer()
    return analyzer.analyze(binary_info)


def _debug_print(*a, **kw):
    if __import__("os").environ.get("BINMIND_DEBUG"):
        print(*a, **kw)

