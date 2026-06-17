import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class CFIStatus(Enum):
    ENABLED = "enabled"
    PARTIAL = "partial"
    DISABLED = "disabled"
    UNKNOWN = "unknown"


class CFIType(Enum):
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
            'description': self.description
        }


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
            'description': self.description
        }


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
            'recommendations': self.recommendations
        }


class CFIIntegrityAnalyzer:
    
    def __init__(self):
        self.cfi_patterns = {
            CFIType.CLANG_CFI: [
                r'__cfi_check',
                r'__cfi_slowpath',
                r'__cfi_fastpath',
                r'clang.*cfi',
                r'CFI.*enabled'
            ],
            CFIType.KCFI: [
                r'kcfi_check',
                r'__kcfi',
                r'kernel_cfi',
                r'KCFI.*enabled'
            ],
            CFIType.MSVC_CFI: [
                r'__guard_check_icall',
                r'__guard_',
                r'CFG.*enabled',
                r'msvc.*cfi'
            ],
            CFIType.SPECTRE_CFI: [
                r'spectre',
                r'SPECTRE_V2',
                r'IBRS',
                r'IBPB'
            ]
        }
        
        self.shadow_stack_patterns = [
            r'shadow_stack',
            r'__shadow_stack',
            r'SHADOW_STACK',
            r'SSP'
        ]
    
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
                cfi_protection = CFIProtection()
                    protection_type=cfi_type,
                    status=CFIStatus.ENABLED if matches >= 2 else CFIStatus.PARTIAL,
                    bypassable=self._is_bypassable(cfi_type),
                    confidence=matches / len(patterns),
                    description=self._get_description(cfi_type)
                
                cfi_protections.append(cfi_protection)
        
        for pattern in self.shadow_stack_patterns:
            if pattern.lower() in strings.lower():
                shadow_stack_enabled = True
                break
        
        violations = self._detect_violations(binary_info)
        
        integrity_score = self._calculate_score(cfi_protections, violations, shadow_stack_enabled)
        recommendations = self._generate_recommendations(cfi_protections, violations)
        
        return CFIIntegrityResult(
            cfi_protections=cfi_protections,
            violations=violations,
            shadow_stack_enabled=shadow_stack_enabled,
            integrity_score=integrity_score,
            recommendations=recommendations)
        

    
    def _is_bypassable(self, cfi_type: CFIType) -> bool:
        bypassable_types = [CFIType.CLANG_CFI, CFIType.MSVC_CFI]
        return cfi_type in bypassable_types
    
    def _get_description(self, cfi_type: CFIType) -> str:
        descriptions = {
            CFIType.CLANG_CFI: 'Clang CFI - 基于 LLVM 的控制流完整性保护',
            CFIType.KCFI: 'kCFI - 内核控制流完整性保护',
            CFIType.MSVC_CFI: 'MSVC CFI - Microsoft Visual Studio CFI 保护',
            CFIType.SPECTRE_CFI: 'Spectre CFI - Spectre 漏洞缓解措施'
        }
        return descriptions.get(cfi_type, '未知 CFI 类型')
    
    def _detect_violations(self, binary_info: Dict[str, Any]) -> List[CFIViolation]:
        violations = []
        
        if binary_info.get('has_jump_table'):
            violations.append(CFIViolation(
                violation_type='indirect_jump',
                address=0,
                expected_target=0,
                actual_target=0,
                severity='medium',
                description='检测到间接跳转表，可能绕过 CFI'
            

        
        if binary_info.get('has_function_pointer'):
            violations.append(CFIViolation(
                violation_type='function_pointer',
                address=0,
                expected_target=0,
                actual_target=0,
                severity='high',
                description='检测到函数指针，可能被利用绕过 CFI'
            

        
        return violations
    
    def _calculate_score(self, protections: List[CFIProtection], violations: List[CFIViolation], shadow_stack: bool) -> int:
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
        
        return max(0, min(100, score

    
    def _generate_recommendations(self, protections: List[CFIProtection], violations: List[CFIViolation]) -> List[str]:
        recommendations = []
        
        clang_cfi = [p for p in protections if p.protection_type == CFIType.CLANG_CFI]
        if not clang_cfi:
            recommendations.append("建议启用 Clang CFI 保护")
        
        if violations:
            recommendations.append("检测到 CFI 绕过风险，建议进行安全审查")
        
        return recommendations


def analyze_cfi_integrity(binary_info: Dict[str, Any]) -> CFIIntegrityResult:
    analyzer = CFIIntegrityAnalyzer()
    return analyzer.analyze(binary_info)))))))