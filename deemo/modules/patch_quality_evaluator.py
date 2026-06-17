import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class PatchStatus(Enum):
    FULLY_FIXED = "fully_fixed"
    PARTIALLY_FIXED = "partially_fixed"
    NOT_FIXED = "not_fixed"
    INTRODUCED_REGRESSION = "introduced_regression"


class BypassRisk(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


@dataclass
class PatchAssessment:
    patch_id: str
    status: PatchStatus
    bypass_risk: BypassRisk
    vulnerabilities_fixed: List[str]
    vulnerabilities_introduced: List[str]
    code_changes: List[Dict[str, Any]]
    bypass_scenarios: List[str]
    confidence: float
    recommendations: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'patch_id': self.patch_id,
            'status': self.status.value,
            'bypass_risk': self.bypass_risk.value,
            'vulnerabilities_fixed': self.vulnerabilities_fixed,
            'vulnerabilities_introduced': self.vulnerabilities_introduced,
            'code_changes': self.code_changes,
            'bypass_scenarios': self.bypass_scenarios,
            'confidence': self.confidence,
            'recommendations': self.recommendations
        }


class PatchQualityEvaluator:
    
    def __init__(self):
        self.bypass_patterns = [
            (r'bounds check.*<.*max', '边界检查使用了小于而不是小于等于'),
            (r'input.*length.*check', '长度检查可能被绕过'),
            (r'strncpy.*sizeof', '使用 sizeof 而不是实际缓冲区大小'),
            (r'memcpy.*without.*length', 'memcpy 缺少长度检查'),
            (r'input.*validation.*only.*once', '输入验证只进行一次'),
            (r'canary.*check.*after.*use', 'canary 检查在使用之后'),
            (r'null.*check.*after.*deref', '空指针检查在解引用之后'),
            (r'security.*check.*bypassed', '安全检查被绕过'),
            (r'privilege.*check.*skipped', '权限检查被跳过')
        ]
        
        self.fix_patterns = [
            (r'add.*bounds.*check', '添加了边界检查'),
            (r'replace.*strcpy.*strncpy', '用 strncpy 替换了 strcpy'),
            (r'add.*null.*check', '添加了空指针检查'),
            (r'add.*canary', '添加了 canary 保护'),
            (r'add.*permission.*check', '添加了权限检查'),
            (r'fix.*memory.*leak', '修复了内存泄漏'),
            (r'remove.*unsafe.*code', '移除了不安全代码'),
            (r'secure.*crypto.*usage', '修复了加密使用')
        ]
    
    def evaluate(self, patch_data: Dict[str, Any]) -> PatchAssessment:
        status = PatchStatus.NOT_FIXED
        bypass_risk = BypassRisk.NONE
        vulnerabilities_fixed = []
        vulnerabilities_introduced = []
        bypass_scenarios = []
        recommendations = []
        confidence = 0.7
        
        code_changes = patch_data.get('code_changes', [])
        
        for change in code_changes:
            if self._contains_fix_pattern(change):
                vulnerabilities_fixed.append(self._extract_vuln_id(change

                status = PatchStatus.FULLY_FIXED
            
            if self._contains_bypass_pattern(change):
                bypass_scenarios.extend(self._detect_bypass_scenarios(change

        
        if bypass_scenarios:
            if len(bypass_scenarios) >= 3:
                bypass_risk = BypassRisk.HIGH
            elif len(bypass_scenarios) >= 1:
                bypass_risk = BypassRisk.MEDIUM
            
            if status == PatchStatus.FULLY_FIXED:
                status = PatchStatus.PARTIALLY_FIXED
        
        if self._detect_regressions(patch_data):
            vulnerabilities_introduced = self._identify_introduced_vulns(patch_data)
            status = PatchStatus.INTRODUCED_REGRESSION
        
        recommendations = self._generate_recommendations(status, bypass_scenarios)
        
        confidence = self._calculate_confidence(patch_data, status)
        
        return PatchAssessment(
            patch_id=patch_data.get('patch_id', ''),
            status=status,
            bypass_risk=bypass_risk,
            vulnerabilities_fixed=vulnerabilities_fixed,
            vulnerabilities_introduced=vulnerabilities_introduced,
            code_changes=code_changes,
            bypass_scenarios=bypass_scenarios,
            confidence=confidence,
            recommendations=recommendations)
        

    
    def _contains_fix_pattern(self, change: Dict[str, Any]) -> bool:
        content = str(change.get('content', '')).lower()
        
        for pattern, _ in self.fix_patterns:
            if pattern in content:
                return True
        
        return False
    
    def _contains_bypass_pattern(self, change: Dict[str, Any]) -> bool:
        content = str(change.get('content', '')).lower()
        
        for pattern, _ in self.bypass_patterns:
            if pattern in content:
                return True
        
        return False
    
    def _detect_bypass_scenarios(self, change: Dict[str, Any]) -> List[str]:
        scenarios = []
        content = str(change.get('content', '')).lower()
        
        for pattern, description in self.bypass_patterns:
            if pattern in content:
                scenarios.append(description)
        
        return scenarios
    
    def _extract_vuln_id(self, change: Dict[str, Any]) -> str:
        content = str(change.get('content', ''

        
        import re
        match = re.search(r'(CVE-\d{4}-\d+)', content)
        if match:
            return match.group(1)
        
        return change.get('vulnerability_id', 'unknown')
    
    def _detect_regressions(self, patch_data: Dict[str, Any]) -> bool:
        for change in patch_data.get('code_changes', []):
            content = str(change.get('content', '')).lower()
            
            if 'add.*unsafe' in content or 'remove.*safe' in content:
                return True
        
        return False
    
    def _identify_introduced_vulns(self, patch_data: Dict[str, Any]) -> List[str]:
        introduced = []
        
        for change in patch_data.get('code_changes', []):
            content = str(change.get('content', '')).lower()
            
            if 'memcpy' in content and 'length' not in content:
                introduced.append('潜在的缓冲区溢出')
            if 'strcpy' in content:
                introduced.append('不安全的字符串复制')
            if 'system(' in content or 'exec(' in content:
                introduced.append('命令注入风险')
        
        return introduced
    
    def _generate_recommendations(self, status: PatchStatus, bypass_scenarios: List[str]) -> List[str]:
        recommendations = []
        
        if status == PatchStatus.PARTIALLY_FIXED:
            recommendations.append("补丁未能完全修复漏洞，请检查绕过场景")
        
        if status == PatchStatus.NOT_FIXED:
            recommendations.append("补丁未能修复漏洞，需要重新分析")
        
        if status == PatchStatus.INTRODUCED_REGRESSION:
            recommendations.append("补丁引入了新的漏洞，请立即回滚")
        
        if bypass_scenarios:
            recommendations.append("检测到潜在的绕过场景，建议进行渗透测试验证")
        
        if status == PatchStatus.FULLY_FIXED:
            recommendations.append("补丁修复完整，建议进行回归测试")
        
        return recommendations
    
    def _calculate_confidence(self, patch_data: Dict[str, Any], status: PatchStatus) -> float:
        factors = []
        
        if patch_data.get('test_coverage'):
            factors.append(0.9)
        else:
            factors.append(0.5)
        
        if status == PatchStatus.FULLY_FIXED:
            factors.append(0.9)
        elif status == PatchStatus.PARTIALLY_FIXED:
            factors.append(0.6)
        else:
            factors.append(0.3)
        
        if patch_data.get('code_review_approved'):
            factors.append(0.9)
        else:
            factors.append(0.6)
        
        return round(sum(factors) / len(factors), 2)


def evaluate_patch(patch_data: Dict[str, Any]) -> PatchAssessment:
    evaluator = PatchQualityEvaluator()
    return evaluator.evaluate(patch_data)))))))))