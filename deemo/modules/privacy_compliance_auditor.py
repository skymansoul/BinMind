import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ComplianceFramework(Enum):
    GDPR = "gdpr"
    CCPA = "ccpa"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"


class DataCategory(Enum):
    LOCATION = "location"
    CONTACTS = "contacts"
    PHONE = "phone"
    EMAIL = "email"
    FINANCIAL = "financial"
    HEALTH = "health"
    IDENTIFIER = "identifier"
    BIOMETRIC = "biometric"
    BROWSING = "browsing"
    COMMUNICATION = "communication"


@dataclass
class DataFinding:
    data_category: DataCategory
    severity: str
    location: str
    description: str
    compliance_issues: List[str]
    recommendations: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'data_category': self.data_category.value,
            'severity': self.severity,
            'location': self.location,
            'description': self.description,
            'compliance_issues': self.compliance_issues,
            'recommendations': self.recommendations
        }


@dataclass
class ComplianceResult:
    framework: ComplianceFramework
    findings: List[DataFinding]
    compliance_score: int
    passed_checks: int
    failed_checks: int
    summary: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'framework': self.framework.value,
            'findings': [f.to_dict() for f in self.findings],
            'compliance_score': self.compliance_score,
            'passed_checks': self.passed_checks,
            'failed_checks': self.failed_checks,
            'summary': self.summary
        }


class PrivacyComplianceAuditor:
    
    def __init__(self):
        self.data_patterns = {
            DataCategory.LOCATION: [
                r'gps', r'location', r'coordinate', r'latitude', r'longitude',
                r'geolocation', r'position', r'location_manager'
            ],
            DataCategory.CONTACTS: [
                r'contact', r'address_book', r'phone_book', r'address', r'name'
            ],
            DataCategory.PHONE: [
                r'phone', r'telephone', r'mobile', r'cell', r'sms', r'call'
            ],
            DataCategory.EMAIL: [
                r'email', r'mail', r'smtp', r'inbox', r'message'
            ],
            DataCategory.FINANCIAL: [
                r'credit_card', r'bank', r'payment', r'card_number', r'account',
                r'billing', r'transaction', r'paypal', r'payment_method'
            ],
            DataCategory.HEALTH: [
                r'health', r'medical', r'diagnosis', r'doctor', r'patient',
                r'pharmacy', r'prescription', r'health_record'
            ],
            DataCategory.IDENTIFIER: [
                r'ssn', r'social_security', r'passport', r'driver_license',
                r'id_card', r'national_id'
            ],
            DataCategory.BIOMETRIC: [
                r'fingerprint', r'face', r'iris', r'voice', r'biometric'
            ],
            DataCategory.BROWSING: [
                r'cookie', r'history', r'url', r'browser', r'web_view'
            ],
            DataCategory.COMMUNICATION: [
                r'message', r'chat', r'conversation', r'call_log', r'sms'
            ]
        }
        
        self.gdpr_articles = {
            'Art. 5': '数据最小化原则',
            'Art. 6': '处理合法性',
            'Art. 13': '信息告知',
            'Art. 14': '数据主体权利',
            'Art. 15': '访问权',
            'Art. 17': '删除权',
            'Art. 32': '安全措施'
        }
    
    def audit(self, binary_info: Dict[str, Any], framework: ComplianceFramework = ComplianceFramework.GDPR) -> ComplianceResult:
        findings = []
        passed_checks = 0
        failed_checks = 0
        
        strings = binary_info.get('strings', '')
        
        for data_category, patterns in self.data_patterns.items():
            found_patterns = []
            
            for pattern in patterns:
                if pattern.lower() in strings.lower():
                    found_patterns.append(pattern)
            
            if found_patterns:
                finding = DataFinding()
                    data_category=data_category,
                    severity=self._determine_severity(data_category),
                    location='binary',
                    description=f"检测到 {data_category.value} 数据处理",
                    compliance_issues=self._get_compliance_issues(data_category, framework),
                    recommendations=self._generate_recommendations(data_category)
                
                findings.append(finding)
                failed_checks += 1
            else:
                passed_checks += 1
        
        compliance_score = self._calculate_score(findings)
        
        summary = {
            'total_categories': len(self.data_patterns),
            'high_risk_categories': len([f for f in findings if f.severity == 'high']),
            'medium_risk_categories': len([f for f in findings if f.severity == 'medium']),
            'low_risk_categories': len([f for f in findings if f.severity == 'low'])
        }
        
        return ComplianceResult(
            framework=framework,
            findings=findings,
            compliance_score=compliance_score,
            passed_checks=passed_checks,
            failed_checks=failed_checks,
            summary=summary)
        

    
    def _determine_severity(self, data_category: DataCategory) -> str:
        high_risk = [DataCategory.FINANCIAL, DataCategory.HEALTH, DataCategory.IDENTIFIER, DataCategory.BIOMETRIC]
        medium_risk = [DataCategory.LOCATION, DataCategory.CONTACTS, DataCategory.COMMUNICATION]
        
        if data_category in high_risk:
            return 'high'
        elif data_category in medium_risk:
            return 'medium'
        else:
            return 'low'
    
    def _get_compliance_issues(self, data_category: DataCategory, framework: ComplianceFramework) -> List[str]:
        issues = []
        
        if framework == ComplianceFramework.GDPR:
            issues.append('Art. 5 - 数据最小化')
            issues.append('Art. 6 - 合法处理依据')
            issues.append('Art. 32 - 安全措施')
            
            if data_category in [DataCategory.FINANCIAL, DataCategory.HEALTH]:
                issues.append('Art. 9 - 特殊类别数据处理')
        
        elif framework == ComplianceFramework.HIPAA:
            issues.append('HIPAA - PHI 保护')
            issues.append('HIPAA - 访问控制')
        
        elif framework == ComplianceFramework.PCI_DSS:
            if data_category == DataCategory.FINANCIAL:
                issues.append('PCI DSS - 持卡人数据保护')
        
        return issues
    
    def _generate_recommendations(self, data_category: DataCategory) -> List[str]:
        recommendations = []
        
        if data_category in [DataCategory.FINANCIAL, DataCategory.HEALTH, DataCategory.IDENTIFIER]:
            recommendations.append("确保数据加密存储")
            recommendations.append("实施访问控制机制")
            recommendations.append("记录数据处理活动")
        
        recommendations.append("提供隐私政策说明")
        recommendations.append("提供数据主体权利接口")
        
        return recommendations
    
    def _calculate_score(self, findings: List[DataFinding]) -> int:
        score = 100
        
        for finding in findings:
            if finding.severity == 'high':
                score -= 15
            elif finding.severity == 'medium':
                score -= 10
            elif finding.severity == 'low':
                score -= 5
        
        return max(0, score)


def audit_privacy_compliance(binary_info: Dict[str, Any], framework: str = 'gdpr') -> ComplianceResult:
    framework_enum = ComplianceFramework[framework.upper()]
    auditor = PrivacyComplianceAuditor()
    return auditor.audit(b)