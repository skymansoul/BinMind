# 零日异常检测器——比较新旧二进制版本的函数与字符串变化，标记安全相关增删。
# 分值由异常计数与置信度加权聚合：critical confidence_bonus=0.2，high=0.1。

import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class AnomalySeverity:
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    def __init__(self, v=None): pass


class ChangeType:
    FUNCTION_ADDED = "function_added"
    FUNCTION_REMOVED = "function_removed"
    FUNCTION_MODIFIED = "function_modified"
    CODE_PATTERN_CHANGE = "code_pattern_change"
    STRING_CHANGE = "string_change"
    IMPORT_CHANGE = "import_change"


class AnomalyFinding:
    __slots__ = ('change_type', 'severity', 'description', 'location',
                 'old_value', 'new_value', 'confidence')

    def __init__(self, change_type, severity, description, location,
                 old_value, new_value, confidence):
        self.change_type = change_type
        self.severity = severity
        self.description = description
        self.location = location
        self.old_value = old_value
        self.new_value = new_value
        self.confidence = confidence

    def to_dict(self) -> Dict[str, Any]:
        return {
            'change_type': self.change_type,
            'severity': self.severity,
            'description': self.description,
            'location': self.location,
            'old_value': self.old_value,
            'new_value': self.new_value,
            'confidence': self.confidence}


class ZeroDayResult:
    __slots__ = ('anomalies', 'total_changes', 'security_relevant_changes',
                 'confidence_score', 'recommendations')

    def __init__(self, anomalies, total_changes, security_relevant_changes,
                 confidence_score, recommendations):
        self.anomalies = anomalies
        self.total_changes = total_changes
        self.security_relevant_changes = security_relevant_changes
        self.confidence_score = confidence_score
        self.recommendations = recommendations

    def to_dict(self) -> Dict[str, Any]:
        return {
            'anomalies': [a.to_dict() for a in self.anomalies],
            'total_changes': self.total_changes,
            'security_relevant_changes': self.security_relevant_changes,
            'confidence_score': self.confidence_score,
            'recommendations': self.recommendations}


class ZeroDayAnomalyDetector:
    def __init__(self):
        self.security_keywords = [
            'auth', 'password', 'token', 'secret', 'key', 'crypto',
            'encrypt', 'decrypt', 'hash', 'verify', 'sign',
            'admin', 'root', 'privilege', 'access', 'permission',
            'backdoor', 'shell', 'exec', 'system', 'inject',
            'log', 'audit', 'trace', 'debug', 'monitor']
        self.dangerous_patterns = [
            r'system\(', r'exec\(', r'popen\(', r'spawn\(',
            r'http_request', r'socket', r'connect',
            r'file_write', r'file_read', r'file_delete',
            r'malloc', r'free', r'memcpy', r'strcpy']

    def detect(self, old_binary: Dict[str, Any],
                new_binary: Dict[str, Any]) -> ZeroDayResult:
        anomalies = []
        total_changes = 0
        security_relevant_changes = 0

        old_funcs = set(f.get('name', '') for f in old_binary.get('functions', []))
        new_funcs = set(f.get('name', '') for f in new_binary.get('functions', []))
        added_funcs = new_funcs - old_funcs
        removed_funcs = old_funcs - new_funcs

        for func in added_funcs:
            anomaly = self._analyze_new_function(func)
            if anomaly:
                anomalies.append(anomaly)
                total_changes += 1
                if anomaly.severity in (AnomalySeverity.CRITICAL, AnomalySeverity.HIGH):
                    security_relevant_changes += 1

        for func in removed_funcs:
            anomaly = self._analyze_removed_function(func)
            if anomaly:
                anomalies.append(anomaly)
                total_changes += 1

        old_strings = set(old_binary.get('strings', '').split('\n'))
        new_strings = set(new_binary.get('strings', '').split('\n'))
        added_strings = new_strings - old_strings

        for string in added_strings:
            anomaly = self._analyze_new_string(string)
            if anomaly:
                anomalies.append(anomaly)
                total_changes += 1
                if anomaly.severity in (AnomalySeverity.CRITICAL, AnomalySeverity.HIGH):
                    security_relevant_changes += 1

        confidence_score = self._calculate_confidence(anomalies)
        recommendations = self._generate_recommendations(anomalies)

        return ZeroDayResult(
            anomalies=anomalies, total_changes=total_changes,
            security_relevant_changes=security_relevant_changes,
            confidence_score=confidence_score,
            recommendations=recommendations)

    def _analyze_new_function(self, func_name: str) -> Optional[AnomalyFinding]:
        if any(kw in func_name.lower() for kw in self.security_keywords):
            severity = AnomalySeverity.HIGH
            if any(kw in func_name.lower() for kw in ['backdoor', 'shell', 'inject']):
                severity = AnomalySeverity.CRITICAL
            return AnomalyFinding(
                change_type=ChangeType.FUNCTION_ADDED, severity=severity,
                description=f"新增安全相关函数: {func_name}",
                location=func_name, old_value=None, new_value=func_name,
                confidence=0.85)
        return None

    def _analyze_removed_function(self, func_name: str) -> Optional[AnomalyFinding]:
        if any(kw in func_name.lower() for kw in ['auth', 'check', 'validate', 'verify']):
            return AnomalyFinding(
                change_type=ChangeType.FUNCTION_REMOVED,
                severity=AnomalySeverity.MEDIUM,
                description=f"校验函数被移除: {func_name}",
                location=func_name, old_value=func_name, new_value=None,
                confidence=0.7)
        return None

    def _analyze_new_string(self, string: str) -> Optional[AnomalyFinding]:
        if any(kw in string.lower() for kw in ['backdoor', 'malware', 'virus', 'payload']):
            return AnomalyFinding(
                change_type=ChangeType.STRING_CHANGE,
                severity=AnomalySeverity.CRITICAL,
                description=f"检测到可疑字符串: {string[:50]}",
                location='strings', old_value=None, new_value=string,
                confidence=0.9)
        if any(kw in string.lower() for kw in self.security_keywords):
            return AnomalyFinding(
                change_type=ChangeType.STRING_CHANGE,
                severity=AnomalySeverity.MEDIUM,
                description=f"新增安全相关字符串: {string[:50]}",
                location='strings', old_value=None, new_value=string,
                confidence=0.6)
        return None

    def _calculate_confidence(self, anomalies: List[AnomalyFinding]) -> float:
        if not anomalies:
            return 0.0
        critical_count = len([a for a in anomalies if a.severity == AnomalySeverity.CRITICAL])
        high_count = len([a for a in anomalies if a.severity == AnomalySeverity.HIGH])
        total_confidence = sum(a.confidence for a in anomalies) / len(anomalies)
        severity_bonus = (critical_count * 0.2) + (high_count * 0.1)
        return min(1.0, total_confidence + severity_bonus)

    def _generate_recommendations(self, anomalies: List[AnomalyFinding]) -> List[str]:
        recommendations = []
        critical_anomalies = [a for a in anomalies if a.severity == AnomalySeverity.CRITICAL]
        if critical_anomalies:
            recommendations.append(f"{len(critical_anomalies)} 个严重异常——需立即调查")
        high_anomalies = [a for a in anomalies if a.severity == AnomalySeverity.HIGH]
        if high_anomalies:
            recommendations.append(f"{len(high_anomalies)} 个高风险异常——建议优先审查")
        if len(anomalies) >= 10:
            recommendations.append("检测到大量变更——建议全面安全审计")
        return recommendations


def detect_zeroday_anomalies(old_binary: Dict[str, Any],
                               new_binary: Dict[str, Any]) -> ZeroDayResult:
    detector = ZeroDayAnomalyDetector()
    return detector.detect(old_binary, new_binary)
