import logging
from dataclasses import dataclass, field
from enum import Enum

from typing import Optional
__log = logging.getLogger(__name__)


class SpoofingTechnique(Enum):
    PROCESS_HOLLOWING = "process_hollowing"
    PROCESS_DOPPELGANGING = "process_doppelganging"
    PPID_SPOOFING = "ppid_spoofing"
    TOKEN_MANIPULATION = "token_manipulation"
    PARENT_PID_SPOOFING = "parent_pid_spoofing"
    RUNPE = "runpe"

class SpoofingFinding:
    __slots__ = ('finding_id', 'technique', 'severity', 'description', 'api_evidence', 'confidence', 'mitre_technique',)

    def __init__(self, finding_id, technique, severity, description, api_evidence=field(default_factory=list), confidence=0.0, mitre_technique=""):
        self.finding_id = finding_id
        self.technique = technique
        self.severity = severity
        self.description = description
        self.api_evidence = api_evidence
        self.confidence = confidence
        self.mitre_technique = mitre_technique


    def to_dict(self) -> Dict[str, Any]:
        return {
            'finding_id': self.finding_id,
            'technique': self.technique,
            'severity': self.severity,
            'description': self.description,
            'api_evidence': self.api_evidence[:5],
            'confidence': self.confidence,
            'mitre': self.mitre_technique
        }


class ProcessSpoofingDetector:
    """基于 API 调用模式匹配检测进程伪装技术。"""

    HOLLOWING_PATTERN = [
        'CreateProcess', 'CREATE_SUSPENDED', 'NtUnmapViewOfSection',
        'VirtualAllocEx', 'WriteProcessMemory', 'SetThreadContext', 'ResumeThread']

    DOPPELGANGING_PATTERN = [
        'NtCreateTransaction', 'CreateFileTransacted', 'NtCreateProcessEx',
        'NtCreateThreadEx', 'RollbackTransaction']

    TOKEN_MANIPULATION_APIS = [
        'OpenProcessToken', 'DuplicateTokenEx', 'ImpersonateLoggedOnUser',
        'SetThreadToken', 'AdjustTokenPrivileges', 'CreateProcessAsUser',
        'CreateProcessWithTokenW', 'NtSetInformationProcess']

    PPID_SPOOFING_APIS = [
        'InitializeProcThreadAttributeList', 'UpdateProcThreadAttribute',
        'PROC_THREAD_ATTRIBUTE_PARENT_PROCESS', 'CreateProcess']

    def __init__(self):
        self._findings: list[SpoofingFinding] = []
        self._counter = 0

    def _next_id(self) -> str:
        self._counter += 1
        return f"SPOOF-{self._counter:04d}"

    def detect_hollowing(self, api_calls: list[str]) -> typing.Optional[SpoofingFinding]:
        api_lower = {c.lower() for c in api_calls}
        matches = [a for a in self.HOLLOWING_PATTERN if a.lower() in api_lower]
        if len(matches) >= 3:
            return SpoofingFinding(
                finding_id=self._next_id(),
                technique=SpoofingTechnique.PROCESS_HOLLOWING,
                severity='critical',
                description='Process Hollowing: CreateProcess(SUSPENDED) + Unmap + SetThreadContext + Resume',
                api_evidence=matches,
                confidence=min(len(matches) / len(self.HOLLOWING_PATTERN) * 1.3, 1.0),
                mitre_technique='T1055.012')
        return None

    def detect_token_manipulation(self, api_calls: list[str]) -> typing.Optional[SpoofingFinding]:
        api_lower = {c.lower() for c in api_calls}
        matches = [a for a in self.TOKEN_MANIPULATION_APIS if a.lower() in api_lower]
        if len(matches) >= 2:
            return SpoofingFinding(
                finding_id=self._next_id(),
                technique=SpoofingTechnique.TOKEN_MANIPULATION,
                severity='high',
                description=f'Token 操纵: {matches[:3]}',
                api_evidence=matches,
                confidence=min(len(matches) / 5, 1.0),
                mitre_technique='T1134')
        return None

    def detect_ppid_spoofing(self, api_calls: list[str],
                             strings_data: list[str]) -> typing.Optional[SpoofingFinding]:
        combined = {s.lower() for s in (api_calls + strings_data)}
        matches = [a for a in self.PPID_SPOOFING_APIS if a.lower() in combined]
        if len(matches) >= 3:
            return SpoofingFinding(
                finding_id=self._next_id(),
                technique=SpoofingTechnique.PPID_SPOOFING,
                severity='high',
                description='父进程 PID 伪装: PROC_THREAD_ATTRIBUTE_PARENT_PROCESS',
                api_evidence=matches,
                confidence=min(len(matches) / 4, 1.0),
                mitre_technique='T1134.004')
        return None

    def analyze(self, api_calls: typing.Optional[List[str]] = None,
                strings_data: typing.Optional[List[str]] = None, **kwargs) -> Dict[str, Any]:
        api_calls = api_calls or []
        strings_data = strings_data or []
        findings: list[SpoofingFinding] = []

        f = self.detect_hollowing(api_calls)
        if f:
            findings.append(f)
        f = self.detect_token_manipulation(api_calls)
        if f:
            findings.append(f)
        f = self.detect_ppid_spoofing(api_calls, strings_data)
        if f:
            findings.append(f)
        if api_calls and any('doppelgang' in s.lower() or 'transacted' in s.lower()
                            for s in strings_data):
            findings.append(SpoofingFinding(
                finding_id=self._next_id(),
                technique=SpoofingTechnique.PROCESS_DOPPELGANGING,
                severity='critical',
                description='检测到 Process Doppelganging 模式',
                mitre_technique='T1055.012'))

        self._findings = findings
        return {
            'success': True,
            'total_findings': len(findings),
            'findings': [f.to_dict() for f in findings],
            'risk_level': 'critical' if any(f.severity == 'critical' for f in findings)
                         else 'high' if findings else 'low'
        }


def detect_process_spoofing(api_calls: list[str],
                            strings_data: typing.Optional[List[str]] = None,
                            **kwargs) -> Dict[str, Any]:
    """便捷入口：实例化检测器并执行全量分析。"""
    detector = ProcessSpoofingDetector()
    return detector.analyze(api_calls=api_calls, strings_data=strings_data)


__all__ = ["ProcessSpoofingDetector", "SpoofingFinding", "SpoofingTechnique",
           "detect_process_spoofing"]
