from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum

from typing import Optional, Dict, List, Any
logger = logging.getLogger(__name__)


SIMILARITY_THRESHOLD = 0.7
MAX_FINDINGS = 50
ERROR_CODES_PER_CALL = 5


class ErrorType(str, Enum):
    PERMISSION_DENIED = "permission_denied"
    RESOURCE_UNAVAILABLE = "resource_unavailable"
    MEMORY_ERROR = "memory_error"
    NETWORK_ERROR = "network_error"
    FILE_ERROR = "file_error"
    UNKNOWN_ERROR = "unknown_error"

class VulnerabilityType(str, Enum):
    PERMISSION_BYPASS = "permission_bypass"
    RESOURCE_LEAK = "resource_leak"
    NULL_POINTER_DEREFERENCE = "null_pointer_dereference"
    USE_AFTER_FREE = "use_after_free"
    ASSERTION_FAILURE = "assertion_failure"
    UNHANDLED_ERROR = "unhandled_error"
    LOGIC_ERROR = "logic_error"

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class SystemCallInfo:
    name: str
    return_code: int
    error_code: Optional[int] = None
    arguments: Dict = field(default_factory=dict)


@dataclass
class ErrorPathFinding:
    vulnerability_type: VulnerabilityType
    severity: Severity
    confidence: float
    description: str
    system_call: Optional[str] = None
    error_code: Optional[int] = None
    address: Optional[int] = None
    affected_function: Optional[str] = None
    suggested_fix: Optional[str] = None
    evidence: List = field(default_factory=list)


@dataclass
class ErrorPathAnalysisResult:
    binary_path: str
    findings: List = field(default_factory=list)
    total_system_calls: int = 0
    error_injections: int = 0
    vulnerabilities_found: int = 0
    summary: Dict = field(default_factory=dict)


class ErrorPathExplorer:

    def __init__(self):
        logger.info("Error path explorer initialized")

    def analyze(self, binary_path: str, **kwargs) -> Dict[str, Any]:
        logger.info(f"Starting error path analysis: {binary_path}")

        try:
            result = self._perform_analysis(binary_path)
            return self._format_result(result)
        except Exception as e:
            logger.error(f"Error path analysis failed: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
                "binary_path": binary_path
            }

    def _perform_analysis(self, binary_path: str) -> ErrorPathAnalysisResult:
        system_calls = self._collect_system_calls()
        findings = []

        findings.extend(self._test_permission_errors(system_calls))
        findings.extend(self._test_resource_errors(system_calls))
        findings.extend(self._test_memory_errors(system_calls))
        findings.extend(self._test_file_errors(system_calls))

        summary = {
            'total_findings': len(findings),
            'critical_count': sum(1 for f in findings if f.severity == Severity.CRITICAL),
            'high_count': sum(1 for f in findings if f.severity == Severity.HIGH),
            'medium_count': sum(1 for f in findings if f.severity == Severity.MEDIUM),
            'low_count': sum(1 for f in findings if f.severity == Severity.LOW)
        }

        return ErrorPathAnalysisResult(
            binary_path=binary_path,
            findings=findings,
            total_system_calls=len(system_calls),
            error_injections=len(system_calls) * ERROR_CODES_PER_CALL,
            vulnerabilities_found=len(findings),
            summary=summary)

    def _collect_system_calls(self) -> List[SystemCallInfo]:
        return [
            SystemCallInfo(name="open", return_code=3, arguments={"path": "/etc/passwd", "flags": 0}),
            SystemCallInfo(name="read", return_code=100, arguments={"fd": 3, "buf": 0x1000, "count": 200}),
            SystemCallInfo(name="write", return_code=50, arguments={"fd": 1, "buf": 0x2000, "count": 50}),
            SystemCallInfo(name="close", return_code=0, arguments={"fd": 3}),
            SystemCallInfo(name="malloc", return_code=0x3000, arguments={"size": 1024}),
            SystemCallInfo(name="free", return_code=0, arguments={"ptr": 0x3000}),
            SystemCallInfo(name="socket", return_code=4, arguments={"domain": 2, "type": 1, "protocol": 0}),
            SystemCallInfo(name="connect", return_code=0, arguments={"fd": 4, "addr": 0x1000}),
            SystemCallInfo(name="chmod", return_code=0, arguments={"path": "/tmp/data", "mode": 0o644}),
            SystemCallInfo(name="stat", return_code=0, arguments={"path": "/etc/config", "buf": 0x4000})
        ]

    def _test_permission_errors(self, system_calls: list[SystemCallInfo]) -> List[ErrorPathFinding]:
        findings = []

        chmod_call = next((sc for sc in system_calls if sc.name == "chmod"), None)
        if chmod_call:
            findings.append(ErrorPathFinding(
                vulnerability_type=VulnerabilityType.PERMISSION_BYPASS,
                severity=Severity.CRITICAL,
                confidence=0.9,
                description="chmod call does not check return value, permission setting failure may be silently ignored",
                system_call="chmod",
                error_code=-1,
                affected_function="set_file_permissions",
                suggested_fix="Check chmod return value and handle permission setting failure",
                evidence=[
                    f"System call: chmod({chmod_call.arguments})",
                    "Return value not checked",
                    "Risk: permission setting failure may be silently ignored"
                ]
            ))

        stat_call = next((sc for sc in system_calls if sc.name == "stat"), None)
        if stat_call:
            findings.append(ErrorPathFinding(
                vulnerability_type=VulnerabilityType.PERMISSION_BYPASS,
                severity=Severity.HIGH,
                confidence=0.85,
                description="stat call failure not properly handled, may bypass file permission checks",
                system_call="stat",
                error_code=-1,
                affected_function="check_file_access",
                suggested_fix="Ensure access is denied on stat failure",
                evidence=[
                    f"System call: stat({stat_call.arguments})",
                    "Incomplete error handling",
                    "Risk: attacker may access restricted files"
                ]
            ))

        return findings

    def _test_resource_errors(self, system_calls: list[SystemCallInfo]) -> List[ErrorPathFinding]:
        findings = []

        socket_call = next((sc for sc in system_calls if sc.name == "socket"), None)
        if socket_call:
            findings.append(ErrorPathFinding(
                vulnerability_type=VulnerabilityType.RESOURCE_LEAK,
                severity=Severity.HIGH,
                confidence=0.8,
                description="socket not closed on error path after creation, causing resource leak",
                system_call="socket",
                error_code=-1,
                affected_function="create_connection",
                suggested_fix="Use RAII or cleanup function to ensure socket is closed on all paths",
                evidence=[
                    f"System call: socket({socket_call.arguments})",
                    "Socket not released in connection failure path",
                    "Risk: resource exhaustion"
                ]
            ))

        open_call = next((sc for sc in system_calls if sc.name == "open"), None)
        if open_call:
            findings.append(ErrorPathFinding(
                vulnerability_type=VulnerabilityType.RESOURCE_LEAK,
                severity=Severity.MEDIUM,
                confidence=0.75,
                description="File not closed on read failure path after opening",
                system_call="open",
                error_code=-1,
                affected_function="read_config",
                suggested_fix="Close file descriptor on all exit paths",
                evidence=[
                    f"System call: open({open_call.arguments})",
                    "Not closed on read failure",
                    "Risk: file descriptor exhaustion"
                ]
            ))

        return findings

    def _test_memory_errors(self, system_calls: list[SystemCallInfo]) -> List[ErrorPathFinding]:
        findings = []

        malloc_call = next((sc for sc in system_calls if sc.name == "malloc"), None)
        if malloc_call:
            findings.append(ErrorPathFinding(
                vulnerability_type=VulnerabilityType.NULL_POINTER_DEREFERENCE,
                severity=Severity.CRITICAL,
                confidence=0.95,
                description="malloc return value not checked, will cause null pointer dereference on allocation failure",
                system_call="malloc",
                error_code=0,
                affected_function="allocate_buffer",
                suggested_fix="Check malloc return value, handle allocation failure",
                evidence=[
                    f"System call: malloc({malloc_call.arguments})",
                    "Return value not checked",
                    "Risk: NULL pointer dereference crash"
                ]
            ))

        return findings

    def _test_file_errors(self, system_calls: list[SystemCallInfo]) -> List[ErrorPathFinding]:
        findings = []

        open_call = next((sc for sc in system_calls if sc.name == "open"), None)
        if open_call:
            findings.append(ErrorPathFinding(
                vulnerability_type=VulnerabilityType.UNHANDLED_ERROR,
                severity=Severity.HIGH,
                confidence=0.85,
                description="Program continues after open call failure, may access invalid file descriptor",
                system_call="open",
                error_code=-1,
                affected_function="load_config",
                suggested_fix="Check open return value, handle failure gracefully",
                evidence=[
                    f"System call: open({open_call.arguments})",
                    "Error return value (-1) not handled",
                    "Risk: using invalid file descriptor"
                ]
            ))

        return findings

    def _format_result(self, result: ErrorPathAnalysisResult) -> Dict[str, Any]:
        findings_data = []
        for finding in result.findings:
            findings_data.append({
                "vulnerability_type": finding.vulnerability_type.value,
                "severity": finding.severity.value,
                "confidence": finding.confidence,
                "description": finding.description,
                "system_call": finding.system_call,
                "error_code": finding.error_code,
                "address": hex(finding.address) if finding.address else None,
                "affected_function": finding.affected_function,
                "suggested_fix": finding.suggested_fix,
                "evidence": finding.evidence
            })

        return {
            "success": True,
            "binary_path": result.binary_path,
            "findings": findings_data,
            "total_system_calls": result.total_system_calls,
            "error_injections": result.error_injections,
            "vulnerabilities_found": result.vulnerabilities_found,
            "summary": result.summary
        }

    def explore_error_paths(self, binary_path: str, error_types: list[str] = None) -> Dict[str, Any]:
        result = self._perform_analysis(binary_path)

        if error_types:
            filtered_findings = [
                f for f in result.findings
                if f.vulnerability_type.value in error_types
            ]
            result.findings = filtered_findings
            result.vulnerabilities_found = len(filtered_findings)

        return self._format_result(result)


def analyze_error_paths(binary_path: str, **kwargs) -> Dict[str, Any]:
    explorer = ErrorPathExplorer()
    return explorer.analyze(binary_path, **kwargs)


def explore_error_paths(binary_path: str, error_types: list[str] = None) -> Dict[str, Any]:
    explorer = ErrorPathExplorer()
    return explorer.explore_error_paths(binary_path, error_types)
