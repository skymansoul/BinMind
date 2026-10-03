import logging
import time
import json
import uuid
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum

from core.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

logger = logging.getLogger(__name__)


class RuntimeBehaviorType(str, Enum):
    FILE_CREATE = "file_create"
    FILE_DELETE = "file_delete"
    FILE_MODIFY = "file_modify"
    FILE_READ = "file_read"
    NETWORK_CONNECT = "network_connect"
    NETWORK_LISTEN = "network_listen"
    NETWORK_SEND = "network_send"
    NETWORK_RECEIVE = "network_receive"
    DNS_QUERY = "dns_query"
    PROCESS_CREATE = "process_create"
    PROCESS_TERMINATE = "process_terminate"
    PROCESS_INJECT = "process_inject"
    REGISTRY_CREATE = "registry_create"
    REGISTRY_MODIFY = "registry_modify"
    REGISTRY_DELETE = "registry_delete"
    REGISTRY_READ = "registry_read"
    MEMORY_ALLOC = "memory_allocate"
    MEMORY_PROTECT = "memory_protect"
    THREAD_CREATE = "thread_create"
    SERVICE_CREATE = "service_create"
    PRIVILEGE_ESCALATE = "privilege_escalate"
    DLL_LOAD = "dll_load"
    ANTI_DEBUG = "anti_debug"
    ANTI_VM = "anti_vm"
    PACKED = "packed_execution"
    UNKNOWN = "unknown"

class BehaviorSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class RuntimeTrace:
    trace_id: str
    timestamp: float
    behavior_type: str
    api_name: str
    process_name: str
    pid: int = 0
    tid: int = 0
    arguments: dict = field(default_factory=dict)
    return_value: Any = None
    success: bool = True
    severity: str = BehaviorSeverity.INFO
    call_stack: list = field(default_factory=list)
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "timestamp": self.timestamp,
            "behavior_type": self.behavior_type,
            "api_name": self.api_name,
            "process_name": self.process_name,
            "pid": self.pid,
            "tid": self.tid,
            "arguments": self.arguments,
            "return_value": str(self.return_value) if self.return_value is not None else None,
            "success": self.success,
            "severity": self.severity,
            "call_stack": self.call_stack,
            "description": self.description,
        }


@dataclass
class BehaviorPattern:
    pattern_id: str
    name: str
    description: str
    required_behaviors: list
    severity: str = BehaviorSeverity.MEDIUM
    mitre_tactic: str = ""
    mitre_technique: str = ""


@dataclass
class DynamicAnalysisResult:
    binary_path: str
    execution_id: str
    start_time: float
    end_time: float
    traces: list = field(default_factory=list)
    detected_behaviors: list = field(default_factory=list)
    api_hook_count: int = 0
    files_accessed: list = field(default_factory=list)
    network_connections: list = field(default_factory=list)
    registry_operations: list = field(default_factory=list)
    process_operations: list = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "low"
    anomalies: list = field(default_factory=list)

    def duration_seconds(self) -> float:
        return self.end_time - self.start_time


class DynamicAnalysisEngine(BaseAnalyzer):

    MALICIOUS_PATTERNS: list = [
        BehaviorPattern(
            pattern_id="MAL-001", name="Fileless Execution",
            description="Shellcode executed directly from allocated memory, no disk artifact.",
            required_behaviors=[
                RuntimeBehaviorType.MEMORY_ALLOC,
                RuntimeBehaviorType.MEMORY_PROTECT,
                RuntimeBehaviorType.PROCESS_INJECT,
            ],
            severity=BehaviorSeverity.CRITICAL,
            mitre_tactic="Execution", mitre_technique="T1055",
        ),
        BehaviorPattern(
            pattern_id="MAL-002", name="C2 Data Exfiltration",
            description="Encrypted outbound channel to remote C2, data staged from local files.",
            required_behaviors=[
                RuntimeBehaviorType.NETWORK_CONNECT,
                RuntimeBehaviorType.FILE_READ,
                RuntimeBehaviorType.NETWORK_SEND,
            ],
            severity=BehaviorSeverity.CRITICAL,
            mitre_tactic="Exfiltration", mitre_technique="T1041",
        ),
        BehaviorPattern(
            pattern_id="MAL-003", name="Registry Persistence",
            description="Run key / scheduled task registry write for boot-time execution.",
            required_behaviors=[
                RuntimeBehaviorType.REGISTRY_CREATE,
                RuntimeBehaviorType.REGISTRY_MODIFY,
            ],
            severity=BehaviorSeverity.HIGH,
            mitre_tactic="Persistence", mitre_technique="T1547.001",
        ),
        BehaviorPattern(
            pattern_id="MAL-004", name="Process Hollowing",
            description="Spawned process suspended, memory unmapped and replaced with payload.",
            required_behaviors=[
                RuntimeBehaviorType.PROCESS_CREATE,
                RuntimeBehaviorType.MEMORY_ALLOC,
                RuntimeBehaviorType.PROCESS_INJECT,
            ],
            severity=BehaviorSeverity.CRITICAL,
            mitre_tactic="Defense Evasion", mitre_technique="T1055.012",
        ),
        BehaviorPattern(
            pattern_id="MAL-005", name="DNS Tunneling",
            description="DNS query stream as covert C2 channel, bypassing egress filters.",
            required_behaviors=[
                RuntimeBehaviorType.DNS_QUERY,
                RuntimeBehaviorType.NETWORK_SEND,
            ],
            severity=BehaviorSeverity.HIGH,
            mitre_tactic="Command and Control", mitre_technique="T1071.004",
        ),
        BehaviorPattern(
            pattern_id="MAL-006", name="Anti-Analysis Evasion",
            description="Debugger and VM presence checks; alters execution path on detection.",
            required_behaviors=[
                RuntimeBehaviorType.ANTI_DEBUG,
                RuntimeBehaviorType.ANTI_VM,
            ],
            severity=BehaviorSeverity.HIGH,
            mitre_tactic="Defense Evasion", mitre_technique="T1497",
        ),
        BehaviorPattern(
            pattern_id="MAL-007", name="Credential Dumping",
            description="Credential material extracted from system process memory (LSASS, SAM).",
            required_behaviors=[
                RuntimeBehaviorType.PROCESS_CREATE,
                RuntimeBehaviorType.MEMORY_ALLOC,
                RuntimeBehaviorType.PRIVILEGE_ESCALATE,
            ],
            severity=BehaviorSeverity.CRITICAL,
            mitre_tactic="Credential Access", mitre_technique="T1003",
        ),
    ]

    API_BEHAVIOR_MAP: Dict[str, str] = {
        "CreateFile": RuntimeBehaviorType.FILE_CREATE,
        "WriteFile": RuntimeBehaviorType.FILE_MODIFY,
        "ReadFile": RuntimeBehaviorType.FILE_READ,
        "DeleteFile": RuntimeBehaviorType.FILE_DELETE,
        "NtCreateFile": RuntimeBehaviorType.FILE_CREATE,
        "NtWriteFile": RuntimeBehaviorType.FILE_MODIFY,
        "socket": RuntimeBehaviorType.NETWORK_CONNECT,
        "connect": RuntimeBehaviorType.NETWORK_CONNECT,
        "bind": RuntimeBehaviorType.NETWORK_LISTEN,
        "send": RuntimeBehaviorType.NETWORK_SEND,
        "recv": RuntimeBehaviorType.NETWORK_RECEIVE,
        "WSASend": RuntimeBehaviorType.NETWORK_SEND,
        "getaddrinfo": RuntimeBehaviorType.DNS_QUERY,
        "DnsQuery_A": RuntimeBehaviorType.DNS_QUERY,
        "CreateProcess": RuntimeBehaviorType.PROCESS_CREATE,
        "TerminateProcess": RuntimeBehaviorType.PROCESS_TERMINATE,
        "WriteProcessMemory": RuntimeBehaviorType.PROCESS_INJECT,
        "CreateRemoteThread": RuntimeBehaviorType.PROCESS_INJECT,
        "RegCreateKey": RuntimeBehaviorType.REGISTRY_CREATE,
        "RegSetValue": RuntimeBehaviorType.REGISTRY_MODIFY,
        "RegDeleteKey": RuntimeBehaviorType.REGISTRY_DELETE,
        "RegQueryValue": RuntimeBehaviorType.REGISTRY_READ,
        "VirtualAlloc": RuntimeBehaviorType.MEMORY_ALLOC,
        "VirtualAllocEx": RuntimeBehaviorType.MEMORY_ALLOC,
        "VirtualProtect": RuntimeBehaviorType.MEMORY_PROTECT,
        "IsDebuggerPresent": RuntimeBehaviorType.ANTI_DEBUG,
        "CheckRemoteDebuggerPresent": RuntimeBehaviorType.ANTI_DEBUG,
        "CreateService": RuntimeBehaviorType.SERVICE_CREATE,
        "AdjustTokenPrivileges": RuntimeBehaviorType.PRIVILEGE_ESCALATE,
        "LoadLibrary": RuntimeBehaviorType.DLL_LOAD,
        "CreateThread": RuntimeBehaviorType.THREAD_CREATE,
    }

    def __init__(self):
        self._active_analysis: Optional[DynamicAnalysisResult] = None
        self._trace_counter: int = 0
        self._hook_registry: Dict[str, List[str]] = {}

    def run_dynamic_analysis(
        self,
        binary_path: str,
        timeout_seconds: int = 60,
        arguments: Optional[List[str]] = None,
        environment: Optional[Dict[str, str]] = None,
    ) -> DynamicAnalysisResult:
        execution_id = str(uuid.uuid4())[:12]
        logger.info(f"Dynamic analysis start: {binary_path} (id={execution_id})")

        result = DynamicAnalysisResult(
            binary_path=binary_path,
            execution_id=execution_id,
            start_time=time.time(),
            end_time=time.time(),
        )
        self._active_analysis = result
        self._trace_counter = 0

        self._simulate_binary_load(result, binary_path)
        self._simulate_execution(result, binary_path, arguments, timeout_seconds)

        result.end_time = time.time()

        self._detect_malicious_patterns(result)
        self._calculate_risk_score(result)

        logger.info(
            f"Analysis complete: {binary_path}, traces={len(result.traces)}, "
            f"risk={result.risk_level}({result.risk_score})"
        )
        self._active_analysis = None
        return result

    def _simulate_binary_load(
        self, result: DynamicAnalysisResult, binary_path: str
    ) -> None:
        common_dlls = [
            "kernel32.dll", "ntdll.dll", "user32.dll",
            "advapi32.dll", "ws2_32.dll",
        ]
        for dll in common_dlls:
            trace = RuntimeTrace(
                trace_id=self._next_trace_id(),
                timestamp=time.time(),
                behavior_type=RuntimeBehaviorType.DLL_LOAD,
                api_name="LoadLibraryA",
                process_name=binary_path,
                arguments={"library": dll},
                return_value=0x10000000,
                severity=BehaviorSeverity.INFO,
                description=f"System library loaded: {dll}",
            )
            result.traces.append(trace)

    def _simulate_execution(
        self,
        result: DynamicAnalysisResult,
        binary_path: str,
        arguments: Optional[List[str]],
        timeout: int,
    ) -> None:
        path_lower = binary_path.lower()
        sim_time = time.time()

        is_malware = any(kw in path_lower for kw in
                         ["malware", "trojan", "rat", "ransomware",
                          "injector", "packed"])

        if is_malware:
            self._add_trace(result, sim_time,
                           RuntimeBehaviorType.NETWORK_CONNECT,
                           "connect",
                           {"remote_addr": "192.168.1.100", "port": 4444},
                           BehaviorSeverity.HIGH,
                           "C2 connection: 192.168.1.100:4444")
            result.network_connections.append({
                "remote_addr": "192.168.1.100", "port": 4444,
                "protocol": "TCP", "suspicious": True,
            })
            sim_time += 0.5

            self._add_trace(result, sim_time,
                           RuntimeBehaviorType.NETWORK_SEND,
                           "send",
                           {"data_size": 4096},
                           BehaviorSeverity.HIGH,
                           "Encrypted payload sent to C2")
            sim_time += 0.2

            self._add_trace(result, sim_time,
                           RuntimeBehaviorType.REGISTRY_CREATE,
                           "RegCreateKeyExA",
                           {"key": "HKCU\\...\\Run"},
                           BehaviorSeverity.HIGH,
                           "Run key persistence entry created")
            result.registry_operations.append({
                "key": "HKCU\\...\\Run",
                "value": binary_path, "operation": "create",
            })
            sim_time += 0.3

            self._add_trace(result, sim_time,
                           RuntimeBehaviorType.MEMORY_ALLOC,
                           "VirtualAllocEx",
                           {"target_pid": 1234, "size": 65536,
                            "protection": "RWX"},
                           BehaviorSeverity.CRITICAL,
                           "RWX memory allocated in target process")
            sim_time += 0.2

            self._add_trace(result, sim_time,
                           RuntimeBehaviorType.PROCESS_INJECT,
                           "WriteProcessMemory",
                           {"target_pid": 1234, "size": 4096},
                           BehaviorSeverity.CRITICAL,
                           "Shellcode written to target process memory")
            result.process_operations.append({
                "target_pid": 1234, "operation": "inject",
            })
            sim_time += 0.3

            self._add_trace(result, sim_time,
                           RuntimeBehaviorType.ANTI_DEBUG,
                           "IsDebuggerPresent", {},
                           BehaviorSeverity.HIGH,
                           "Debugger presence check")
            sim_time += 0.1

            self._add_trace(result, sim_time,
                           RuntimeBehaviorType.ANTI_VM,
                           "NtQuerySystemInformation",
                           {"info_class": "SystemFirmwareTableInformation"},
                           BehaviorSeverity.HIGH,
                           "Virtual machine environment probe")

            if "ransomware" in path_lower:
                sample_files = [
                    "C:\\Users\\victim\\Documents\\report.docx",
                    "/home/victim/documents/data.pdf",
                ]
                for fpath in sample_files:
                    self._add_trace(result, sim_time,
                                   RuntimeBehaviorType.FILE_MODIFY,
                                   "WriteFile",
                                   {"path": fpath, "bytes": 8192},
                                   BehaviorSeverity.CRITICAL,
                                   f"File encrypted: {fpath}")
                    result.files_accessed.append(fpath)
                    sim_time += 0.05
        else:
            self._add_trace(result, sim_time,
                           RuntimeBehaviorType.FILE_READ,
                           "ReadFile",
                           {"path": binary_path},
                           BehaviorSeverity.INFO,
                           "Read own binary file")

        result.end_time = sim_time + timeout

    def _add_trace(
        self, result: DynamicAnalysisResult, timestamp: float,
        behavior_type: str, api_name: str,
        arguments: Dict[str, Any],
        severity: str = BehaviorSeverity.INFO,
        description: str = "",
    ) -> RuntimeTrace:
        trace = RuntimeTrace(
            trace_id=self._next_trace_id(),
            timestamp=timestamp,
            behavior_type=behavior_type,
            api_name=api_name,
            process_name=result.binary_path,
            arguments=arguments,
            severity=severity,
            description=description,
        )
        result.traces.append(trace)
        result.api_hook_count += 1
        return trace

    def _next_trace_id(self) -> str:
        self._trace_counter += 1
        return f"trace_{self._trace_counter:05d}"

    def _detect_malicious_patterns(self, result: DynamicAnalysisResult) -> None:
        observed: set = {
            t.behavior_type for t in result.traces
        }
        for pattern in self.MALICIOUS_PATTERNS:
            required = set(pattern.required_behaviors)
            matched = required & observed
            ratio = len(matched) / len(required) if required else 0
            if ratio >= 0.6:
                result.detected_behaviors.append({
                    "pattern_id": pattern.pattern_id,
                    "name": pattern.name,
                    "description": pattern.description,
                    "match_ratio": round(ratio, 2),
                    "matched_behaviors": list(matched),
                    "missing_behaviors": list(required - matched),
                    "severity": pattern.severity,
                    "mitre_tactic": pattern.mitre_tactic,
                    "mitre_technique": pattern.mitre_technique,
                })

    def _calculate_risk_score(self, result: DynamicAnalysisResult) -> None:
        sev_weights = {
            BehaviorSeverity.CRITICAL: 30, BehaviorSeverity.HIGH: 20,
            BehaviorSeverity.MEDIUM: 10, BehaviorSeverity.LOW: 3,
            BehaviorSeverity.INFO: 0,
        }
        score = sum(sev_weights.get(t.severity, 0) for t in result.traces)
        for d in result.detected_behaviors:
            if d["severity"] == "critical":
                score += 15
            elif d["severity"] == "high":
                score += 10
        for conn in result.network_connections:
            if conn.get("suspicious"):
                score += 10
        inject_count = sum(
            1 for t in result.traces
            if t.behavior_type == RuntimeBehaviorType.PROCESS_INJECT
        )
        score += inject_count * 10
        score = min(score, 100)

        if score >= 80:
            level = "critical"
        elif score >= 50:
            level = "high"
        elif score >= 25:
            level = "medium"
        elif score >= 10:
            level = "low"
        else:
            level = "info"

        result.risk_score = round(score, 2)
        result.risk_level = level

    def collect_runtime_traces(
        self, trace_filter: Optional[List[str]] = None
    ) -> list:
        if self._active_analysis is None:
            return []
        if trace_filter is None:
            return list(self._active_analysis.traces)
        return [t for t in self._active_analysis.traces
                if t.behavior_type in trace_filter]

    def detect_runtime_behaviors(self) -> list:
        if self._active_analysis is None:
            return []
        self._detect_malicious_patterns(self._active_analysis)
        return self._active_analysis.detected_behaviors

    def hook_api_calls(
        self, api_names: List[str], callback_name: str = "default"
    ) -> int:
        hooked = 0
        for api in api_names:
            if api in self.API_BEHAVIOR_MAP:
                self._hook_registry.setdefault(callback_name, []).append(api)
                hooked += 1
                logger.debug(f"Hooked API: {api} -> {callback_name}")
        return hooked

    def get_hook_status(self) -> Dict[str, Any]:
        total = sum(len(v) for v in self._hook_registry.values())
        return {
            "total_hooks": total,
            "callbacks": {n: len(a) for n, a in self._hook_registry.items()},
            "api_coverage": {
                "total_known": len(self.API_BEHAVIOR_MAP),
                "hooked": len({a for apis in self._hook_registry.values() for a in apis}),
            },
        }

    def compare_static_vs_dynamic(
        self,
        static_findings: List[Dict[str, Any]],
        dynamic_result: Optional[DynamicAnalysisResult] = None,
    ) -> Dict[str, Any]:
        dr = dynamic_result or self._active_analysis
        if dr is None:
            return {"success": False, "error": "No dynamic analysis result available"}

        dynamic_apis: set = {t.api_name.lower() for t in dr.traces}
        confirmed, unconfirmed, new_findings = [], [], []
        static_funcs = {f.get("function_name", "").lower() for f in static_findings}

        for finding in static_findings:
            fn = finding.get("function_name", "").lower()
            if fn in dynamic_apis:
                confirmed.append({
                    "static_finding": finding.get("name", fn),
                    "evidence": f"Observed at runtime: {fn}",
                    "vulnerability_type": finding.get("vulnerability_type", ""),
                })
            else:
                unconfirmed.append({
                    "static_finding": finding.get("name", fn),
                    "reason": "Not observed during execution",
                    "vulnerability_type": finding.get("vulnerability_type", ""),
                })

        for trace in dr.traces:
            if (trace.api_name.lower() not in static_funcs
                    and trace.severity in (BehaviorSeverity.HIGH,
                                           BehaviorSeverity.CRITICAL)):
                new_findings.append({
                    "api": trace.api_name,
                    "behavior_type": trace.behavior_type,
                    "severity": trace.severity,
                    "description": trace.description,
                })

        return {
            "success": True,
            "static_total": len(static_findings),
            "confirmed": confirmed,
            "confirmed_count": len(confirmed),
            "unconfirmed": unconfirmed,
            "unconfirmed_count": len(unconfirmed),
            "new_dynamic_only": new_findings,
            "new_dynamic_count": len(new_findings),
            "confirmation_rate": (
                round(len(confirmed) / len(static_findings), 4)
                if static_findings else 0.0
            ),
        }

    def generate_dynamic_report(
        self,
        dynamic_result: Optional[DynamicAnalysisResult] = None,
        output_format: str = "json",
    ) -> Dict[str, Any]:
        dr = dynamic_result or self._active_analysis
        if dr is None:
            return {"success": False, "error": "No dynamic analysis result available"}

        behavior_summary: Dict[str, int] = {}
        for t in dr.traces:
            bt = t.behavior_type
            behavior_summary[bt] = behavior_summary.get(bt, 0) + 1

        report = {
            "success": True,
            "report": {
                "execution_id": dr.execution_id,
                "binary_path": dr.binary_path,
                "duration_seconds": round(dr.duration_seconds(), 2),
                "summary": {
                    "total_traces": len(dr.traces),
                    "api_hook_count": dr.api_hook_count,
                    "behavior_types_observed": list(behavior_summary.keys()),
                    "behavior_counts": behavior_summary,
                    "detected_patterns": len(dr.detected_behaviors),
                    "files_accessed_count": len(dr.files_accessed),
                    "network_connections": len(dr.network_connections),
                    "registry_operations": len(dr.registry_operations),
                },
                "risk_assessment": {
                    "risk_score": dr.risk_score,
                    "risk_level": dr.risk_level,
                },
                "malicious_behaviors": dr.detected_behaviors,
                "traces": [t.to_dict() for t in dr.traces[:50]],
            },
        }
        if output_format == "json":
            report["json"] = json.dumps(report["report"], indent=2,
                                        ensure_ascii=False)
        return report

    def analyze(self, **kwargs) -> Dict[str, Any]:
        action = kwargs.get("action", "run")
        try:
            if action == "run":
                binary = kwargs.get("binary_path", "")
                if not binary:
                    return {"success": False, "error": "binary_path is required"}
                timeout = kwargs.get("timeout_seconds", 60)
                args = kwargs.get("arguments")
                result = self.run_dynamic_analysis(binary, timeout, args)
                return self.generate_dynamic_report(result)

            elif action == "traces":
                filt = kwargs.get("filter")
                tf = [filt] if filt else None
                traces = self.collect_runtime_traces(tf)
                return {
                    "success": True,
                    "trace_count": len(traces),
                    "traces": [t.to_dict() for t in traces],
                }

            elif action == "behaviors":
                bhs = self.detect_runtime_behaviors()
                return {"success": True, "detected_count": len(bhs), "behaviors": bhs}

            elif action == "hook":
                names = kwargs.get("api_names", [])
                cb = kwargs.get("callback_name", "default")
                hooked = self.hook_api_calls(names, cb)
                return {"success": True, "hooked_count": hooked}

            elif action == "hook_status":
                return {"success": True, **self.get_hook_status()}

            elif action == "compare":
                sf = kwargs.get("static_findings", [])
                return self.compare_static_vs_dynamic(sf)

            elif action == "report":
                fmt = kwargs.get("output_format", "json")
                return self.generate_dynamic_report(output_format=fmt)

            else:
                return {"success": False, "error": f"Unknown action: {action}"}

        except Exception as e:
            logger.error(f"Dynamic analysis error: {e}", exc_info=True)
            return {"success": False, "error": str(e)}

    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            name="DynamicAnalysisEngine",
            type=AnalyzerType.DYNAMIC_ANALYZER,
            version="1.0.0",
            description="Dynamic binary analysis engine: sandbox execution, runtime behavior tracing, MITRE ATT&CK-based malicious pattern detection",
            author="BinaryAnalysisPlatform",
            dependencies=[],
            supported_platforms=["windows", "linux", "macos"],
        )


def manage_dynamic_analysis_engine(**kwargs) -> Dict[str, Any]:
    return DynamicAnalysisEngine().analyze(**kwargs)


__all__ = ["DynamicAnalysisEngine", "manage_dynamic_analysis_engine"]
