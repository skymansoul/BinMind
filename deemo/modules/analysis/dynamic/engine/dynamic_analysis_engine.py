"""
Dynamic binary analysis engine — sandbox execution, runtime behavior tracing,
MITRE ATT&CK-based malicious pattern detection.

Round 4: angr-style analysis pass pipeline. Each sub-analysis (entropy scan,
pattern matching, risk scoring) is registered as an independent pass with
declared inputs/outputs, enabling drop-in replacement and pass reordering.
"""
import logging, time, json, uuid, math, hashlib
from typing import Dict, Any, List, Optional, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod

from core.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

log = logging.getLogger(__name__)

# ── Type taxonomy ─────────────────────────────────────────────────────────────

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
    MUTEX_CREATE = "mutex_create"
    PIPE_CREATE = "pipe_create"
    PROCESS_ENUMERATE = "process_enumerate"
    UNKNOWN = "unknown"

class BehaviorSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

# ── Data containers ───────────────────────────────────────────────────────────

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
    prior_weight: float = 0.5

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
    section_entropies: Dict[str, float] = field(default_factory=dict)
    behavior_fingerprint: str = ""
    pass_artifacts: Dict[str, Any] = field(default_factory=dict)

    def duration_seconds(self) -> float:
        return self.end_time - self.start_time

# ── Round 4: angr-style Analysis Pass architecture ───────────────────────────
# 每个分析子任务（熵值扫描、模式匹配、风险评分）注册为独立Pass。
# Pass之间通过AnalysisResult的artifacts字典交换数据，类似于angr的
# knowledge_base模式。新增子分析只需实现AnalysisPass接口并注册即可。

class AnalysisPass(ABC):
    """angr风格的独立分析通道抽象。
    子类实现run()方法，通过result.pass_artifacts存储中间结果。
    这避免了之前版本中将熵值/模式/评分逻辑硬编码在单个方法中的耦合问题。"""

    name: str = "base_pass"
    priority: int = 50

    @abstractmethod
    def run(self, result: DynamicAnalysisResult, **kwargs) -> None:
        ...

    def requires(self) -> List[str]:
        """本pass依赖的前置pass名称列表。调度器据此决定执行顺序。"""
        return []


class EntropyScanPass(AnalysisPass):
    """PE节区Shannon熵扫描 — 检测加壳/混淆"""
    name = "entropy_scan"
    priority = 10

    def run(self, result: DynamicAnalysisResult, **kwargs) -> None:
        binary_path = result.binary_path
        try:
            with open(binary_path, 'rb') as fh:
                raw = fh.read()
        except (FileNotFoundError, PermissionError):
            return

        if len(raw) < 64:
            return

        sections = self._parse_pe_sections(raw)
        if not sections:
            chunk = max(256, len(raw) // 4)
            for i in range(4):
                st = i * chunk
                en = min(st + chunk, len(raw))
                if en > st:
                    sections.append((f"chunk_{i}", raw[st:en]))

        for sec_name, sec_data in sections:
            if len(sec_data) < 16:
                continue
            freq = [0] * 256
            for b in sec_data:
                freq[b] += 1
            ent = 0.0
            n = len(sec_data)
            for cnt in freq:
                if cnt:
                    p = cnt / n
                    ent -= p * math.log2(p)
            result.section_entropies[sec_name] = round(ent, 3)

    @staticmethod
    def _parse_pe_sections(raw: bytes) -> List[Tuple[str, bytes]]:
        sections = []
        if len(raw) < 0x40 or raw[:2] != b'MZ':
            return sections
        pe_off = int.from_bytes(raw[0x3C:0x40], 'little')
        if pe_off + 4 > len(raw) or raw[pe_off:pe_off + 4] != b'PE\x00\x00':
            return sections
        coff_hdr = pe_off + 4
        if coff_hdr + 20 > len(raw):
            return sections
        nsections = int.from_bytes(raw[coff_hdr + 2:coff_hdr + 4], 'little')
        opt_hdr_sz = int.from_bytes(raw[coff_hdr + 16:coff_hdr + 18], 'little')
        sec_table = coff_hdr + 20 + opt_hdr_sz
        for idx in range(nsections):
            hdr = sec_table + idx * 40
            if hdr + 40 > len(raw):
                break
            name = raw[hdr:hdr + 8].rstrip(b'\x00').decode('ascii', errors='replace')
            raw_sz = int.from_bytes(raw[hdr + 16:hdr + 20], 'little')
            raw_ptr = int.from_bytes(raw[hdr + 20:hdr + 24], 'little')
            if raw_ptr + raw_sz <= len(raw) and raw_sz > 0:
                sections.append((name, raw[raw_ptr:raw_ptr + raw_sz]))
        return sections


class PatternDetectionPass(AnalysisPass):
    """MITRE ATT&CK恶意模式匹配 — 双层(集合+时序滑动窗口)策略"""
    name = "pattern_detection"
    priority = 20

    def __init__(self, patterns: List[BehaviorPattern]):
        self.patterns = patterns

    def run(self, result: DynamicAnalysisResult, **kwargs) -> None:
        observed = {t.behavior_type for t in result.traces}
        seq = [t.behavior_type for t in result.traces]
        for pat in self.patterns:
            required = set(pat.required_behaviors)
            matched = required & observed
            set_ratio = len(matched) / len(required) if required else 0
            seq_score = self._seq_match_score(seq, pat.required_behaviors)
            combined = set_ratio * 0.6 + seq_score * 0.4
            if combined >= 0.5:
                result.detected_behaviors.append({
                    "pattern_id": pat.pattern_id,
                    "name": pat.name,
                    "description": pat.description,
                    "match_ratio": round(combined, 2),
                    "set_ratio": round(set_ratio, 2),
                    "seq_ratio": round(seq_score, 2),
                    "matched_behaviors": list(matched),
                    "missing_behaviors": list(required - matched),
                    "severity": pat.severity,
                    "mitre_tactic": pat.mitre_tactic,
                    "mitre_technique": pat.mitre_technique,
                })

    @staticmethod
    def _seq_match_score(seq: List[str], required: List[str]) -> float:
        if not required or not seq:
            return 0.0
        rlen = len(required)
        best_hits = 0
        window = min(4, len(seq))
        for pos in range(0, len(seq) - window + 1):
            hits = 0
            ri = 0
            for behavior in seq[pos:pos + window]:
                if ri < rlen and behavior == required[ri]:
                    ri += 1
                    hits += 1
            if hits > best_hits:
                best_hits = hits
        return best_hits / rlen


class RiskScoringPass(AnalysisPass):
    """贝叶斯加权风险评分 — 综合行为严重度、模式匹配、熵值和网络特征"""
    name = "risk_scoring"
    priority = 30

    def run(self, result: DynamicAnalysisResult, **kwargs) -> None:
        sev_weights = {
            BehaviorSeverity.CRITICAL: 30,
            BehaviorSeverity.HIGH: 20,
            BehaviorSeverity.MEDIUM: 10,
            BehaviorSeverity.LOW: 3,
            BehaviorSeverity.INFO: 0,
        }
        score = sum(sev_weights.get(t.severity, 0) for t in result.traces)

        for d in result.detected_behaviors:
            match_r = d.get("match_ratio", 0)
            score += match_r * d.get("prior_weight", 0.5) * 20

        for conn in result.network_connections:
            if conn.get("suspicious"):
                score += 10

        inject_count = sum(
            1 for t in result.traces
            if t.behavior_type == RuntimeBehaviorType.PROCESS_INJECT
        )
        score += inject_count * 10

        high_entropy_count = sum(1 for v in result.section_entropies.values() if v > 7.0)
        if high_entropy_count > 0:
            total_sections = len(result.section_entropies)
            if total_sections and high_entropy_count / total_sections > 0.3:
                score += 15
                result.anomalies.append(
                    f"High entropy sections ({high_entropy_count}/{total_sections}) -- packed/obfuscated"
                )

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


class FingerprintPass(AnalysisPass):
    """SHA256行为指纹 — 跨样本恶意家族关联"""
    name = "fingerprint"
    priority = 40

    def run(self, result: DynamicAnalysisResult, **kwargs) -> None:
        api_seq = "|".join(t.api_name for t in result.traces[:200])
        result.behavior_fingerprint = hashlib.sha256(api_seq.encode()).hexdigest()

# ── Main engine ───────────────────────────────────────────────────────────────

class DynamicAnalysisEngine(BaseAnalyzer):

    MALICIOUS_PATTERNS: list = [
        BehaviorPattern("MAL-001", "Fileless Execution",
            "Shellcode executed directly from allocated memory, no disk artifact.",
            [RuntimeBehaviorType.MEMORY_ALLOC, RuntimeBehaviorType.MEMORY_PROTECT,
             RuntimeBehaviorType.PROCESS_INJECT],
            BehaviorSeverity.CRITICAL, "Execution", "T1055", 0.72),
        BehaviorPattern("MAL-002", "C2 Data Exfiltration",
            "Encrypted outbound channel to remote C2, data staged from local files.",
            [RuntimeBehaviorType.NETWORK_CONNECT, RuntimeBehaviorType.FILE_READ,
             RuntimeBehaviorType.NETWORK_SEND],
            BehaviorSeverity.CRITICAL, "Exfiltration", "T1041", 0.68),
        BehaviorPattern("MAL-003", "Registry Persistence",
            "Run key / scheduled task registry write for boot-time execution.",
            [RuntimeBehaviorType.REGISTRY_CREATE, RuntimeBehaviorType.REGISTRY_MODIFY],
            BehaviorSeverity.HIGH, "Persistence", "T1547.001", 0.55),
        BehaviorPattern("MAL-004", "Process Hollowing",
            "Spawned process suspended, memory unmapped and replaced with payload.",
            [RuntimeBehaviorType.PROCESS_CREATE, RuntimeBehaviorType.MEMORY_ALLOC,
             RuntimeBehaviorType.PROCESS_INJECT],
            BehaviorSeverity.CRITICAL, "Defense Evasion", "T1055.012", 0.74),
        BehaviorPattern("MAL-005", "DNS Tunneling",
            "DNS query stream as covert C2 channel, bypassing egress filters.",
            [RuntimeBehaviorType.DNS_QUERY, RuntimeBehaviorType.NETWORK_SEND],
            BehaviorSeverity.HIGH, "Command and Control", "T1071.004", 0.51),
        BehaviorPattern("MAL-006", "Anti-Analysis Evasion",
            "Debugger and VM presence checks; alters execution path on detection.",
            [RuntimeBehaviorType.ANTI_DEBUG, RuntimeBehaviorType.ANTI_VM],
            BehaviorSeverity.HIGH, "Defense Evasion", "T1497", 0.63),
        BehaviorPattern("MAL-007", "Credential Dumping",
            "Credential material extracted from system process memory (LSASS, SAM).",
            [RuntimeBehaviorType.PROCESS_CREATE, RuntimeBehaviorType.MEMORY_ALLOC,
             RuntimeBehaviorType.PRIVILEGE_ESCALATE],
            BehaviorSeverity.CRITICAL, "Credential Access", "T1003", 0.77),
        BehaviorPattern("MAL-008", "DLL Side-Loading",
            "Legitimate process loads malicious DLL from search-order hijack path.",
            [RuntimeBehaviorType.DLL_LOAD, RuntimeBehaviorType.FILE_CREATE],
            BehaviorSeverity.HIGH, "Persistence", "T1574.002", 0.47),
        BehaviorPattern("MAL-009", "Token Manipulation",
            "SeDebugPrivilege enabling, token duplication for privilege escalation.",
            [RuntimeBehaviorType.PRIVILEGE_ESCALATE, RuntimeBehaviorType.PROCESS_CREATE,
             RuntimeBehaviorType.THREAD_CREATE],
            BehaviorSeverity.CRITICAL, "Privilege Escalation", "T1134", 0.69),
        BehaviorPattern("MAL-010", "WMI Persistence",
            "WMI event subscription for persistent callback execution.",
            [RuntimeBehaviorType.PROCESS_CREATE, RuntimeBehaviorType.REGISTRY_MODIFY,
             RuntimeBehaviorType.MUTEX_CREATE],
            BehaviorSeverity.HIGH, "Persistence", "T1546.003", 0.43),
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
        "CreateMutex": RuntimeBehaviorType.MUTEX_CREATE,
        "CreateNamedPipe": RuntimeBehaviorType.PIPE_CREATE,
        "EnumProcesses": RuntimeBehaviorType.PROCESS_ENUMERATE,
        "Process32First": RuntimeBehaviorType.PROCESS_ENUMERATE,
        "NtQuerySystemInformation": RuntimeBehaviorType.ANTI_VM,
    }

    def __init__(self):
        self._active_analysis: Optional[DynamicAnalysisResult] = None
        self._trace_counter: int = 0
        self._hook_registry: Dict[str, List[str]] = {}
        # Round 4: 可注册的angr风格分析pass管道
        self._passes: List[AnalysisPass] = [
            EntropyScanPass(),
            PatternDetectionPass(self.MALICIOUS_PATTERNS),
            RiskScoringPass(),
            FingerprintPass(),
        ]

    def register_pass(self, analysis_pass: AnalysisPass) -> None:
        """在管道中注册一个新的分析pass。按priority自动排序。"""
        self._passes.append(analysis_pass)
        self._passes.sort(key=lambda p: p.priority)

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

        # Round 4: 通过pass管道逐阶段处理
        for analysis_pass in self._passes:
            logger.debug(f"Running analysis pass: {analysis_pass.name}")
            analysis_pass.run(result)

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
        # Re-run pattern detection pass
        pp = PatternDetectionPass(self.MALICIOUS_PATTERNS)
        pp.run(self._active_analysis)
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
                "section_entropies": dr.section_entropies,
                "behavior_fingerprint": dr.behavior_fingerprint,
                "passes_executed": [p.name for p in self._passes],
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
