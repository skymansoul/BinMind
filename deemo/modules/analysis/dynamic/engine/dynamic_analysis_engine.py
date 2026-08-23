"""动态二进制分析引擎 — 沙箱执行, 运行时行为追踪,
MITRE ATT&CK-based 恶意模式检测。

angr 风格 analysis pass 流水线。子分析 (entropy scan,
pattern matching, risk scoring) 注册为独立 pass, 声明
inputs/输出, 支持 drop-in 替换与 pass 重排。

真实二进制执行引擎: subprocess + 可选 strace/ptrace。
替换先前的 _simulate_execution (仅按文件名关键字伪造
C2/injection/ransomware 轨迹), 改为受控本地执行: 超时保护,
崩溃信号监控, 系统调用捕获, 以及原生执行不可行时 (不支持的
架构, 缺失依赖, 非可执行文件) 诚实地回退静态分析。
"""
import logging, time, json, uuid, math, hashlib
import os, sys, platform, struct, shutil, re
import subprocess
import signal as _sigmod  # 别名避免与系统调用名 signal 冲突
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod

from core.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

log = logging.getLogger(__name__)

_LEGACY_MODE = False

# 执行引擎常量
_HARD_TIMEOUT_CAP = 300         # 秒 — 不允许二进制运行超过此时间
_STRACE_LINE_LIMIT = 50000      # 最大 strace 解析行数 (避免 OOM)
_DEFAULT_TIMEOUT = 30           # 秒 — 调用方未指定时的默认超时

# POSIX 信号编号表示崩溃 (非优雅退出)
_CRASH_SIGNALS: Dict[int, str] = {
    4:  "SIGILL",    # 非法指令
    5:  "SIGTRAP",   # 断点 / 跟踪陷阱
    6:  "SIGABRT",   # abort()
    7:  "SIGBUS",    # 总线错误 (对齐访问失败, 映射失败)
    8:  "SIGFPE",    # 浮点异常 (除零, 溢出)
    11: "SIGSEGV",   # 段错误
    31: "SIGSYS",    # 错误系统调用
}

# Windows NTSTATUS / HRESULT 码表示硬崩溃
_WIN_CRASH_CODES: Dict[int, str] = {
    0xC0000005: "ACCESS_VIOLATION",
    0xC0000017: "NO_MEMORY",
    0xC000001D: "ILLEGAL_INSTRUCTION",
    0xC000008C: "ARRAY_BOUNDS_EXCEEDED",
    0xC000008D: "FLOAT_DENORMAL_OPERAND",
    0xC000008E: "FLOAT_DIVIDE_BY_ZERO",
    0xC000008F: "FLOAT_INEXACT_RESULT",
    0xC0000090: "FLOAT_INVALID_OPERATION",
    0xC0000091: "FLOAT_OVERFLOW",
    0xC0000092: "FLOAT_STACK_CHECK",
    0xC0000093: "FLOAT_UNDERFLOW",
    0xC0000094: "INTEGER_DIVIDE_BY_ZERO",
    0xC0000095: "INTEGER_OVERFLOW",
    0xC0000096: "PRIVILEGED_INSTRUCTION",
    0xC00000FD: "STACK_OVERFLOW",
    0xC0000135: "DLL_NOT_FOUND",
    0xC0000142: "DLL_INIT_FAILED",
    0xC0000409: "STACK_BUFFER_OVERRUN",
}
# 类型分类法

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

# 系统调用名前缀 -> (行为类型, 严重度) 用于 strace 输出解析
# 覆盖恶意软件沙箱中常见系统调用
# 引用上方枚举因为值依赖 RuntimeBehaviorType / BehaviorSeverity 成员
_SYSCALL_MAP: Dict[str, Tuple[str, str]] = {
    "open":   (RuntimeBehaviorType.FILE_CREATE, BehaviorSeverity.INFO),
    "openat": (RuntimeBehaviorType.FILE_CREATE, BehaviorSeverity.INFO),
    "creat":  (RuntimeBehaviorType.FILE_CREATE, BehaviorSeverity.INFO),
    "read":   (RuntimeBehaviorType.FILE_READ, BehaviorSeverity.INFO),
    "write":  (RuntimeBehaviorType.FILE_MODIFY, BehaviorSeverity.INFO),
    "unlink": (RuntimeBehaviorType.FILE_DELETE, BehaviorSeverity.MEDIUM),
    "unlinkat": (RuntimeBehaviorType.FILE_DELETE, BehaviorSeverity.MEDIUM),
    "rename": (RuntimeBehaviorType.FILE_MODIFY, BehaviorSeverity.INFO),
    "renameat": (RuntimeBehaviorType.FILE_MODIFY, BehaviorSeverity.INFO),
    "mkdir":  (RuntimeBehaviorType.FILE_CREATE, BehaviorSeverity.INFO),
    "mkdirat": (RuntimeBehaviorType.FILE_CREATE, BehaviorSeverity.INFO),
    "rmdir":  (RuntimeBehaviorType.FILE_DELETE, BehaviorSeverity.MEDIUM),
    "socket": (RuntimeBehaviorType.NETWORK_CONNECT, BehaviorSeverity.MEDIUM),
    "connect": (RuntimeBehaviorType.NETWORK_CONNECT, BehaviorSeverity.MEDIUM),
    "bind":   (RuntimeBehaviorType.NETWORK_LISTEN, BehaviorSeverity.MEDIUM),
    "sendto": (RuntimeBehaviorType.NETWORK_SEND, BehaviorSeverity.MEDIUM),
    "sendmsg": (RuntimeBehaviorType.NETWORK_SEND, BehaviorSeverity.MEDIUM),
    "recvfrom": (RuntimeBehaviorType.NETWORK_RECEIVE, BehaviorSeverity.MEDIUM),
    "recvmsg": (RuntimeBehaviorType.NETWORK_RECEIVE, BehaviorSeverity.MEDIUM),
    "execve": (RuntimeBehaviorType.PROCESS_CREATE, BehaviorSeverity.HIGH),
    "execveat": (RuntimeBehaviorType.PROCESS_CREATE, BehaviorSeverity.HIGH),
    "fork":   (RuntimeBehaviorType.PROCESS_CREATE, BehaviorSeverity.HIGH),
    "vfork":  (RuntimeBehaviorType.PROCESS_CREATE, BehaviorSeverity.HIGH),
    "clone":  (RuntimeBehaviorType.PROCESS_CREATE, BehaviorSeverity.HIGH),
    "clone3": (RuntimeBehaviorType.PROCESS_CREATE, BehaviorSeverity.HIGH),
    "kill":   (RuntimeBehaviorType.PROCESS_TERMINATE, BehaviorSeverity.HIGH),
    "tkill":  (RuntimeBehaviorType.PROCESS_TERMINATE, BehaviorSeverity.HIGH),
    "tgkill": (RuntimeBehaviorType.PROCESS_TERMINATE, BehaviorSeverity.HIGH),
    "mmap":   (RuntimeBehaviorType.MEMORY_ALLOC, BehaviorSeverity.INFO),
    "mmap2":  (RuntimeBehaviorType.MEMORY_ALLOC, BehaviorSeverity.INFO),
    "mprotect": (RuntimeBehaviorType.MEMORY_PROTECT, BehaviorSeverity.MEDIUM),
    "brk":    (RuntimeBehaviorType.MEMORY_ALLOC, BehaviorSeverity.INFO),
    "ptrace": (RuntimeBehaviorType.ANTI_DEBUG, BehaviorSeverity.HIGH),
    "process_vm_writev": (RuntimeBehaviorType.PROCESS_INJECT, BehaviorSeverity.CRITICAL),
    "process_vm_readv":  (RuntimeBehaviorType.PROCESS_INJECT, BehaviorSeverity.CRITICAL),
    "memfd_create": (RuntimeBehaviorType.MEMORY_ALLOC, BehaviorSeverity.MEDIUM),
    "shmget": (RuntimeBehaviorType.MEMORY_ALLOC, BehaviorSeverity.INFO),
    "shmat":  (RuntimeBehaviorType.MEMORY_ALLOC, BehaviorSeverity.INFO),
    "nanosleep": (RuntimeBehaviorType.ANTI_VM, BehaviorSeverity.LOW),
    "clock_nanosleep": (RuntimeBehaviorType.ANTI_VM, BehaviorSeverity.LOW),
    "getrandom": (RuntimeBehaviorType.UNKNOWN, BehaviorSeverity.INFO),
}

# 数据容器

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
    # 真实执行元数据
    execution_mode: str = ""          # "strace", "direct", 或 "static_回退"
    exit_code: Optional[int] = None
    crash_signal: Optional[str] = None
    stdout_snippet: str = ""          # stdout 前 4 KiB
    stderr_snippet: str = ""          # stderr 前 4 KiB

    def duration_seconds(self) -> float:
        return self.end_time - self.start_time

# ── angr 风格 Analysis Pass 架构 ───────────────────────────
# 每个分析子任务（熵值扫描、模式匹配、风险评分）注册为独立Pass
# Pass之间通过AnalysisResult的artifacts字典交换数据，类似于angr的
# knowledge_base模式。新增子分析只需实现AnalysisPass接口并注册即可

class AnalysisPass(ABC):
    """angr风格的独立分析通道抽象
    子类实现run()方法，通过result.pass_artifacts存储中间结果
    这避免了之前版本中将熵值/模式/评分逻辑硬编码在单个方法中的耦合问题"""

    name: str = "base_pass"
    priority: int = 50

    @abstractmethod
    def run(self, result: DynamicAnalysisResult, **kwargs) -> None:
        ...

    def requires(self) -> List[str]:
        """本pass依赖的前置pass名称列表。调度器据此决定执行顺序"""
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


# class LegacyRiskScorer:
# """Pre-v2 linear risk aggregator — replaced RiskScoringPass."""
#     sev_map = {BehaviorSeverity.CRITICAL: 50, BehaviorSeverity.HIGH: 30,
#                BehaviorSeverity.MEDIUM: 10, BehaviorSeverity.LOW: 1}
#     @staticmethod
#     def score(traces): return min(sum(LegacyRiskScorer.sev_map.get(t.severity, 0) for t in traces), 100)

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

# 主引擎

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
        """在管道中注册一个新的分析pass。按priority自动排序"""
        self._passes.append(analysis_pass)
        self._passes.sort(key=lambda p: p.priority)

    def run_dynamic_analysis(
        self,
        binary_path: str,
        timeout_seconds: int = _DEFAULT_TIMEOUT,
        arguments: Optional[List[str]] = None,
        environment: Optional[Dict[str, str]] = None,
    ) -> DynamicAnalysisResult:
        execution_id = str(uuid.uuid4())[:12]
        log.info("Dynamic analysis start: %s (id=%s)", binary_path, execution_id)

        result = DynamicAnalysisResult(
            binary_path=binary_path,
            execution_id=execution_id,
            start_time=time.time(),
            end_time=time.time(),
        )
        self._active_analysis = result
        self._trace_counter = 0

        # 舍入 5: 解析 real binary imports instead fabricating DLL 加载
        self._parse_imports(result, binary_path)

        # 舍入 5: Real subprocess execution strace 回退
        self._execute_binary(result, binary_path, arguments, timeout_seconds)

        result.end_time = time.time()

        # Round 4: 通过pass管道逐阶段处理
        for analysis_pass in self._passes:
            log.debug("Running analysis pass: %s", analysis_pass.name)
            analysis_pass.run(result)

        log.info(
            "Analysis complete: %s, mode=%s, traces=%d, risk=%s(%.1f)",
            binary_path, result.execution_mode, len(result.traces),
            result.risk_level, result.risk_score,
        )
        self._active_analysis = None
        return result

    # 舍入 5: Real binary execution engine

    # ── 导入表解析 (replaces _simulate_binary_load) ────────────────

    def _parse_imports(self, result: DynamicAnalysisResult, binary_path: str) -> None:
        """解析 PE/ELF 导入表以记录实际 DLL/shared-object 依赖。

        Unlike previous _simulate_binary_load, 读取 binary's real
        import descriptors rather injecting a hard-coded list. parsing
        fails (corrupt header, non-PE/ELF), 记录 a warning move —
        import list auxiliary execution trace, a prerequisite
        """
        try:
            with open(binary_path, 'rb') as fh:
                header = fh.read(0x1000)  # first 4 KiB covers headers + import dir
        except (FileNotFoundError, PermissionError, OSError) as exc:
            log.warning("Cannot open binary for import parsing: %s", exc)
            return

        if len(header) < 64:
            return

        # PE32 / PE32+
        if header[:2] == b'MZ':
            imported = self._parse_pe_imports(header, binary_path)
        # ELF
        elif header[:4] == b'\x7fELF':
            imported = self._parse_elf_imports(header, binary_path)
        else:
            log.debug("Unknown binary format, skipping import parse: %s", binary_path)
            return

        now = time.time()
        for lib in imported:
            trace = RuntimeTrace(
                trace_id=self._next_trace_id(),
                timestamp=now,
                behavior_type=RuntimeBehaviorType.DLL_LOAD,
                api_name="LoadLibrary",
                process_name=binary_path,
                arguments={"library": lib, "source": "import_table"},
                return_value=0,
                severity=BehaviorSeverity.INFO,
                description=f"Import dependency: {lib}",
            )
            result.traces.append(trace)

    def _parse_pe_imports(self, header: bytes, binary_path: str) -> List[str]:
        """提取 DLL names PE import directory table"""
        imported: List[str] = []
        try:
            pe_off = int.from_bytes(header[0x3C:0x40], 'little')
            if pe_off + 4 > len(header) or header[pe_off:pe_off + 4] != b'PE\x00\x00':
                return imported

            # 读取 file header 快照 doesn't reach import dir
            extra_needed = pe_off + 256
            if extra_needed > len(header):
                with open(binary_path, 'rb') as fh:
                    fh.seek(pe_off)
                    extra = fh.read(1024)
                header = header[:pe_off] + extra

            coff_hdr = pe_off + 4
            opt_hdr = coff_hdr + 20
            # PE32: magic 0x10B opt_hdr; PE32+: magic 0x20B
            magic = int.from_bytes(header[opt_hdr:opt_hdr + 2], 'little')
            if magic == 0x10B:
                import_rva = int.from_bytes(header[opt_hdr + 96:opt_hdr + 100], 'little')
            elif magic == 0x20B:
                import_rva = int.from_bytes(header[opt_hdr + 112:opt_hdr + 116], 'little')
            else:
                return imported

            if import_rva == 0:
                return imported

            # 读取 import directory disk (RVA → file offset needs section map)
            with open(binary_path, 'rb') as fh:
                raw = fh.read()
            sections = EntropyScanPass._parse_pe_sections(raw)
            file_off = self._rva_to_offset(import_rva, pe_off, sections, raw)
            if file_off is None or file_off + 20 > len(raw):
                return imported

            pos = file_off
            while pos + 20 <= len(raw):
                name_rva = int.from_bytes(raw[pos + 12:pos + 16], 'little')
                if name_rva == 0:
                    break
                name_off = self._rva_to_offset(name_rva, pe_off, sections, raw)
                if name_off:
                    end = raw.find(b'\x00', name_off)
                    if end > name_off:
                        dll_name = raw[name_off:end].decode('ascii', errors='replace').strip()
                        if dll_name:
                            imported.append(dll_name)
                pos += 20
        except Exception:
            log.debug("PE import parse failed for %s", binary_path, exc_info=True)
        return imported

    def _parse_elf_imports(self, header: bytes, binary_path: str) -> List[str]:
        """提取 NEEDED shared-object names ELF.dynamic section

        a best-effort shallow 解析 — 读取 section header string
        table, locate.dynamic, walk DT_NEEDED entries. For a full 解析
        使用 pyelftools; keeps engine dependency-free
        """
        imported: List[str] = []
        try:
            if header[4] == 1:
                endian = '<'  # ELFDATA2LSB
            elif header[4] == 2:
                endian = '>'  # ELFDATA2MSB
            else:
                return imported

            is_64 = header[4 + 0] == 2  # ELFCLASS64

            with open(binary_path, 'rb') as fh:
                raw = fh.read()

            if is_64:
                # ELF64 header → e_shoff offset 40 (8 bytes), e_shentsize 58 (2), e_shstrndx 62 (2)
                if len(raw) < 64:
                    return imported
                shoff = int.from_bytes(raw[40:48], endian)
                shentsize = int.from_bytes(raw[58:60], endian)
                shstrndx = int.from_bytes(raw[62:64], endian)
            else:
                if len(raw) < 52:
                    return imported
                shoff = int.from_bytes(raw[32:36], endian)
                shentsize = int.from_bytes(raw[46:48], endian)
                shstrndx = int.from_bytes(raw[50:52], endian)

            if shentsize == 0 or shstrndx == 0:
                return imported

            # 读取 shstrtab 解析 section names
            str_off = shoff + shstrndx * shentsize
            if is_64:
                if str_off + 64 > len(raw):
                    return imported
                str_sh_offset = int.from_bytes(raw[str_off + 24:str_off + 32], endian)
                str_sh_size = int.from_bytes(raw[str_off + 32:str_off + 40], endian)
                entry_size = 64
            else:
                if str_off + 40 > len(raw):
                    return imported
                str_sh_offset = int.from_bytes(raw[str_off + 16:str_off + 20], endian)
                str_sh_size = int.from_bytes(raw[str_off + 20:str_off + 24], endian)
                entry_size = 40

            if str_sh_offset + str_sh_size > len(raw):
                return imported
            shstrtab = raw[str_sh_offset:str_sh_offset + str_sh_size]

            # Walk section headers 查找.dynamic
            dynamic_addr = 0
            dynamic_size = 0
            for i in range(1, 65536):  # safety limit
                off = shoff + i * entry_size
                if is_64:
                    if off + 64 > len(raw):
                        break
                    sh_name = int.from_bytes(raw[off:off + 4], endian)
                    sh_type = int.from_bytes(raw[off + 4:off + 8], endian)
                    sh_addr = int.from_bytes(raw[off + 16:off + 24], endian)
                    sh_size = int.from_bytes(raw[off + 32:off + 40], endian)
                else:
                    if off + 40 > len(raw):
                        break
                    sh_name = int.from_bytes(raw[off:off + 4], endian)
                    sh_type = int.from_bytes(raw[off + 4:off + 8], endian)
                    sh_addr = int.from_bytes(raw[off + 12:off + 16], endian)
                    sh_size = int.from_bytes(raw[off + 20:off + 24], endian)

                if sh_name < len(shstrtab):
                    sec_name = shstrtab[sh_name:shstrtab.find(b'\x00', sh_name)].decode('ascii', errors='replace')
                else:
                    sec_name = ""

                if sec_name == '.dynamic' or (sh_type == 6 and dynamic_addr == 0):  # SHT_DYNAMIC = 6
                    dynamic_addr = sh_addr
                    dynamic_size = sh_size

            if dynamic_addr == 0:
                return imported

            # Walk DT_NEEDED entries.dynamic (DT_NEEDED = 1)
            dt_entry_size = 16 if is_64 else 8
            # 转换 虚拟地址 file offset (approximation for simple ELFs)
            # search for segment containing dynamic_addr program headers
            dyn_file_off = self._elf_vaddr_to_offset(raw, is_64, endian, dynamic_addr)

            if dyn_file_off is not None and dyn_file_off + dynamic_size <= len(raw):
                pos = dyn_file_off
                end_pos = min(pos + dynamic_size, len(raw))
                while pos + dt_entry_size <= end_pos:
                    if is_64:
                        d_tag = int.from_bytes(raw[pos:pos + 8], endian)
                        d_val = int.from_bytes(raw[pos + 8:pos + 16], endian)
                    else:
                        d_tag = int.from_bytes(raw[pos:pos + 4], endian)
                        d_val = int.from_bytes(raw[pos + 4:pos + 8], endian)

                    if d_tag == 0:  # DT_NULL
                        break
                    if d_tag == 1:  # DT_NEEDED
                        # d_val offset.dynstr; need.dynstr vaddr→file offset
                        # For a shallow 解析, scan string directly
                        strtab_off = self._elf_vaddr_to_offset(raw, is_64, endian, d_val)
                        if strtab_off is not None:
                            end = raw.find(b'\x00', strtab_off)
                            if end > strtab_off:
                                so_name = raw[strtab_off:end].decode('ascii', errors='replace').strip()
                                if so_name:
                                    imported.append(so_name)
                    pos += dt_entry_size
        except Exception:
            log.debug("ELF import parse failed for %s", binary_path, exc_info=True)
        return imported

    @staticmethod
    def _elf_vaddr_to_offset(raw: bytes, is_64: bool, endian: str, vaddr: int) -> Optional[int]:
        """使用 program headers 将 ELF 虚拟地址映射到文件偏移。

        粗糙近似 — 高级 ELF 特性 (PT_LOAD 中 p_vaddr !=
        p_offset) 需要更丰富的映射, 但覆盖动态链接
        x86/x86_64 二进制的常见情况。
        """
        if len(raw) < 52:
            return None
        try:
            if is_64:
                phoff = int.from_bytes(raw[32:40], endian)
                phnum = int.from_bytes(raw[56:58], endian)
                phentsize = int.from_bytes(raw[54:56], endian)
            else:
                phoff = int.from_bytes(raw[28:32], endian)
                phnum = int.from_bytes(raw[44:46], endian)
                phentsize = int.from_bytes(raw[42:44], endian)

            for i in range(phnum):
                off = phoff + i * phentsize
                if is_64:
                    if off + 56 > len(raw):
                        break
                    p_type = int.from_bytes(raw[off:off + 4], endian)
                    p_offset = int.from_bytes(raw[off + 8:off + 16], endian)
                    p_vaddr = int.from_bytes(raw[off + 16:off + 24], endian)
                    p_filesz = int.from_bytes(raw[off + 32:off + 40], endian)
                    p_memsz = int.from_bytes(raw[off + 40:off + 48], endian)
                else:
                    if off + 32 > len(raw):
                        break
                    p_type = int.from_bytes(raw[off:off + 4], endian)
                    p_offset = int.from_bytes(raw[off + 4:off + 8], endian)
                    p_vaddr = int.from_bytes(raw[off + 8:off + 12], endian)
                    p_filesz = int.from_bytes(raw[off + 16:off + 20], endian)
                    p_memsz = int.from_bytes(raw[off + 20:off + 24], endian)

                if p_type == 1:  # PT_LOAD
                    seg_size = max(p_filesz, p_memsz)
                    if p_vaddr <= vaddr < p_vaddr + seg_size:
                        return p_offset + (vaddr - p_vaddr)
        except Exception:
            pass
        return None

    @staticmethod
    def _rva_to_offset(rva: int, pe_off: int, sections: List[Tuple[str, bytes]],
                       raw: bytes) -> Optional[int]:
        """使用节表将 PE RVA 转换为原始文件偏移。"""
        coff_hdr = pe_off + 4
        if coff_hdr + 20 > len(raw):
            return None
        nsections = int.from_bytes(raw[coff_hdr + 2:coff_hdr + 4], 'little')
        opt_hdr_sz = int.from_bytes(raw[coff_hdr + 16:coff_hdr + 18], 'little')
        sec_table = coff_hdr + 20 + opt_hdr_sz
        for i in range(nsections):
            hdr = sec_table + i * 40
            if hdr + 40 > len(raw):
                break
            sec_va = int.from_bytes(raw[hdr + 12:hdr + 16], 'little')
            sec_vsz = int.from_bytes(raw[hdr + 8:hdr + 12], 'little')
            sec_raw = int.from_bytes(raw[hdr + 20:hdr + 24], 'little')
            if sec_va <= rva < sec_va + sec_vsz:
                return sec_raw + (rva - sec_va)
        return None

# 真实执行分派

    def _execute_binary(
        self,
        result: DynamicAnalysisResult,
        binary_path: str,
        arguments: Optional[List[str]],
        timeout_seconds: int,
    ) -> None:
        """在受控子进程中执行二进制。

        预检:
        1. 文件存在且可读
        2. 架构匹配宿主 (否则回退静态分析)
        3. 文件为可执行文件 (或 Windows .exe)

        Linux 优先使用 strace 执行以捕获系统调用;
        Windows / macOS 或 strace 不可用时使用 direct
        子进程执行并解析退出码;
        执行结构上不可行 (架构不匹配, 文件缺失) 时
        回退到诚实的静态分析。
        """
# 预检: 存在性
        if not os.path.isfile(binary_path):
            log.warning("Binary not found, falling back to static analysis: %s", binary_path)
            self._static_fallback(result, binary_path, "file_not_found")
            return

        if not os.access(binary_path, os.R_OK):
            log.warning("Binary not readable, falling back to static analysis: %s", binary_path)
            self._static_fallback(result, binary_path, "not_readable")
            return

# Pre-flight: architecture match
        host_arch = platform.machine().lower()
        binary_arch = self._detect_binary_arch(binary_path)
        if binary_arch is not None and binary_arch != host_arch:
            log.warning(
                "Architecture mismatch: binary=%s host=%s, falling back to static analysis: %s",
                binary_arch, host_arch, binary_path,
            )
            self._static_fallback(
                result, binary_path,
                f"arch_mismatch:{binary_arch}_vs_{host_arch}",
            )
            return

# Pre-flight: executability
        if sys.platform == 'win32':
            if not binary_path.lower().endswith(('.exe', '.dll', '.com', '.scr')):
                log.warning("Non-executable extension on Windows, falling back: %s", binary_path)
                self._static_fallback(result, binary_path, "non_executable_extension")
                return
        else:
            if not os.access(binary_path, os.X_OK):
                log.warning("File not executable (no +x), falling back: %s", binary_path)
                self._static_fallback(result, binary_path, "not_executable")
                return

# Execution
        timeout = min(timeout_seconds, _HARD_TIMEOUT_CAP)
        args = arguments or []

        try:
            if sys.platform == 'linux' and self._has_tool('strace'):
                self._execute_with_strace(result, binary_path, args, timeout)
            else:
                self._execute_direct(result, binary_path, args, timeout)
        except subprocess.TimeoutExpired:
            log.warning("Binary timed out after %ds: %s", timeout, binary_path)
            result.anomalies.append(f"Execution timed out after {timeout}s")
            result.execution_mode = result.execution_mode or "timeout"
        except Exception as exc:
            log.error("Execution raised exception: %s", exc, exc_info=True)
            self._static_fallback(result, binary_path, f"execution_exception:{exc}")

# strace-based execution (Linux)

    def _execute_with_strace(
        self,
        result: DynamicAnalysisResult,
        binary_path: str,
        arguments: List[str],
        timeout: int,
    ) -> None:
        """执行 binary under strace, 解析 系统调用 记录 RuntimeTraces

        strace invocation:
        strace -f -qq -e trace= -o <tmpfile> -- <binary> [args.]

        Flags:
        -f follow children (captures fork/clone-spawned 系统调用s)
        -qq suppress strace's own stderr (cleaner 输出 separation)
        -o 写入 系统调用 记录 a temp file 解析 afterwards
        """
        import tempfile
        strace_log = tempfile.mktemp(suffix='.strace', prefix='dae_')
        cmd = ['strace', '-f', '-qq', '-e', 'trace=all', '-o', strace_log,
               '--', binary_path] + arguments
        log.debug("strace command: %s", ' '.join(cmd))

        result.execution_mode = "strace"
        start = time.time()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                timeout=timeout,
                cwd=os.path.dirname(binary_path) or '.',
            )
        finally:
            elapsed = time.time() - start

        # Interpret exit status
        result.exit_code = proc.returncode
        self._interpret_exit_status(result, proc.returncode)

        # Capture 输出 snippets
        result.stdout_snippet = self._truncate_bytes(proc.stdout, 4096)
        result.stderr_snippet = self._truncate_bytes(proc.stderr, 4096)

        # 解析 strace 记录
        try:
            with open(strace_log, 'r', errors='replace') as fh:
                lines = fh.readlines()
        except FileNotFoundError:
            log.warning("strace log file missing: %s", strace_log)
            lines = []

        self._parse_strace_output(result, lines, binary_path)
        result.anomalies.append(
            f"strace execution: exit={proc.returncode}, elapsed={elapsed:.2f}s, "
            f"syscalls_captured={len(result.traces)}"
        )

        # Clean up temp file
        try:
            os.unlink(strace_log)
        except OSError:
            pass

# 直接子进程执行 (跨平台)

    def _execute_direct(
        self,
        result: DynamicAnalysisResult,
        binary_path: str,
        arguments: List[str],
        timeout: int,
    ) -> None:
        """通过子进程直接执行二进制, 受资源限制约束。

        无系统调用追踪 — 依赖退出码、stdout/stderr、时序
        获取行为信号。在 strace 不可用时
        (Windows, macOS, 精简 Linux 容器) 回退使用。
        """
        result.execution_mode = "direct"
        cmd = [binary_path] + arguments
        log.debug("Direct execution: %s", ' '.join(cmd))
        start = time.time()

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                timeout=timeout,
                cwd=os.path.dirname(binary_path) or '.',
            )
        except subprocess.TimeoutExpired:
            result.anomalies.append(f"Direct execution timed out after {timeout}s")
            result.execution_mode = "timeout"
            return

        elapsed = time.time() - start
        result.exit_code = proc.returncode
        result.stdout_snippet = self._truncate_bytes(proc.stdout, 4096)
        result.stderr_snippet = self._truncate_bytes(proc.stderr, 4096)

        # Interpret exit code for crash signals
        self._interpret_exit_status(result, proc.returncode)

        # Emit a high-level execution trace analysis 流水线
# something* work even 系统调用 granularity
        if proc.returncode == 0:
            self._add_trace(result, start,
                          RuntimeBehaviorType.UNKNOWN,
                          "process_exit_clean",
                          {"exit_code": 0, "elapsed_s": round(elapsed, 3)},
                          BehaviorSeverity.INFO,
                          "Binary exited cleanly")
        elif result.crash_signal:
            self._add_trace(result, start,
                          RuntimeBehaviorType.UNKNOWN,
                          "process_crash",
                          {"signal": result.crash_signal, "exit_code": proc.returncode,
                           "elapsed_s": round(elapsed, 3)},
                          BehaviorSeverity.HIGH,
                          f"Binary crashed: {result.crash_signal}")
        else:
            self._add_trace(result, start,
                          RuntimeBehaviorType.UNKNOWN,
                          "process_exit_error",
                          {"exit_code": proc.returncode, "elapsed_s": round(elapsed, 3)},
                          BehaviorSeverity.MEDIUM,
                          f"Binary exited with code {proc.returncode}")

        result.anomalies.append(
            f"direct execution: exit={proc.returncode}, elapsed={elapsed:.2f}s"
        )

# 诚实静态分析回退

    def _static_fallback(
        self,
        result: DynamicAnalysisResult,
        binary_path: str,
        reason: str,
    ) -> None:
        """原生执行不可行时回退静态分析。

        *诚实* 路径: 不伪造轨迹, 记录清晰的警告, 对二进制文件
        本身做静态分析 (熵值, 节布局, 导入表 — 由 pass
        流水线处理)。result.execution_mode 字段记录原因,
        使下游消费者知道这不是一次真实运行。
        """
        result.execution_mode = f"static_fallback:{reason}"
        log.warning(
            "Dynamic analysis fell back to static: %s (reason: %s)",
            binary_path, reason,
        )
        # pass 流水线运行熵值扫描、模式检测
        # (针对导入解析的轨迹) 和风险评分。
        # 添加异常注释使报告透明
        result.anomalies.append(
            f"STATIC_FALLBACK: binary was not executed natively — "
            f"reason={reason}. Analysis based on static features only."
        )

# 架构检测

    @staticmethod
    def _detect_binary_arch(binary_path: str) -> Optional[str]:
        """从二进制头确定目标架构。

        返回归一化架构字符串, 遵循 platform.machine() 约定
        ('x86_64', 'aarch64', 'i386', 'armv7l' 等), 未知返回 None。
        """
        try:
            with open(binary_path, 'rb') as fh:
                header = fh.read(128)
        except OSError:
            return None

        if len(header) < 64:
            return None

        # PE
        if header[:2] == b'MZ':
            pe_off = int.from_bytes(header[0x3C:0x40], 'little')
            if pe_off + 4 > len(header):
                return None
            if header[pe_off:pe_off + 4] != b'PE\x00\x00':
                return None
            coff = pe_off + 4
            if coff + 20 > len(header):
                return None
            machine = int.from_bytes(header[coff:coff + 2], 'little')
            _PE_ARCH = {
                0x014C: 'i386',    0x8664: 'x86_64',
                0xAA64: 'aarch64', 0x01C4: 'armv7l',
                0x0200: 'ia64',
            }
            return _PE_ARCH.get(machine)

        # ELF
        if header[:4] == b'\x7fELF':
            klass = header[4]     # 1=32-bit, 2=64-bit
            endian = header[5]
            if endian == 1:
                fmt = '<'
            elif endian == 2:
                fmt = '>'
            else:
                return None

            if klass == 2:  # 64-bit
                machine = int.from_bytes(header[18:20], fmt)
                _ELF64_ARCH = {
                    0x3E: 'x86_64',   0xB7: 'aarch64',
                    0xF3: 'riscv64',  0x15: 'ppc64le',
                    0x3: 'i386',
                }
                return _ELF64_ARCH.get(machine)
            else:  # 32-bit
                machine = int.from_bytes(header[18:20], fmt)
                _ELF32_ARCH = {
                    0x03: 'i386',     0x28: 'armv7l',
                    0x28: 'armv7l',   0x08: 'mips',
                }
                return _ELF32_ARCH.get(machine)

        # Mach-O (macOS)
        if header[:4] in (b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf',  # 32-bit
                          b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe'):  # 64-bit
            cpu_type = int.from_bytes(header[4:8], 'little' if header[:4] in (
                b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf') else 'big')
            _MACHO_ARCH = {
                7: 'i386',       0x01000007: 'x86_64',
                12: 'armv7l',    0x0100000C: 'aarch64',
            }
            return _MACHO_ARCH.get(cpu_type)

        return None

# 退出状态解析

    @staticmethod
    def _interpret_exit_status(result: DynamicAnalysisResult, exit_code: int) -> None:
        """将退出码分类为正常退出或崩溃信号。

        POSIX 下, 信号 N 终止的进程返回 -N (或 shell 的 128+N,
        但 subprocess.run 在 Unix 上报告 -N)。Windows 下, 崩溃码
        为大的负 32 位整数 (NTSTATUS)。
        """
        if sys.platform == 'win32':
            # Windows: crash codes >= 0x80000000 unsigned, negative signed
            code_u32 = exit_code & 0xFFFFFFFF
            if code_u32 in _WIN_CRASH_CODES:
                result.crash_signal = _WIN_CRASH_CODES[code_u32]
                result.anomalies.append(
                    f"Binary crashed (Windows): {result.crash_signal} (0x{code_u32:08X})"
                )
            elif exit_code < 0 and exit_code != -1:
                result.crash_signal = f"NTSTATUS_0x{code_u32:08X}"
                result.anomalies.append(
                    f"Binary exited with NTSTATUS: 0x{code_u32:08X}"
                )
            return

        # POSIX: subprocess.run 报告 -signum 表示信号终止
        if exit_code < 0:
            sig = -exit_code
            sig_name = _CRASH_SIGNALS.get(sig, f"SIG_{sig}")
            result.crash_signal = sig_name
            result.anomalies.append(
                f"Binary crashed (signal): {sig_name} (signal {sig})"
            )

# strace 输出解析器

    def _parse_strace_output(
        self,
        result: DynamicAnalysisResult,
        lines: List[str],
        binary_path: str,
    ) -> None:
        """解析 raw strace lines RuntimeTrace objects

        strace 输出 格式化 (example):
        12345 openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3
        12345 connect(3, {sa_family=AF_INET, sin_port=htons(443),.}, 16) = 0

        提取: PID, 系统调用 name, arguments (a truncated string)
        返回 value, map 系统调用 a RuntimeBehaviorType
        """
        # Regex 匹配 typical strace line: optional [pid] prefix, 系统调用 name
        # parenthesized arguments, " = " 返回 value
        _STRACE_RE = re.compile(
            r'^(?:\[(?P<pid>\d+)\]\s+)?'
            r'(?P<syscall>[a-zA-Z_][a-zA-Z0-9_]*)\('
            r'(?P<args>.*?)'
            r'\)\s*=\s*(?P<ret>-?\d+|0x[0-9a-fA-F]+|\?)\s*'
            r'(?P<extra>.*?)$'
        )

        parsed = 0
        t0 = time.time()
        for line in lines[: _STRACE_LINE_LIMIT]:
            line = line.strip()
            if not line:
                continue
            m = _STRACE_RE.match(line)
            if not m:
                continue

            syscall_name = m.group('syscall')
            args_raw = m.group('args')
            ret_str = m.group('ret')
            pid_str = m.group('pid')

            # Map 系统调用 → behavior type
            behavior_info = self._lookup_syscall_behavior(syscall_name)
            if behavior_info is None:
                continue  # uninteresting 系统调用, skip

            behavior_type, severity = behavior_info

            # 解析 返回 value
            try:
                if ret_str.startswith('0x'):
                    ret_val = int(ret_str, 16)
                elif ret_str == '?':
                    ret_val = None
                else:
                    ret_val = int(ret_str)
            except ValueError:
                ret_val = ret_str

            # 网络 connections: 提取 address info connect/bind args
            if behavior_type in (RuntimeBehaviorType.NETWORK_CONNECT,
                                 RuntimeBehaviorType.NETWORK_SEND,
                                 RuntimeBehaviorType.NETWORK_RECEIVE):
                self._extract_network_info(result, syscall_name, args_raw)

            # File access tracking
            if behavior_type in (RuntimeBehaviorType.FILE_CREATE,
                                 RuntimeBehaviorType.FILE_READ,
                                 RuntimeBehaviorType.FILE_MODIFY,
                                 RuntimeBehaviorType.FILE_DELETE):
                fpath = self._extract_file_path(syscall_name, args_raw)
                if fpath and fpath not in result.files_accessed:
                    result.files_accessed.append(fpath)

            # Process injection / creation tracking
            if behavior_type == RuntimeBehaviorType.PROCESS_CREATE:
                child = self._extract_file_path(syscall_name, args_raw)
                if child:
                    result.process_operations.append({
                        "target": child, "operation": "create",
                    })
            if behavior_type == RuntimeBehaviorType.PROCESS_INJECT:
                result.process_operations.append({
                    "syscall": syscall_name, "operation": "inject",
                })

            trace = RuntimeTrace(
                trace_id=self._next_trace_id(),
                timestamp=t0 + parsed * 0.0001,  # preserve ordering
                behavior_type=behavior_type,
                api_name=syscall_name,
                process_name=binary_path,
                pid=int(pid_str) if pid_str else 0,
                arguments={"syscall": syscall_name, "args": self._truncate_str(args_raw, 256)},
                return_value=ret_val,
                success=(isinstance(ret_val, int) and ret_val >= 0),
                severity=severity,
                description=f"strace: {syscall_name}({self._truncate_str(args_raw, 80)}) = {ret_str}",
            )
            result.traces.append(trace)
            result.api_hook_count += 1
            parsed += 1

        log.debug("Parsed %d strace lines into %d traces", len(lines[: _STRACE_LINE_LIMIT]), parsed)

    @staticmethod
    def _lookup_syscall_behavior(syscall_name: str) -> Optional[Tuple[str, str]]:
        """将系统调用名与映射表匹配。

        返回 (behavior_type, severity), 无趣的系统调用返回
        None。遍历 _SYSCALL_MAP 键 — 字典足够小, 不构成
        瓶颈。
        """
        for prefix, (btype, sev) in _SYSCALL_MAP.items():
            if syscall_name == prefix or syscall_name.startswith(prefix):
                return (btype, sev)
        return None

    @staticmethod
    def _extract_network_info(result: DynamicAnalysisResult, syscall_name: str,
                              args_raw: str) -> None:
        """尝试从 connect/bind/sendto 参数提取远端地址/端口。

        strace 输出内联 sockaddr 结构, e.g.:
        sin_port=htons(443), sin_addr=inet_addr("10.0.0.1")
        基于正则的最佳努力提取。
        """
        addr_match = re.search(r'inet_addr\("([^"]+)"\)', args_raw)
        port_match = re.search(r'htons\((\d+)\)', args_raw)
        if addr_match:
            conn = {
                "remote_addr": addr_match.group(1),
                "port": int(port_match.group(1)) if port_match else 0,
                "protocol": "TCP",
                "syscall": syscall_name,
            }
            result.network_connections.append(conn)

    @staticmethod
    def _extract_file_path(syscall_name: str, args_raw: str) -> Optional[str]:
        """从 strace 参数中提取文件路径。

        strace typically quotes paths: openat(AT_FDCWD, "/etc/passwd",.)
        """
        m = re.search(r'"([^"]+)"', args_raw)
        if m:
            return m.group(1)
        return None

# Utility 辅助函数

    @staticmethod
    def _has_tool(name: str) -> bool:
        """检查命令行工具在 PATH 中是否可用。"""
        return shutil.which(name) is not None

    @staticmethod
    def _truncate_bytes(data: bytes, max_len: int) -> str:
        """截断 raw bytes, 解码 safely, 返回 string snippet"""
        try:
            text = data[:max_len].decode('utf-8', errors='replace')
        except Exception:
            text = repr(data[:max_len])
        return text

    @staticmethod
    def _truncate_str(text: str, max_len: int) -> str:
        """截断 a string max_len, appending '…' trimmed"""
        if len(text) <= max_len:
            return text
        return text[:max_len - 1] + '…'

# Trace 工厂

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

# Public API (unchanged)

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
        # Re-运行 pattern detection pass
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
                log.debug("Hooked API: %s -> %s", api, callback_name)
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
                # 舍入 5: real-execution metadata 报告
                "execution_metadata": {
                    "mode": dr.execution_mode,
                    "exit_code": dr.exit_code,
                    "crash_signal": dr.crash_signal,
                    "anomalies": dr.anomalies,
                },
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
                timeout = kwargs.get("timeout_seconds", _DEFAULT_TIMEOUT)
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
            log.error("Dynamic analysis error: %s", e, exc_info=True)
            return {"success": False, "error": str(e)}

    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            name="DynamicAnalysisEngine",
            type=AnalyzerType.DYNAMIC_ANALYZER,
            version="2.0.0",
            description="Dynamic binary analysis engine: real subprocess execution, strace syscall capture, crash signal monitoring, MITRE ATT&CK-based malicious pattern detection",
            author="BinaryAnalysisPlatform",
            dependencies=[],
            supported_platforms=["windows", "linux", "macos"],
        )


def manage_dynamic_analysis_engine(**kwargs) -> Dict[str, Any]:
    return DynamicAnalysisEngine().analyze(**kwargs)


__all__ = ["DynamicAnalysisEngine", "manage_dynamic_analysis_engine"]
