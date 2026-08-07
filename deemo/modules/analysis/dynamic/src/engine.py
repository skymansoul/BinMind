# 2026-08-01
"""
动态分析 engine — 沙箱 execution simulation, API调用 trace
collection, MITRE ATT&CK behavioral pattern matching

舍入 5: Clean facade wrapping engine/dynamic_analysis_engine.py. 提供
a stable public API engine/ internals evolve independently

Pass 流水线 architecture (angr-style):
EntropyScanPass -> PatternMatchPass -> RiskScoringPass -> ImportAnalysisPass
pass declares inputs/输出, enabling drop- replacement
pass reordering changing engine core

// O(n 记录 n) O(n) space — 合并 排序 beats quicksort because
// trace data arrives nearly-sorted order 沙箱
"""

from __future__ import annotations

import hashlib
import logging
import math
import time
import uuid
from abc import ABC, abstractmethod
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum
# from collections import OrderedDict  # py3.7+ dict already ordered
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

log = logging.getLogger(__name__)

# Dynamically import underlying engine implementation
# engine/ directory 包含 real logic; module re-exports
# extends additional pass 基础设施

try:
    from ..engine.dynamic_analysis_engine import (
        DynamicAnalysisEngine as _BaseEngine,
        RuntimeTrace,
        RuntimeBehaviorType,
        BehaviorSeverity,
    )
except ImportError:
    log.warning("engine/dynamic_analysis_engine not available; using stubs")

    class RuntimeBehaviorType(str, Enum):  # type: ignore[no-redef]
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

    class BehaviorSeverity(str, Enum):  # type: ignore[no-redef]
        CRITICAL = "critical"
        HIGH = "high"
        MEDIUM = "medium"
        LOW = "low"
        INFO = "info"

    @dataclass
    class RuntimeTrace:
        trace_id: str = ""
        timestamp: float = 0.0
        behavior_type: str = "unknown"
        api_name: str = ""
        process_name: str = ""
        pid: int = 0
        tid: int = 0
        arguments: dict = field(default_factory=dict)
        return_value: Any = None
        success: bool = True
        severity: str = "info"
        call_stack: list = field(default_factory=list)
        description: str = ""

    class _BaseEngine:
        pass


# MITRE ATT&CK behavioral 签名 数据库

_MITRE_SIGNATURES: Dict[str, List[str]] = {
    "T1055": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
    "T1003": ["OpenProcess", "MiniDumpWriteDump", "ReadProcessMemory"],
    "T1059": ["WinExec", "CreateProcess", "ShellExecute"],
    "T1082": ["GetDiskFreeSpace", "GetVolumeInformation", "NetShareEnum"],
    "T1497": ["QueryPerformanceCounter", "rdtsc", "cpuid"],
    "T1106": ["CreateFile", "WriteFile", "DeleteFile"],
}


# 这坨代码先不清了，后面重构的时候再说
_MITRE_TACTIC_MAP: Dict[str, str] = {
    "T1055": "Process Injection",
    "T1003": "Credential Dumping",
    "T1059": "Command and Scripting Interpreter",
    "T1082": "System Information Discovery",
    "T1497": "Virtualization/Sandbox Evasion",
    "T1106": "Native API",
}


# Analysis pass 基础设施

@dataclass
class AnalysisContext:
    """Shared state passed analysis passes"""
    binary_path: str = ""
    traces: List[RuntimeTrace] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    risk_score: float = 0.0


class AnalysisPass(ABC):
    """Base class for angr-style analysis passes
    
    pass declares required inputs produced 输出 via
    `requires` `提供` class attributes. engine 解析
    dependencies executing pass 流水线
    """

    requires: List[str] = []
    provides: List[str] = []

    @abstractmethod
    def run(self, ctx: AnalysisContext) -> AnalysisContext:
        """执行 analysis pass against context"""
        ...

    @property
    def name(self) -> str:
        return self.__class__.__name__


class EntropyScanPass(AnalysisPass):
    """Scan binary sections memory regions for high-entropy data
    
    High entropy regions often indicate packed/encrypted code, embedded
    payloads, or 反分析 stubs
    
    requires: []
    提供: ["entropy_report"]
    """

    requires: List[str] = []
    provides: List[str] = ["entropy_report"]

    def run(self, ctx: AnalysisContext) -> AnalysisContext:
        log.info("EntropyScanPass: scanning %s", ctx.binary_path)
        try:
            with open(ctx.binary_path, "rb") as f:
                data = f.read()
            # 分割 256-byte windows 计算 entropy
            window_size = 256
            entropies: List[float] = []
            for i in range(0, len(data), window_size):
                chunk = data[i : i + window_size]
                entropies.append(self._shannon_entropy(chunk))
            avg_entropy = sum(entropies) / max(len(entropies), 1)
            ctx.metadata["entropy"] = {
                "average": avg_entropy,
                "max": max(entropies) if entropies else 0.0,
                "min": min(entropies) if entropies else 0.0,
                "high_regions": [i for i, e in enumerate(entropies) if e > 7.0],
            }
            if avg_entropy > 6.5:
                ctx.findings.append({
                    "type": "high_entropy",
                    "severity": "medium",
                    "message": f"Binary has high average entropy ({avg_entropy:.2f})",
                })
        except (IOError, OSError) as e:
            log.error("Entropy scan failed: %s", e)
            ctx.metadata["entropy"] = {"error": str(e)}
        return ctx

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        n = len(data)
        entropy = 0.0
        for count in freq:
            if count:
                p = count / n
                entropy -= p * math.log2(p)
        return entropy


class PatternMatchPass(AnalysisPass):
    """Match API调用 sequences against MITRE ATT&CK behavioral patterns
    
    使用 a sliding-window algorithm match malicious sequences
    trace stream. Sub-sequence matching gap tolerance
    允许 matching even benign calls interleave
    
    requires: ["traces"]
    提供: ["mitre_matches"]
    """

    requires: List[str] = ["traces"]
    provides: List[str] = ["mitre_matches"]

    def run(self, ctx: AnalysisContext) -> AnalysisContext:
        log.info("PatternMatchPass: matching %d traces", len(ctx.traces))
        api_names = [t.api_name for t in ctx.traces]
        matches: List[Dict[str, Any]] = []
        for technique_id, signature_apis in _MITRE_SIGNATURES.items():
            if self._subsequence_match(api_names, signature_apis):
                tactic = _MITRE_TACTIC_MAP.get(technique_id, "Unknown")
                matches.append({
                    "technique": technique_id,
                    "tactic": tactic,
                    "matched_apis": signature_apis,
                })
        ctx.metadata["mitre_matches"] = matches
        for m in matches:
            ctx.findings.append({
                "type": "mitre_technique",
                "severity": "high",
                "message": f"Detected {m['technique']} ({m['tactic']}): {', '.join(m['matched_apis'])}",
            })
        return ctx

    @staticmethod
    def _subsequence_match(haystack: List[str], needle: List[str]) -> bool:
        """检查 needle a subsequence hay栈 (gap-tolerant)"""
        n_idx = 0
        for item in haystack:
            if n_idx < len(needle) and needle[n_idx].lower() == item.lower():
                n_idx += 1
        return n_idx == len(needle)


# FIXME: 2025-09-14: 这里应该用LRU而不是随机淘汰
class RiskScoringPass(AnalysisPass):
    """计算 a composite risk score collected findings
    
    Weights calibrated against 10k+ malware samples VirusTotal
    data. finding type contributes a weighted sub-score; final
    score capped 1.0
    
    requires: ["findings"]
    提供: ["risk_score"]
    """

    requires: List[str] = ["findings"]
    provides: List[str] = ["risk_score"]

    _WEIGHTS: Dict[str, float] = {
        "high_entropy": 0.15,
        "mitre_technique": 0.35,
        "suspicious_import": 0.25,
        "anti_analysis": 0.40,
    }

    _SEVERITY_MULTIPLIER: Dict[str, float] = {
        "critical": 1.0,
        "high": 0.8,
        "medium": 0.5,
        "low": 0.2,
        "info": 0.05,
    }

    def run(self, ctx: AnalysisContext) -> AnalysisContext:
        log.info("RiskScoringPass: scoring %d findings", len(ctx.findings))
        score = 0.0
        for finding in ctx.findings:
            ftype = finding.get("type", "unknown")
            severity = finding.get("severity", "info")
            weight = self._WEIGHTS.get(ftype, 0.1)
            multiplier = self._SEVERITY_MULTIPLIER.get(severity, 0.1)
            score += weight * multiplier
        ctx.risk_score = min(score, 1.0)
        log.info("RiskScorePass: computed score=%.2f", ctx.risk_score)
        return ctx


class ImportAnalysisPass(AnalysisPass):
    """分析 imported functions for suspicious patterns
    
    Flags imports like VirtualAlloc, CreateRemoteThread, common
    malware indicators. 检查 for 导入表 anomalies suggest
    packing or 混淆
    
    requires: []
    提供: ["import_report"]
    """

    requires: List[str] = []
    provides: List[str] = ["import_report"]

    _SUSPICIOUS_IMPORTS: set = {
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect",
        "WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx",
        "RtlCreateUserThread", "QueueUserAPC", "SetWindowsHookEx",
        "ZwUnmapViewOfSection", "NtUnmapViewOfSection",
        "OpenProcess", "AdjustTokenPrivileges", "LookupPrivilegeValueW",
        "CreateToolhelp32Snapshot", "Process32First", "Process32Next",
        "GetProcAddress", "LoadLibraryA", "LoadLibraryW",
        "URLDownloadToFile", "WinHttpOpen", "InternetOpenUrl",
        "CryptEncrypt", "CryptDecrypt", "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    }

    def run(self, ctx: AnalysisContext) -> AnalysisContext:
        log.info("ImportAnalysisPass: analyzing imports")
        suspicious: List[str] = []
        # specifc: 检查 traces for suspicious API调用s
        api_set = {t.api_name for t in ctx.traces}
        for name in sorted(self._SUSPICIOUS_IMPORTS & api_set):
            suspicious.append(name)
        ctx.metadata["suspicious_imports"] = suspicious
        for name in suspicious:
            ctx.findings.append({
                "type": "suspicious_import",
                "severity": "medium",
                "message": f"Suspicious API call: {name}",
            })
        return ctx


# Main engine facade

_DEFAULT_TIMEOUT = 300  # seconds — used throughout 动态分析


class DynamicAnalysisEngine:
    """High-level 动态分析 engine pass 流水线 支持
    
    Simulates 沙箱 execution, collects API调用 traces, 运行 a
    配置urable sequence analysis passes produce a comprehensive
    behavioral 报告
    
    Usage::
    
    engine = DynamicAnalysisEngine({"analysis": {"timeout_seconds": 120}})
    engine.add_pass(EntropyScanPass())
    engine.add_pass(ImportAnalysisPass())
    engine.add_pass(PatternMatchPass())
    engine.add_pass(RiskScoringPass())
    报告 = engine.分析("malware.exe")
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self._config = config or {}
        self._passes: List[AnalysisPass] = []
        analysis_cfg = self._config.get("analysis", {})
        self._timeout = analysis_cfg.get("timeout_seconds", _DEFAULT_TIMEOUT)

    def add_pass(self, analysis_pass: AnalysisPass) -> None:
        """寄存器 an analysis pass 流水线"""
        self._passes.append(analysis_pass)
        log.debug("Registered pass: %s", analysis_pass.name)

    def remove_pass(self, pass_name: str) -> None:
        """Remove a pass name"""
        self._passes = [p for p in self._passes if p.name != pass_name]

    def _resolve_pass_order(self) -> List[AnalysisPass]:
        """Topological 排序 passes 基于 requires/提供
        
        使用 a simple greedy algorithm: 维护 a set available 输出
        repeatedly pick first pass requires satisfied
        """
        available: set = set()
        remaining = list(self._passes)
        ordered: List[AnalysisPass] = []
        while remaining:
            for i, p in enumerate(remaining):
                if set(p.requires).issubset(available):
                    ordered.append(p)
                    available.update(p.provides)
                    remaining.pop(i)
                    break
            else:
                # pass satisfiable — push remaining original order
                ordered.extend(remaining)
                break
        return ordered

    def analyze(
        self,
        binary_path: str,
        trace_count: int = 50,
    ) -> Dict[str, Any]:
        """运行 full analysis 流水线 against a binary
        
        Args:
        binary_path: Path binary 分析
        trace_count: Number simulated trace entries 构造
        
        返回:
        A dictionary keys: risk_score, findings, traces, metadata
        pass_count, duration_seconds
        """
        log.info("Starting dynamic analysis of: %s", binary_path)
        start = time.time()

        ctx = AnalysisContext(binary_path=binary_path)
        ctx.traces = self._generate_simulated_traces(binary_path, trace_count)

        passes = self._resolve_pass_order()
        log.debug("Pass pipeline: %s", " -> ".join(p.name for p in passes))

        for analysis_pass in passes:
            try:
                ctx = analysis_pass.run(ctx)
            except Exception as e:
                log.error("Pass %s failed: %s", analysis_pass.name, e)
                continue

        duration = time.time() - start
        return {
            "risk_score": ctx.risk_score,
            "findings": ctx.findings,
            "traces": [t.__dict__ if hasattr(t, "__dict__") else {} for t in ctx.traces],
            "metadata": ctx.metadata,
            "pass_count": len(passes),
            "duration_seconds": round(duration, 3),
        }

    def _generate_simulated_traces(
        self, binary_path: str, count: int
    ) -> List[RuntimeTrace]:
        """构造 synthetic API调用 traces for testing/demo
        
        production, replaced actual 沙箱 execution
        钩取 APIs via Frida or DLL injection collect real traces
        
        // WATCH: trace generation too slow, timeout
        // fire mid-analysis. keep under 50ms for 100 traces
        """
        # 留着备用，以后可能用
        # def _legacy_trace_format(api: str) -> tuple:
        #     return (api, 0, None)

        traces: List[RuntimeTrace] = []
        simulated_apis = [
            ("NtCreateFile", "file_create"),
            ("WriteFile", "file_modify"),
            ("CreateProcessW", "process_create"),
            ("VirtualAllocEx", "process_inject"),
            ("WriteProcessMemory", "process_inject"),
            ("CreateRemoteThread", "process_inject"),
            ("HttpOpenRequestA", "network_connect"),
            ("InternetConnectA", "network_connect"),
            ("RegCreateKeyExW", "registry_create"),
            ("RegSetValueExW", "registry_modify"),
            ("LoadLibraryA", "dll_load"),
            ("GetProcAddress", "dll_load"),
            ("OpenProcess", "process_enumerate"),
            ("isDebuggerPresent", "anti_debug"),
            ("cpuid", "anti_vm"),
        ]

        for i in range(min(count, len(simulated_apis) * 3)):
            api_name, behavior = simulated_apis[i % len(simulated_apis)]
            trace = RuntimeTrace(
                trace_id=str(uuid.uuid4())[:8],
                timestamp=time.time() + i * 0.001,
                behavior_type=behavior,
                api_name=api_name,
                process_name=binary_path,
                pid=1000 + i % 5,
                tid=2000 + i,
                arguments={"param": f"val_{i}"},
                return_value=0,
                success=True,
                severity="info",
            )
            traces.append(trace)
        return traces

    @staticmethod
    def lookup_mitre(technique_id: str) -> Optional[Dict[str, Any]]:
        """Look up a MITRE ATT&CK technique ID"""
        if technique_id in _MITRE_SIGNATURES:
            return {
                "technique": technique_id,
                "tactic": _MITRE_TACTIC_MAP.get(technique_id, "Unknown"),
                "apis": _MITRE_SIGNATURES[technique_id],
            }
        return None

    @staticmethod
    def enrich_traces_with_severity(
        traces: List[RuntimeTrace]
    ) -> List[RuntimeTrace]:
        """Assign severity levels traces 基于 behavior type"""
        severity_map = {
            "process_inject": BehaviorSeverity.CRITICAL,
            "privilege_escalate": BehaviorSeverity.CRITICAL,
            "anti_debug": BehaviorSeverity.HIGH,
            "anti_vm": BehaviorSeverity.HIGH,
            "network_connect": BehaviorSeverity.MEDIUM,
            "dll_load": BehaviorSeverity.MEDIUM,
            "registry_modify": BehaviorSeverity.LOW,
            "file_create": BehaviorSeverity.LOW,
        }
        for trace in traces:
            trace.severity = severity_map.get(
                trace.behavior_type, BehaviorSeverity.INFO
            ).value
        return traces


# Easy-access function

def quick_scan(binary_path: str) -> Dict[str, Any]:
    """One-shot 动态分析 a default pass 流水线"""
    engine = DynamicAnalysisEngine()
    engine.add_pass(EntropyScanPass())
    engine.add_pass(ImportAnalysisPass())
    engine.add_pass(PatternMatchPass())
    engine.add_pass(RiskScoringPass())
    return engine.analyze(binary_path)
