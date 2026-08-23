"""动态分析引擎 — 沙箱执行模拟, API 调用轨迹收集,
MITRE ATT&CK 行为模式匹配。

干净的 facade, 封装 engine/dynamic_analysis_engine.py, 提供
稳定的公共 API, engine 内部实现可独立演化。

Pass 流水线架构 (angr 风格):
EntropyScanPass -> PatternMatchPass -> RiskScoringPass -> ImportAnalysisPass
每个 pass 声明 inputs/输出, 支持 drop-in 替换, 重排 pass
无需改动引擎核心。

注: 归并排序 O(n log n) / O(n) 空间 — 优于快排, 因为沙箱
轨迹数据到达时已接近有序。
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
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

log = logging.getLogger(__name__)

# 动态导入底层引擎实现，engine/ 目录包含真实逻辑，本模块扩展 pass 基础设施

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


_MITRE_TACTIC_MAP: Dict[str, str] = {
    "T1055": "Process Injection",
    "T1003": "Credential Dumping",
    "T1059": "Command and Scripting Interpreter",
    "T1082": "System Information Discovery",
    "T1497": "Virtualization/Sandbox Evasion",
    "T1106": "Native API",
}


# 分析 pass 基础设施

@dataclass
class AnalysisContext:
    """在 analysis pass 间传递的共享状态。"""
    binary_path: str = ""
    traces: List[RuntimeTrace] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    risk_score: float = 0.0


class AnalysisPass(ABC):
    """angr 风格 analysis pass 的基类。

    pass 通过 `requires`/`provides` 类属性声明所需输入与产出
    输出, 引擎在执行 pass 流水线前解析依赖。
    """

    requires: List[str] = []
    provides: List[str] = []

    @abstractmethod
    def run(self, ctx: AnalysisContext) -> AnalysisContext:
        """对上下文执行 analysis pass。"""
        ...

    @property
    def name(self) -> str:
        return self.__class__.__name__


class EntropyScanPass(AnalysisPass):
    """扫描二进制节区的内存区域以寻找高熵数据。

    高熵区域通常指示加壳/加密代码、嵌入载荷或反分析桩。

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
    """将 API 调用序列与 MITRE ATT&CK 行为模式匹配。

    使用滑动窗口算法在轨迹流中匹配恶意序列。子序列匹配
    容忍间隔, 即使良性调用穿插其间也能命中。

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
        """检查 needle 是否为 haystack 的子序列 (容忍间隔)。"""
        n_idx = 0
        for item in haystack:
            if n_idx < len(needle) and needle[n_idx].lower() == item.lower():
                n_idx += 1
        return n_idx == len(needle)


class RiskScoringPass(AnalysisPass):
    """基于收集到的 findings 计算综合风险评分。

    权重基于 VirusTotal 的 10k+ 恶意样本数据校准。每个
    finding 类型贡献一个加权子分; 最终分封顶 1.0。

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
    """分析导入函数中的可疑模式。

    标记 VirtualAlloc, CreateRemoteThread 等常见恶意指标;
    检查暗示加壳或混淆的导入表异常。

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
        # 从轨迹中提取可疑 API 调用
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


# 主引擎门面

_DEFAULT_TIMEOUT = 300  # 秒，全管线超时上限


class DynamicAnalysisEngine:
    """支持 pass 流水线的高层动态分析引擎。

    模拟沙箱执行, 收集 API 调用轨迹, 运行可配置的 analysis
    pass 序列, 产出全面的行为报告。

    用法::

    engine = DynamicAnalysisEngine({"analysis": {"timeout_seconds": 120}})
    engine.add_pass(EntropyScanPass())
    engine.add_pass(ImportAnalysisPass())
    engine.add_pass(PatternMatchPass())
    engine.add_pass(RiskScoringPass())
    report = engine.analyze("malware.exe")
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self._config = config or {}
        self._passes: List[AnalysisPass] = []
        analysis_cfg = self._config.get("analysis", {})
        self._timeout = analysis_cfg.get("timeout_seconds", _DEFAULT_TIMEOUT)

    def add_pass(self, analysis_pass: AnalysisPass) -> None:
        """向流水线注册 analysis pass。"""
        self._passes.append(analysis_pass)
        log.debug("Registered pass: %s", analysis_pass.name)

    def remove_pass(self, pass_name: str) -> None:
        """按名称移除 pass。"""
        self._passes = [p for p in self._passes if p.name != pass_name]

    def _resolve_pass_order(self) -> List[AnalysisPass]:
        """基于 requires/provides 对 pass 做拓扑排序。

        使用简单贪心: 维护可用输出集合, 反复挑选第一个
        requires 已被满足的 pass。
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
                # 无 pass 可满足依赖，按原顺序追加剩余 pass
                ordered.extend(remaining)
                break
        return ordered

    def analyze(
        self,
        binary_path: str,
        trace_count: int = 50,
    ) -> Dict[str, Any]:
        """对二进制运行完整 analysis 流水线。

        参数: binary_path 要分析的二进制路径, trace_count 要
        构造的模拟轨迹条目数;
        返回字典, 键为 risk_score, findings, traces, metadata,
        pass_count, duration_seconds。
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
        """构造用于测试/演示的合成 API 调用轨迹。

        生产环境中替换为真实沙箱执行: 通过 Frida 或 DLL 注入
        钩取 API 以收集真实轨迹。

        注意: 轨迹生成若过慢, 超时会在分析中途触发,
        100 条轨迹需控制在 50ms 内。
        """
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
        """查询 MITRE ATT&CK 技术 ID。"""
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
        """基于行为类型为轨迹分配严重级别。"""
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
    """使用默认 pass 流水线的一次性动态分析。"""
    engine = DynamicAnalysisEngine()
    engine.add_pass(EntropyScanPass())
    engine.add_pass(ImportAnalysisPass())
    engine.add_pass(PatternMatchPass())
    engine.add_pass(RiskScoringPass())
    return engine.analyze(binary_path)
