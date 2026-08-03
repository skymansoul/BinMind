# — 攻击面分析器
# 提取导出函数、网络端口、文件路径、IPC/RPC端点，加权评分
# AttackSurfaceType/RiskLevel采用StrEnum

from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set
from collections import Counter
import os
import re
import hashlib

from vuln_detection.src.logger import get_logger

_log = get_logger("vuln_detection.attack_surface")


class AttackSurfaceType(str, Enum):
    NETWORK = "network"
    FILE = "file"
    MEMORY = "memory"
    PROCESS = "process"
    IPC = "ipc"
    RPC = "rpc"
    USER_INPUT = "user_input"
    HARDWARE = "hardware"
    EXECUTION = "execution"
    UNKNOWN = "unknown"


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


# 风险权重：网络/执行类暴露面威胁系数更高
_RISK_WEIGHTS = {
    AttackSurfaceType.NETWORK: 0.30,
    AttackSurfaceType.RPC: 0.25,
    AttackSurfaceType.EXECUTION: 0.20,
    AttackSurfaceType.IPC: 0.15,
    AttackSurfaceType.FILE: 0.10,
    AttackSurfaceType.MEMORY: 0.12,
    AttackSurfaceType.PROCESS: 0.08,
    AttackSurfaceType.USER_INPUT: 0.18,
    AttackSurfaceType.HARDWARE: 0.05,
    AttackSurfaceType.UNKNOWN: 0.02,
}

# 危险API模式：命中此类符号风险权重加倍
_DANGEROUS_EXPORTS = {
    re.compile(r, re.IGNORECASE) for r in [
        r"^(system|popen|exec[lv]?[pe]?)$",
        r"^(strcpy|strcat|sprintf|vsprintf|gets|scanf)$",
        r"^(memcpy|memmove|memset)\b",
        r"^dlopen$", r"^mmap$", r"^mprotect$",
        r"^(connect|send|recv|bind|listen|accept)\b",
        r"^(CreateProcess|WinExec|ShellExecute)\b",
    ]
}


@dataclass
class SurfaceEntry:
    entry_type: AttackSurfaceType
    name: str
    address: int = 0
    risk_weight: float = 0.0
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SurfaceReport:
    entries: List[SurfaceEntry] = field(default_factory=list)
    total_score: float = 0.0
    risk_level: str = "none"
    type_breakdown: Dict[str, int] = field(default_factory=dict)
    top_threats: List[SurfaceEntry] = field(default_factory=list)

    entry_count = property(lambda self: len(self.entries))


class AttackSurfaceAnalyzer:
    """二进制攻击面分析器。
    提取四类暴露面：导出符号、字符串嵌入的网络/路径模式、
    危险API调用、入口点。加权评分得风险等级。
    """

    DANGEROUS_FUNCTIONS = {
        "strcpy", "strcat", "sprintf", "gets", "scanf", "sscanf",
        "memcpy", "memmove", "system", "popen", "execve", "execl",
        "dlopen", "CreateProcess", "WinExec", "ShellExecute",
    }

    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self._entries: List[SurfaceEntry] = []
        self._r2_available = False

    def _check_r2(self) -> bool:
        try:
            import subprocess
            r = subprocess.run(["r2", "-v"], capture_output=True, text=True, timeout=5)
            self._r2_available = r.returncode == 0
        except Exception:
            self._r2_available = False
        return self._r2_available

    def analyze(self) -> SurfaceReport:
        if not os.path.isfile(self.binary_path):
            _log.warning("binary not found: %s", self.binary_path)
            return SurfaceReport()

        self._extract_exports()
        self._extract_string_patterns()
        self._extract_dangerous_calls()
        self._compute_scores()
        return self._build_report()

    def _extract_exports(self) -> None:
        """提取导出符号及入口点暴露面。"""
        if self._check_r2():
            try:
                import subprocess, json
                r = subprocess.run(
                    ["r2", "-q", "-c", "iEj", self.binary_path],
                    capture_output=True, text=True, timeout=15)
                if r.returncode == 0:
                    exports = json.loads(r.stdout)
                    for exp in exports:
                        name = exp.get("name", "")
                        if name:
                            ent = SurfaceEntry(
                                entry_type=self._classify_export(name),
                                name=name,
                                address=exp.get("vaddr", 0) or exp.get("paddr", 0),
                                description=f"Export: {name}",
                            )
                            self._entries.append(ent)
            except Exception:
                pass

    def _classify_export(self, name: str) -> AttackSurfaceType:
        name_lower = name.lower()
        if any(k in name_lower for k in ("net", "socket", "connect", "http", "send", "recv", "bind", "listen")):
            return AttackSurfaceType.NETWORK
        if any(k in name_lower for k in ("file", "open", "read", "write", "fopen", "fread", "fwrite")):
            return AttackSurfaceType.FILE
        if any(k in name_lower for k in ("rpc", "dcom", "com_", "dispatch")):
            return AttackSurfaceType.RPC
        if any(k in name_lower for k in ("pipe", "shm", "mq_", "sem_", "msg")):
            return AttackSurfaceType.IPC
        if any(k in name_lower for k in ("exec", "system", "popen", "spawn", "fork")):
            return AttackSurfaceType.EXECUTION
        if any(k in name_lower for k in ("alloc", "free", "malloc", "mem", "heap")):
            return AttackSurfaceType.MEMORY
        if any(k in name_lower for k in ("input", "parse", "xml", "json", "decode", "deserialize")):
            return AttackSurfaceType.USER_INPUT
        return AttackSurfaceType.UNKNOWN

    def _extract_string_patterns(self) -> None:
        try:
            with open(self.binary_path, "rb") as f:
                data = f.read(2 * 1024 * 1024)
            text = "".join(chr(b) if 32 <= b < 127 else " " for b in data)
            # IP/URL模式匹配
            for m in re.finditer(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text):
                self._entries.append(SurfaceEntry(
                    entry_type=AttackSurfaceType.NETWORK,
                    name=m.group(), description="Hardcoded IP"))
            # 文件路径模式匹配
            for m in re.finditer(r'(?:/[a-zA-Z0-9_.-]+)+/[a-zA-Z0-9_.-]+', text):
                self._entries.append(SurfaceEntry(
                    entry_type=AttackSurfaceType.FILE,
                    name=m.group(), description="Hardcoded path"))
        except Exception:
            pass

    def _extract_dangerous_calls(self) -> None:
        if not self._r2_available:
            return
        try:
            import subprocess
            r = subprocess.run(
                ["r2", "-q", "-c", "afl", self.binary_path],
                capture_output=True, text=True, timeout=15)
            for line in r.stdout.split("\n"):
                for func in self.DANGEROUS_FUNCTIONS:
                    if func.lower() in line.lower():
                        parts = line.split()
                        if len(parts) >= 1:
                            self._entries.append(SurfaceEntry(
                                entry_type=AttackSurfaceType.EXECUTION,
                                name=func, description=f"Dangerous call to {func}",
                            ))
        except Exception:
            pass

    def _compute_scores(self) -> None:
        for ent in self._entries:
            ent.risk_weight = _RISK_WEIGHTS.get(ent.entry_type, 0.02)
            # 危险函数风险翻倍
            if ent.name in self.DANGEROUS_FUNCTIONS:
                ent.risk_weight *= 2.0

    def _build_report(self) -> SurfaceReport:
        total = sum(e.risk_weight for e in self._entries)
        if total >= 10:
            rl = RiskLevel.CRITICAL.value
        elif total >= 5:
            rl = RiskLevel.HIGH.value
        elif total >= 2:
            rl = RiskLevel.MEDIUM.value
        elif total > 0:
            rl = RiskLevel.LOW.value
        else:
            rl = RiskLevel.NONE.value

        breakdown = dict(Counter(e.entry_type.value for e in self._entries))
        top = sorted(self._entries, key=lambda e: e.risk_weight, reverse=True)[:10]

        return SurfaceReport(
            entries=self._entries, total_score=round(total, 2),
            risk_level=rl, type_breakdown=breakdown, top_threats=top,
        )


def compute_surface_score(binary_path: str) -> float:
    analyzer = AttackSurfaceAnalyzer(binary_path)
    return analyzer.analyze().total_score
