"""
API 参数感知的杀伤链阶段推断。

PeerJ CS (2025) 的 "Function Parameters Encoding for Malware Detection"
表明 API 参数 (文件路径、注册表键、IP 地址、URL) 携带的安全语义
比 API 名称本身更丰富 —— 同一个 WriteFile 写入临时目录和写入
系统目录的杀伤链含义完全不同。

本模块从 API 调用参数中提取阶段信号:
- 文件路径 → 目标目录层级 (System32 → 安装/持久化, Temp → 投递)
- 注册表键 → 键路径层级 (Run → 持久化, Services → 安装)
- 网络地址 → IP/域名特征 (内网 → 横向移动, 外网 → C2/外传)
- 进程名 → 目标进程类型 (lsass → 凭证窃取, explorer → 持久化)

与 phase_sequence.py 的差异: 时序模块从 "调用顺序" 推断,
本模块从 "调用目标" 推断, 两者正交且互补。
"""

# File: api_argument_phase.py  |  2026-08-02 create APE; 2026-08-04 audit: escape fix

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# 参数特征 → 阶段信号映射
# ---------------------------------------------------------------------------

_PATH_SIGNALS: Dict[str, Tuple[str, float]] = {
    r"(?i)\\(?:system32|syswow64)\\": ("安装", 0.7),
    r"(?i)\\windows\\system32\\drivers\\": ("安装", 0.85),
    r"(?i)\\temp\\": ("投递", 0.65),
    r"(?i)\\appdata\\local\\temp\\": ("投递", 0.75),
    r"(?i)\\startup\\": ("持久化", 0.80),
    r"(?i)\\desktop\\": ("投递", 0.40),
    r"(?i)\\downloads\\": ("投递", 0.55),
    r"(?i)\\windows\\tasks\\": ("持久化", 0.75),
    r"(?i)\\.(?:doc|docx|xls|xlsx|pdf|ppt)": ("数据窃取", 0.50),
    r"(?i)\\.(?:pst|ost|db|sqlite)": ("数据窃取", 0.60),
    r"(?i)\\users\\[^\\]+\\documents\\": ("数据窃取", 0.55),
    r"(?i)\\windows\\system32\\": ("安装", 0.60),
    r"(?i)\\program\s*data\\": ("安装", 0.45),
    r"(?i)\\program\s*files\\": ("安装", 0.40),
}

_REGISTRY_SIGNALS: Dict[str, Tuple[str, float]] = {
    r"(?i)software\\microsoft\\windows\\currentversion\\run": ("持久化", 0.90),
    r"(?i)software\\microsoft\\windows\\currentversion\\runonce": ("持久化", 0.85),
    r"(?i)system\\currentcontrolset\\services\\": ("持久化", 0.85),
    r"(?i)system\\currentcontrolset\\control\\": ("安装", 0.55),
    r"(?i)software\\microsoft\\windows\\currentversion\\policies\\": ("持久化", 0.70),
    r"(?i)software\\microsoft\\windows\\currentversion\\explorer\\": ("持久化", 0.55),
    r"(?i)software\\microsoft\\windows\\currentversion\\uninstall\\": ("安装", 0.50),
    r"(?i)sam\\sam\\domains\\": ("数据窃取", 0.85),
    r"(?i)security\\policy\\secrets\\": ("数据窃取", 0.80),
}

_NETWORK_SIGNALS: Dict[str, Tuple[str, float]] = {
    r"^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)": ("侦察", 0.50),
    r"^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.).*:(?:22|3389|5985|5986)$": ("利用", 0.60),
    r"^(?!10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.)": ("命令与控制", 0.55),
    r"(?i)(?:\.onion|\.bit|\.exit$)": ("命令与控制", 0.70),
    r"(?i)(?:pastebin|pastie|zerobin|ghostbin)": ("数据窃取", 0.65),
    r":(?:443|8443|8080|4443)$": ("命令与控制", 0.50),
    r":(?:21|22|25|587|993|995)$": ("数据窃取", 0.45),
}

_PROCESS_SIGNALS: Dict[str, Tuple[str, float]] = {
    r"(?i)lsass\.exe": ("数据窃取", 0.85),
    r"(?i)explorer\.exe": ("持久化", 0.65),
    r"(?i)svchost\.exe": ("安装", 0.55),
    r"(?i)csrss\.exe": ("利用", 0.50),
    r"(?i)winlogon\.exe": ("持久化", 0.70),
    r"(?i)cmd\.exe": ("利用", 0.50),
    r"(?i)powershell\.exe": ("利用", 0.55),
    r"(?i)wmic\.exe": ("侦察", 0.55),
    r"(?i)wscript\.exe|cscript\.exe": ("投递", 0.50),
    r"(?i)regsvr32\.exe": ("安装", 0.50),
    r"(?i)rundll32\.exe": ("利用", 0.45),
    r"(?i)schtasks\.exe": ("持久化", 0.65),
    r"(?i)sc\.exe": ("持久化", 0.60),
    r"(?i)net\.exe": ("侦察", 0.55),
    r"(?i)whoami\.exe|systeminfo\.exe|ipconfig\.exe": ("侦察", 0.70),
}

# API 函数 → 参数位置 → 参数类型 (0-indexed)
_API_ARG_LAYOUT: Dict[str, Dict[int, str]] = {
    "WriteFile": {0: "handle", 1: "buffer"},
    "CreateFile": {0: "path"},
    "RegSetValueEx": {0: "key_handle", 2: "value_name"},
    "RegCreateKeyEx": {0: "key_handle", 2: "subkey"},
    "RegOpenKeyEx": {0: "key_handle", 2: "subkey"},
    "CreateProcess": {0: "path", 1: "cmdline"},
    "WinExec": {0: "cmdline"},
    "URLDownloadToFile": {1: "url", 2: "local_path"},
    "HttpOpenRequest": {0: "verb", 1: "url_path"},
    "connect": {0: "socket", 1: "address"},
    "send": {0: "socket", 1: "data"},
    "recv": {0: "socket", 1: "buffer"},
    "CopyFile": {0: "src_path", 1: "dst_path"},
    "MoveFile": {0: "src_path", 1: "dst_path"},
    "DeleteFile": {0: "path"},
    "FindFirstFile": {0: "pattern"},
}


@dataclass
class ArgumentSignal:
    """单个参数提取的阶段信号。"""
    api_name: str
    argument_value: str
    argument_type: str  # "path" | "registry" | "network" | "process" | "unknown"
    phase: str
    strength: float     # 信号强度 [0, 1]


@dataclass
class ArgumentPhaseReport:
    """参数感知的阶段推断报告。"""
    signals: List[ArgumentSignal]
    phase_scores: Dict[str, float]
    top_phase: str
    confidence: float
    argument_coverage: float  # 有参数信息的 API 占比


class ArgumentPhaseExtractor:
    """
    API 参数感知的阶段信号提取器。

    输入: (api_name, arg_string) 对列表, 其中 arg_string 是从反编译
    代码中提取的参数值文本 (字符串常量或可解析的地址)。

    对每个参数, 按类型 (path/registry/network/process) 匹配对应的
    信号模式, 累积各阶段的证据权重。
    """

    def extract(
        self,
        api_args: List[Tuple[str, str]],
        # [(api_name, arg_value), ...]
    ) -> ArgumentPhaseReport:
        """
        从 API 参数列表提取阶段信号。

        api_args: 每个元素是 (API 名称, 参数值字符串)。
        参数值可以是文件路径、注册表键、IP 地址、进程名等。
        """
        signals: List[ArgumentSignal] = []
        phase_scores: Dict[str, float] = defaultdict(float)
        arg_count = 0
        matched_count = 0

        for api_name, arg_value in api_args:
            if not arg_value or len(arg_value) < 2:
                continue
            arg_count += 1
            arg_type = self._classify_arg(arg_value)

            signal = self._match_signal(api_name, arg_value, arg_type)
            if signal is not None:
                signals.append(signal)
                phase_scores[signal.phase] += signal.strength
                matched_count += 1

        # 归一化
        total = sum(phase_scores.values())
        if total > 0:
            phase_scores = {p: round(s / total, 4) for p, s in phase_scores.items()}

        ranked = sorted(phase_scores.items(), key=lambda x: x[1], reverse=True)
        top_phase, top_conf = ranked[0] if ranked else ("未知", 0.0)
        arg_cov = matched_count / arg_count if arg_count > 0 else 0.0

        return ArgumentPhaseReport(
            signals=signals,
            phase_scores=phase_scores,
            top_phase=top_phase,
            confidence=round(min(0.95, top_conf * arg_cov + 0.1), 4),
            argument_coverage=round(arg_cov, 4),
        )

    def _classify_arg(self, value: str) -> str:
        if re.search(r"(?i)(?:\\windows\\|\\system32\\|\.(?:exe|dll|sys|bat|ps1)$)", value):
            if re.search(r"(?i)\\registry\\|\\software\\|hkey_|hklm|hkcu", value):
                return "registry"
            return "path"
        if re.search(r"(?i)hkey_|hklm|hkcu|\\registry\\|\\software\\", value):
            return "registry"
        if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", value):
            return "network"
        if re.search(r"(?i)(?:https?://|ftp://|\.onion|\.com|\.net|\.org)", value):
            return "network"
        if re.search(r"(?i)\.exe$", value):
            return "process"
        return "unknown"

    def _match_signal(
        self, api_name: str, arg_value: str, arg_type: str,
    ) -> Optional[ArgumentSignal]:
        """按参数类型匹配信号模式。"""
        patterns: Dict[str, Tuple[str, float]] = {}

        if arg_type == "path":
            patterns = _PATH_SIGNALS
        elif arg_type == "registry":
            patterns = _REGISTRY_SIGNALS
        elif arg_type == "network":
            patterns = _NETWORK_SIGNALS
        elif arg_type == "process":
            patterns = _PROCESS_SIGNALS

        best_phase: Optional[str] = None
        best_strength = 0.0
        for pattern, (phase, strength) in patterns.items():
            if re.search(pattern, arg_value):
                if strength > best_strength:
                    best_phase = phase
                    best_strength = strength

        if best_phase is not None:
            return ArgumentSignal(
                api_name=api_name,
                argument_value=arg_value[:100],
                argument_type=arg_type,
                phase=best_phase,
                strength=best_strength,
            )
        return None


__all__ = [
    "ArgumentSignal",
    "ArgumentPhaseReport",
    "ArgumentPhaseExtractor",
]
