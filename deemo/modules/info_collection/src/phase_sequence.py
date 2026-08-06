"""
API 时序模式匹配的杀伤链阶段推断。

问题: llm_intent_infer._heuristic_phase 仅统计单个 API 关键词的出现次数,
完全忽略 API 调用顺序。然而杀伤链阶段的本质特征之一是时序依赖 ——
先 VirtualAlloc 再 WriteProcessMemory 再 CreateRemoteThread 的顺序
比三个 API 各自独立出现携带更强的 EXPLOITATION 信号。

方案: 为每个杀伤链阶段定义若干 API 调用时序模式 (pattern),
在观测到的 API 调用序列中做最长公共子序列 (LCS) 匹配,
按匹配覆盖率分配阶段信念质量。一个函数可同时属于多个阶段。

与 RINSER (arXiv:2509.04887) 的差异: RINSER 预测被混淆的 API 名称,
本模块从已识别的 API 序列中推断阶段归属, 属于下游任务。
"""

# File: phase_sequence.py  |  2026-08-02 create PSM; 2026-08-04 audit: LCS backtracking

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# 杀伤链阶段 → API 调用时序模式
# 每个模式是一个 API 调用列表, 按调用顺序排列。
# 支持通配符 '*' 表示任意单个 API。
# ---------------------------------------------------------------------------

_PHASE_PATTERNS: Dict[str, List[List[str]]] = {
    "侦察": [
        ["GetComputerName*", "GetUserName*", "NetShareEnum"],
        ["gethostbyname", "getaddrinfo", "connect"],
        ["FindFirstFile*", "FindNextFile*", "ReadFile"],
        ["RegOpenKeyEx*", "RegQueryValueEx*"],
    ],
    "武器化": [
        ["CreateFile*", "WriteFile", "CreateProcess*"],
        ["URLDownloadToFile*", "CreateFile*", "WinExec"],
        ["CryptAcquireContext*", "CryptCreateHash", "CryptHashData"],
    ],
    "投递": [
        ["socket", "connect", "send"],
        ["InternetOpen*", "InternetConnect*", "HttpOpenRequest*", "HttpSendRequest*"],
        ["CreateFile*", "WriteFile", "WinExec"],
    ],
    "利用": [
        ["VirtualAlloc*", "WriteProcessMemory", "CreateRemoteThread"],
        ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
        ["NtCreateThreadEx", "ResumeThread"],
        ["CreateProcess*", "WriteProcessMemory", "ResumeThread"],
    ],
    "安装": [
        ["CreateFile*", "WriteFile", "RegCreateKeyEx*", "RegSetValueEx*"],
        ["URLDownloadToFile*", "MoveFile*", "CreateProcess*"],
        ["CopyFile*", "RegCreateKeyEx*", "RegSetValueEx*"],
    ],
    "持久化": [
        ["RegCreateKeyEx*", "RegSetValueEx*", "RegCloseKey"],
        ["OpenSCManager*", "CreateService*", "StartService*"],
        ["CreateTask*", "RegisterTask*"],
    ],
    "命令与控制": [
        ["InternetOpen*", "InternetConnect*", "HttpOpenRequest*", "InternetReadFile"],
        ["socket", "connect", "recv", "send"],
        ["WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest", "WinHttpReceiveResponse"],
    ],
    "数据窃取": [
        ["FindFirstFile*", "FindNextFile*", "ReadFile", "HttpSendRequest*"],
        ["RegQueryValueEx*", "CryptEncrypt", "send"],
        ["CreateFile*", "ReadFile", "WriteFile", "InternetWriteFile"],
    ],
    "影响": [
        ["CryptEncrypt", "DeleteFile*"],
        ["CreateFile*", "WriteFile", "DeleteFile*"],
        ["OpenProcess", "TerminateProcess"],
        ["StartService*", "ControlService"],
    ],
}


def _normalize_api(api_name: str) -> str:
    """标准化 API 名称: 去后缀 (Ex/A/W) 用于模式匹配。"""
    # 保留核心名称, 移除常见的 Windows API 后缀变体
    base = api_name.rstrip("AW")
    if base.endswith("Ex"):
        base = base[:-2]
    return base


def _api_matches(pattern_token: str, api_name: str) -> bool:
    """检查 API 名称是否匹配模式标记 (支持 '*' 通配符)。"""
    if pattern_token.endswith("*"):
        prefix = pattern_token[:-1]
        return api_name.startswith(prefix) or _normalize_api(api_name).startswith(prefix)
    return api_name == pattern_token or _normalize_api(api_name) == pattern_token


def _lcs_length(pattern: List[str], calls: List[str]) -> int:
    """LCS 长度 —— 使用 _api_matches 进行通配符感知的比较。"""
    n, m = len(pattern), len(calls)
    if n == 0 or m == 0:
        return 0
    prev = [0] * (m + 1)
    for i in range(1, n + 1):
        curr = [0] * (m + 1)
        for j in range(1, m + 1):
            if _api_matches(pattern[i - 1], calls[j - 1]):
                curr[j] = prev[j - 1] + 1
            else:
                curr[j] = max(prev[j], curr[j - 1])
        prev = curr
    return prev[m]


@dataclass
class PhaseMatch:
    """单个模式的匹配结果。"""
    phase: str
    pattern: List[str]
    matched_indices: List[int]    # API 序列中匹配到的位置
    coverage: float               # 模式覆盖率 [0, 1]
    lcs_len: int


@dataclass
class SequencePhaseReport:
    """基于时序模式的阶段推断报告。"""
    phase_beliefs: Dict[str, float]  # 阶段 → 信念质量 (归一化)
    matches: List[PhaseMatch]
    top_phase: str
    top_confidence: float
    is_multi_phase: bool             # 是否显著属于多个阶段


class PhaseSequenceMatcher:
    """
    API 时序模式匹配器。

    对每个观测到的 API 调用序列, 与预定义的阶段模式做 LCS 匹配。
    匹配结果按覆盖率加权后汇总为各阶段的信念质量分布。

    LCS 而非精确匹配: API 序列中可能夹杂与当前阶段无关的调用
    (如错误处理、日志记录), LCS 对这些噪声具有天然的鲁棒性。
    """

    def __init__(self, patterns: Optional[Dict[str, List[List[str]]]] = None):
        self._patterns = patterns or _PHASE_PATTERNS

    def infer(
        self, api_calls: List[str], confidence_weight: float = 0.7,
    ) -> SequencePhaseReport:
        """
        从 API 调用序列推断杀伤链阶段。

        confidence_weight: 时序模式匹配在最终信念中的权重。
        剩余的 (1-confidence_weight) 保留给其他信号源 (如参数分析)。
        """
        if not api_calls:
            return SequencePhaseReport(
                phase_beliefs={"未知": 1.0}, matches=[],
                top_phase="未知", top_confidence=0.3, is_multi_phase=False,
            )

        all_matches: List[PhaseMatch] = []
        phase_scores: Dict[str, float] = defaultdict(float)

        for phase, pattern_list in self._patterns.items():
            for pattern in pattern_list:
                lcs_len = _lcs_length(pattern, api_calls)
                # 覆盖率: LCS 长度 / 模式长度
                # LCS 不要求连续匹配, 对噪声 API 调用具有鲁棒性
                coverage = lcs_len / len(pattern) if pattern else 0.0

                if coverage > 0:
                    # 用 LCS 回溯找到实际匹配的索引
                    matched_idx = self._lcs_indices(pattern, api_calls)
                    match = PhaseMatch(
                        phase=phase, pattern=pattern,
                        matched_indices=matched_idx, coverage=coverage,
                        lcs_len=lcs_len,
                    )
                    all_matches.append(match)
                    phase_scores[phase] += coverage * confidence_weight

        # 归一化为信念分布
        total = sum(phase_scores.values())
        if total > 0:
            beliefs = {p: s / total for p, s in phase_scores.items()}
        else:
            beliefs = {"未知": 1.0}

        # 排序
        ranked = sorted(beliefs.items(), key=lambda x: x[1], reverse=True)
        top_phase, top_conf = ranked[0] if ranked else ("未知", 0.3)

        # 多阶段判定: 次高信念 > 0.25
        is_multi = len(ranked) > 1 and ranked[1][1] > 0.25

        return SequencePhaseReport(
            phase_beliefs=beliefs,
            matches=all_matches,
            top_phase=top_phase,
            top_confidence=round(top_conf, 4),
            is_multi_phase=is_multi,
        )

    @staticmethod
    def _lcs_indices(pattern: List[str], calls: List[str]) -> List[int]:
        """LCS 回溯: 返回 API 序列中匹配模式 token 的索引列表。"""
        n, m = len(pattern), len(calls)
        if n == 0 or m == 0:
            return []
        dp = [[0] * (m + 1) for _ in range(n + 1)]
        for i in range(1, n + 1):
            for j in range(1, m + 1):
                if _api_matches(pattern[i - 1], calls[j - 1]):
                    dp[i][j] = dp[i - 1][j - 1] + 1
                else:
                    dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])
        # 回溯
        indices: List[int] = []
        i, j = n, m
        while i > 0 and j > 0:
            if _api_matches(pattern[i - 1], calls[j - 1]):
                indices.append(j - 1)
                i -= 1
                j -= 1
            elif dp[i - 1][j] >= dp[i][j - 1]:
                i -= 1
            else:
                j -= 1
        indices.reverse()
        return indices

    def explain(self, report: SequencePhaseReport) -> str:
        """生成可读的阶段推断解释。"""
        if not report.matches:
            return "未匹配到任何杀伤链阶段模式"
        parts: List[str] = []
        for m in report.matches[:5]:
            pattern_str = " → ".join(m.pattern[:4])
            parts.append(
                f"{m.phase}: 模式 [{pattern_str}] 覆盖率 {m.coverage:.0%}"
            )
        return "; ".join(parts)


__all__ = [
    "PhaseMatch",
    "SequencePhaseReport",
    "PhaseSequenceMatcher",
]
