"""
恶意意图推断器 — API 调用序列行为链分析与杀伤链阶段标注。

方法参照 ReCopilot 的领域特化语义分析,
及 DeBinVul 的多架构样本分类策略。

模块位置: info_collection/src/llm_intent_infer.py
"""

import os, re, hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional
import logging
_log = logging.getLogger(__name__)


class KillChainPhase(Enum):
    """杀伤链阶段 (Lockheed Martin Cyber Kill Chain)。"""
    RECON = "侦察"
    WEAPONIZATION = "武器化"
    DELIVERY = "投递"
    EXPLOITATION = "利用"
    INSTALLATION = "安装"
    PERSISTENCE = "持久化"
    C2 = "命令与控制"
    EXFILTRATION = "数据窃取"
    IMPACT = "影响"
    UNKNOWN = "未知"


@dataclass
class IntentReport:
    """意图分析报告, 汇总阶段推断、置信度与证据项。"""
    function_name: str
    kill_chain_phase: KillChainPhase
    confidence: float
    summary: str = ""                    # 行为摘要
    indicators: List[str] = field(default_factory=list)
    evidence_functions: List[str] = field(default_factory=list)


class LLMIntentInferrer:
    """
    恶意意图推断器。

    分析反编译代码中的 API 调用序列与代码模式,
    推断函数意图并标注杀伤链阶段。
    """

    _PHASE_KEYWORDS: Dict[KillChainPhase, List[str]] = {
        KillChainPhase.RECON: ["GetComputerName", "gethostbyname", "net view", "FindWindow"],
        KillChainPhase.PERSISTENCE: ["RegSetValue", "CreateService", "Task Scheduler", "Startup"],
        KillChainPhase.C2: ["InternetConnect", "WinHttpOpen", "socket", "connect", "recv"],
        KillChainPhase.EXFILTRATION: ["HttpSendRequest", "WriteFile", "send", "upload"],
        KillChainPhase.IMPACT: ["CryptEncrypt", "DeleteFile", "FindFirstFile", "SHFileOperation"],
        KillChainPhase.EXPLOITATION: ["CreateProcess", "WinExec", "VirtualAlloc", "WriteProcessMemory"],
        KillChainPhase.INSTALLATION: ["URLDownloadToFile", "MoveFile", "CopyFile", "RegCreateKey"],
    }

    _DANGER_APIS = [
        "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread",
        "RegSetValueEx", "CreateService", "CryptEncrypt",
        "InternetOpenUrl", "WinHttpOpenRequest", "socket",
    ]

    def __init__(self, api_key: str = ""):
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self._cache: Dict[str, IntentReport] = {}

    def infer_intent(
        self, func_name: str, pseudocode: str, api_calls: List[str]
    ) -> IntentReport:
        """
        推断函数恶意意图: 关键词启发式 + 远端模型混合。

        回退策略: 远端不可用时使用关键词匹配的启发式推断。
        """
        cache_key = hashlib.md5(pseudocode.encode()).hexdigest()
        if cache_key in self._cache:
            return self._cache[cache_key]

        phase, conf = self._heuristic_phase(api_calls)

        if self._api_key:
            summary = self._llm_summarize(func_name, pseudocode, phase)
        else:
            summary = f"启发式推断: {phase.value} 阶段 (置信度 {conf:.2f})"

        report = IntentReport(
            function_name=func_name,
            kill_chain_phase=phase,
            confidence=conf,
            summary=summary,
            indicators=[api for api in api_calls if api in self._DANGER_APIS],
            evidence_functions=api_calls[:10],
        )
        self._cache[cache_key] = report
        return report

    def _heuristic_phase(self, api_calls: List[str]) -> tuple:
        """基于 API 调用序列的启发式阶段推断。"""
        scores: Dict[KillChainPhase, int] = {}
        apis_lower = [a.lower() for a in api_calls]
        for phase, keywords in self._PHASE_KEYWORDS.items():
            score = sum(1 for kw in keywords if any(kw.lower() in a for a in apis_lower))
            scores[phase] = score

        if not scores or max(scores.values()) == 0:
            return KillChainPhase.UNKNOWN, 0.3

        best = max(scores, key=scores.get)
        total = sum(scores.values())
        conf = scores[best] / max(1, total) if total > 0 else 0.3
        return best, min(0.95, conf)

    def _llm_summarize(self, name: str, code: str, phase: KillChainPhase) -> str:
        """调用远端模型生成函数行为摘要。"""
        try:
            import anthropic
            prompt = (
                f"分析此函数 '{name}' ({phase.value}阶段), 用一句中文描述其恶意行为:"
                f"\n```\n{code[:1500]}\n```"
            )
            client = anthropic.Anthropic(api_key=self._api_key)
            resp = client.messages.create(
                model="claude-sonnet-5-20251001", max_tokens=200, temperature=0.1,
                messages=[{"role": "user", "content": prompt}],
            )
            return resp.content[0].text.strip()
        except Exception:
            return f"函数 '{name}' 被推断为 {phase.value} 阶段行为"


__all__ = ["KillChainPhase", "IntentReport", "LLMIntentInferrer"]
