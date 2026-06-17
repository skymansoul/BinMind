"""
多 AI 模型集成与漏洞分析投票机制模块

功能:
    1. 支持同时调用 OpenAI / Ollama / 本地模型
    2. 对同一代码片段做漏洞分析
    3. 投票 / 加权平均 / 基于历史准确率动态权重
    4. 输出综合漏洞置信度, 减少单一模型误报/漏报

核心技术:
    - 提供商统一抽象 (BaseProvider)
    - 历史准确率跟踪 (滑动窗口)
    - 投票策略: hard vote, soft vote, weighted soft vote
    - 置信度融合
"""

import logging
import os
import time
import json
import threading
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque

logger = logging.getLogger(__name__)


class VoteStrategy(Enum):
    """投票策略"""
    HARD = "hard"                 # 多数表决
    SOFT = "soft"                 # 概率平均
    WEIGHTED_SOFT = "weighted_soft"   # 加权概率平均
    CONFIDENCE_MAX = "confidence_max"  # 取最高置信度


@dataclass
class ModelVerdict:
    """单个模型裁决"""
    provider: str
    model: str
    is_vulnerable: bool
    confidence: float             # 0-1
    vuln_type: str = ""
    cwe_id: str = ""
    severity: str = "low"
    explanation: str = ""
    latency_ms: float = 0.0
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EnsembleResult:
    """集成结果"""
    is_vulnerable: bool
    confidence: float
    vuln_type: str
    cwe_id: str
    severity: str
    votes: List[ModelVerdict]
    strategy: VoteStrategy
    agreement_score: float        # 一致性 0-1


class BaseProvider:
    """AI Provider 抽象基类"""

    def __init__(self, name: str, model: str, weight: float = 1.0):
        self.name = name
        self.model = model
        self.weight = weight
        self._accuracy_window: deque = deque(maxlen=200)
        self._lock = threading.Lock()

    def analyze(self, code: str, context: Dict[str, Any]) -> ModelVerdict:
        """子类必须实现"""
        raise NotImplementedError

    def record_feedback(self, correct: bool):
        with self._lock:
            self._accuracy_window.append(1.0 if correct else 0.0)

    def accuracy(self) -> float:
        if not self._accuracy_window:
            return 0.7  # 缺省精度
        with self._lock:
            return sum(self._accuracy_window) / len(self._accuracy_window)

    def dynamic_weight(self) -> float:
        """基于历史准确率动态调整权重"""
        a = self.accuracy()
        # 0.5 -> 0.5x, 0.9 -> 1.5x
        return max(0.2, min(2.0, a * 1.7 - 0.1))


class OpenAIProvider(BaseProvider):
    """OpenAI 兼容 Provider"""

    def __init__(self, model: str = "gpt-4o-mini", api_key: Optional[str] = None,
                 base_url: Optional[str] = None, weight: float = 1.0):
        super().__init__("openai", model, weight)
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self.base_url = base_url

    def analyze(self, code: str, context: Dict[str, Any]) -> ModelVerdict:
        start = time.time()
        try:
            import openai
            client = openai.OpenAI(api_key=self.api_key, base_url=self.base_url)
            sys_prompt = (
                "你是一个二进制安全分析专家。请基于以下伪代码/汇编判断是否存在漏洞。"
                "严格以 JSON 输出 {vulnerable: bool, confidence: float(0-1), "
                "vuln_type: str, cwe_id: str, severity: str, explanation: str}。"
            )
            user_prompt = f"代码:\n```\n{code[:6000]}\n```\n\n上下文:\n{json.dumps(context, ensure_ascii=False)[:1500]}"
            resp = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": sys_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.0,
                response_format={"type": "json_object"}
            )
            content = resp.choices[0].message.content
            data = json.loads(content)
            latency = (time.time() - start) * 1000
            return ModelVerdict(
                provider=self.name,
                model=self.model,
                is_vulnerable=bool(data.get("vulnerable", False)),
                confidence=float(data.get("confidence", 0.5)),
                vuln_type=str(data.get("vuln_type", "")),
                cwe_id=str(data.get("cwe_id", "")),
                severity=str(data.get("severity", "low")),
                explanation=str(data.get("explanation", "")),
                latency_ms=latency,
                raw=data
            )
        except Exception as e:
            logger.warning(f"OpenAI 分析失败: {e}")
            return ModelVerdict(
                provider=self.name,
                model=self.model,
                is_vulnerable=False,
                confidence=0.0,
                latency_ms=(time.time() - start) * 1000,
                raw={"error": str(e)}
            )


class OllamaProvider(BaseProvider):
    """Ollama 本地模型 Provider"""

    def __init__(self, model: str = "qwen2.5-coder:7b",
                 host: str = "http://localhost:11434",
                 weight: float = 1.0):
        super().__init__("ollama", model, weight)
        self.host = host.rstrip("/")

    def analyze(self, code: str, context: Dict[str, Any]) -> ModelVerdict:
        start = time.time()
        try:
            import requests
            sys_prompt = (
                "你是一个二进制安全分析专家。请基于以下伪代码/汇编判断是否存在漏洞。"
                "严格以 JSON 输出。"
            )
            user_prompt = (
                f"代码:\n```\n{code[:4000]}\n```\n"
                f"上下文:\n{json.dumps(context, ensure_ascii=False)[:1000]}\n"
                f'输出 JSON: {{"vulnerable": bool, "confidence": float, '
                f'"vuln_type": str, "cwe_id": str, "severity": str, "explanation": str}}'
            )
            r = requests.post(
                f"{self.host}/api/chat",
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": sys_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    "format": "json",
                    "stream": False
                },
                timeout=120
            )
            r.raise_for_status()
            data = json.loads(r.json()["message"]["content"])
            latency = (time.time() - start) * 1000
            return ModelVerdict(
                provider=self.name,
                model=self.model,
                is_vulnerable=bool(data.get("vulnerable", False)),
                confidence=float(data.get("confidence", 0.5)),
                vuln_type=str(data.get("vuln_type", "")),
                cwe_id=str(data.get("cwe_id", "")),
                severity=str(data.get("severity", "low")),
                explanation=str(data.get("explanation", "")),
                latency_ms=latency,
                raw=data
            )
        except Exception as e:
            logger.warning(f"Ollama 分析失败: {e}")
            return ModelVerdict(
                provider=self.name,
                model=self.model,
                is_vulnerable=False,
                confidence=0.0,
                latency_ms=(time.time() - start) * 1000,
                raw={"error": str(e)}
            )


class LocalHeuristicProvider(BaseProvider):
    """无外部依赖的本地启发式 Provider (作为兜底)"""

    DANGEROUS_PATTERNS = {
        "strcpy": ("CWE-120", "high", "buffer_overflow"),
        "strcat": ("CWE-120", "high", "buffer_overflow"),
        "sprintf": ("CWE-120", "high", "format_string_buffer"),
        "gets": ("CWE-242", "critical", "buffer_overflow"),
        "memcpy": ("CWE-805", "medium", "buffer_overflow"),
        "system": ("CWE-78", "high", "command_injection"),
        "execve": ("CWE-78", "high", "command_injection"),
        "popen": ("CWE-78", "high", "command_injection"),
        "free": ("CWE-416", "medium", "use_after_free"),
    }

    def __init__(self, weight: float = 0.3):
        super().__init__("local_heuristic", "rule-v1", weight)

    def analyze(self, code: str, context: Dict[str, Any]) -> ModelVerdict:
        start = time.time()
        text = code.lower()
        hits = []
        for pat, (cwe, sev, vt) in self.DANGEROUS_PATTERNS.items():
            if pat in text:
                hits.append((cwe, sev, vt))
        if hits:
            cwe, sev, vt = hits[0]
            conf = min(0.9, 0.4 + 0.15 * len(hits))
            return ModelVerdict(
                provider=self.name,
                model=self.model,
                is_vulnerable=True,
                confidence=conf,
                vuln_type=vt,
                cwe_id=cwe,
                severity=sev,
                explanation=f"匹配危险函数: {[h[0] for h in hits]}",
                latency_ms=(time.time() - start) * 1000,
                raw={'matches': [h[2] for h in hits]}
            )
        return ModelVerdict(
            provider=self.name,
            model=self.model,
            is_vulnerable=False,
            confidence=0.3,
            latency_ms=(time.time() - start) * 1000
        )


class AIEnsembleVoter:
    """多 AI 集成投票器"""

    def __init__(self,
                 providers: Optional[List[BaseProvider]] = None,
                 strategy: VoteStrategy = VoteStrategy.WEIGHTED_SOFT,
                 min_providers: int = 2,
                 max_concurrency: int = 4):
        self.providers = providers or [
            LocalHeuristicProvider(weight=0.3),
        ]
        self.strategy = strategy
        self.min_providers = min_providers
        self.max_concurrency = max_concurrency

    def add_provider(self, p: BaseProvider):
        self.providers.append(p)

    def _vote_hard(self, verdicts: List[ModelVerdict]) -> Tuple[bool, float]:
        v_cnt = sum(1 for v in verdicts if v.is_vulnerable)
        nv_cnt = len(verdicts) - v_cnt
        return v_cnt > nv_cnt, max(v_cnt, nv_cnt) / max(1, len(verdicts))

    def _vote_soft(self, verdicts: List[ModelVerdict],
                   weighted: bool) -> Tuple[bool, float, List[float]]:
        ws = [v.confidence for v in verdicts]
        ww = [p.dynamic_weight() for p in self.providers[:len(verdicts)]]
        if weighted:
            num = sum(c * w for c, w in zip(ws, ww))
            den = sum(ww)
        else:
            num = sum(ws)
            den = len(ws)
        avg = num / max(1e-9, den)
        return avg >= 0.5, avg, ws

    def _agreement(self, verdicts: List[ModelVerdict]) -> float:
        if not verdicts:
            return 0.0
        pos = sum(1 for v in verdicts if v.is_vulnerable)
        ratio = max(pos, len(verdicts) - pos) / len(verdicts)
        return ratio

    def ensemble_analyze(self, code: str,
                         context: Optional[Dict[str, Any]] = None) -> EnsembleResult:
        context = context or {}
        verdicts: List[ModelVerdict] = []
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=self.max_concurrency) as pool:
            futures = {pool.submit(p.analyze, code, context): p
                       for p in self.providers}
            for fut, provider in futures.items():
                try:
                    v = fut.result(timeout=120)
                    verdicts.append(v)
                except Exception as e:
                    logger.warning(f"{provider.name} 分析异常: {e}")
                    verdicts.append(ModelVerdict(
                        provider=provider.name, model=provider.model,
                        is_vulnerable=False, confidence=0.0,
                        raw={"error": str(e)}
                    ))

        if not verdicts:
            return EnsembleResult(False, 0.0, "", "", "low", [],
                                   self.strategy, 0.0)

        if self.strategy == VoteStrategy.HARD:
            is_vuln, conf = self._vote_hard(verdicts)
        elif self.strategy == VoteStrategy.SOFT:
            is_vuln, conf, _ = self._vote_soft(verdicts, weighted=False)
        elif self.strategy == VoteStrategy.WEIGHTED_SOFT:
            is_vuln, conf, _ = self._vote_soft(verdicts, weighted=True)
        else:
            best = max(verdicts, key=lambda v: v.confidence)
            is_vuln, conf = best.is_vulnerable, best.confidence

        # 类型/CWE 取多数
        vt_counter: Dict[str, int] = defaultdict(int)
        cwe_counter: Dict[str, int] = defaultdict(int)
        sev_counter: Dict[str, int] = defaultdict(int)
        for v in verdicts:
            if v.is_vulnerable:
                vt_counter[v.vuln_type] += 1
                cwe_counter[v.cwe_id] += 1
                sev_counter[v.severity] += 1
        vt = max(vt_counter.items(), key=lambda kv: kv[1])[0] if vt_counter else ""
        cwe = max(cwe_counter.items(), key=lambda kv: kv[1])[0] if cwe_counter else ""
        sev = max(sev_counter.items(), key=lambda kv: kv[1])[0] if sev_counter else "low"

        return EnsembleResult(
            is_vulnerable=is_vuln,
            confidence=conf,
            vuln_type=vt,
            cwe_id=cwe,
            severity=sev,
            votes=verdicts,
            strategy=self.strategy,
            agreement_score=self._agreement(verdicts)
        )


def build_default_ensemble(openai_model: Optional[str] = None,
                           ollama_model: Optional[str] = None) -> AIEnsembleVoter:
    providers: List[BaseProvider] = [LocalHeuristicProvider(weight=0.3)]
    if openai_model and os.environ.get("OPENAI_API_KEY"):
        providers.append(OpenAIProvider(model=openai_model, weight=1.0))
    if ollama_model:
        providers.append(OllamaProvider(model=ollama_model, weight=0.8))
    return AIEnsembleVoter(providers=providers,
                           strategy=VoteStrategy.WEIGHTED_SOFT)
