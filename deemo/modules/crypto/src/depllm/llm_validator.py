"""
LLM 语义验证层。
依赖上下文 + 调用链摘要 → 提示词 → OpenAI 兼容 API → verdict。
未配置 API → 降级为启发式路径。异常 → uncertain，不中断。
判定由上层 VerdictCache 缓存，本层不做缓存。
"""

import json
import logging
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Dict, Optional

_log = logging.getLogger(__name__)


@dataclass
class LLMVerdict:
    """LLM 判定结果."""
    verdict: str            # confirmed / rejected / uncertain
    reason: str = ""
    raw: str = ""           # 模型原始输出，调试用
    source: str = "llm"


# 提示词 — 将依赖上下文压缩为可判定的语义证据
_PROMPT_TEMPLATE = """You are a cryptographic API misuse auditor. A static pattern
matcher flagged the following candidate misuse in a binary. Decide whether it is a
REAL cryptographic misuse or a FALSE POSITIVE (test vector, lookup table,
documentation string, or random byte coincidence).

Candidate misuse:
- type: {misuse_type}
- api: {api}
- severity: {severity}

Dependency context (from static binary analysis):
- upstream APIs (before the hit): {upstream}
- downstream APIs (after the hit): {downstream}
- call chain: {call_chain}
- region entropy: {region_entropy}
- repetition count (same constant occurrences in file): {repetition_count}

Reply with ONLY a JSON object:
{{"verdict": "confirmed"|"rejected"|"uncertain", "reason": "<one sentence>"}}
- "confirmed": the context genuinely indicates hardcoded/weak cryptographic
  material flowing into a production crypto operation.
- "rejected": the hit is an artifact unrelated to real crypto usage.
- "uncertain": insufficient evidence.
"""


class LLMValidator:
    """OpenAI 兼容 chat/completions 客户端。"""

    def __init__(self,
                 base_url: Optional[str] = None,
                 model: Optional[str] = None,
                 api_key: Optional[str] = None,
                 timeout: float = 30,
                 max_tokens: int = 256) -> None:
        self.base_url = (base_url or "").strip().rstrip('/')
        self.model = (model or "").strip()
        self.api_key = (api_key or "").strip()
        self.timeout = float(timeout or 30)
        self.max_tokens = int(max_tokens or 256)

    def is_configured(self) -> bool:
        """base_url 与 model 均需配置."""
        return bool(self.base_url and self.model)

    def _endpoint(self) -> str:
        """规范化 chat/completions 端点。兼容多种 base_url 形态。"""
        if self.base_url.endswith('/chat/completions'):
            return self.base_url
        if self.base_url.endswith('/v1'):
            return self.base_url + '/chat/completions'
        if self.base_url.endswith('/v1/'):
            return self.base_url + 'chat/completions'
        return self.base_url + '/v1/chat/completions'

    def validate(self, context: Dict[str, object]) -> LLMVerdict:
        """语义验证；未配置或异常 → uncertain."""
        if not self.is_configured():
            return LLMVerdict('uncertain', 'LLM not configured', source='heuristic')
        prompt = _PROMPT_TEMPLATE.format(
            misuse_type=context.get('misuse_type', ''),
            api=context.get('api', ''),
            severity=context.get('severity', ''),
            upstream=', '.join(sorted(context.get('upstream_apis') or [])) or 'none',
            downstream=', '.join(sorted(context.get('downstream_apis') or [])) or 'none',
            call_chain=context.get('call_chain', '') or 'none',
            region_entropy=context.get('region_entropy', 0.0),
            repetition_count=context.get('repetition_count', 1),
        )
        try:
            raw = self._call(prompt)
            parsed = self._parse(raw)
            return LLMVerdict(parsed.get('verdict', 'uncertain'),
                              parsed.get('reason', ''),
                              raw=raw[:400])
        except Exception as exc:  # noqa: BLE001 — 失败降级，不中断主流程
            _log.debug("LLM validation failed: %s", exc)
            return LLMVerdict('uncertain', 'llm_error', source='llm')

    def _call(self, prompt: str) -> str:
        """POST chat/completions，返回消息文本."""
        payload = json.dumps({
            'model': self.model,
            'messages': [
                {'role': 'system',
                 'content': 'You are a precise security auditor. Output only JSON.'},
                {'role': 'user', 'content': prompt},
            ],
            'temperature': 0,
            'max_tokens': self.max_tokens,
        }).encode('utf-8')
        req = urllib.request.Request(self._endpoint(), data=payload, method='POST')
        req.add_header('Content-Type', 'application/json')
        if self.api_key:
            req.add_header('Authorization', 'Bearer ' + self.api_key)
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            body = resp.read().decode('utf-8', errors='replace')
        data = json.loads(body)
        return data['choices'][0]['message']['content']

    @staticmethod
    def _parse(raw: str) -> Dict[str, str]:
        """解析模型输出 → {verdict, reason}。首选 JSON，失败则关键词扫描。"""
        text = raw.strip()
        start = text.find('{')
        end = text.rfind('}')
        if start != -1 and end > start:
            try:
                obj = json.loads(text[start:end + 1])
                verdict = str(obj.get('verdict', 'uncertain')).lower()
                if verdict in ('confirmed', 'rejected', 'uncertain'):
                    return {'verdict': verdict,
                            'reason': str(obj.get('reason', ''))[:200]}
            except (ValueError, TypeError):
                pass
        low = text.lower()
        verdict = 'uncertain'
        for tok in ('confirmed', 'rejected', 'uncertain'):
            if tok in low:
                verdict = tok
                break
        return {'verdict': verdict, 'reason': text[:200]}
