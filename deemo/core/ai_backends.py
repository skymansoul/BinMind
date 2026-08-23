# core/ai_backends.py - LLM 后端抽象层
# 统一接口查询 OpenAI / Anthropic / Ollama / llamacpp / custom 五通道;
# 每次调用(含跳过事件)追加记录到 logs/llm_calls.jsonl。

import json
import logging
import os
import time
from typing import Dict, Optional

from config import AI_PROVIDER, OPENAI_API_KEY, ANTHROPIC_API_KEY, LLM_ENDPOINTS
# 委托 modules.llm_client 统一分发, 不在本层维护 provider 调用逻辑
from modules.llm_client import call_llm_simple, call_llm, is_ai_configured, PROMPT_VERSION

__log = logging.getLogger(__name__)

# 调用日志落盘路径 - deemo/logs/llm_calls.jsonl，运行时追加
_LLM_LOG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'logs', 'llm_calls.jsonl')


def _record_llm_call(provider: str, system: str, user: str,
                     model: str = None, output: str = '',
                     duration: float = None, error: str = '',
                     skipped: bool = False, reason: str = '',
                     status: str = '') -> None:
    """把一次 LLM 调用（或跳过事件）追加到 jsonl。写失败不影响主流程。

    status 取值: ok / skipped / error; duration_ms 为 duration 的毫秒形式。
    """
    entry = {
        'ts': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'provider': provider,
        'model': model,
        'prompt_version': PROMPT_VERSION,
        'input_head': (user or '')[:200],
        'output_head': (output or '')[:200],
        'duration_sec': round(duration, 3) if duration is not None else None,
        'duration_ms': round(duration * 1000) if duration is not None else None,
        'error': (error or '')[:300],
        'skipped': skipped,
        'reason': reason,
        'status': status,
    }
    try:
        os.makedirs(os.path.dirname(_LLM_LOG_PATH), exist_ok=True)
        with open(_LLM_LOG_PATH, 'a', encoding='utf-8') as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + '\n')
    except OSError as err:
        __log.debug("llm call log write failed: %s", err)


def _provider_configured(provider: str) -> bool:
    if provider == 'openai':
        return bool(OPENAI_API_KEY)
    if provider == 'anthropic':
        return bool(ANTHROPIC_API_KEY)
    if provider == 'deepseek':
        return bool(os.environ.get('CUSTOM_API_KEY') or OPENAI_API_KEY)
    return bool(LLM_ENDPOINTS.get(provider))


# Claude 通道常量 - Messages API 契约与 SDK messages.create 等价
_CLAUDE_MODEL = 'claude-3-5-sonnet-20241022'
_CLAUDE_MAX_TOKENS = 2048
_CLAUDE_TEMPERATURE = 0.3
_ANTHROPIC_MESSAGES_URL = 'https://api.anthropic.com/v1/messages'
_ANTHROPIC_VERSION = '2023-06-01'


def _effective_provider() -> str:
    """LLM_PROVIDER 环境变量优先, 回退 config.AI_PROVIDER。"""
    return os.environ.get('LLM_PROVIDER', AI_PROVIDER).lower()


def _claude_key() -> str:
    """读取 Claude 密钥: 环境变量优先, 其次 deemo/.temp_claude_key。"""
    key = os.environ.get('ANTHROPIC_API_KEY', '').strip()
    if key:
        return key
    key_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        '.temp_claude_key')
    try:
        with open(key_path, encoding='utf-8') as fh:
            return fh.read().strip()
    except OSError:
        return ''


def _mock_response(provider: str, system: str, user: str,
                   model: str = None) -> str:
    """模拟回退: 记录跳过事件并返回空内容, 不抛异常。"""
    _record_llm_call(provider, system, user, model=model,
                     skipped=True, reason='no_key', status='skipped')
    return ''


class BaseBackend:
    """LLM 后端基类: generate 返回 {fallback, content}。"""

    def generate(self, system: str, user: str) -> Dict[str, str]:
        raise NotImplementedError


# Claude 后端：读取 ANTHROPIC_API_KEY，若缺失则回退模拟。
# 仅用于实验对照，不持久化密钥。
class ClaudeBackend(BaseBackend):
    """Claude 后端。

    密钥优先级: ANTHROPIC_API_KEY 环境变量 - deemo/.temp_claude_key。
    两者均无时回退模拟模式 (status=skipped, reason=no_key)。
    异常 (超时/认证/限流) 记入 error 字段, 返回回退结果, 不中断流水线。
    """

    def __init__(self):
        self.api_key = _claude_key()

    def generate(self, system: str, user: str) -> Dict[str, str]:
        """调用 Messages API, 返回 {fallback, content}。

        content 前 200 字符由 _record_llm_call 截断写入 jsonl。
        """
        if not self.api_key:
            content = _mock_response('claude', system, user, _CLAUDE_MODEL)
            return {'fallback': True, 'content': content}
        t0 = time.time()
        try:
            import requests as _rq
            resp = _rq.post(
                _ANTHROPIC_MESSAGES_URL,
                headers={
                    'x-api-key': self.api_key,
                    'anthropic-version': _ANTHROPIC_VERSION,
                    'content-type': 'application/json',
                },
                json={
                    'model': _CLAUDE_MODEL,
                    'max_tokens': _CLAUDE_MAX_TOKENS,
                    'temperature': _CLAUDE_TEMPERATURE,
                    'system': system,
                    'messages': [{'role': 'user', 'content': user}],
                },
                timeout=120,
            )
            resp.raise_for_status()
            text = resp.json()['content'][0]['text']
            _record_llm_call('claude', system, user, model=_CLAUDE_MODEL,
                             output=text, duration=time.time() - t0,
                             status='ok')
            return {'fallback': False, 'content': text}
        except Exception as err:
            _record_llm_call('claude', system, user, model=_CLAUDE_MODEL,
                             duration=time.time() - t0, error=str(err),
                             status='error')
            return {'fallback': True,
                    'content': 'LLM unavailable, using static heuristics'}


def get_backend():
    """后端工厂: provider 为 claude 时返回 ClaudeBackend, 其余返回 None。"""
    if _effective_provider() == 'claude':
        return ClaudeBackend()
    return None


def query_llm(system: str, user: str, model: str = None,
              temperature: float = 0.3, max_tokens: int = 4096) -> str:
    """向配置的 LLM 后端发提示, 返回文本响应。

    Provider 取自 LLM_PROVIDER 环境变量 (缺省回退 config.AI_PROVIDER)。
    未配置凭据时记录一次跳过事件并返回空串, 不抛异常。
    claude 通道经 ClaudeBackend 处理, 异常不回抛。
    其余通道统一委托 modules.llm_client.call_llm_simple。
    """
    provider = _effective_provider()

    if provider == 'claude':
        # 跳过/错误/成功记录均由 ClaudeBackend 内聚完成
        return get_backend().generate(system, user).get('content', '')

    if not _provider_configured(provider):
        _record_llm_call(provider, system, user, model=model,
                         skipped=True, reason='provider not configured',
                         status='skipped')
        return ''

    t0 = time.time()
    try:
        result = call_llm_simple(
            prompt=user, system_prompt=system, model=model,
            temperature=temperature, max_tokens=max_tokens,
            use_cache=False)
        text = result.get('text', '')
        if result.get('simulation'):
            raise RuntimeError(result.get('error', 'simulation mode'))
        _record_llm_call(provider, system, user, model=model,
                         output=text, duration=time.time() - t0,
                         status='ok')
        return text
    except Exception as err:
        _record_llm_call(provider, system, user, model=model,
                         duration=time.time() - t0, error=str(err),
                         status='error')
        raise


def _openai_chat(system: str, user: str, model: str,
                 temperature: float, max_tokens: int) -> str:
    import openai
    # base_url / organization 透传 - 缺失时为 None, SDK 使用官方默认端点
    from config import Config
    client_kwargs = {'api_key': OPENAI_API_KEY}
    if Config.OPENAI_BASE_URL:
        client_kwargs['base_url'] = Config.OPENAI_BASE_URL
    if Config.OPENAI_ORGANIZATION:
        client_kwargs['organization'] = Config.OPENAI_ORGANIZATION
    client = openai.OpenAI(**client_kwargs)
    resp = client.chat.completions.create(
        model=model or 'gpt-4o',
        messages=[
            {'role': 'system', 'content': system},
            {'role': 'user', 'content': user},
        ],
        temperature=temperature,
        max_tokens=max_tokens,
    )
    return resp.choices[0].message.content


def _anthropic_chat(system: str, user: str, model: str,
                    temperature: float, max_tokens: int) -> str:
    import anthropic
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    resp = client.messages.create(
        model=model or 'claude-sonnet-4-20250514',
        system=system,
        messages=[{'role': 'user', 'content': user}],
        temperature=temperature,
        max_tokens=max_tokens,
    )
    return resp.content[0].text


def _ollama_chat(system: str, user: str, model: str,
                 temperature: float, max_tokens: int) -> str:
    import requests
    host = LLM_ENDPOINTS['ollama']
    resp = requests.post(f'{host}/api/chat', json={
        'model': model or 'llama3',
        'messages': [
            {'role': 'system', 'content': system},
            {'role': 'user', 'content': user},
        ],
        'options': {'temperature': temperature},
        'stream': False,
    }, timeout=300)
    resp.raise_for_status()
    return resp.json()['message']['content']


def _llamacpp_chat(system: str, user: str, model: str,
                   temperature: float, max_tokens: int) -> str:
    import requests
    host = LLM_ENDPOINTS['llamacpp']
    resp = requests.post(f'{host}/v1/chat/completions', json={
        'messages': [
            {'role': 'system', 'content': system},
            {'role': 'user', 'content': user},
        ],
        'temperature': temperature,
        'max_tokens': max_tokens,
    }, timeout=300)
    resp.raise_for_status()
    return resp.json()['choices'][0]['message']['content']


def _custom_chat(system: str, user: str, model: str,
                 temperature: float, max_tokens: int) -> str:
    import requests
    url = LLM_ENDPOINTS['custom']
    if not url:
        raise RuntimeError("CUSTOM_LLM_URL not set")
    # OpenAI 兼容端点必须显式携带 model; DeepSeek 代理缺省 deepseek-chat
    resp = requests.post(url, json={
        'model': model or 'deepseek-chat',
        'messages': [
            {'role': 'system', 'content': system},
            {'role': 'user', 'content': user},
        ],
        'temperature': temperature,
        'max_tokens': max_tokens,
    }, timeout=300)
    resp.raise_for_status()
    return resp.json()['choices'][0]['message']['content']
