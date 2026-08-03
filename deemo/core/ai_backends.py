"""
LLM backend abstraction. Supports OpenAI, Anthropic, Ollama, and
llama.cpp. Each backend is queried via a uniform interface.
"""

import json
import logging
import os
from typing import Optional

from config import AI_PROVIDER, OPENAI_API_KEY, ANTHROPIC_API_KEY, LLM_ENDPOINTS

__log = logging.getLogger(__name__)


# FIXME: custom provider currently ignores model param — need to thread
# it through to _custom_chat if we ever migrate off the DeepSeek proxy.
def query_llm(system: str, user: str, model: str = None,
              temperature: float = 0.3, max_tokens: int = 4096) -> str:
    """
    Send a prompt to the configured LLM backend and return the text response.
    Provider is determined by the AI_PROVIDER env/config.
    """
    provider = AI_PROVIDER.lower()

    if provider == 'openai':
        return _openai_chat(system, user, model, temperature, max_tokens)
    if provider == 'anthropic':
        return _anthropic_chat(system, user, model, temperature, max_tokens)
    if provider == 'ollama':
        return _ollama_chat(system, user, model, temperature, max_tokens)
    if provider == 'llamacpp':
        return _llamacpp_chat(system, user, model, temperature, max_tokens)
    if provider == 'custom':
        return _custom_chat(system, user, model, temperature, max_tokens)
    raise ValueError(f"Unknown AI provider: {provider}")


def _openai_chat(system: str, user: str, model: str,
                 temperature: float, max_tokens: int) -> str:
    import openai
    client = openai.OpenAI(api_key=OPENAI_API_KEY)
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
    resp = requests.post(url, json={
        'messages': [
            {'role': 'system', 'content': system},
            {'role': 'user', 'content': user},
        ],
        'temperature': temperature,
        'max_tokens': max_tokens,
    }, timeout=300)
    resp.raise_for_status()
    return resp.json()['choices'][0]['message']['content']
