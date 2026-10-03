# 日志脱敏工具
# 提供 API Key / token / secret 的正则脱敏和日志过滤器
import re
import logging

# AI 提供商常量
AI_PROVIDER_OPENAI = 'openai'
AI_PROVIDER_AZURE = 'azure'
AI_PROVIDER_OLLAMA = 'ollama'
AI_PROVIDER_LLAMACPP = 'llamacpp'
AI_PROVIDER_CUSTOM = 'custom'

logger = logging.getLogger('config')


def mask_api_key(api_key: str, show_first: int = 4, show_last: int = 4) -> str:
    """脱敏 API Key - 保留首尾各 N 位，中间替换为 *"""
    if not api_key or not isinstance(api_key, str):
        return api_key

    key_length = len(api_key)

    if key_length <= show_first + show_last:
        return '*' * key_length

    prefix = api_key[:show_first]
    suffix = api_key[-show_last:]
    middle = '*' * (key_length - show_first - show_last)

    return f"{prefix}{middle}{suffix}"


def mask_sensitive_data(text: str) -> str:
    """脱敏日志中的 API key / token / secret-前4后4保留，中间替换为*"""
    if not text or not isinstance(text, str):
        return text

    def replace_partial(match):
        prefix = match.group(1) if len(match.groups()) >= 2 else ''
        key = match.group(2) if len(match.groups()) >= 2 else match.group(1)

        if key:
            masked_key = mask_api_key(key)
            return prefix + masked_key

        return match.group(0)

    api_key_patterns = [
        r'(api[_-]?key\s*[=:]\s*["\']?)([a-zA-Z0-9\-_]{8,})',
        r'(key\s*[=:]\s*["\']?)(sk-[a-zA-Z0-9_\-]{32,})',
        r'()(sk-[a-zA-Z0-9_\-]{32,})',
        r'(authorization\s*[=:]\s*["\']?Bearer\s+)([a-zA-Z0-9\-_.]+)',
        r'(AZURE_OPENAI_API_KEY\s*[=:]\s*["\']?)([a-zA-Z0-9\-_]{8,})',
        r'(CUSTOM_API_KEY\s*[=:]\s*["\']?)([a-zA-Z0-9\-_]{8,})',
    ]

    masked = text
    for pattern in api_key_patterns:
        masked = re.sub(pattern, replace_partial, masked, flags=re.IGNORECASE)

    token_patterns = [
        r'(token\s*[=:]\s*["\']?)([a-zA-Z0-9\-_.]{8,})',
        r'(access[_-]?token\s*[=:]\s*["\']?)([a-zA-Z0-9\-_.]{8,})',
        r'(secret\s*[=:]\s*["\']?)([a-zA-Z0-9\-_.]{8,})',
        r'(password\s*[=:]\s*["\']?)([^"\'\s]{4,})',
    ]

    for pattern in token_patterns:
        masked = re.sub(pattern, replace_partial, masked, flags=re.IGNORECASE)

    env_patterns = [
        r'([A-Z0-9_]+_API_KEY)\s*[=:]\s*["\']?([^"\'\s]{8,})["\']?',
        r'([A-Z0-9_]+_SECRET)\s*[=:]\s*["\']?([^"\'\s]{8,})["\']?',
        r'([A-Z0-9_]+_TOKEN)\s*[=:]\s*["\']?([^"\'\s]{8,})["\']?',
    ]

    for pattern in env_patterns:
        masked = re.sub(pattern, r'\1=***MASKED***', masked, flags=re.IGNORECASE)

    return masked


class SensitiveFilter(logging.Filter):
    """日志过滤器，自动脱敏敏感信息"""

    def filter(self, record):
        if isinstance(record.msg, str):
            record.msg = mask_sensitive_data(record.msg)

        if record.args:
            args_list = list(record.args)
            for i, arg in enumerate(args_list):
                if isinstance(arg, str):
                    args_list[i] = mask_sensitive_data(arg)
            record.args = tuple(args_list)

        return True
