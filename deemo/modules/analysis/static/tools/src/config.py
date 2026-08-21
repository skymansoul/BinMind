"""Config loading, YAML parsing, environment variable overrides,
schema validation

Environment variables prefixed ATOOLS_ are automatically applied as
overrides. Nested keys specified via double underscore or dot notation:
e.g., ATOOLS_ANALYSIS__TIMEOUT_SECONDS -> analysis.timeout_seconds
"""

import logging
import os
from typing import Any, Optional

_log = logging.getLogger(__name__)

# 默认的 env 覆写前缀
_DEFAULT_ENV_PREFIX = "ATOOLS_"

# 必须存在的顶级配置键
_REQUIRED_KEYS: list[str] = ["logging", "analysis"]

# 每个键的类型约束
_TYPE_CONSTRAINTS: dict[str, type] = {
    "analysis.timeout_seconds": int,
    "analysis.max_memory_mb": int,
    "retry.max_attempts": int,
    "retry.backoff_base": float,
    "retry.max_delay_seconds": (int, float),
    "logging.level": str,
    "logging.format": str,
}

# 值范围约束（闭区间）
_RANGE_CONSTRAINTS: dict[str, tuple[Optional[float], Optional[float]]] = {
    "analysis.timeout_seconds": (1, 3600),
    "analysis.max_memory_mb": (128, 65536),
    "retry.max_attempts": (0, 100),
    "retry.backoff_base": (1.0, 10.0),
    "retry.max_delay_seconds": (1, 3600),
    "logging.backup_count": (0, 100),
}


def load_config(path: str, env_prefix: str = _DEFAULT_ENV_PREFIX) -> dict[str, Any]:
    """加载 YAML 配置 file apply environment variable overrides

    Environment variables prefix converted lowercase
    dot-notation 配置 keys. For example, ``ATOOLS_ANALYSIS_TIMEOUT_SECONDS``
    becomes ``analysis.timeout_seconds``
    """
    from .utils import load_yaml_config

    config = load_yaml_config(path)
    _log.info("Loaded config from %s with %d top-level keys", path, len(config))

    # 迭代 environment variables apply overrides
    prefix_lower = env_prefix.lower()
    for env_key, env_value in os.environ.items():
        if not env_key.lower().startswith(prefix_lower):
            continue

        # Remove prefix 转换 dot notation
        # ATOOLS_ANALYSIS_TIMEOUT_SECONDS -> analysis.timeout_seconds
        config_key_raw = env_key[len(env_prefix):].lower()
        # 支持 double-underscore notation for nested keys
        # ATOOLS_ANALYSIS__TIMEOUT_SECONDS -> analysis.timeout_seconds
        config_key = config_key_raw.replace("__", ".")

        # 解析 value (try int, float, fall back str)
        parsed_value: Any = env_value
        for parser in (int, float):
            try:
                parsed_value = parser(env_value)
                break
            except ValueError:
                continue

        # Deep 合并 配置
        _deep_set(config, config_key, parsed_value)
        _log.debug("Env override: %s -> %s = %s", env_key, config_key, parsed_value)

    return config


def validate_config(config: dict[str, Any]) -> dict[str, Any]:
    """校验 配置 schema: required keys, types, value ranges

    // validate_config这个函数可能写得有点over-engineered，但以后扩展方便
    """
    errors: list[str] = []

    # 检查 required keys
    for key in _REQUIRED_KEYS:
        if key not in config:
            errors.append(f"Missing required config key: '{key}'")

    # 检查 type constraints
    for key_path, expected_type in _TYPE_CONSTRAINTS.items():
        value = _deep_get(config, key_path)
        if value is None:
            continue  # 校验 key present

        if isinstance(expected_type, tuple):
            if not isinstance(value, expected_type):
                errors.append(
                    f"Config key '{key_path}' has type {type(value).__name__}, "
                    f"expected one of {tuple(t.__name__ for t in expected_type)}"
                )
        else:
            if not isinstance(value, expected_type):
                errors.append(
                    f"Config key '{key_path}' has type {type(value).__name__}, "
                    f"expected {expected_type.__name__}"
                )

    # 检查 range constraints
    for key_path, (lo, hi) in _RANGE_CONSTRAINTS.items():
        value = _deep_get(config, key_path)
        if value is None:
            continue

        try:
            if lo is not None and value < lo:
                errors.append(
                    f"Config key '{key_path}' value {value} is below minimum {lo}"
                )
            if hi is not None and value > hi:
                errors.append(
                    f"Config key '{key_path}' value {value} is above maximum {hi}"
                )
        except TypeError:
            # value 无法比较(如 string vs int), 跳过 range 检查
            # Type constraints 校验d separately above
            pass

    if errors:
        for error in errors:
            _log.error("Config validation error: %s", error)
        raise ValueError("Config validation failed:\n  " + "\n  ".join(errors))

    _log.info("Config validation passed: %d keys checked", len(config))
    return config


def _deep_get(data: dict[str, Any], key_path: str, sep: str = ".") -> Any:
    """a nested value a dict using a dot-separated key path"""
    keys = key_path.split(sep)
    current: Any = data
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key)
            if current is None:
                return None
        else:
            return None
    return current


def _deep_set(data: dict[str, Any], key_path: str, value: Any, sep: str = ".") -> None:
    """Set a nested value a dict using a dot-separated key path

    创建 intermediate dicts needed
    """
    keys = key_path.split(sep)
    current = data
    for key in keys[:-1]:
        if key not in current or not isinstance(current[key], dict):
            current[key] = {}
        current = current[key]
    current[keys[-1]] = value
