from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional

log = logging.getLogger(__name__)

# 默认配置 — 与 config/default.yaml 对齐
_DEFAULT_CONFIG: Dict[str, Any] = {
    "paths": {
        "data_dir": "data",
        "output_dir": "output",
        "log_dir": "logs",
    },
    "logging": {
        "level": "INFO",
        "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        "file": "logs/dynamic.log",
        "max_bytes": 10 * 1024 * 1024,
        "backup_count": 3,
    },
    "retry": {
        "max_attempts": 3,
        "backoff_base": 2.0,
        "max_delay_seconds": 60,
    },
    "analysis": {
        "timeout_seconds": 300,
        "max_memory_mb": 2048,
    },
}


def _get_default_config_path() -> str:
    """返回内置 default.yaml 的路径。"""
    return os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "config",
        "default.yaml",
    )


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """深度合并两个字典, 冲突时 override 值优先。"""
    result = dict(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _apply_env_overrides(config: Dict[str, Any], prefix: str = "DYN_") -> Dict[str, Any]:
    for env_key, env_value in os.environ.items():
        if not env_key.startswith(prefix):
            continue

        # 解析 DYN_SECTION_KEY ["section", "key"]
        parts = env_key[len(prefix):].lower().split("_", 1)
        if len(parts) != 2:
            continue

        section, key = parts
        if section in config and isinstance(config[section], dict):
            # 按类型推断转换值
            typed_value = _cast_env_value(env_value)
            config[section][key] = typed_value
            log.debug("Env override: %s -> %s.%s = %s", env_key, section, key, typed_value)

    return config


def _cast_env_value(value: str) -> Any:
    lowered = value.lower()
    if lowered in ("true", "yes", "1"):
        return True
    if lowered in ("false", "no", "0"):
        return False
    if value.isdigit():
        return int(value)
    if value.replace(".", "", 1).isdigit() and value.count(".") <= 1:
        return float(value)
    # 去除引号包裹
    if (value.startswith('"') and value.endswith('"')) or \
       (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    return value


def load_config(user_config_path: Optional[str] = None) -> Dict[str, Any]:
    config = dict(_DEFAULT_CONFIG)

    # 合并 bundled default.yaml
    default_path = _get_default_config_path()
    if os.path.isfile(default_path):
        try:
            from .utils import load_yaml_config
            bundled = load_yaml_config(default_path)
            config = _deep_merge(config, bundled)
            log.debug("Loaded bundled config: %s", default_path)
        except Exception as e:
            log.warning("Failed to load bundled config %s: %s", default_path, e)

    # 合并用户配置
    if user_config_path is not None:
        if not os.path.isfile(user_config_path):
            raise FileNotFoundError(f"User config not found: {user_config_path}")
        try:
            from .utils import load_yaml_config
            user_config = load_yaml_config(user_config_path)
            config = _deep_merge(config, user_config)
            log.debug("Loaded user config: %s", user_config_path)
        except Exception as e:
            log.warning("Failed to load user config %s: %s", user_config_path, e)

    # Apply environment variable overrides
    config = _apply_env_overrides(config, "DYN_")

    return config


def get_config_value(config: Dict[str, Any], dotted_key: str, default: Any = None) -> Any:
    """用点号路径读取嵌套配置值，如 get_config_value(config, "analysis.timeout_seconds", 300)。
    """
    keys = dotted_key.split(".")
    current: Any = config
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return default
    return current
