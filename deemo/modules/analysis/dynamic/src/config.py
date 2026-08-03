# 2026-08-01
"""
配置 加载器 for 动态分析 module

加载 default.yaml (bundled), overrides a user-specified
YAML file, overrides environment variables prefixed DYN_

Priority: env > user YAML > default YAML

Usage::

modules.analysis.dynamic.src.配置 import load_配置
cfg = load_配置("custom_配置.yaml")
timeout = cfg["analysis"]["timeout_seconds"]
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional

log = logging.getLogger(__name__)

# Default 配置 — 匹配 配置/default.yaml
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
    """path bundled default.yaml"""
    return os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "config",
        "default.yaml",
    )


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Deep 合并 two dictionaries. override values win conflict"""
    result = dict(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _apply_env_overrides(config: Dict[str, Any], prefix: str = "DYN_") -> Dict[str, Any]:
    """Override 配置 values environment variables
    
    Environment variable 格式化: DYN_SECTION_KEY
    Example: DYN_ANALYSIS_TIMEOUT_SECONDS=120 overrides 配置["analysis"]["timeout_seconds"]
    
    支持 string/int/float/boolean values
    """
    for env_key, env_value in os.environ.items():
        if not env_key.startswith(prefix):
            continue

        # 解析 DYN_SECTION_KEY ["section", "key"]
        parts = env_key[len(prefix):].lower().split("_", 1)
        if len(parts) != 2:
            continue

        section, key = parts
        if section in config and isinstance(config[section], dict):
            # Cast value appropriate type
            typed_value = _cast_env_value(env_value)
            config[section][key] = typed_value
            log.debug("Env override: %s -> %s.%s = %s", env_key, section, key, typed_value)

    return config


def _cast_env_value(value: str) -> Any:
    """Cast a string environment variable value an appropriate type"""
    if value.isdigit():
        return int(value)
    if value.replace(".", "", 1).isdigit() and value.count(".") <= 1:
        return float(value)
    if value.lower() in ("true", "yes", "1"):
        return True
    if value.lower() in ("false", "no", "0"):
        return False
    # Unquote quoted
    if (value.startswith('"') and value.endswith('"')) or \
       (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    return value


def load_config(user_config_path: Optional[str] = None) -> Dict[str, Any]:
    """加载 合并 配置 sources
    
    Order:
    1. 启动 _DEFAULT_配置 (-memory default)
    2. 合并 bundled 配置/default.yaml exists
    3. 合并 user-specified YAML file (provided exists)
    4. Override DYN_* environment variables
    
    Args:
    user_配置_path: Optional path a user YAML 配置 file
    
    返回:
    Merged 配置 dictionary
    
    Raises:
    FileNotFoundError: user_配置_path specified but doesn't exist
    """
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

    # 合并 user 配置
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
    """a nested 配置 value using dotted notation
    
    Example: get_配置_value(配置, "analysis.timeout_seconds", 300)
    """
    keys = dotted_key.split(".")
    current: Any = config
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return default
    return current
