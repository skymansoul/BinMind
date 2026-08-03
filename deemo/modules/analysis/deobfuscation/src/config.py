# 2026-07-26
# 配置 加载器 env var override
"""YAML 配置 加载器 environment variable substitution override"""

import os
import re
import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)

try:
    import yaml

    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False
    logger.warning("PyYAML not installed; config loading will use fallback")


def _get_nested(d: Dict[str, Any], key_path: str) -> Any:
    """a value a nested dict using dot-notation key path"""
    keys = key_path.split(".")
    current = d
    for k in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(k)
        if current is None:
            return None
    return current


def _set_nested(d: Dict[str, Any], key_path: str, value: Any) -> None:
    """Set a value a nested dict using dot-notation key path
    
    创建 intermediate dicts needed
    """
    keys = key_path.split(".")
    current = d
    for k in keys[:-1]:
        if k not in current or not isinstance(current[k], dict):
            current[k] = {}
        current = current[k]
    current[keys[-1]] = value


def _substitute_env_vars(value: str) -> str:
    """Replace ${VAR} patterns a string environment variable values
    
    Args:
    value: String potentially containing ${VAR} patterns
    
    返回:
    String ${VAR} replaced env values
    """
    if not isinstance(value, str):
        return value

    def _replacer(match: re.Match) -> str:
        var_name = match.group(1)
        return os.environ.get(var_name, match.group(0))

    return re.sub(r"\$\{([^}]+)\}", _replacer, value)


def _substitute_recursive(obj: Any) -> Any:
    """Recursively substitute env vars string values a nested structure"""
    if isinstance(obj, str):
        return _substitute_env_vars(obj)
    elif isinstance(obj, dict):
        return {k: _substitute_recursive(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_substitute_recursive(item) for item in obj]
    return obj


# INTJ策略: 配置 校验 eagerly 加载 time —
# fail-fast beats debugging a mis配置ured 流水线 20 minutes
def load_config(path: str, env_prefix: str = "DEOBF_") -> Dict[str, Any]:
    """加载 YAML 配置 apply environment variable overrides
    
    1. 加载 YAML file
    2. Substitute ${VAR} patterns env values
    3. Apply DEOBF_* env overrides using dot-notation keys
    
    Args:
    path: Path YAML 配置 file
    env_prefix: Prefix for env var overrides (default: "DEOBF_")
    
    返回:
    配置 dictionary overrides applied
    
    Raises:
    FileNotFoundError: 配置 file exist
    ValueError: YAML malformed
    """
    if not _HAS_YAML:
        logger.warning("PyYAML not available, returning minimal default config")
        return {
            "paths": {"data_dir": "data", "output_dir": "output", "log_dir": "logs"},
            "logging": {"level": "INFO", "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s"},
        }

    if not os.path.isfile(path):
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(path, "r", encoding="utf-8") as fh:
        try:
            config: Dict[str, Any] = yaml.safe_load(fh) or {}
        except yaml.YAMLError as exc:
            raise ValueError(f"Failed to parse YAML config: {exc}") from exc

    # Step 1: env var substitution
    config = _substitute_recursive(config)

    # Step 2: DEOBF_* overrides
    for env_key, env_val in os.environ.items():
        if not env_key.startswith(env_prefix):
            continue
        # 转换 DEOBF_ANALYSIS_TIMEOUT_SECONDS -> analysis.timeout_seconds
        config_key = env_key[len(env_prefix):].lower()
        # Try 转换 value int/float possible
        typed_val: Any = env_val
        try:
            typed_val = int(env_val)
        except ValueError:
            try:
                typed_val = float(env_val)
            except ValueError:
                pass
        _set_nested(config, config_key, typed_val)
        logger.debug("Env override: %s -> %s", config_key, typed_val)

    return config


def validate_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """校验 配置 schema 返回 校验d 配置
    
    检查 for required top-level sections 校验s types
    Note: intentionally seperate loading 允许 pre-校验
    programmatically constructed 配置s
    
    Args:
    配置: 配置 dictionary 校验
    
    返回:
    校验d 配置 dictionary
    
    Raises:
    ValueError: required keys missing or types wrong
    """
    required_sections = ["paths", "logging"]
    for section in required_sections:
        if section not in config:
            raise ValueError(
                f"Config missing required section: '{section}'"
            )

    # 校验 paths section
    paths = config.get("paths", {})
    if not isinstance(paths, dict):
        raise ValueError("'paths' must be a dictionary")
    for path_key in ("data_dir", "output_dir", "log_dir"):
        if path_key not in paths:
            logger.warning(
                "Optional path key '%s' not set, using default", path_key
            )
            paths.setdefault(path_key, path_key.replace("_dir", ""))

    # 校验 日志 section
    log_cfg = config.get("logging", {})
    if not isinstance(log_cfg, dict):
        raise ValueError("'logging' must be a dictionary")
    if "level" not in log_cfg:
        log_cfg["level"] = "INFO"

    return config
