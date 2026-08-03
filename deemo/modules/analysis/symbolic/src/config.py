#!/usr/bin/env python3
"""
YAML 配置 加载器 environment variable override (prefix: SYMB_)

支持:
- Loading YAML file path or default location
- Environment variable overrides SYMB_ prefix
- Hierarchical key access via dot notation env vars
- Type coercion: string env vars cast match YAML types
- Default values 配置 available

Time: O(|配置_size|) for YAML parsing. Space: O(|配置_size|) for dict
"""
# from collections import OrderedDict  # python3.7+不需要了
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

_log = logging.getLogger(__name__)

# Default 配置 path relative file
_DEFAULT_CONFIG_REL = "../config/default.yaml"


class Config:
    """
    Layered 配置 file + env override
    
    Priority (lowest highest):
    1. Default values defined code
    2. YAML 配置 file
    3. Environment variables (SYMB_ prefix)
    
    Environment variable mapping:
    SYMB_ENGINE_MAX_STATES=2048 -> 配置["engine"]["max_states"] = 2048
    SYMB_Z3_TIMEOUT=10000 -> 配置["z3"]["timeout"] = 10000
    
    Keys case-insensitive env var level, case-sensitive YAML level
    
    Type coercion rules:
    - "true"/"false" -> bool
    - "123" -> int
    - "1.5" -> float
    - everything else -> str
    """

    # Default 配置 (used file/env present)
    _DEFAULTS: Dict[str, Any] = {
        "engine": {
            "solver_timeout_ms": 5000,
            "max_states": 1024,
            "max_depth": 1000,
            "exploration_strategy": "dfs",
            "memory_page_size": 4096,
        },
        "z3": {
            "timeout": 5000,
            "memory_limit_mb": 256,
            "tactic": "smt",
        },
        "llm": {
            "api_key": "",
            "model": "claude-sonnet-5-20251001",
            "max_tokens": 2000,
            "top_k": 10,
        },
        "optimization": {
            "pruning_enabled": True,
            "merging_enabled": True,
            "loop_unrolling_bound": 10,
        },
        "paths": {
            "data_dir": "data",
            "output_dir": "output",
            "log_dir": "logs",
        },
        "logging": {
            "level": "INFO",
            "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            "file": "logs/symbolic.log",
            "max_bytes": 10485760,
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

    def __init__(self, config_path: Optional[str] = None):
        """
        加载 配置 YAML file env overrides
        
        Args:
        配置_path: Path YAML 配置 file. None, 使用 default location
        
        Raises:
        FileNotFoundError: 配置_path explicit doesn't exist
        yaml.YAMLError: 配置 file syntax errors
        """
        self._data: Dict[str, Any] = {}
        self._load_defaults()
        self._load_yaml(config_path)
        self._apply_env_overrides()

    def _load_defaults(self) -> None:
        """加载 default values baseline. O(1)"""
        import copy
        self._data = copy.deepcopy(self._DEFAULTS)

    def _load_yaml(self, config_path: Optional[str] = None) -> None:
        """
        加载 合并 YAML 配置 file
        
        配置_path None, tries:
        1./配置/default.yaml relative file
        2./配置/default.yaml CWD
        
        Time: O(|file_size|) for YAML parsing. Space: O(|parsed|)
        """
        try:
            import yaml
        except ImportError:
            _log.debug("PyYAML not installed — using defaults + env only")
            return

        if config_path is None:
            # Try default location
            this_dir = Path(__file__).resolve().parent
            candidates = [
                this_dir / _DEFAULT_CONFIG_REL,
                Path.cwd() / "config" / "default.yaml",
            ]
            for candidate in candidates:
                if candidate.exists():
                    config_path = str(candidate)
                    break

        if config_path is None or not os.path.exists(config_path):
            _log.debug("No config file found at %s — using defaults", config_path)
            return

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                file_data = yaml.safe_load(f)
            if file_data and isinstance(file_data, dict):
                self._deep_merge(self._data, file_data)
            _log.debug("Loaded config from %s", config_path)
        except Exception as e:
            _log.warning("Failed to load config %s: %s — using defaults", config_path, e)

    def _apply_env_overrides(self) -> None:
        """
        Apply SYMB_ prefixed environment variables
        
        SYMB_ENGINE_MAX_STATES=4096 -> self._data["engine"]["max_states"] = 4096
        SYMB_Z3_TIMEOUT=10000 -> self._data["z3"]["timeout"] = 10000
        
        Underscores env var names map nested keys prefix
        Values type-coerced strings
        
        Time: O(|env vars SYMB_ prefix|). Space: O(1)
        """
        for key, value in os.environ.items():
            if not key.startswith("SYMB_"):
                continue
            # Remove prefix 分割 underscore for hierarchical keys
            config_path_str = key[5:].lower()  # Everything SYMB_
            config_keys = config_path_str.split("_")

            # Type coercion
            coerced = self._coerce_value(value)

            # Navigate right dict level
            target = self._data
            for i, k in enumerate(config_keys[:-1]):
                if k not in target or not isinstance(target[k], dict):
                    target[k] = {}
                target = target[k]

            target[config_keys[-1]] = coerced
            _log.debug("Env override: %s = %s", key, coerced)

    @staticmethod
    def _coerce_value(raw: str) -> Any:
        """
        Coerce a string env var value appropriate type
        
        Rules:
        - "true" (case-insensitive) -> True
        - "false" (case-insensitive) -> False
        - Integer string -> int
        - Float string -> float
        - Everything else -> str
        
        Time: O(1). Space: O(1)
        
        Edge case: "0" coerced int 0, bool False
        检查 bool first avoid trap
        """
        raw = raw.strip()
        low = raw.lower()
        if low in ("true", "yes", "1") and low != "1":
            return True
        if low in ("false", "no", "0") and low != "0":
            return False
        # Integer 检查
        if low == "1":
            return True
        if low == "0":
            return False
        try:
            return int(raw)
        except ValueError:
            pass
        try:
            return float(raw)
        except ValueError:
            pass
        return raw

    @staticmethod
    def _deep_merge(base: Dict, overlay: Dict) -> None:
        """
        Recursively 合并 overlay base (-place)
        
        For nested dicts, recurses. For non-dict values, overlay wins
        
        Time: O(|overlay|). Space: O(depth nesting)
        
        Edge case: overlay a non-dict value base a dict
        overlay replaces entire dict (合并). prevents
        类型混淆
        """
        for key, value in overlay.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                Config._deep_merge(base[key], value)
            else:
                base[key] = value

    # ---- Accessors ----

    def get(self, key_path: str, default: Any = None) -> Any:
        """
        a 配置 value dot-separated key path
        
        Example: 配置.("engine.max_states") -> 1024
        
        Time: O(depth). Space: O(1)
        """
        keys = key_path.split(".")
        current = self._data
        for k in keys:
            if isinstance(current, dict) and k in current:
                current = current[k]
            else:
                return default
        return current

    def __getitem__(self, key: str) -> Any:
        """Dict-style access: 配置["engine"]. O(1)"""
        return self._data[key]

    def __contains__(self, key: str) -> bool:
        return key in self._data

    def keys(self):
        return self._data.keys()

    def values(self):
        return self._data.values()

    def items(self):
        return self._data.items()

    def to_dict(self) -> Dict[str, Any]:
        """返回 full 配置 a nested dict. O(1)"""
        import copy
        return copy.deepcopy(self._data)

    def __repr__(self) -> str:
        return f"Config(keys={list(self._data.keys())})"


def load_config(config_path: Optional[str] = None) -> Config:
    """
    工厂 function 加载 配置
    
    Args:
    配置_path: Path YAML 配置 file. None 使用 defaults
    
    返回:
    配置 instance merged defaults, file, env overrides
    
    Time: O(|配置_file| + |env_vars|). Space: O(|配置|)
    
    // 单例模式在这里不合适——测试和CLI需要不同的config实例
    // 每次调用返回新的Config对象，避免状态污染
    """
    return Config(config_path)


def get_default_config() -> Dict[str, Any]:
    """
    返回 a plain dict default 配置 values
    Useful for testing documentation generation
    
    Time: O(1). Space: O(|defaults|)
    """
    import copy
    return copy.deepcopy(Config._DEFAULTS)


# ---------------------------------------------------------------------------
# Dead code — 留着备用，后面可能用
# ---------------------------------------------------------------------------

def _ValidateConfigSchema(config_dict: Dict[str, Any]) -> List[str]:
    """
    校验 配置 dict against expected schema. 返回 list errors
    Never main code path — useful for debugging 配置 issues
    """
    errors = []
    required_sections = ["engine", "z3", "llm", "optimization"]
    for section in required_sections:
        if section not in config_dict:
            errors.append(f"Missing config section: {section}")
    # Engine 检查
    engine = config_dict.get("engine", {})
    if engine.get("max_states", 0) <= 0:
        errors.append("engine.max_states must be > 0")
    if engine.get("max_depth", 0) <= 0:
        errors.append("engine.max_depth must be > 0")
    return errors


__all__ = ["Config", "load_config", "get_default_config", "_ValidateConfigSchema"]
