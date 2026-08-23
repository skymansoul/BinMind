#!/usr/bin/env python3
"""
YAML 配置加载器, 支持 SYMB_ 前缀环境变量覆盖。

支持:
- 从文件路径或默认位置加载 YAML
- SYMB_ 前缀环境变量覆盖
- 下划线分隔的环境变量名映射为层级键
- 类型强制转换: 字符串环境变量值转为与 YAML 匹配的类型
- 内置默认配置兜底
"""
# from collections import OrderedDict  # python3.7+不需要了
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

_log = logging.getLogger(__name__)

# 默认配置路径 (相对本文件)
_DEFAULT_CONFIG_REL = "../config/default.yaml"


class Config:
    """
    分层配置: 文件 + 环境变量覆盖。

    优先级 (从低到高):
    1. 代码中定义的默认值
    2. YAML 配置文件
    3. 环境变量 (SYMB_ 前缀)

    环境变量映射:
    SYMB_ENGINE_MAX_STATES=2048 -> config["engine"]["max_states"] = 2048
    SYMB_Z3_TIMEOUT=10000 -> config["z3"]["timeout"] = 10000

    环境变量层键名不区分大小写, YAML 层区分。

    类型强制转换规则:
    - "true"/"false" -> bool
    - "123" -> int
    - "1.5" -> float
    - 其余 -> str
    """

    # 默认配置 (文件与环境变量均缺失时使用)
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
        """加载配置: 先取默认值, 再合并 YAML 文件, 最后应用环境变量覆盖。"""
        self._data: Dict[str, Any] = {}
        self._load_defaults()
        self._load_yaml(config_path)
        self._apply_env_overrides()

    def _load_defaults(self) -> None:
        """加载默认值基线, O(1)。"""
        import copy
        self._data = copy.deepcopy(self._DEFAULTS)

    def _load_yaml(self, config_path: Optional[str] = None) -> None:
        """
        加载并合并 YAML 配置文件。

        config_path 为 None 时依次尝试:
        1. ../config/default.yaml (相对本文件)
        2. ./config/default.yaml (相对 CWD)
        """
        try:
            import yaml
        except ImportError:
            _log.debug("PyYAML not installed — using defaults + env only")
            return

        if config_path is None:
            # 尝试默认位置
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
        应用 SYMB_ 前缀的环境变量覆盖。

        SYMB_ENGINE_MAX_STATES=4096 -> self._data["engine"]["max_states"] = 4096
        SYMB_Z3_TIMEOUT=10000 -> self._data["z3"]["timeout"] = 10000

        去掉前缀后按下划线拆分: 连续段若匹配已有嵌套字典则下钻,
        剩余段合并为叶子键, 值经类型强制转换。
        """
        for key, value in os.environ.items():
            if not key.startswith("SYMB_"):
                continue
            config_path_str = key[5:].lower()  # 去掉 SYMB_ 前缀
            config_keys = config_path_str.split("_")

            # 类型强制转换
            coerced = self._coerce_value(value)

            # 贪心下钻: 连续段匹配已有嵌套字典时进入,
            # 剩余段合并为叶子键 (支持 max_states 这类含下划线键名)
            target = self._data
            idx = 0
            while idx < len(config_keys) - 1:
                k = config_keys[idx]
                if k in target and isinstance(target[k], dict):
                    target = target[k]
                    idx += 1
                else:
                    break
            target["_".join(config_keys[idx:])] = coerced
            _log.debug("Env override: %s = %s", key, coerced)

    @staticmethod
    def _coerce_value(raw: str) -> Any:
        """
        把环境变量字符串值强制转换为对应类型。

        规则:
        - "true"/"yes"/"1" (不区分大小写) -> True
        - "false"/"no"/"0" -> False
        - 整数串 -> int
        - 浮点串 -> float
        - 其余 -> str

        先判 bool 再判 int/float, 避免 "0"/"1" 被当数值解析。
        """
        raw = raw.strip()
        low = raw.lower()
        if low in ("true", "yes", "1"):
            return True
        if low in ("false", "no", "0"):
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
        把 overlay 递归合并进 base (原地)。

        嵌套字典继续递归; 非字典值以 overlay 为准。边界情况:
        overlay 的非字典值覆盖 base 的整棵子树, 防止类型混淆。
        """
        for key, value in overlay.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                Config._deep_merge(base[key], value)
            else:
                base[key] = value

# 访问器

    def get(self, key_path: str, default: Any = None) -> Any:
        """按点分隔键路径取配置值, 如 get("engine.max_states") -> 1024。"""
        keys = key_path.split(".")
        current = self._data
        for k in keys:
            if isinstance(current, dict) and k in current:
                current = current[k]
            else:
                return default
        return current

    def __getitem__(self, key: str) -> Any:
        """字典式访问: config["engine"], O(1)。"""
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
        """返回完整配置的深拷贝嵌套字典。"""
        import copy
        return copy.deepcopy(self._data)

    def __repr__(self) -> str:
        return f"Config(keys={list(self._data.keys())})"


def load_config(config_path: Optional[str] = None) -> Config:
    """加载配置的工厂函数。

    config_path 为 None 时使用默认值; 返回合并了默认值、文件
    与环境变量覆盖的 Config 实例。

    # 单例模式在此不合适——测试和 CLI 需要不同的 config 实例
    # 每次调用返回新的 Config 对象，避免状态污染
    """
    return Config(config_path)


def get_default_config() -> Dict[str, Any]:
    """返回默认配置的普通字典深拷贝, 供测试与文档生成用。"""
    import copy
    return copy.deepcopy(Config._DEFAULTS)


def validate_config_schema(config_dict: Dict[str, Any]) -> List[str]:
    """对照预期 schema 校验配置字典, 返回错误列表。"""
    errors = []
    required_sections = ["engine", "z3", "llm", "optimization"]
    for section in required_sections:
        if section not in config_dict:
            errors.append(f"Missing config section: {section}")
    # engine 配置检查
    engine = config_dict.get("engine", {})
    if engine.get("max_states", 0) <= 0:
        errors.append("engine.max_states must be > 0")
    if engine.get("max_depth", 0) <= 0:
        errors.append("engine.max_depth must be > 0")
    return errors


__all__ = ["Config", "load_config", "get_default_config", "validate_config_schema"]
