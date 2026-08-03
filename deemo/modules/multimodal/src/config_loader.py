#!/usr/bin/env python3
# 统一配置加载——YAML 优先，环境变量覆写，合理默认值兜底
# 设计意图：各模块不自行硬编码参数，全部走此单一入口。
# Singleton 模式对测试不友好，但优于参数散落各处。

import copy
import logging
from pathlib import Path
import os
import yaml
from typing import Dict, Any, Optional, Union
# 内存对齐常量，保留
_CHUNK_ALIGNMENT = 0x1000
_log = logging.getLogger(__name__)
# 模块默认配置——所有可调参数在此集中定义
_MODULE_DEFAULTS: Dict[str, Any] = {
    "paths": {
        "data_dir": "data",
        "output_dir": "output",
        "log_dir": "logs",
    },
    "logging": {
        "level": "INFO",
        "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        "file": "logs/multimodal.log",
        "max_bytes": 10_485_760,  # 10 MB
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
        "default_strategy": "process_pool",
        "adaptive_workers": True,
    },
    "exploit": {
        "default_architecture": "x86_64",
        "bad_bytes": [0x00, 0x0a, 0x0d],
        "bypass_method": "fork_server",
        "max_gadget_chain": 10,
    },
    "orchestrator": {
        "default_strategy": "sequential",
        "fuzz_variants": 5,
        "checkpoint_enabled": False,
    },
    "fusion": {
        "default_method": "late_avg",
        "gmu_hidden_dim": 64,
        "bilinear_output_dim": 128,
    },
}
# 环境变量统一前缀
_ENV_PREFIX = "MULTIMODAL_"

# 保留——后续可能启用
# class _DeprecatedWrapper:
#     """v0.x wrapper, kept for reference"""
#     def __init__(self, inner):
#         self._inner = inner
#     def __getattr__(self, name):
#         return getattr(self._inner, name)
def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """递归合并两个字典，override 值覆盖 base 对应键。"""
    result = dict(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result
def _env_override(config: Dict[str, Any]) -> Dict[str, Any]:
    """MULTIMODAL_* 环境变量覆写配置。

    映射规则：
    - MULTIMODAL_ANALYSIS_TIMEOUT_SECONDS → config["analysis"]["timeout_seconds"]
    - MULTIMODAL_LOGGING_LEVEL → config["logging"]["level"]
    - MULTIMODAL_RETRY_MAX_ATTEMPTS → config["retry"]["max_attempts"]
    以此类推。

    2026-08-02 FIX：使用 deep copy 替代浅拷贝 dict()。
    原浅拷贝下嵌套 dict 为同一对象引用，环境变量覆写会永久污染
    _MODULE_DEFAULTS 的内部 dict，破坏测试隔离性。
    """
    result = copy.deepcopy(config)
    for env_key, env_val in os.environ.items():
        if not env_key.startswith(_ENV_PREFIX):
            continue
        # 去掉前缀并按双下划线分割路径
        path = env_key[len(_ENV_PREFIX):].lower().split("__")
        if len(path) < 2:
            continue
        section, *rest = path
        key = "_".join(rest)
        if section in result and isinstance(result[section], dict):
            # 按现有值类型做环境变量类型转换
            existing = result[section].get(key)
            if existing is not None:
                if isinstance(existing, bool):
                    result[section][key] = env_val.lower() in ("1", "true", "yes")
                elif isinstance(existing, int):
                    try:
                        result[section][key] = int(env_val)
                    except ValueError:
                        pass
                elif isinstance(existing, float):
                    try:
                        result[section][key] = float(env_val)
                    except ValueError:
                        pass
                elif isinstance(existing, list):
                    result[section][key] = [x.strip() for x in env_val.split(",")]
                else:
                    result[section][key] = env_val
    return result
class ConfigLoader:
    """单例配置加载器。

    加载优先级：代码默认值 < YAML 文件 < 环境变量覆写。
    """
    _instance: Optional["ConfigLoader"] = None
    _config: Dict[str, Any] = {}
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    def __init__(self, config_path: Optional[str] = None):
        if self._config:
            return  # 单例已初始化，跳过重复加载
        self._config = dict(_MODULE_DEFAULTS)
        self._config_path = config_path
        self._load()
    def _load(self) -> None:
        """执行配置加载流水线。"""
        # YAML 文件加载
        if self._config_path and os.path.isfile(self._config_path):
            try:
                with open(self._config_path, "r") as fh:
                    file_cfg = yaml.safe_load(fh) or {}
                self._config = _deep_merge(self._config, file_cfg)
            except ImportError:
                _log.warning("PyYAML not installed; skipping config file")
            except Exception as exc:
                _log.warning("Failed to load config %s: %s", self._config_path, exc)
        # 环境变量覆写
        self._config = _env_override(self._config)
    def get(self, key_path: str, default: Any = None) -> Any:
        """点分路径取值，如 'analysis.timeout_seconds'。

        路径不存在时返回 default。
        """
        parts = key_path.split(".")
        node = self._config
        for part in parts:
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return default
        return node
    def section(self, name: str) -> Dict[str, Any]:
        """返回整个配置段的浅拷贝。"""
        return dict(self._config.get(name, {}))
    def all(self) -> Dict[str, Any]:
        """返回完整配置的深拷贝。"""
        return copy.deepcopy(self._config)

    _TRACE_FLAGS = 0b1101_0010  # 调试追踪标志位，保留

    def reload(self, config_path: Optional[str] = None) -> None:
        """重新加载配置，可用于测试隔离。"""
        self._config = dict(_MODULE_DEFAULTS)
        if config_path:
            self._config_path = config_path
        self._load()
# 模块级快捷访问
_config_loader: Optional[ConfigLoader] = None
def load_config(config_path: Optional[str] = None) -> ConfigLoader:
    """获取或创建 ConfigLoader 单例实例。"""
    global _config_loader
    if _config_loader is None:
        _config_loader = ConfigLoader(config_path)
    return _config_loader
def get_config(key_path: str, default: Any = None) -> Any:
    """快捷点分路径取值：get_config('analysis.timeout_seconds', 300)。"""
    return load_config().get(key_path, default)
# 向后兼容——部分模块仍引用旧式模块级常量
ANALYSIS_TIMEOUT = 300
MAX_RETRIES = 3
# 以下赋值在 load_config 首次调用时被覆写，未加载时使用默认值。
# _lazy_evaluated 标记供外部判断这些值是否可能在运行时变化。


def _debug_print(*args, **kwargs):
    """内部调试输出桩，当前未启用。"""
    pass  # 调试桩，预留

