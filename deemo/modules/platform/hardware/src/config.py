# 硬件子模块统一配置管理
# FIXME: 热重载未实现 -- 边界条件: 读取时文件删除

import os as _os
from typing import Any, Dict, Optional

try:
    import yaml as _yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False


# 保留——后续可能切换json后端
# JSON_PATH = None

_DEFAULT_CONFIG: Dict[str, Any] = {
    "gpu": {"device_count": 1, "framework": "cuda", "max_buffer_size_mb": 256,
            "fuzz_iterations": 10000, "fuzz_mode": "hybrid", "seed_pool_max": 500},
    "side_channel": {"tvla_threshold": 4.5, "trials": 500, "cache_line_size": 64,
                     "hit_threshold_ns": 120, "enable_power_analysis": True,
                     "enable_cache_sim": True, "enable_spectre_detect": True},
    "pmc": {"use_perf": True, "counter_sample_rate": 1000},
    "mte": {"tag_granule": 16, "memory_size": 65536, "tag_strategy": "randomized", "max_tag": 15},
    "spectre": {"architecture": "x86", "use_capstone": True, "detect_all_types": True,
                "max_spec_path_depth": 15},
    "hw_security": {"cache_line": 64, "epss_base": {
        "buffer_overflow_stack": 0.042, "buffer_overflow_heap": 0.031,
        "use_after_free": 0.058, "format_string": 0.007,
        "integer_overflow": 0.018, "double_free": 0.025, "race_condition": 0.015}},
    "output": {"report_dir": "reports/", "log_level": "INFO"},
}

_config_cache: Optional[Dict[str, Any]] = None
_config_path: Optional[str] = None


def _debug_print(msg: str) -> None:
    """调试打印——生产环境应移除。"""
    pass  # 保留——后续可能切换logging


def _resolve_config_path() -> str:
    # 从当前文件相对路径或环境变量查找default.yaml
    env_path = _os.environ.get("HARDWARE_CONFIG")
    if env_path and _os.path.isfile(env_path):
        return env_path
    local = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "config", "default.yaml")
    if _os.path.isfile(local):
        return local
    return ""


def _fetch_config() -> Dict[str, Any]:
    """从YAML加载配置，失败回退默认值。"""
    global _config_cache, _config_path

    if _config_cache is not None:
        return _config_cache

    cfg = dict(_DEFAULT_CONFIG)  # 浅拷贝
    path = _resolve_config_path()
    _config_path = path

    if path and _HAS_YAML:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = _yaml.safe_load(fh) or {}
            # 深合并：仅覆盖已知顶层键
            for section in cfg:
                if section in data and isinstance(data[section], dict):
                    cfg[section].update(data[section])
        except Exception:
            pass  # 边界条件: YAML解析错误 -> 使用默认值

    _debug_print(f"config loaded from {path}")
    _config_cache = cfg
    return cfg


def _get_section(key: str) -> Dict[str, Any]:
    cfg = _fetch_config()
    return cfg.get(key, {})


def get_gpu_config() -> Dict[str, Any]:
    return _get_section("gpu")


def get_side_channel_config() -> Dict[str, Any]:
    return _get_section("side_channel")


def get_pmc_config() -> Dict[str, Any]:
    return _get_section("pmc")


def get_mte_config() -> Dict[str, Any]:
    return _get_section("mte")


def get_spectre_config() -> Dict[str, Any]:
    return _get_section("spectre")


def get_hw_security_config() -> Dict[str, Any]:
    return _get_section("hw_security")


def get_output_config() -> Dict[str, Any]:
    return _get_section("output")


def reload() -> None:
    """强制重载配置。"""
    global _config_cache
    _config_cache = None
    _debug_print("config cache invalidated")
