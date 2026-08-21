# 配置加载器 - JSON/YAML + BINMIND_TESTING__前缀环境变量覆盖
# 三层合并策略: 默认值 - 文件 - 环境变量
# 优先JSON（无外部依赖），YAML为可选增强（需PyYAML）
import json
import os
from dataclasses import dataclass, field
from typing import Dict, Any, Optional


DEFAULT_SEARCH_PATHS = [
    ".binmind_testing.json",
    "config/testing.yaml",
    os.path.expanduser("~/.binmind/testing.conf"),
]

_ENV_PREFIX = "BINMIND_TESTING__"


@dataclass
class TestingConfig:
    engine_paths: Dict[str, str] = field(default_factory=dict)
    timeout: int = 300
    differential_rounds: int = 100
    fuzz_time: int = 60
    output_dir: str = "test_output"
    compare_mode: str = "strict"  # strict | normalized | fuzzy
    seed_dir: str = "seeds"
    workers: int = 4
    property_tests: int = 100

    @classmethod
    def defaults(cls) -> "TestingConfig":
        return cls()


def load_config(filepath: Optional[str] = None) -> TestingConfig:
    """从文件加载配置，环境变量覆盖。

    ENV命名规则:
    BINMIND_TESTING__TIMEOUT=500 - timeout=500
    BINMIND_TESTING__ENGINE_PATHS__MYENGINE=/path/to/bin - engine_paths.myengine
    """
    _cfg = TestingConfig.defaults()

    # 尝试加载文件
    _paths = [filepath] if filepath else DEFAULT_SEARCH_PATHS
    for _p in _paths:
        if _p and os.path.isfile(_p):
            _file_cfg = _load_file(_p)
            if _file_cfg:
                _cfg = _apply_override(_cfg, _file_cfg)
                break

    # 环境变量覆盖
    _env_cfg = _parse_env_vars()
    if _env_cfg:
        _cfg = _apply_override(_cfg, _env_cfg)

    return _cfg


def _load_file(path: str) -> Optional[dict]:
    ext = os.path.splitext(path)[1].lower()
    if ext in (".json", ".conf"):
        with open(path, "r", encoding="utf-8") as _f:
            return json.load(_f)
    elif ext in (".yaml", ".yml"):
        try:
            import yaml
            with open(path, "r", encoding="utf-8") as _f:
                return yaml.safe_load(_f)
        except ImportError:
            raise ImportError("PyYAML required for YAML config files")
    return None


def _parse_env_vars() -> dict:
    """将 BINMIND_TESTING__KEY__SUBKEY 转换为嵌套字典。"""
    _r = {}
    for _k, _v in os.environ.items():
        if not _k.startswith(_ENV_PREFIX):
            continue
        _parts = _k[len(_ENV_PREFIX):].lower().split("__")
        _d = _r
        for _part in _parts[:-1]:
            _d = _d.setdefault(_part, {})
        # 类型转换
        _d[_parts[-1]] = _coerce_value(_v)
    return _r


def _coerce_value(val: str):
    """自动类型转换: 整数、浮点、布尔、字符串。"""
    _vl = val.lower()
    if _vl == "true":
        return True
    if _vl == "false":
        return False
    try:
        return int(val)
    except ValueError:
        pass
    try:
        return float(val)
    except ValueError:
        pass
    return val


def _apply_override(config: TestingConfig, overrides: dict) -> TestingConfig:
    """递归合并字典覆盖至dataclass字段。"""
    from dataclasses import fields
    _field_map = {f.name: f for f in fields(config)}
    for _k, _v in overrides.items():
        if _k in _field_map:
            setattr(config, _k, _v)
    return config


def save_config(config: TestingConfig, filepath: str):
    """导出配置为JSON文件。"""
    _d = {}
    for _f in config.__dataclass_fields__:
        _d[_f] = getattr(config, _f)
    with open(filepath, "w", encoding="utf-8") as _fh:
        json.dump(_d, _fh, indent=2, default=str)
    # 确保末尾换行
    _fh.write("\n")


def merge_configs(base: dict, override: dict) -> dict:
    """递归字典合并，override优先。"""
    _result = dict(base)
    for _k, _v in override.items():
        if _k in _result and isinstance(_result[_k], dict) and isinstance(_v, dict):
            _result[_k] = merge_configs(_result[_k], _v)
        else:
            _result[_k] = _v
    return _result


# //// 便捷入口 ////
def config_from_env() -> TestingConfig:
    """从环境变量快速构建配置，跳过文件读取。"""
    _cfg = TestingConfig.defaults()
    _env = _parse_env_vars()
    return _apply_override(_cfg, _env)
