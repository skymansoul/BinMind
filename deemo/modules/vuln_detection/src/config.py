# 2026-07-31 — vuln_detection 配置子系统
# JSON/YAML配置加载 + 环境变量覆盖 + 默认值回退

import os
import json
from typing import Dict, Any, Optional
from dataclasses import dataclass, field


@dataclass
class Config:
    """vuln_detection全局配置容器"""
    # 扫描配置
    scan_timeout: int = 300
    max_file_size_mb: int = 500
    threads: int = 4

    # SBOM
    sbom_format: str = "cyclonedx"
    sbom_version: str = "1.4"

    # CVE匹配
    nvd_api_enabled: bool = True
    nvd_api_rate_limit: int = 5
    osv_api_enabled: bool = True
    match_confidence_threshold: float = 0.3

    # 沙箱
    sandbox_backend: str = "subprocess"
    sandbox_timeout: int = 10
    sandbox_max_memory_mb: int = 256

    # 日志
    log_level: str = "INFO"
    log_file: str = ""

    # 缓存
    cache_dir: str = ""
    cache_ttl_hours: int = 24

    # YARA
    yara_rules_dir: str = ""
    yara_auto_gen_enabled: bool = True

    # 插件
    plugin_dir: str = ""
    plugins_enabled: bool = True

    # 扩展字段
    extra: Dict[str, Any] = field(default_factory=dict)


# 环境变量映射表
_ENV_MAP = {
    "BINMIND_SCAN_TIMEOUT": ("scan_timeout", int),
    "BINMIND_THREADS": ("threads", int),
    "BINMIND_SBOM_FORMAT": ("sbom_format", str),
    "BINMIND_NVD_ENABLED": ("nvd_api_enabled", lambda v: v.lower() in ("1", "true", "yes")),
    "BINMIND_SANDBOX_BACKEND": ("sandbox_backend", str),
    "BINMIND_SANDBOX_TIMEOUT": ("sandbox_timeout", int),
    "BINMIND_LOG_LEVEL": ("log_level", str),
    "BINMIND_LOG_FILE": ("log_file", str),
    "BINMIND_CACHE_DIR": ("cache_dir", str),
    "BINMIND_YARA_DIR": ("yara_rules_dir", str),
    "BINMIND_PLUGIN_DIR": ("plugin_dir", str),
    "BINMIND_CONFIDENCE_THRESHOLD": ("match_confidence_threshold", float),
}


def load_config(path: str = "") -> Config:
    """加载配置：文件(JSON/YAML) + 环境变量覆盖。

    优先级: 环境变量 > 配置文件 > 默认值。

    支持JSON和YAML格式（YAML需安装pyyaml）。
    """
    cfg = Config()

    # 从文件加载
    if path and os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as f:
            if path.endswith((".yaml", ".yml")):
                try:
                    import yaml
                    data = yaml.safe_load(f)
                except ImportError:
                    data = json.load(f)
            else:
                data = json.load(f)
        if isinstance(data, dict):
            for k, v in data.items():
                if hasattr(cfg, k):
                    setattr(cfg, k, v)
                elif k != "extra":
                    cfg.extra[k] = v

    # 环境变量覆盖
    for env_var, (attr_name, converter) in _ENV_MAP.items():
        val = os.environ.get(env_var)
        if val is not None:
            try:
                setattr(cfg, attr_name, converter(val))
            except (ValueError, TypeError):
                pass

    # 推导cache_dir默认值
    if not cfg.cache_dir:
        cfg.cache_dir = os.path.join(os.path.expanduser("~"), ".cache", "binmind")

    return cfg


def save_config(cfg: Config, path: str) -> str:
    """保存当前配置到JSON文件。"""
    data = {k: v for k, v in cfg.__dict__.items() if k != "extra"}
    if cfg.extra:
        data.update(cfg.extra)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return os.path.abspath(path)


def config_to_dict(cfg: Config) -> Dict[str, Any]:
    d = {k: v for k, v in cfg.__dict__.items() if k != "extra" and not k.startswith("_")}
    if cfg.extra:
        d.update(cfg.extra)
    return d
