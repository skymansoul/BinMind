# 2026-07-15
# config — 全局配置入口，环境变量覆盖默认值
# 设计考量：不依赖外部 .env 解析库，直接 os.environ 读取，减少依赖链

import os
import logging
from dataclasses import dataclass, field

# ---- 平台无关默认值 ----
_DEFAULT_BINARY_PATHS = ["/usr/bin", "/bin", "/usr/local/bin", "C:\\Windows\\System32"]
_DEFAULT_ENTROPY_THRESHOLD = 7.2
_DEFAULT_STRING_MIN_LENGTH = 4
_DEFAULT_LOG_LEVEL = "INFO"
_DEFAULT_ANONYMIZER_THRESHOLD = 0.6
_DEFAULT_PII_CONFIDENCE_THRESHOLD = 0.75
_DEFAULT_OUTPUT_DIR = os.path.join(os.getcwd(), "binmind_output")
_DEFAULT_YARA_OUTPUT_DIR = os.path.join(os.getcwd(), "binmind_yara")

@dataclass
class Config:
    binary_paths: list = field(default_factory=lambda: list(_DEFAULT_BINARY_PATHS))
    entropy_threshold: float = _DEFAULT_ENTROPY_THRESHOLD
    string_min_length: int = _DEFAULT_STRING_MIN_LENGTH
    log_level: str = _DEFAULT_LOG_LEVEL
    anonymizer_threshold: float = _DEFAULT_ANONYMIZER_THRESHOLD
    pii_confidence_threshold: float = _DEFAULT_PII_CONFIDENCE_THRESHOLD
    output_dir: str = _DEFAULT_OUTPUT_DIR
    yara_output_dir: str = _DEFAULT_YARA_OUTPUT_DIR

# ===== 环境变量映射 =====
_ENV_MAP = {
    "BINMIND_INFO_BINARY_PATHS": ("binary_paths", lambda v: [p.strip() for p in v.split(os.pathsep) if p.strip()]),
    "BINMIND_INFO_ENTROPY_THRESHOLD": ("entropy_threshold", float),
    "BINMIND_INFO_STRING_MIN_LENGTH": ("string_min_length", int),
    "BINMIND_INFO_LOG_LEVEL": ("log_level", str),
    "BINMIND_INFO_ANONYMIZER_THRESHOLD": ("anonymizer_threshold", float),
    "BINMIND_INFO_PII_CONFIDENCE_THRESHOLD": ("pii_confidence_threshold", float),
    "BINMIND_INFO_OUTPUT_DIR": ("output_dir", str),
    "BINMIND_INFO_YARA_OUTPUT_DIR": ("yara_output_dir", str),
}

def load_config() -> Config:
    """合并环境变量覆盖到默认值，返回最终的 Config 实例。

    优先级：环境变量 > 硬编码默认值。
    设计意图：避免重复 os.environ.get 调用分散在各子模块中 —— 集中一处，
    方便审计哪些参数由外部控制。
    """
    _cfg = Config()
    for _env_key, (_attr, _caster) in _ENV_MAP.items():
        _raw = os.environ.get(_env_key)
        if _raw is not None and _raw != "":
            try:
                setattr(_cfg, _attr, _caster(_raw))
            except (ValueError, TypeError):
                pass  # 解析失败静默回退默认值，避免启动炸
    return _cfg

# //// 模块初始化日志配置 ////
def _setup_logging(level: str) -> None:
    _level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        level=_level,
    )

# 模块 import 时不做自动日志配置，交给 CLI/入口显式调用
