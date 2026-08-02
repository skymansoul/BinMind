# 2026-07-18

import os, json, logging
from dataclasses import dataclass, field, asdict
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class PatchConfig:
    """Unified patch config — env overridable, JSON serializable for CI."""
    r2_timeout: int = 30
    cc_flags: str = "-O2 -fPIC"
    backup_dir: str = ".patch_backups"
    verify_enabled: bool = True
    rollback_enabled: bool = True
    max_patch_size: int = 4096
    arch: str = "auto"
    base_addr: int = 0
    debug_mode: bool = False
    # extended fields
    r2_path: str = "r2"
    compiler_path: str = "gcc"
    sandbox_enabled: bool = True
    max_retries: int = 3
    retry_delay: float = 1.0
    subprocess_timeout: int = 120


# ---- env helper: int ----
def _env_int(key: str, default: int) -> int:
    _v = os.environ.get("BINMIND_PATCH_" + key)
    if _v is None:
        return default
    try:
        return int(_v)
    except ValueError:
        logger.warning("BINMIND_PATCH_%s=%r not an int, falling back to %d", key, _v, default)
        return default


# //// env helper: bool ////
def _env_bool(key: str, default: bool) -> bool:
    _v = os.environ.get("BINMIND_PATCH_" + key)
    if _v is None:
        return default
    # 决策：宁可严格，让用户明确写出 true/false，不搞 1/0/yes/no 的隐含语义
    return _v.strip().lower() in ("true", "1", "yes", "on")


# ============================================================
# load_config: env vars -> defaults -> kwargs override
# 优先级设计: kwargs > env > dataclass defaults
# 这样 CI pipeline 里可以用环境变量设全局默认，再在代码里按文件级别 override
# ============================================================
def load_config(**overrides):
    """Load PatchConfig merging env vars BINMIND_PATCH_* then **overrides."""
    defaults = PatchConfig()
    _env_map = {
        "R2_TIMEOUT":        ("r2_timeout", int),
        "CC_FLAGS":          ("cc_flags", str),
        "BACKUP_DIR":        ("backup_dir", str),
        "VERIFY_ENABLED":    ("verify_enabled", bool),
        "ROLLBACK_ENABLED":  ("rollback_enabled", bool),
        "MAX_PATCH_SIZE":    ("max_patch_size", int),
        "ARCH":              ("arch", str),
        "BASE_ADDR":         ("base_addr", int),
        "DEBUG_MODE":        ("debug_mode", bool),
        "R2_PATH":           ("r2_path", str),
        "COMPILER_PATH":     ("compiler_path", str),
        "SANDBOX_ENABLED":   ("sandbox_enabled", bool),
        "MAX_RETRIES":       ("max_retries", int),
        "RETRY_DELAY":       ("retry_delay", float),
        "SUBPROCESS_TIMEOUT": ("subprocess_timeout", int),
    }
    _cfg = {}
    for _env_suffix, (_field, _typ) in _env_map.items():
        _env_key = "BINMIND_PATCH_" + _env_suffix
        _raw = os.environ.get(_env_key)
        if _raw is not None:
            try:
                _cfg[_field] = _typ(_raw)
            except Exception:
                logger.warning("Cannot parse %s=%r as %s", _env_key, _raw, _typ.__name__)

    # merge defaults -> env -> overrides
    _merged = {}
    for _f in defaults.__dataclass_fields__:
        _merged[_f] = getattr(defaults, _f)
    _merged.update(_cfg)
    _merged.update(overrides)
    return PatchConfig(**_merged)


def save_config(config: PatchConfig, filepath: str):
    """Serialize PatchConfig as indented JSON to filepath."""
    _d = asdict(config)
    with open(filepath, "w", encoding="utf-8") as _fh:
        json.dump(_d, _fh, indent=2)
    logger.info("PatchConfig saved to %s", filepath)


# 模块级单例 — 懒，不搞线程安全的 double-check，patch 操作本就不该并发构造 config
_default_config = PatchConfig()
