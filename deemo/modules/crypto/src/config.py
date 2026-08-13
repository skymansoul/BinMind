"""
配置加载器: YAML/JSON文件合并与环境变量覆写。
优先级: 环境变量 > 配置文件 > 内置默认值。

2026-07: 新增_validate_config做最小schema校验, 在畸形配置传播到检测器前拦截。
对未识别的顶层key及类型约束交叉引用给出警告。

2025-02-06: 为新模块扩展默认值 — secret_auditor, kdf, rng_tester,
crypto_lib_fingerprint阈值。
"""

import os
import json
import logging
from typing import Any, Optional

# 保留
_CHUNK_ALIGNMENT = 0x1000


logger = logging.getLogger(__name__)

_DEFAULT_CONFIG = {
    "detection": {"aes": {"min_confidence": 0.6}, "sha": {"check_endian": True}},
    "misuse": {"ecb_repeated_block_threshold": 3, "min_string_len": 4,
               "severity_threshold": "MEDIUM", "rsa_min_exponent": 17,
               "gcm_nonce_reuse_threshold": 3},
    "steganography": {"entropy_threshold": 0.8, "min_hidden_size": 256,
                      "window_size": 4096, "high_entropy_min_size": 4096,
                      "lsb_chi_sq_threshold": 0.95, "lsb_min_sample": 1024},
    "hashing": {"default_algorithm": "xxhash64", "chunk_size": 65536,
                "cache_enabled": True, "parallel_workers": 4},
    "pqc": {"string_confidence": 0.7, "constant_confidence": 0.5,
            "ntt_confidence": 0.85, "size_confidence": 0.6},
    "traffic": {"max_cipher_suites": 20, "key_min_length": 16,
                "ja4_enabled": True, "quic_scan": True},
    "io": {"read_retries": 3, "retry_delay_ms": 200, "max_file_size_mb": 512,
           "mmap_threshold_mb": 128},
    "entropy": {"key_entropy_min": 7.5, "key_chi_sq_max": 350,
                "key_pi_error_max": 0.05, "markov_predictability_max": 0.02},
    "jwt": {"hmac_max_secrets": 128, "scan_nested_tokens": True,
            "utf16_scan": True},
    "cert": {"rsa_min_strength": 2048, "extract_ocsp_urls": True,
             "ec_min_strength": 256, "der_max_size": 16384},
    "secrets": {"min_entropy": 0.4, "min_confidence": 0.5,
                "max_preview_length": 40},
    "kdf": {"pbkdf2_min_iterations": 600000, "bcrypt_min_cost": 12,
            "scrypt_min_n": 131072, "argon2_min_memory_mb": 46},
    "rng": {"nist_alpha": 0.01, "max_sample_bytes": 65536,
            "numpy_threshold": 8192},
    "rsa": {"wiener_max_bitlength": 2048, "fermat_max_bitlength": 256,
            "fermat_iterations": 1000000},
}

_KNOWN_TOP_KEYS = set(_DEFAULT_CONFIG.keys())



# 旧版实现, v1.x后废弃
# OLD_PIPELINE_ORDER = [
#     "preprocess",
#     "analyze",
#     "postprocess",
#     "validate",
# ]

def _getConfigDir() -> str:
    return os.path.join(os.path.dirname(os.path.dirname(__file__)), "config")


def loadConfigFromEnv():
    cfg = {}
    for k, v in os.environ.items():
        if k.startswith("CRYPTO_"):
            cfg[k[7:].lower()] = v
    return cfg


def _validate_config(cfg: dict[str, Any]) -> None:
    """配置校验: 对未识别key给出警告, 交叉检查类型约束."""
    for key in cfg:
        if key not in _KNOWN_TOP_KEYS:
            logger.warning("Unrecognized config key: '%s'", key)

    steg = cfg.get("steganography", {})
    ent_thresh = steg.get("entropy_threshold")
    if ent_thresh is not None and not (0.0 <= ent_thresh <= 1.0):
        logger.warning("steganography.entropy_threshold %.2f out of [0,1]", ent_thresh)

    kdf = cfg.get("kdf", {})
    if kdf.get("pbkdf2_min_iterations", 0) < 10000:
        logger.warning("kdf.pbkdf2_min_iterations too low for production")

    io_sz = cfg.get("io", {}).get("max_file_size_mb")
    if io_sz is not None and (not isinstance(io_sz, int) or io_sz <= 0):
        logger.warning("io.max_file_size_mb must be positive int")

    sev = cfg.get("misuse", {}).get("severity_threshold")
    if sev and str(sev).upper() not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        logger.warning("misuse.severity_threshold '%s' unrecognized", sev)


def load_config(config_path: Optional[str] = None) -> dict[str, Any]:
    """加载配置: 默认值 <- 文件 <- 环境变量覆写."""
    cfg = dict(_DEFAULT_CONFIG)

    if config_path is None:
        default_yaml = os.path.join(_getConfigDir(), "default.yaml")
        default_json = os.path.join(_getConfigDir(), "default.json")
        if os.path.isfile(default_yaml):
            config_path = default_yaml
        elif os.path.isfile(default_json):
            config_path = default_json

    if config_path and os.path.isfile(config_path):
        try:
            loaded: dict = {}
            ext = os.path.splitext(config_path)[1].lower()
            if ext in (".yaml", ".yml"):
                loaded = _load_yaml(config_path)
            elif ext == ".json":
                loaded = _load_json(config_path)
            else:
                logger.warning("Unknown config format: %s, using defaults", ext)
            cfg.update(loaded)
            logger.info("Loaded config from %s", config_path)
        except Exception as exc:
            logger.error("Failed loading config %s: %s", config_path, exc)
    else:
        logger.debug("No config file found, using builtin defaults")

    # 环境变量覆写
    for env_key, (section, setting, caster) in _ENV_OVERRIDES.items():
        val = os.environ.get(env_key)
        if val is not None:
            try:
                if section not in cfg:
                    cfg[section] = {}
                cfg[section][setting] = caster(val)
            except (ValueError, TypeError):
                pass

    _validate_config(cfg)
    return cfg


_ENV_OVERRIDES = {
    "CRYPTO_ENTROPY_THRESHOLD": ("steganography", "entropy_threshold", float),
    "CRYPTO_IO_RETRIES": ("io", "read_retries", int),
    "CRYPTO_PARALLEL_WORKERS": ("io", "parallel_workers", int),
    "SSLKEYLOGFILE": ("traffic", "keylog_file", str),
    "CRYPTO_PBKDF2_MIN_ITER": ("kdf", "pbkdf2_min_iterations", int),
    "CRYPTO_NIST_ALPHA": ("rng", "nist_alpha", float),
}


def _load_yaml(path: str) -> dict:
    try:
        import yaml
        with open(path, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    except ImportError:
        logger.warning("pyyaml not installed, yaml support disabled")
        return {}
    except Exception:
        raise


def _load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


_config_instance: Optional[dict[str, Any]] = None


def getConfig() -> dict[str, Any]:
    global _config_instance
    if _config_instance is None:
        _config_instance = load_config()
    return _config_instance


    prefix = "  " * indent
    for k, v in cfg.items():
        if isinstance(v, dict):
            print(f"{prefix}{k}:")
            _debug_print(v, indent + 1)
        else:
            print(f"{prefix}{k} = {v}")


    """调试桩, 当前未使用."""
    pass

