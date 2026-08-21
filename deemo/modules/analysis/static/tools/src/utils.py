"""Common utilities: entropy computation, sliding windows, YAML config loading,
logging setup, error hierarchy for static analysis tools"""

import logging
import math
import os
import re
from typing import Any, Iterator, Optional

__all__ = [
    "compute_entropy",
    "sliding_window",
    "load_yaml_config",
    "setup_logging",
    "ToolsError",
    "StaticAnalysisError",
    "FuzzError",
]

_log = logging.getLogger(__name__)


# Error classes

class ToolsError(Exception):
    """Base 异常 for tools errors"""
    pass


class StaticAnalysisError(ToolsError):
    """Error 静态分析 operations"""
    pass


class FuzzError(ToolsError):
    """Error 模糊测试 operations"""
    pass


# Entropy computation

def compute_entropy(data: bytes) -> float:
    """计算 Shannon entropy LaPlace smoothing (add-1 counts)

    LaPlace smoothing prevents zero probabilities causing
    log(0) errors and gives a small probability mass to unseen bytes
    """
    if not data:
        return 0.0

    # Count byte frequencies
    counts: dict[int, int] = {b: 0 for b in range(256)}
    for byte in data:
      counts[byte] = counts.get(byte, 0) + 1

    # LaPlace smoothing: add 1 count
    total = len(data) + 256  # +256 for add-1 256 possible bytes
    entropy = 0.0
    for count in counts.values():
        prob = (count + 1) / total
        entropy -= prob * math.log2(prob)

    return entropy


# 留着备用，以后可能用
def _legacy_entropy_calc(data: bytes) -> float:
    """Old entropy calculation LaPlace smoothing"""
    if not data:
        return 0.0
    counts: dict[int, int] = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


# Sliding window

def sliding_window(items: list[Any], n: int) -> Iterator[tuple[Any, ...]]:
    """构造 n-grams via sliding window over a list"""
    if n <= 0:
        raise ValueError("Window size n must be positive")
    if n > len(items):
        return
    for i in range(len(items) - n + 1):
        yield tuple(items[i : i + n])


# YAML 配置 loading env var substitution

_ENV_VAR_PATTERN: re.Pattern[str] = re.compile(r"\$\{(\w+)\}")


def load_yaml_config(path: str) -> dict[str, Any]:
    """Load a YAML config file with ${VAR} environment variable substitution"""
    try:
        import yaml
    except ImportError:
        _log.error("PyYAML is required for config loading. Install with: pip install pyyaml")
        raise

    if not os.path.isfile(path):
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()

    # Substitute ${VAR} environment variable values
    def _substitute(match: re.Match[str]) -> str:
        var_name = match.group(1)
        return os.environ.get(var_name, f"${{{var_name}}}")

    substituted = _ENV_VAR_PATTERN.sub(_substitute, raw)

    config: dict[str, Any] = yaml.safe_load(substituted)
    if config is None:
        config = {}
    return config


# Logging setup

def setup_logging(config: dict[str, Any]) -> logging.Logger:
    """Set up a unified logger from a config dict"""
    log_config = config.get("logging", {})
    level_name = log_config.get("level", "INFO").upper()
    log_format = log_config.get(
        "format",
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level_name, logging.INFO))

    # Remove existing handlers to avoid duplicates
    root_logger.handlers.clear()

    # Console handler
    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter(log_format))
    root_logger.addHandler(console)

    # File handler
    log_file = log_config.get("file")
    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        from logging.handlers import RotatingFileHandler

        max_bytes = log_config.get("max_bytes", 10 * 1024 * 1024)
        backup_count = log_config.get("backup_count", 3)
        fh = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        fh.setFormatter(logging.Formatter(log_format))
        root_logger.addHandler(fh)

    return root_logger
