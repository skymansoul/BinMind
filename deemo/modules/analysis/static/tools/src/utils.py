"""通用工具: 熵值计算、滑动窗口、YAML 配置加载,
日志设置、静态分析工具的错误层级。"""

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


# 错误类

class ToolsError(Exception):
    """工具错误基类。"""
    pass


class StaticAnalysisError(ToolsError):
    """静态分析操作错误。"""
    pass


class FuzzError(ToolsError):
    """模糊测试操作错误。"""
    pass


# 熵值计算

def compute_entropy(data: bytes) -> float:
    """计算带拉普拉斯平滑 (加1计数) 的 Shannon 熵。

    拉普拉斯平滑防止零概率导致 log(0) 错误,
    并为未出现的字节分配小概率质量。
    """
    if not data:
        return 0.0

    # 统计字节频率
    counts: dict[int, int] = {b: 0 for b in range(256)}
    for byte in data:
      counts[byte] = counts.get(byte, 0) + 1

    # 拉普拉斯平滑: 加1计数
    total = len(data) + 256  # +256 为 256 种可能字节各加1
    entropy = 0.0
    for count in counts.values():
        prob = (count + 1) / total
        entropy -= prob * math.log2(prob)

    return entropy


# 留着备用，以后可能用
def _legacy_entropy_calc(data: bytes) -> float:
    """旧版熵值计算 (无拉普拉斯平滑)。"""
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


# 滑动窗口

def sliding_window(items: list[Any], n: int) -> Iterator[tuple[Any, ...]]:
    """通过滑动窗口在列表上构造 n-gram。"""
    if n <= 0:
        raise ValueError("Window size n must be positive")
    if n > len(items):
        return
    for i in range(len(items) - n + 1):
        yield tuple(items[i : i + n])


# YAML 配置加载与环境变量替换

_ENV_VAR_PATTERN: re.Pattern[str] = re.compile(r"\$\{(\w+)\}")


def load_yaml_config(path: str) -> dict[str, Any]:
    """加载 YAML 配置文件, 替换 ${VAR} 环境变量。"""
    try:
        import yaml
    except ImportError:
        _log.error("PyYAML is required for config loading. Install with: pip install pyyaml")
        raise

    if not os.path.isfile(path):
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()

    # 替换 ${VAR} 为环境变量值
    def _substitute(match: re.Match[str]) -> str:
        var_name = match.group(1)
        return os.environ.get(var_name, f"${{{var_name}}}")

    substituted = _ENV_VAR_PATTERN.sub(_substitute, raw)

    config: dict[str, Any] = yaml.safe_load(substituted)
    if config is None:
        config = {}
    return config


# 日志设置

def setup_logging(config: dict[str, Any]) -> logging.Logger:
    """从配置字典设置统一日志器。"""
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
