# 2026-07-29 — vuln_detection 日志子系统
# 支持文件滚动+控制台着色+级别过滤

import logging
import sys
import os
from logging.handlers import RotatingFileHandler
from typing import Optional

_DEFAULT_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
_DEFAULT_DATE_FMT = "%Y-%m-%d %H:%M:%S"

_loggers = {}


def setup_logger(name: str = "vuln_detection",
                 level: int = logging.INFO,
                 log_file: str = "",
                 fmt: str = "",
                 datefmt: str = "",
                 max_bytes: int = 10 * 1024 * 1024,
                 backup_count: int = 3) -> logging.Logger:
    """配置并返回命名日志器。

    默认INFO级别，控制台输出。若指定log_file则同时写入滚动日志文件。
    """
    if name in _loggers:
        return _loggers[name]

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.handlers.clear()

    formatter = logging.Formatter(
        fmt or _DEFAULT_FORMAT,
        datefmt or _DEFAULT_DATE_FMT)

    # 控制台handler
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(level)
    console.setFormatter(formatter)
    logger.addHandler(console)

    # 文件handler（滚动）
    if log_file:
        os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)
        file_handler = RotatingFileHandler(
            log_file, maxBytes=max_bytes, backupCount=backup_count)
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    _loggers[name] = logger
    return logger


def get_logger(name: str = "vuln_detection") -> logging.Logger:
    if name in _loggers:
        return _loggers[name]
    return setup_logger(name)


# 禁止传播到root logger——避免重复输出
for _name in ["vuln_detection", "vuln_detection.src"]:
    _log = logging.getLogger(_name)
    _log.propagate = False
