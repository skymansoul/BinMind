# 2026-07-31
# 结构化日志配置: 彩色终端输出、JSON 行日志、自动轮转
# VulBinLLM [2025] 的 CoT 记忆管理依赖日志追踪长上下文窗口的事件序列；
# Binary Diff Summarization [arXiv:2509.23970] 的 FSS (Function Sensitivity Score)
# 计算流程也需要可追溯的结构化日志记录。
import logging
import sys
import json
import os
from datetime import datetime
from typing import Optional, Dict, Any

# ANSI 彩色终端日志格式化器

class ColoredFormatter(logging.Formatter):
    """终端 ANSI 颜色日志格式化器。
    LEVEL: DEBUG→灰, INFO→默认, WARNING→黄, ERROR→红, CRITICAL→红+粗体"""

    COLORS = {
        "DEBUG": "\033[90m",    # 灰
        "INFO": "\033[0m",      # 默认
        "WARNING": "\033[33m",  # 黄
        "ERROR": "\033[31m",    # 红
        "CRITICAL": "\033[1;31m", # 红粗
    }
    RESET = "\033[0m"

    def __init__(self, fmt: Optional[str] = None, datefmt: Optional[str] = None,
                 *, use_colors: bool = True):
        super().__init__(fmt, datefmt)
        self.use_colors = use_colors and sys.stderr.isatty()

    def format(self, record: logging.LogRecord) -> str:
        if self.use_colors:
            color = self.COLORS.get(record.levelname, "")
            record.levelname = f"{color}{record.levelname}{self.RESET}"
            if record.name:
                record.name = f"\033[36m{record.name}{self.RESET}"  # 青色模块名
        return super().format(record)

# ---- JSON 行日志格式化器 -----------------------------------------------

class JSONLineFormatter(logging.Formatter):
    """每行一条 JSON 日志: 便于 logstash / jq / ELK 摄入。"""
    def format(self, record: logging.LogRecord) -> str:
        entry: Dict[str, Any] = {
            "ts": datetime.utcfromtimestamp(record.created).isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info and record.exc_info[1]:
            entry["exc"] = str(record.exc_info[1])
        if record.args and isinstance(record.args, dict):
            entry["extra"] = record.args
        return json.dumps(entry, ensure_ascii=False, default=str)

# ---- 简单配置函数 --------------------------------------------------------

_LOG_CONFIGURED = False

def setup_logging(level: str = "INFO", *,
                  console: bool = True,
                  json_file: Optional[str] = None,
                  module_filter: Optional[str] = None):
    """一次性配置 root logger。
    level: DEBUG|INFO|WARNING|ERROR
    console: True → 彩色终端输出
    json_file: 可选 JSON 行日志文件路径
    module_filter: 仅记录匹配此前缀的 logger（如 'modules.'）"""
    global _LOG_CONFIGURED
    if _LOG_CONFIGURED:
        return
    _LOG_CONFIGURED = True

    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.handlers.clear()

    if console:
        h = logging.StreamHandler(sys.stderr)
        h.setLevel(root.level)
        h.setFormatter(ColoredFormatter(
            fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%H:%M:%S",
        ))
        root.addHandler(h)

    if json_file:
        h = logging.FileHandler(json_file, encoding="utf-8")
        h.setLevel(root.level)
        h.setFormatter(JSONLineFormatter())
        root.addHandler(h)

    if module_filter:
        # 降低 root 噪音，仅为目标模块提高日志级别
        logging.getLogger(module_filter).setLevel(root.level)

def get_logger(name: str) -> logging.Logger:
    """获取命名的 logger —— 简写。"""
    return logging.getLogger(name)

# ---- 带上下文的结构化日志记录器 ------------------------------------------

class ContextLogger:
    """携带默认上下文字典的日志记录器包装。
    用法:
        clog = ContextLogger("analysis", {"binary": "foo.exe"})
        clog.info("decompiling", func_count=42)
    """

    def __init__(self, name: str, default_context: Optional[Dict[str, Any]] = None):
        self._logger = logging.getLogger(name)
        self._ctx = default_context or {}

    def _merge(self, msg: str, **kw) -> str:
        ctx = dict(self._ctx)
        ctx.update(kw)
        if ctx:
            return f"{msg}  context={ctx}"
        return msg

    def debug(self, msg: str, **kw):
        self._logger.debug(self._merge(msg, **kw))

    def info(self, msg: str, **kw):
        self._logger.info(self._merge(msg, **kw))

    def warning(self, msg: str, **kw):
        self._logger.warning(self._merge(msg, **kw))

    def error(self, msg: str, **kw):
        self._logger.error(self._merge(msg, **kw))

    def exception(self, msg: str, **kw):
        self._logger.exception(self._merge(msg, **kw))

    def set_context(self, **kw):
        self._ctx.update(kw)

# ---- 轮转日志辅助 --------------------------------------------------------

def add_rotating_file_handler(logger_name: str, filepath: str,
                              max_bytes: int = 10 * 1024 * 1024,
                              backup_count: int = 5,
                              level: str = "DEBUG"):
    """为指定 logger 添加基于大小的轮转文件处理器。
    max_bytes: 单文件上限（默认 10 MiB）。
    backup_count: 保留的历史文件数。"""
    from logging.handlers import RotatingFileHandler
    handler = RotatingFileHandler(
        filepath, maxBytes=max_bytes, backupCount=backup_count,
        encoding="utf-8"
    )
    handler.setLevel(getattr(logging, level.upper(), logging.INFO))
    handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    logging.getLogger(logger_name).addHandler(handler)
