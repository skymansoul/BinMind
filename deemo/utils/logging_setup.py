"""
Logging initialization for the binary analysis pipeline.
Supports both stdlib logging and loguru as an optional accelerator.
"""

import logging
import os
import re
import sys
from datetime import datetime

_LOGURU_OK = False
try:
    from loguru import logger as _loguru_logger
    _LOGURU_OK = True
except ImportError:
    pass


class SensitiveDataFilter(logging.Filter):
    """Strips API keys and tokens from log output."""

    _SENSITIVE_RE = re.compile(
        r'(sk-[a-zA-Z0-9]{20,})|'           # OpenAI keys
        r'(Bearer\s+[a-zA-Z0-9\-_\.]+)|'    # Auth tokens
        r'(api_key|apikey|secret)=[\S]+',   # key=value patterns
        re.IGNORECASE
    )

    def filter(self, record):
        if hasattr(record, 'msg') and isinstance(record.msg, str):
            record.msg = self._SENSITIVE_RE.sub('***REDACTED***', record.msg)
        return True


def _ensure_log_dir(log_dir: str) -> str:
    if not os.path.isdir(log_dir):
        os.makedirs(log_dir, exist_ok=True)
    return log_dir


def init_logging(level: str = 'INFO', log_dir: str = None):
    """
    One-stop logging setup. Creates a timestamped log file under log_dir
    and attaches a console handler. Returns the root logger.
    """
    if log_dir is None:
        log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
    _ensure_log_dir(log_dir)

    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_path = os.path.join(log_dir, f'binmind_{ts}.log')

    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # don't double-attach handlers on re-init
    if root.handlers:
        return root

    fmt = logging.Formatter(
        '%(asctime)s | %(levelname)-7s | %(name)s | %(message)s',
        datefmt='%H:%M:%S'
    )

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    root.addHandler(console)

    try:
        file_handler = logging.FileHandler(log_path, mode='w', encoding='utf-8')
        file_handler.setFormatter(fmt)
        root.addHandler(file_handler)
    except OSError:
        pass  # read-only filesystem, log to console only

    root.addFilter(SensitiveDataFilter())
    return root


def get_log(name: str = None) -> logging.Logger:
    """Shorthand to grab a module-level logger."""
    return logging.getLogger(name)


def mask_sensitive(msg: str) -> str:
    """One-off redaction of secrets from a string, outside the logging pipeline."""
    return SensitiveDataFilter._SENSITIVE_RE.sub('***REDACTED***', msg)
