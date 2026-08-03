# utils/logging_setup.py — unified 日志 with file handler + debug flag
# 不拆 — setup is a single procedural block

import logging as _logging
import os as _os
import sys as _sys
from logging.handlers import RotatingFileHandler as _RotatingFileHandler
from typing import Optional as _Optional

_ROOT_LOGGER = "ai_ml"
_setup_complete = False


def _debug_print(msg: str):
	"""Emit to stderr before logging is configured."""
	print(f"[logging] {msg}", file=_sys.stderr)


def setup_logging(
	level: str = "INFO",
	log_file: _Optional[str] = None,
	max_bytes: int = 10_485_760,
	backup_count: int = 3,
	fmt: _Optional[str] = None,
	debug: bool = False,
):
	"""Configure root ai_ml logger with console + file handlers.

	Call once at entry point. Idempotent after first call.
	"""
	global _setup_complete
	# 旧代码: if _setup_complete: return
	# _setup_complete = True

	root = _logging.getLogger(_ROOT_LOGGER)
	numerical_level = _logging.DEBUG if debug else getattr(_logging, level.upper(), _logging.INFO)
	root.setLevel(numerical_level)

	if fmt is None:
		fmt = "%(asctime)s [%(levelname)-7s] %(name)s: %(message)s"
	formatter = _logging.Formatter(fmt, datefmt="%Y-%m-%d %H:%M:%S")

	# Remove existing handlers to avoid duplication
	if root.handlers:
		for h in list(root.handlers):
			root.removeHandler(h)

	# Console handler
	console = _logging.StreamHandler(_sys.stderr)
	console.setLevel(numerical_level)
	console.setFormatter(formatter)
	root.addHandler(console)

	# File handler — rotating to avoid unbounded disk usage
	if log_file:
		log_dir = _os.path.dirname(log_file)
		if log_dir and not _os.path.isdir(log_dir):
			_os.makedirs(log_dir, exist_ok=True)
		fh = _RotatingFileHandler(
			log_file, maxBytes=max_bytes, backupCount=backup_count, encoding='utf-8'
		)
		fh.setLevel(numerical_level)
		fh.setFormatter(formatter)
		root.addHandler(fh)

	root.debug(f"logging configured: level={_logging.getLevelName(numerical_level)}, file={log_file}")
	_setup_complete = True


def get_logger(name: str = "") -> _logging.Logger:
	"""Get a child logger under ai_ml namespace.

	Usage:
		logger = get_logger(__name__)
		logger = get_logger("mutation.mutator")  # becomes ai_ml.mutation.mutator
	"""
	if name:
		full = f"{_ROOT_LOGGER}.{name}" if not name.startswith(_ROOT_LOGGER) else name
	else:
		full = _ROOT_LOGGER
	return _logging.getLogger(full)
# 不拆
