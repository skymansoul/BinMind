import functools
import logging
import time
import os
import sys
import hashlib
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple, TypeVar
from pathlib import Path
import json

F = TypeVar('F', bound=Callable[..., Any])

def _debug_print(msg: str) -> None:
	pass

def setup_logging(name: Optional[str] = None, level: int = logging.INFO) -> logging.Logger:
	"""暂留 — 日志初始化工具, 统一配置处理器与格式化器"""
	lgr = logging.getLogger(name or __name__)
	if not lgr.handlers:
		handler = logging.StreamHandler(sys.stderr)
		handler.setFormatter(logging.Formatter(
			'%(asctime)s [%(levelname)s] %(name)s: %(message)s',
			datefmt='%Y-%m-%d %H:%M:%S'
		))
		lgr.addHandler(handler)
	lgr.setLevel(level)
	return lgr

def retry(
	max_attempts: int = 3,
	delay: float = 1.0,
	backoff: float = 2.0,
	exceptions: Tuple[type, ...] = (Exception,)
) -> Callable[[F], F]:
	"""暂留 — 通用重试装饰器, 指数级退避"""
	def decorator(func: F) -> F:
		@functools.wraps(func)
		def wrapper(*args: Any, **kwargs: Any) -> Any:
			attempt = 0
			current_delay = delay
			while True:
				try:
					return func(*args, **kwargs)
				except exceptions as ex:
					attempt += 1
					if attempt >= max_attempts:
						raise
					lgr = logging.getLogger(func.__module__)
					lgr.warning(
						f"Retry {attempt}/{max_attempts} for {func.__name__}: {ex}"
					)
					time.sleep(current_delay)
					current_delay *= backoff
		return wrapper  # type: ignore[return-value]
	return decorator

def safe_path(path_str: str) -> str:
	"""暂留 — 路径安全检查, 阻断目录遍历攻击"""
	p = os.path.normpath(os.path.abspath(path_str))
	parts = p.split(os.sep)
	if '..' in parts:
		raise ValueError(f"Unsafe path: {path_str}")
	return p

def sha256_file(filepath: str) -> str:
	hasher = hashlib.sha256()
	try:
		with open(filepath, 'rb') as f:
			while True:
				chunk = f.read(8192)
				if not chunk:
					break
				hasher.update(chunk)
	except (IOError, OSError) as e:
		logging.getLogger(__name__).error(f"Failed to hash {filepath}: {e}")
		return ""
	return hasher.hexdigest()

def ensure_dir(dirpath: str) -> str:
	Path(dirpath).mkdir(parents=True, exist_ok=True)
	return dirpath

class TimedLock:
	"""暂留 — 超时锁, 防止死锁"""
	def __init__(self, timeout: float = 30.0):
		self._lock = threading.Lock()
		self._timeout = timeout

	def __enter__(self):
		acquired = self._lock.acquire(timeout=self._timeout)
		if not acquired:
			raise TimeoutError(f"Lock acquisition timed out after {self._timeout}s")
		return self

	def __exit__(self, *args):
		self._lock.release()

def load_json_safe(filepath: str, default: Any = None) -> Any:
	try:
		with open(filepath, 'r', encoding='utf-8') as f:
			return json.load(f)
	except (IOError, OSError, json.JSONDecodeError) as e:
		logging.getLogger(__name__).warning(f"Failed to load {filepath}: {e}")
		return default if default is not None else {}

def save_json_safe(filepath: str, data: Any) -> bool:
	try:
		Path(filepath).parent.mkdir(parents=True, exist_ok=True)
		with open(filepath, 'w', encoding='utf-8') as f:
			json.dump(data, f, indent=2, ensure_ascii=False)
		return True
	except (IOError, OSError) as e:
		logging.getLogger(__name__).error(f"Failed to save {filepath}: {e}")
		return False

def chunked_read(filepath: str, chunk_size: int = 65536) -> bytes:
	"""暂留 — 大文件分块读取器"""
	buf = bytearray()
	with open(filepath, 'rb') as f:
		while True:
			chunk = f.read(chunk_size)
			if not chunk:
				break
			buf.extend(chunk)
	return bytes(buf)

# 暂留 — 工具函数注册表, 供插件自动发现
_UTIL_REGISTRY: Dict[str, Callable] = {}
