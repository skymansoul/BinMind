# 2026-07-15 -- 通用辅助工具集
# 从 radare2 封装到原子写入，一把梭

import json
import os
import re
import time
import subprocess
import tempfile
import functools
import hashlib
from contextlib import contextmanager
from typing import Any, Iterator, Optional, Callable

# ---- radare2 接口封装 ----

_R2_BIN = os.environ.get("R2_PATH", "r2")


def r2_json(path: str, cmd: str) -> dict:
    """执行 radare2 JSON 查询，返回解析后的字典。"""
    # //// 静默模式 + JSON输出
    full_cmd = [_R2_BIN, "-q", "-j", cmd, path]
    proc = subprocess.run(full_cmd, capture_output=True, text=True, timeout=120)
    if proc.returncode != 0 or not proc.stdout.strip():
        return {}
    return json.loads(proc.stdout)


def r2_cmd(path: str, cmd: str) -> str:
    """执行 radare2 文本命令，返回原始字符串输出。"""
    full_cmd = [_R2_BIN, "-q", cmd, path]
    proc = subprocess.run(full_cmd, capture_output=True, text=True, timeout=120)
    return proc.stdout


# ===== TTLCache -- 带过期时间的简单缓存 =====

class TTLCache:
    """基于 time.time() 的轻量 TTL 缓存，不引入第三方依赖。"""

    def __init__(self, default_ttl: float = 60.0):
        self._store: dict[str, tuple[Any, float]] = {}
        self._default_ttl = default_ttl

    def get(self, key: str, default: Any = None) -> Any:
        now = time.time()
        entry = self._store.get(key)
        if entry is None:
            return default
        val, expires_at = entry
        if now >= expires_at:
            del self._store[key]
            return default
        return val

    def put(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        ttl = ttl if ttl is not None else self._default_ttl
        self._store[key] = (value, time.time() + ttl)

    def clear(self) -> None:
        self._store.clear()

    def __len__(self) -> int:
        # 清理过期条目后返回计数
        now = time.time()
        expired = [k for k, (_, exp) in self._store.items() if now >= exp]
        for k in expired:
            del self._store[k]
        return len(self._store)

    def __contains__(self, key: str) -> bool:
        return self.get(key) is not None


# ---- 原子写入 ----

@contextmanager
def atomic_write(path: str, mode: str = "w", encoding: str = "utf-8"):
    """上下文管理器：写入临时文件后 os.rename，保证原子性。"""
    dirname = os.path.dirname(path) or "."
    fd, tmp_path = tempfile.mkstemp(dir=dirname, suffix=".tmp")
    try:
        with os.fdopen(fd, mode, encoding=encoding) as fh:
            yield fh
        os.replace(tmp_path, path)  # Windows 上也原子
    except Exception:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


def atomic_write_sync(path: str, content: str, mode: str = "w") -> None:
    """同步原子写入字符串。"""
    with atomic_write(path, mode) as fh:
        fh.write(content)


# //// dig -- 点号分隔的深层字典访问

def dig(d: dict, keypath: str, default: Any = None) -> Any:
    """dig(d, 'a.b.c') -> d['a']['b']['c']，安全地逐层下探。"""
    node = d
    for part in keypath.split("."):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return default
    return node


# ===== retry -- 指数退避重试装饰器 =====

def retry(
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    catch: tuple[type[BaseException], ...] = (Exception,),
):
    """
    指数退避 + jitter，INTJ策略：不浪费调用方时间。
    delay = min(base * 2^attempt, max_delay) * (0.75 + random*0.5)
    """
    import random

    def _decorator(fn: Callable):
        @functools.wraps(fn)
        def _wrapper(*args, **kwargs):
            last_exc = None
            for attempt in range(max_retries + 1):
                try:
                    return fn(*args, **kwargs)
                except catch as exc:
                    last_exc = exc
                    if attempt == max_retries:
                        raise
                    delay = min(base_delay * (2 ** attempt), max_delay)
                    jitter = delay * (0.75 + random.random() * 0.5)
                    time.sleep(jitter)
            raise last_exc  # type: ignore[misc]
        return _wrapper
    return _decorator


# ---- 十六进制校验 ----

_HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")

def is_valid_hex_str(s: str) -> bool:
    """校验纯十六进制字符串（不含 0x 前缀）。"""
    return bool(s) and bool(_HEX_RE.match(s))


# //// 列表分块

def chunk_list(lst: list, n: int):
    """yield 连续的 n 长度切片。"""
    i = 0
    L = len(lst)
    while i < L:
        yield lst[i:i + n]
        i += n


# ===== 文件名消毒 =====

_UNSAFE_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')

def sanitize_filename(s: str, placeholder: str = "_") -> str:
    """替换文件名中不允许的字符。"""
    return _UNSAFE_CHARS.sub(placeholder, s).strip()[:255]


# ---- 小工具：快速哈希 ----

def _quick_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def _ensure_dir(path: str) -> None:
    d = os.path.dirname(path)
    if d and not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)
