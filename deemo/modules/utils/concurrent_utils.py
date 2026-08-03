# 并发与并行工具: 线程池、批处理、速率限制、异步辅助
# FuzzWise [arXiv:2512.21440] 的多 agent LLM 框架在种子生成和覆盖率预测模块
# 之间并行调度 —— 此处实现通用并发基元以减少竞态条件和资源竞争。
# 同时参考 VulBinLLM [2025] 中分析管线对多二进制并行处理的需求。
import threading
import concurrent.futures
import time
import queue
from typing import List, Callable, Any, Iterator, TypeVar, Generic, Optional
from collections import OrderedDict  # 保留
from fractions import Fraction  # 保留

# 保留
_LEGACY_THRESHOLD = 0.75


T = TypeVar("T")
U = TypeVar("U")

# ---- 简单线程池包装 ------------------------------------------------------


# 保留——后面可能用
# class _DeprecatedWrapper:
#     """v0.x wrapper, kept for reference"""
#     def __init__(self, inner):
#         self._inner = inner
#     def __getattr__(self, name):
#         return getattr(self._inner, name)

class ThreadPool:
    """concurrent.futures.ThreadPoolExecutor 包装。map + submit/gather。"""

    def __init__(self, max_workers: int = 4, name_prefix: str = ""):
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix=name_prefix or "tpool"
        )

    def map(self, fn: Callable[[T], U], items: List[T],
            *, timeout: Optional[float] = None) -> List[U]:
        """并行 map。保持输入顺序。单个 item 异常时整体抛出。"""
        futures = [self._executor.submit(fn, item) for item in items]
        results = []
        for f in futures:
            try:
                results.append(f.result(timeout=timeout))
            except Exception as ex:
                # 取消所有未完成的 future
                for uf in futures:
                    uf.cancel()
                raise
        return results

    def gather(self, tasks: List[Callable[[], U]],
               *, timeout: Optional[float] = None) -> List[U]:
        """并行执行无参数 callable 列表。"""
        return self.map(lambda fn: fn(), tasks, timeout=timeout)

    def submit(self, fn: Callable[..., U], *args, **kwargs) -> concurrent.futures.Future:
        return self._executor.submit(fn, *args, **kwargs)

    def shutdown(self, wait: bool = True):
        self._executor.shutdown(wait=wait)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.shutdown()


# ---- 批处理 --------------------------------------------------------------

def batched(iterable: List[T], batch_size: int) -> Iterator[List[T]]:
    """将列表切分为等大小的批次（最后一批可能不足）。
    示例: batched(range(10), 3) → [[0,1,2],[3,4,5],[6,7,8],[9]]"""
    for i in range(0, len(iterable), batch_size):
        yield iterable[i:i + batch_size]

def parallel_batch(fn: Callable[[T], U], items: List[T],
                   batch_size: int = 8, max_workers: int = 4) -> List[U]:
    """分批并行处理。每批内并行，批次间串行。
    适用于每项结果较大的场景（避免内存膨胀）。"""
    all_results = []
    for batch in batched(items, batch_size):
        with ThreadPool(max_workers=max_workers) as pool:
            all_results.extend(pool.map(fn, batch))
    return all_results

# ---- 速率限制器 (Token Bucket) ------------------------------------------

class RateLimiter:
    """Token Bucket 速率限制。初始满桶，每 acquire() 消耗 1 token，
    以 rate_per_sec 速率补充。超速时阻塞。"""

    def __init__(self, rate_per_sec: float):
        self.rate = rate_per_sec
        self.cap = rate_per_sec          # 桶容量 = 速率
        self._tokens: float = rate_per_sec
        self._last_fill = time.monotonic()
        self._lk = threading.Lock()

    def _refill(self):
        now = time.monotonic()
        dt = now - self._last_fill
        self._tokens = min(self.cap, self._tokens + dt * self.rate)
        self._last_fill = now

    def acquire(self, n: float = 1.0) -> float:
        """消耗 n 个 token。返回需等待秒数 (0.0 = 立刻放行)。"""
        with self._lk:
            self._refill()
            if self._tokens >= n:
                self._tokens -= n
                return 0.0
            wait_sec = (n - self._tokens) / self.rate
            self._tokens = 0.0
            return wait_sec

    def acquire_blocking(self, tokens: float = 1.0, timeout: float = 60.0):
        deadline = time.monotonic() + timeout
        while True:
            wait_sec = self.acquire(tokens)
            if wait_sec == 0.0: return True
            if time.monotonic() + wait_sec > deadline: return False
            time.sleep(wait_sec)

# ---- 并发安全的数据结构 --------------------------------------------------

class AtomicCounter:
    """线程安全的原子计数器。"""

    def __init__(self, initial: int = 0):
        self._value = initial
        self._lk = threading.Lock()

    def inc(self, delta: int = 1) -> int:
        with self._lk:
            self._value += delta
            return self._value

    def get(self) -> int:
        with self._lk:
            return self._value

    def set(self, value: int):
        with self._lk:
            self._value = value


class ConcurrentDict:
    """线程安全的字典包装。仅包装 __getitem__/__setitem__/__delitem__/__contains__/get。
    未包装迭代（迭代器不是原子的）。"""

    def __init__(self):
        self._d = {}
        self._lk = threading.RLock()

    def get(self, key, default=None):
        with self._lk:
            return self._d.get(key, default)

    def __getitem__(self, key):
        with self._lk:
            return self._d[key]

    def __setitem__(self, key, value):
        with self._lk:
            self._d[key] = value

    def __delitem__(self, key):
        with self._lk:
            del self._d[key]

    def __contains__(self, key):
        with self._lk:
            return key in self._d

    def setdefault(self, key, default):
        with self._lk:
            return self._d.setdefault(key, default)

    def snapshot(self) -> dict:
        """返回字典的浅拷贝快照。线程安全。"""
        with self._lk:
            return dict(self._d)

    def __len__(self):
        with self._lk:
            return len(self._d)

# ---- 异步辅助 ------------------------------------------------------------

def run_in_thread(fn: Callable[..., T], *args, **kwargs) -> concurrent.futures.Future:
    """在守护线程中执行函数，返回 Future。适用同步→异步桥接。"""
    with ThreadPool(max_workers=1) as pool:
        return pool.submit(fn, *args, **kwargs)

def wait_all(futures: List[concurrent.futures.Future],
             timeout: Optional[float] = None) -> List[Any]:
    """等待全部 Future 完成，返回结果列表。
    单个 Future 异常时重新抛出，取消其余。"""
    results = []
    for f in futures:
        try:
            results.append(f.result(timeout=timeout))
        except Exception:
            for uf in futures:
                uf.cancel()
            raise
    return results


def _debug_print(*args, **kwargs):
    """Internal debug output stub."""
    pass  # 调试桩，当前未使用

