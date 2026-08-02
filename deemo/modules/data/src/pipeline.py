# 数据流水线 — 生成器模式 + 线程池并行处理
# 每个 stage 是 callable(item) → transformed_item
# ParallelPipeline 对独立 item 并行处理，带 barrier 收集
# retry + exponential backoff 参考 Faust 的 async agent 模式
#
# FanOutPipeline: 扇出流水线 — 一个 item 分发给 N 个 worker 并行处理，
# 结果按输入顺序合并后继续流向下游。类似 Apache Beam 的 ParDo 但更轻。
# 适用场景：单条数据需要多个独立 I/O 操作（如同时查 NVD + Exploit-DB + GHSA）。

import hashlib
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, List, Any, Optional, Iterable, Iterator
from .config import PipelineConfig
from .metrics import get_registry


def batch_iter(iterator: Iterator, batch_size: int) -> Iterator[List]:
    """将迭代器聚合成固定大小的批次。
    用于将大流拆分为可批量处理的 chunk —— 减少 DB 写事务频率。
    """
    batch = []
    for item in iterator:
        batch.append(item)
        if len(batch) >= batch_size:
            yield batch
            batch = []
    if batch:
        yield batch


class Pipeline:
    """序列流水线 — 惰性求值，不吃内存。

    内建阶段延迟追踪：每个 stage 记录 p50/p95/p99 延迟，
    通过 MetricsRegistry 暴露为 Prometheus histogram。
    """

    def __init__(self, name: str = "", config: PipelineConfig = None):
        self.name = name
        self.config = config or PipelineConfig()
        self._stages: List[tuple] = []  # (fn, histogram)
        self._reg = get_registry()

    def add_stage(self, name: str, fn: Callable):
        h_name = f"pipeline_{self.name}_{name}_latency" if self.name else f"pipeline_{name}_latency"
        hist = self._reg.histogram(h_name, f"Latency of stage {name}")
        self._stages.append((fn, hist))

    def run(self, items: Iterable[Any]) -> Iterable[Any]:
        stream = items
        for fn, hist in self._stages:
            stream = self._apply_stage(fn, hist, stream)
        return stream

    @property
    def stats_summary(self) -> dict:
        """一站式统计摘要 —— 比 stats 更紧凑，适合 CLI 输出。"""
        stage_times = {}
        for fn, hist in self._stages:
            name = hist.name.replace("pipeline_", "").replace("_latency", "")
            v = hist.value()
            stage_times[name] = {
                "count": v["count"], "avg_ms": round(v["sum"] / max(v["count"], 1) * 1000, 3),
            }
        return {"name": self.name, "stages": stage_times}

    def _apply_stage(self, fn: Callable, hist, items: Iterable[Any]) -> Iterable[Any]:
        for item in items:
            t0 = time.monotonic()
            for attempt in range(self.config.retry_count + 1):
                try:
                    result = fn(item)
                    hist.observe(time.monotonic() - t0)
                    yield result
                    break
                except Exception:
                    if attempt == self.config.retry_count:
                        raise
                    time.sleep(self.config.retry_delay * (2 ** attempt))


class FanOutPipeline:
    """扇出流水线 — 每项数据同时走 N 个并行 stage，结果合并回单流。

    与 ParallelPipeline 的区别：ParallelPipeline 是"N 个 item 并发执行同一个 stage"，
    FanOut 是"单个 item 同时走 N 个不同 stage → 结果合并"。
    适用于一条数据需要同时查询多个独立数据源的场景。

    merge_fn 默认为浅合并 `{**item, **result}`。
    """

    def __init__(self, name: str = "", config: PipelineConfig = None,
                 max_workers: int = 4, merge_fn: Callable = None):
        self.name = name
        self.config = config or PipelineConfig()
        self.max_workers = max_workers
        self._fan_stages: List[tuple] = []  # (name, fn)
        self.merge = merge_fn or (lambda item, r: {**item, **r})

    def add_branch(self, name: str, fn: Callable):
        """添加一个并行分支。每个分支从同一个 input item 出发独立计算。"""
        self._fan_stages.append((name, fn))

    def run(self, items: Iterable[Any]) -> Iterable[Any]:
        for item in items:
            yield self._fan_out_one(item)

    def _fan_out_one(self, item: Any) -> Any:
        if len(self._fan_stages) == 0:
            return item
        if len(self._fan_stages) == 1:
            _, fn = self._fan_stages[0]
            result = fn(item)
            return self.merge(item, result) if isinstance(result, dict) else result

        merged = item if isinstance(item, dict) else {"_input": item}
        futures_map = {}
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(self._fan_stages))) as ex:
            for name, fn in self._fan_stages:
                futures_map[ex.submit(fn, item)] = name
            for future in as_completed(futures_map):
                name = futures_map[future]
                try:
                    r = future.result()
                    if isinstance(r, dict):
                        prefixed = {f"{name}_{k}": v for k, v in r.items()}
                        merged.update(prefixed)
                except Exception:
                    pass  # 单个分支失败不影响其他
        return merged


class ParallelPipeline:
    """并行流水线 — 独立 item 并发处理，带 barrier 收集。
    使用 ThreadPoolExecutor: I/O bound 场景提升明显。
    """

    def __init__(self, name: str = "", config: PipelineConfig = None):
        self.name = name
        self.config = config or PipelineConfig()

    def run(self, items: List[Any], stage_fn: Callable,
            unordered: bool = False) -> List[Any]:
        max_w = self.config.max_workers
        if max_w <= 1 or len(items) <= 1:
            return [stage_fn(item) for item in items]

        results = [None] * len(items)

        def _process(idx, item):
            for attempt in range(self.config.retry_count + 1):
                try:
                    return idx, stage_fn(item)
                except Exception:
                    if attempt == self.config.retry_count:
                        raise
                    time.sleep(self.config.retry_delay * (2 ** attempt))
            return idx, None

        with ThreadPoolExecutor(max_workers=max_w) as executor:
            futures = {executor.submit(_process, i, item): i for i, item in enumerate(items)}
            if unordered:
                for future in as_completed(futures):
                    idx, result = future.result()
                    results[idx] = result
            else:
                for future in futures:
                    idx, result = future.result()
                    results[idx] = result

        return results


def make_hash_stage(algorithm: str = "sha256") -> Callable:
    """创建哈希计算 stage，供 Pipeline 使用。"""
    h = hashlib.new(algorithm)

    def _hash_stage(item: dict) -> dict:
        data = item.get("data", b"")
        if not data:
            return item
        h_copy = h.copy()
        h_copy.update(data)
        item[f"{algorithm}_hash"] = h_copy.hexdigest()
        return item

    return _hash_stage


def make_compress_stage(min_size: int = 1024) -> Callable:
    """创建压缩 stage，小数据跳过。"""
    from .compression import compress as _compress

    def _stage(item: dict) -> dict:
        data = item.get("data", b"")
        if len(data) < min_size:
            return item
        compressed, codec = _compress(data, min_size=min_size)
        item["data"] = compressed
        item["compressed"] = codec
        return item

    return _stage
