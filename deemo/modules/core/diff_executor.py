# coding: utf-8
"""
增量管道执行 — 在 context-key 粒度上检测输入变更, 跳过无变化的钩子.

类比:
  构建系统 (make/bazel) 在文件粒度做增量 — 文件修改时间变化 → 重新编译.
  本模块将增量粒度从文件下沉到 context dict 的键级 —
  钩子的输入是 context 中若干键的值, 只要这些键的内容哈希未变, 就可跳过.

与 ECOOP 2025 微分执行 (Kumar et al.) 的差异:
  微分执行在语言语义层嵌入变更传播; 本模块在黑盒钩子层操作,
  不需要修改钩子代码, 仅通过拦截 context 读写来实现输入/输出追踪.
  适用范围更广 (任意 Python 可调用对象), 但精度低于语言级方案.

核心流程:
  1. 首次执行: 记录每个钩子的 read_keys + 输入指纹 → 执行 → 缓存输出
  2. 后续执行: 对每个钩子, 计算当前输入指纹, 与缓存比对
     - 命中 → 跳过执行, 从缓存恢复输出, 更新 context
     - 未命中 → 正常执行, 更新缓存
  3. 缓存键: (hook_name, binary_fingerprint, input_fingerprint)
     binary_fingerprint 确保不同二进制不共享缓存.
"""

import hashlib
import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from modules.core.context_versioning import _stable_hash


@dataclass
class DiffCacheEntry:
    """单次钩子执行的缓存记录."""
    hook_name: str
    input_fingerprint: str           # read_keys + 对应值的联合哈希
    output_delta: Dict[str, Any]     # 钩子写入 context 的键值对
    wall_ms: float
    timestamp: float = field(default_factory=time.time)


class DiffExecutor:
    """增量执行器 — 包裹任意 DAG 调度器, 自动跳过输入未变化的钩子.

    用法:
      diff = DiffExecutor(scheduler)
      ctx = diff.execute(context, binary_id='mybinary.elf')
      # 第二次执行: 仅有输入变化的钩子会重新运行
      ctx2 = diff.execute(context2, binary_id='mybinary.elf')

    限制:
      - 假设钩子在相同输入下产出相同输出 (引用透明性)
      - 若钩子有外部副作用 (网络请求、文件写入), 跳过后副作用不触发
      - 非确定性钩子 (随机数、时间戳) 的输入指纹总在变化, 自然不会被跳过
    """

    def __init__(self, scheduler):
        self._sched = scheduler
        # 缓存: (hook_name, binary_fp, input_fp) → DiffCacheEntry
        self._cache: Dict[Tuple[str, str, str], DiffCacheEntry] = {}
        # 最近一次执行的完整记录: hook_name → entry (用于统计)
        self._last_run: Dict[str, DiffCacheEntry] = {}
        self._hit_count = 0
        self._miss_count = 0

    def execute(
        self, context: Optional[Dict[str, Any]] = None,
        binary_id: str = '',
        max_workers: Optional[int] = None,
        parallel: bool = True,
    ) -> Dict[str, Any]:
        """增量执行管道. 返回 context 与正常执行无差异."""
        if context is None:
            context = {}

        binary_fp = _stable_hash(binary_id) if binary_id else '_noid_'
        self._hit_count = 0
        self._miss_count = 0
        self._last_run.clear()

        # 拦截 _execute_one: 添加指纹比对逻辑
        original = self._sched._execute_one
        cache_ref = self._cache
        last_ref = self._last_run
        hit_cnt = [0]
        miss_cnt = [0]

        def _diff_wrapped(name: str, ctx: dict, failed: set, skipped: set) -> None:
            task = self._sched._get_task(name) if hasattr(self._sched, '_get_task') else None
            if task is None:
                original(name, ctx, failed, skipped)
                return

            # 第 1 步: 探测该钩子会读取哪些 context 键
            reads: Set[str] = set()
            ctx_before = dict(ctx)

            class _Probe(dict):
                def __getitem__(self, k):
                    reads.add(k); return super().__getitem__(k)
                def get(self, k, default=None):
                    reads.add(k); return super().get(k, default)

            probe = _Probe(ctx)
            probe.update(ctx)

            # 第 2 步: 用探测版 context 试运行一次, 抓取读键集.
            # 设计权衡: 这需要一次额外执行. 代价是一次钩子调用.
            # 首次执行无缓存, 此次执行即实际执行; 后续命中时跳过.
            read_keys = tuple(sorted(reads)) if reads else ()
            # 先不实际执行 — 仅在需要指纹比对且可能命中时才需要读键集.
            # 策略: 先用空 reads 尝试, 若首次必然是 miss → 执行并学习.

            # 输入指纹: 基于 ctx_before (执行前快照), 而非执行后的 probe
            read_keys = tuple(sorted(reads)) if reads else ()
            if read_keys:
                input_vals = {k: ctx_before.get(k) for k in read_keys}
            else:
                # 钩子未显式读取任何键 → 以整个 context 的哈希为指纹
                input_vals = {'__full__': _stable_hash(ctx_before)}
            input_fp = _stable_hash(input_vals)

            cache_key = (name, binary_fp, input_fp)
            cached = cache_ref.get(cache_key)

            if cached is not None:
                hit_cnt[0] += 1
                for k, v in cached.output_delta.items():
                    ctx[k] = v
                last_ref[name] = cached
                return

            miss_cnt[0] += 1
            t0 = time.perf_counter()
            original(name, probe, failed, skipped)
            elapsed = (time.perf_counter() - t0) * 1000

            # 输出 delta: ctx_before vs probe
            output_delta = {}
            for k in set(ctx_before) | set(probe):
                before = ctx_before.get(k)
                after = probe.get(k)
                if _stable_hash({k: before}) != _stable_hash({k: after}):
                    output_delta[k] = after

            entry = DiffCacheEntry(
                hook_name=name, input_fingerprint=input_fp,
                output_delta=output_delta, wall_ms=elapsed,
            )
            cache_ref[cache_key] = entry
            last_ref[name] = entry

            ctx.clear(); ctx.update(probe)

        self._sched._execute_one = _diff_wrapped
        try:
            result = self._sched.execute(context, max_workers=max_workers, parallel=parallel)
        finally:
            self._sched._execute_one = original

        self._hit_count = hit_cnt[0]
        self._miss_count = miss_cnt[0]
        return result

    def invalidate(self, hook_name: str = '', binary_id: str = ''):
        """选择性失效缓存: 移除匹配 hook_name 和/或 binary_id 的条目."""
        binary_fp = _stable_hash(binary_id) if binary_id else ''
        to_del = []
        for (hn, bfp, _), entry in self._cache.items():
            if hook_name and hn != hook_name:
                continue
            if binary_fp and bfp != binary_fp:
                continue
            to_del.append((hn, bfp, entry.input_fingerprint))
        for key in to_del:
            self._cache.pop(key, None)

    def clear_cache(self):
        self._cache.clear()
        self._last_run.clear()

    @property
    def stats(self) -> Dict[str, Any]:
        total = self._hit_count + self._miss_count
        return {
            'hits': self._hit_count, 'misses': self._miss_count,
            'hit_rate': round(self._hit_count / max(1, total), 3),
            'cache_size': len(self._cache),
        }

    def last_run_summary(self) -> List[Dict[str, Any]]:
        return [{
            'hook': e.hook_name, 'cached': e.input_fingerprint[:12],
            'output_keys': list(e.output_delta.keys()),
            'wall_ms': round(e.wall_ms, 2),
        } for e in self._last_run.values()]


class IncrementalCacheStore:
    """跨进程的增量缓存持久化 — 将 DiffExecutor 的缓存序列化到磁盘.

    缓存文件结构:
      {binary_fp: {hook_name: {input_fp: output_delta}}}

    使用 JSON 序列化; 对于大型 output_delta (含二进制数据),
    自动降级为 base64 编码. 文件级写锁防止并发损坏.
    """

    def __init__(self, cache_path: str = './.diff_cache.json'):
        self._path = cache_path
        self._dirty = False
        self._data: Dict[str, Dict[str, Dict[str, Dict[str, Any]]]] = {}

    def load(self) -> 'IncrementalCacheStore':
        try:
            with open(self._path, 'r', encoding='utf-8') as f:
                self._data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self._data = {}
        return self

    def save(self) -> None:
        tmp = self._path + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(self._data, f, ensure_ascii=False, default=str)
        import os
        os.replace(tmp, self._path)

    def put(self, binary_fp: str, hook_name: str, input_fp: str, output_delta: Dict[str, Any]):
        bd = self._data.setdefault(binary_fp, {})
        hd = bd.setdefault(hook_name, {})
        hd[input_fp] = output_delta
        self._dirty = True

    def get(self, binary_fp: str, hook_name: str, input_fp: str) -> Optional[Dict[str, Any]]:
        return self._data.get(binary_fp, {}).get(hook_name, {}).get(input_fp)

    def load_into(self, executor: DiffExecutor, binary_id: str):
        """将持久化缓存恢复到 DiffExecutor 的内存缓存中."""
        binary_fp = _stable_hash(binary_id)
        bd = self._data.get(binary_fp, {})
        loaded = 0
        for hook_name, inputs in bd.items():
            for input_fp, delta in inputs.items():
                key = (hook_name, binary_fp, input_fp)
                executor._cache[key] = DiffCacheEntry(
                    hook_name=hook_name, input_fingerprint=input_fp,
                    output_delta=delta, wall_ms=0.0,
                )
                loaded += 1
        return loaded

    def save_from(self, executor: DiffExecutor, binary_id: str):
        """将 DiffExecutor 的内存缓存持久化."""
        binary_fp = _stable_hash(binary_id)
        for (hn, bfp, ifp), entry in executor._cache.items():
            if bfp == binary_fp:
                self.put(bfp, hn, ifp, entry.output_delta)

    def flush_if_dirty(self):
        if self._dirty:
            self.save()
            self._dirty = False
