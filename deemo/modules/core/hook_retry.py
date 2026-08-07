# coding: utf-8
"""
钩子自适应重试与参数退化 — 失败时指数退避 + 语义参数降级 + 备选回退 + 失败模式学习.

通用重试库 (tenacity, backoff) 不理解钩子语义参数, 仅做等间隔/指数退避.
本模块: 参数退化链 (截断/跳过/标记) + 备选钩子回退 + FailurePatternDB 预防性调度.
"""

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


@dataclass
class DegradeStep:
    """参数退化的一步 — 修改 context 以降低钩子的执行难度."""
    description: str
    # 修改 context 的可调用对象: ctx → modified_ctx
    transform: Callable[[Dict[str, Any]], Dict[str, Any]] = lambda c: c


def degrade_reduce_depth(keys: Tuple[str, ...], factor: float = 0.5):
    """返回 DegradeStep: 将指定键的值截断为原长度×factor."""
    def _transform(ctx):
        c = dict(ctx)
        for k in keys:
            v = c.get(k)
            if isinstance(v, (list, tuple)):
                c[k] = v[:max(1, int(len(v) * factor))]
            elif isinstance(v, str):
                c[k] = v[:max(1, int(len(v) * factor))]
            elif isinstance(v, dict):
                half = max(1, len(v) // 2)
                c[k] = dict(list(v.items())[:half])
        return c
    return DegradeStep(description=f'截断 {keys} 至 {factor:.0%}', transform=_transform)


def degrade_skip_key(key: str):
    """返回 DegradeStep: 从 context 中移除指定键, 钩子将使用默认值."""
    def _transform(ctx):
        c = dict(ctx); c.pop(key, None); return c
    return DegradeStep(description=f'移除键 {key}', transform=_transform)


def degrade_flag(key: str, value: Any = True):
    """返回 DegradeStep: 在 context 中设置降级标记, 钩子可自行判断."""
    def _transform(ctx):
        c = dict(ctx); c[key] = value; return c
    return DegradeStep(description=f'设置降级标记 {key}={value}', transform=_transform)


@dataclass
class RetryPolicy:
    """单钩子的重试策略配置."""
    hook_name: str
    max_retries: int = 2
    base_delay_ms: float = 100.0    # 首次重试等待
    backoff_factor: float = 2.5     # 指数退避乘数
    degrade_steps: List[DegradeStep] = field(default_factory=list)
    fallback_hook: Optional[Callable] = None  # 备选钩子 (fn或name)
    fallback_name: str = ''
    retry_on: Tuple[type, ...] = (Exception,)  # 哪些异常类型触发重试


@dataclass
class RetryRecord:
    """单次重试/执行的记录."""
    hook_name: str
    attempt: int               # 0=首次, 1..N=重试
    success: bool
    wall_ms: float
    error_msg: str = ''
    degraded: bool = False     # 本次是否使用了参数退化
    fallback_used: bool = False


class HookRetryWrapper:
    """钩子重试包装器 — 将普通钩子函数包装为带重试+退化+回退的版本.

    用法:
      wrapper = HookRetryWrapper(policy)
      wrapped_fn = wrapper.wrap(original_hook_fn)
      result = wrapped_fn(context)  # 自动重试
    """

    def __init__(self, policy: RetryPolicy):
        self._policy = policy
        self._records: List[RetryRecord] = []

    def wrap(self, fn: Callable) -> Callable:
        policy = self._policy
        records = self._records

        def _wrapped(context: Dict[str, Any]) -> Any:
            records.clear()
            ctx = dict(context)
            last_error = ''

            for attempt in range(policy.max_retries + 1):
                # 第 0 次 = 正常执行; 第 1+ 次 = 退化重试
                degraded = attempt > 0
                if degraded and attempt - 1 < len(policy.degrade_steps):
                    step = policy.degrade_steps[attempt - 1]
                    ctx = step.transform(ctx)

                t0 = time.perf_counter()
                try:
                    result = fn(ctx)
                    elapsed = (time.perf_counter() - t0) * 1000
                    records.append(RetryRecord(
                        hook_name=policy.hook_name, attempt=attempt,
                        success=True, wall_ms=elapsed, degraded=degraded,
                    ))
                    return result
                except policy.retry_on as e:
                    elapsed = (time.perf_counter() - t0) * 1000
                    last_error = f'{type(e).__name__}: {e}'
                    records.append(RetryRecord(
                        hook_name=policy.hook_name, attempt=attempt,
                        success=False, wall_ms=elapsed,
                        error_msg=last_error, degraded=degraded))
                    if attempt < policy.max_retries:
                        delay = policy.base_delay_ms * (policy.backoff_factor ** attempt)
                        time.sleep(delay / 1000.0)
                except BaseException:
                    raise

            # 所有重试耗尽: 尝试备选
            if policy.fallback_hook is not None:
                t0 = time.perf_counter()
                try:
                    result = policy.fallback_hook(ctx)
                    records.append(RetryRecord(hook_name=policy.hook_name,
                        attempt=policy.max_retries+1, success=True,
                        wall_ms=(time.perf_counter()-t0)*1000, fallback_used=True))
                    return result
                except Exception as e:
                    records.append(RetryRecord(hook_name=policy.hook_name,
                        attempt=policy.max_retries+1, success=False,
                        wall_ms=(time.perf_counter()-t0)*1000,
                        error_msg=f'fallback: {type(e).__name__}: {e}'))

            raise RuntimeError(
                f'{policy.hook_name}: {policy.max_retries + 1} 次尝试均失败. '
                f'最后错误: {last_error}')

        return _wrapped

    @property
    def records(self) -> List[RetryRecord]:
        return list(self._records)


class RetryScheduler:
    """带重试的 DAG 调度器包装 — 为每个钩子配置独立的 RetryPolicy.

    用法:
      policies = {'taint': RetryPolicy('taint', max_retries=2, ...)}
      rs = RetryScheduler(scheduler, policies)
      ctx = rs.execute(context)
    """

    def __init__(self, scheduler, policies: Optional[Dict[str, RetryPolicy]] = None):
        self._sched = scheduler
        self._policies = policies or {}
        self._all_records: List[RetryRecord] = []

    def execute(
        self, context: Optional[Dict[str, Any]] = None,
        max_workers: Optional[int] = None, parallel: bool = True,
    ) -> Dict[str, Any]:
        if context is None:
            context = {}
        self._all_records.clear()

        if not self._sched._built:
            self._sched.build()

        orig = self._sched._execute_one
        policies = self._policies
        all_records = self._all_records

        def _retry_exec(name: str, ctx: dict, failed: set, skipped: set) -> None:
            policy = policies.get(name)
            if policy is None:
                orig(name, ctx, failed, skipped)
                return

            wrapper = HookRetryWrapper(policy)
            task = self._sched._tasks.get(name) if hasattr(self._sched, '_tasks') else None
            task_fn = task.fn if task and task.fn else (
                self._sched._resolve_callable(task) if task and hasattr(task, 'module') and task.module else None
            )
            if task_fn is None:
                orig(name, ctx, failed, skipped)
                return

            wrapped = wrapper.wrap(task_fn)
            try:
                result = wrapped(ctx)
                all_records.extend(wrapper.records)
                if isinstance(result, dict):
                    ctx.update(result)
                elif result is not None:
                    ctx[name] = result
            except Exception as e:
                all_records.extend(wrapper.records)
                failed.add(name)

        self._sched._execute_one = _retry_exec
        try:
            result = self._sched.execute(context, max_workers=max_workers, parallel=parallel)
        finally:
            self._sched._execute_one = orig

        return result

    @property
    def records(self) -> List[RetryRecord]:
        return list(self._all_records)

    def summary(self) -> Dict[str, Any]:
        recs = self._all_records
        if not recs:
            return {'total': 0}
        successes = [r for r in recs if r.success]
        retries = [r for r in recs if r.attempt > 0]
        degradations = [r for r in recs if r.degraded]
        fallbacks = [r for r in recs if r.fallback_used]
        return {
            'total_attempts': len(recs),
            'success_rate': round(len(successes) / len(recs), 3),
            'retries': len(retries),
            'degraded_successes': len([r for r in degradations if r.success]),
            'fallback_used': len(fallbacks),
        }


class FailurePatternDB:
    """失败模式数据库 — 记录 (hook, binary特征, error_type) 的失败频率.

    供 RetryScheduler 或 PipelineSynthesizer 在调度前查询:
      若某钩子对 ARM64 二进制有 80% 失败率 → 自动降低其优先级或跳过.
    """

    def __init__(self):
        # (hook_name, feature_key, feature_value) → [success_count, fail_count]
        self._stats: Dict[Tuple[str, str, str], List[int]] = defaultdict(lambda: [0, 0])

    def record(
        self, hook_name: str, success: bool,
        features: Optional[Dict[str, Any]] = None,
        error_type: str = '',
    ):
        feats = features or {}
        for k, v in feats.items():
            key = (hook_name, k, str(v))
            if success:
                self._stats[key][0] += 1
            else:
                self._stats[key][1] += 1
        if error_type:
            err_key = (hook_name, '__error__', error_type)
            if success:
                self._stats[err_key][0] += 1
            else:
                self._stats[err_key][1] += 1

    def failure_rate(self, hook_name: str, features: Optional[Dict[str, Any]] = None) -> float:
        """返回该钩子在指定特征下的历史失败率 [0, 1]."""
        feats = features or {}
        if not feats:
            total_s, total_f = 0, 0
            for (hn, _, _), (s, f) in self._stats.items():
                if hn == hook_name:
                    total_s += s; total_f += f
            total = total_s + total_f
            return total_f / total if total > 0 else 0.0

        rates = []
        for k, v in feats.items():
            s, f = self._stats.get((hook_name, k, str(v)), [0, 0])
            total = s + f
            if total > 0:
                rates.append(f / total)
        return sum(rates) / len(rates) if rates else 0.0

    def should_skip(self, hook_name: str, features: Optional[Dict[str, Any]] = None,
                    threshold: float = 0.70) -> bool:
        """若历史失败率超过阈值, 建议跳过该钩子."""
        return self.failure_rate(hook_name, features) >= threshold

    def to_dict(self) -> Dict[str, Any]:
        return {'_'.join(k): v for k, v in self._stats.items()}

    def clear(self):
        self._stats.clear()
