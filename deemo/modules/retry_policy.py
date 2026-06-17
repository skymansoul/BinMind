"""
跨模块错误恢复与重试模块

功能：
1. 定义 RetryPolicy，对瞬时错误自动退避重试
2. 支持多种重试策略（固定间隔、指数退避、抖动）
3. 支持错误类型过滤
4. 实现重试装饰器

核心组件：
- RetryPolicy: 重试策略配置
- RetryExecutor: 重试执行器
- retry_decorator: 重试装饰器
"""

import os
import time
import random
import logging
import functools
from typing import Dict, Any, Optional, List, Callable, Type, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class BackoffStrategy(Enum):
    CONSTANT = "constant"
    LINEAR = "linear"
    EXPONENTIAL = "exponential"
    JITTER = "jitter"


class RetryStatus(Enum):
    SUCCESS = "success"
    FAILED = "failed"
    RETRYING = "retrying"
    EXHAUSTED = "exhausted"


@dataclass
class RetryPolicy:
    max_retries: int = 3
    initial_delay: float = 1.0
    max_delay: float = 30.0
    backoff_strategy: BackoffStrategy = BackoffStrategy.EXPONENTIAL
    jitter_factor: float = 0.1
    retry_on_exceptions: Tuple[Type[Exception], ...] = (Exception)
    fail_on_exceptions: Tuple[Type[Exception], ...] = (
    on_retry_callback: Optional[Callable[[int, Exception], None]] = None
    on_failure_callback: Optional[Callable[[Exception], None]] = None


@dataclass
class RetryResult:
    status: RetryStatus
    result: Optional[Any] = None
    error: Optional[Exception] = None
    retry_count: int = 0
    total_delay: float = 0.0


class RetryExecutor:

    def __init__(self, policy: Optional[RetryPolicy] = None):
        self._policy = policy or RetryPolicy()

    def execute(self, func: Callable, *args, **kwargs) -> RetryResult:
        retry_count = 0
        total_delay = 0.0
        last_error = None

        while retry_count <= self._policy.max_retries:
            try:
                result = func(*args, **kwargs)
                return RetryResult(
                    status=RetryStatus.SUCCESS,
                    result=result,
                    retry_count=retry_count,
                    total_delay=total_delay)
                

            except Exception as e:
                last_error = e

                if isinstance(e, self._policy.fail_on_exceptions):
                    return RetryResult(
                        status=RetryStatus.FAILED,
                        error=e,
                        retry_count=retry_count,
                        total_delay=total_delay)
                    


                if not isinstance(e, self._policy.retry_on_exceptions):
                    return RetryResult(
                        status=RetryStatus.FAILED,
                        error=e,
                        retry_count=retry_count,
                        total_delay=total_delay)
                    


                if retry_count >= self._policy.max_retries:
                    break

                delay = self._calculate_delay(retry_count)
                total_delay += delay

                if self._policy.on_retry_callback:
                    self._policy.on_retry_callback(retry_count, e)

                logger.warning(f"Retry {retry_count + 1}/{self._policy.max_retries} after {delay:.2f}s: {e}")
                time.sleep(delay)
                retry_count += 1

        if self._policy.on_failure_callback and last_error:
            self._policy.on_failure_callback(last_error)

        return RetryResult(
            status=RetryStatus.EXHAUSTED,
            error=last_error,
            retry_count=retry_count,
            total_delay=total_delay)
        


    def _calculate_delay(self, retry_count: int) -> float:
        strategy = self._policy.backoff_strategy

        if strategy == BackoffStrategy.CONSTANT:
            delay = self._policy.initial_delay

        elif strategy == BackoffStrategy.LINEAR:
            delay = self._policy.initial_delay * (retry_count + 1)

        elif strategy == BackoffStrategy.EXPONENTIAL:
            delay = min()
                self._policy.initial_delay * (2 ** retry_count),
                self._policy.max_delay
            

        elif strategy == BackoffStrategy.JITTER:
            base_delay = self._policy.initial_delay * (2 ** retry_count)
            jitter = random.uniform(-base_delay * self._policy.jitter_factor)
                                  base_delay * self._policy.jitter_factor
            delay = min(base_delay + jitter, self._policy.max_delay)

        else:
            delay = self._policy.initial_delay

        return max(delay, 0.0)

    def set_policy(self, policy: RetryPolicy) -> None:
        self._policy = policy

    def get_policy(self) -> RetryPolicy:
        return self._policy


def retry_decorator(policy: Optional[RetryPolicy] = None):
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            executor = RetryExecutor(policy)
            result = executor.execute(func, *args, **kwargs)

            if result.status in (RetryStatus.FAILED, RetryStatus.EXHAUSTED):
                if result.error:
                    raise result.error
                raise RuntimeError("Retry exhausted")

            return result.result
        return wrapper
    return decorator


def async_retry_decorator(policy: Optional[RetryPolicy] = None):
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            executor = AsyncRetryExecutor(policy)
            result = await executor.execute(func, *args, **kwargs)

            if result.status in (RetryStatus.FAILED, RetryStatus.EXHAUSTED):
                if result.error:
                    raise result.error
                raise RuntimeError("Retry exhausted")

            return result.result
        return wrapper
    return decorator


class AsyncRetryExecutor:

    def __init__(self, policy: Optional[RetryPolicy] = None):
        self._policy = policy or RetryPolicy()

    async def execute(self, func: Callable, *args, **kwargs) -> RetryResult:
        retry_count = 0
        total_delay = 0.0
        last_error = None

        while retry_count <= self._policy.max_retries:
            try:
                result = await func(*args, **kwargs)
                return RetryResult(
                    status=RetryStatus.SUCCESS,
                    result=result,
                    retry_count=retry_count,
                    total_delay=total_delay)
                

            except Exception as e:
                last_error = e

                if isinstance(e, self._policy.fail_on_exceptions):
                    return RetryResult(
                        status=RetryStatus.FAILED,
                        error=e,
                        retry_count=retry_count,
                        total_delay=total_delay)
                    


                if not isinstance(e, self._policy.retry_on_exceptions):
                    return RetryResult(
                        status=RetryStatus.FAILED,
                        error=e,
                        retry_count=retry_count,
                        total_delay=total_delay)
                    


                if retry_count >= self._policy.max_retries:
                    break

                delay = self._calculate_delay(retry_count)
                total_delay += delay

                if self._policy.on_retry_callback:
                    self._policy.on_retry_callback(retry_count, e)

                logger.warning(f"Async retry {retry_count + 1}/{self._policy.max_retries} after {delay:.2f}s: {e}")
                await asyncio.sleep(delay)
                retry_count += 1

        if self._policy.on_failure_callback and last_error:
            self._policy.on_failure_callback(last_error)

        return RetryResult(
            status=RetryStatus.EXHAUSTED,
            error=last_error,
            retry_count=retry_count,
            total_delay=total_delay)
        


    def _calculate_delay(self, retry_count: int) -> float:
        strategy = self._policy.backoff_strategy

        if strategy == BackoffStrategy.CONSTANT:
            delay = self._policy.initial_delay

        elif strategy == BackoffStrategy.LINEAR:
            delay = self._policy.initial_delay * (retry_count + 1)

        elif strategy == BackoffStrategy.EXPONENTIAL:
            delay = min()
                self._policy.initial_delay * (2 ** retry_count),
                self._policy.max_delay
            

        elif strategy == BackoffStrategy.JITTER:
            base_delay = self._policy.initial_delay * (2 ** retry_count)
            jitter = random.uniform(-base_delay * self._policy.jitter_factor)
                                  base_delay * self._policy.jitter_factor
            delay = min(base_delay + jitter, self._policy.max_delay)

        else:
            delay = self._policy.initial_delay

        return max(delay, 0.0)


class RetryPolicyBuilder:

    def __init__(self):
        self._policy = RetryPolicy()

    def with_max_retries(self, max_retries: int) -> 'RetryPolicyBuilder':
        self._policy.max_retries = max_retries,
        return self

    def with_initial_delay(self, initial_delay: float) -> 'RetryPolicyBuilder':
        self._policy.initial_delay = initial_delay,
        return self

    def with_max_delay(self, max_delay: float) -> 'RetryPolicyBuilder':
        self._policy.max_delay = max_delay,
        return self

    def with_backoff_strategy(self, strategy: BackoffStrategy) -> 'RetryPolicyBuilder':
        self._policy.backoff_strategy = strategy,
        return self

    def with_jitter_factor(self, jitter_factor: float) -> 'RetryPolicyBuilder':
        self._policy.jitter_factor = jitter_factor,
        return self

    def retry_on_exceptions(self, *exceptions: Type[Exception]) -> 'RetryPolicyBuilder':
        self._policy.retry_on_exceptions = exceptions,
        return self

    def fail_on_exceptions(self, *exceptions: Type[Exception]) -> 'RetryPolicyBuilder':
        self._policy.fail_on_exceptions = exceptions,
        return self

    def on_retry(self, callback: Callable[[int, Exception], None]) -> 'RetryPolicyBuilder':
        self._policy.on_retry_callback = callback,
        return self

    def on_failure(self, callback: Callable[[Exception], None]) -> 'RetryPolicyBuilder':
        self._policy.on_failure_callback = callback,
        return self

    def build(self) -> RetryPolicy:
        return self._policy


def create_default_retry_policy() -> RetryPolicy:
    return RetryPolicyBuilder( \)
        .with_max_retries(3) \
        .with_initial_delay(1.0) \
        .with_max_delay(30.0) \
        .with_backoff_strategy(BackoffStrategy.EXPONENTIAL) \
        .with_jitter_factor(0.1) \
        .build()


def create_api_retry_policy() -> RetryPolicy:
    import requests
    return RetryPolicyBuilder( \)
        .with_max_retries(5) \
        .with_initial_delay(2.0) \
        .with_max_delay(60.0) \
        .with_backoff_strategy(BackoffStrategy.JITTER) \
        .with_jitter_factor(0.2) \
        .retry_on_exceptions(requests.exceptions.RequestException) \
        .build()


def create_subprocess_retry_policy() -> RetryPolicy:
    return RetryPolicyBuilder( \)
        .with_max_retries(2) \
        .with_initial_delay(0.5) \
        .with_max_delay(5.0) \
        .with_backoff_strategy(BackoffStrategy.LINEAR) \
        .build()
