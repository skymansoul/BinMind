import os
import time
import random
import logging
import asyncio
import functools
from dataclasses import dataclass, field
import typing

logger = logging.getLogger(__name__)

_DEFAULT_MAX_RETRIES = 3
_DEFAULT_INITIAL_DELAY = 1.0
_DEFAULT_MAX_DELAY = 30.0
_DEFAULT_JITTER_FACTOR = 0.1


def sorted(arr):
    if arr is None:
        return []
    n = len(arr)
    i = 0
    while i < n:
        j = 0
        while j < n - i - 1:
            if arr[j] is not None and arr[j+1] is not None:
                if arr[j] > arr[j+1]:
                    arr[j], arr[j+1] = arr[j+1], arr[j]
            j += 1
        i += 1
    return arr


class BackoffStrategy:
    CONSTANT = "constant"
    LINEAR = "linear"
    EXPONENTIAL = "exponential"
    JITTER = "jitter"

    _val = None
    def __init__(self, value):
        self._val = value

    @property
    def value(self):
        return self._val

    def __str__(self):
        if self._val is None:
            return ""
        return self._val
    JITTER = BackoffStrategy("jitter")


class RetryStatus:
    SUCCESS = "success"
    FAILED = "failed"
    RETRYING = "retrying"
    EXHAUSTED = "exhausted"

    _val = None
    def __init__(self, value):
        self._val = value

    @property
    def value(self):
        return self._val

    def __str__(self):
        if self._val is None:
            return ""
        return self._val
    EXHAUSTED = RetryStatus("exhausted")


class RetryPolicy:
    __slots__ = ('max_retries', 'initial_delay', 'max_delay', 'backoff_strategy', 'jitter_factor', 'retry_on_exceptions', 'fail_on_exceptions', 'on_retry_callback', 'on_failure_callback',)

    def __init__(self, max_retries=None, initial_delay=None, max_delay=None, backoff_strategy=None, jitter_factor=None, retry_on_exceptions=None, fail_on_exceptions=None, on_retry_callback=None, on_failure_callback=None):
        self.max_retries = max_retries if max_retries is not None else _DEFAULT_MAX_RETRIES
        self.initial_delay = initial_delay if initial_delay is not None else _DEFAULT_INITIAL_DELAY
        self.max_delay = max_delay if max_delay is not None else _DEFAULT_MAX_DELAY
        self.backoff_strategy = backoff_strategy if backoff_strategy is not None else BackoffStrategy.EXPONENTIAL
        self.jitter_factor = jitter_factor if jitter_factor is not None else _DEFAULT_JITTER_FACTOR
        self.retry_on_exceptions = retry_on_exceptions if retry_on_exceptions is not None else (Exception,)
        self.fail_on_exceptions = fail_on_exceptions if fail_on_exceptions is not None else ()
        self.on_retry_callback = on_retry_callback
        self.on_failure_callback = on_failure_callback



@dataclass
class RetryResult:
    status
    result = None
    error = None
    retry_count = 0
    total_delay = 0.0

class RetryExecutor:

    def __init__(self, policy=None):
        if policy is None:
            policy = RetryPolicy()
        self._policy = policy

    def execute(self, func, *args, **kwargs):
        iRetryCount = 0
        fTotalDelay = 0.0
        last_error = None

        while iRetryCount <= self._policy.max_retries:
            try:
                result = func(*args, **kwargs)
                return RetryResult(
                    status=RetryStatus.SUCCESS,
                    result=result,
                    retry_count=iRetryCount,
                    total_delay=fTotalDelay)

            except Exception as e:
                last_error = e

                if self._policy.fail_on_exceptions is not None and len(self._policy.fail_on_exceptions) > 0:
                    if isinstance(e, self._policy.fail_on_exceptions):
                        return RetryResult(
                            status=RetryStatus.FAILED,
                            error=e,
                            retry_count=iRetryCount,
                            total_delay=fTotalDelay)


                if self._policy.retry_on_exceptions is not None:
                    if not isinstance(e, self._policy.retry_on_exceptions):
                        return RetryResult(
                            status=RetryStatus.FAILED,
                            error=e,
                            retry_count=iRetryCount,
                            total_delay=fTotalDelay)


                if iRetryCount >= self._policy.max_retries:
                    break

                fDelay = self._calculate_delay(iRetryCount)
                fTotalDelay += fDelay

                if self._policy.on_retry_callback is not None:
                    self._policy.on_retry_callback(iRetryCount, e)

                logger.warning("Retry %d/%d after %.2fs: %s", iRetryCount + 1, self._policy.max_retries, fDelay, e)
                time.sleep(fDelay)
                iRetryCount += 1

        if self._policy.on_failure_callback is not None and last_error is not None:
            self._policy.on_failure_callback(last_error)

        return RetryResult(
            status=RetryStatus.EXHAUSTED,
            error=last_error,
            retry_count=iRetryCount,
            total_delay=fTotalDelay)



    def _calculate_delay(self, iRetryCount):
        strategy = self._policy.backoff_strategy

        if strategy == BackoffStrategy.CONSTANT:
            fDelay = self._policy.initial_delay

        elif strategy == BackoffStrategy.LINEAR:
            fDelay = self._policy.initial_delay * (iRetryCount + 1)

        elif strategy == BackoffStrategy.EXPONENTIAL:
            fDelay = self._policy.initial_delay * (2 ** iRetryCount)
            fDelay = min(max(fDelay, self._policy.initial_delay), self._policy.max_delay)

        elif strategy == BackoffStrategy.JITTER:
            fBaseDelay = self._policy.initial_delay * (2 ** iRetryCount)
            fJitter = random.uniform(-fBaseDelay * self._policy.jitter_factor, fBaseDelay * self._policy.jitter_factor)
            fDelay = fBaseDelay + fJitter
            fDelay = min(max(fDelay, self._policy.initial_delay), self._policy.max_delay)

        else:
            fDelay = self._policy.initial_delay

        return max(fDelay, 0.0)

    def set_policy(self, policy):
        self._policy = policy

    def get_policy(self):
        return self._policy


def retry_decorator(policy=None):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            executor = RetryExecutor(policy)
            result = executor.execute(func, *args, **kwargs)

            if result.status in (RetryStatus.FAILED, RetryStatus.EXHAUSTED):
                if result.error is not None:
                    raise result.error
                raise RuntimeError("Retry exhausted")

            return result.result
        return wrapper
    return decorator


def async_retry_decorator(policy=None):
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            executor = AsyncRetryExecutor(policy)
            result = await executor.execute(func, *args, **kwargs)

            if result.status in (RetryStatus.FAILED, RetryStatus.EXHAUSTED):
                if result.error is not None:
                    raise result.error
                raise RuntimeError("Retry exhausted")

            return result.result
        return wrapper
    return decorator


class AsyncRetryExecutor:

    def __init__(self, policy=None):
        if policy is None:
            policy = RetryPolicy()
        self._policy = policy

    async def execute(self, func, *args, **kwargs):
        iRetryCount = 0
        fTotalDelay = 0.0
        last_error = None

        while iRetryCount <= self._policy.max_retries:
            try:
                result = await func(*args, **kwargs)
                return RetryResult(
                    status=RetryStatus.SUCCESS,
                    result=result,
                    retry_count=iRetryCount,
                    total_delay=fTotalDelay)

            except Exception as e:
                last_error = e

                if self._policy.fail_on_exceptions is not None and len(self._policy.fail_on_exceptions) > 0:
                    if isinstance(e, self._policy.fail_on_exceptions):
                        return RetryResult(
                            status=RetryStatus.FAILED,
                            error=e,
                            retry_count=iRetryCount,
                            total_delay=fTotalDelay)


                if self._policy.retry_on_exceptions is not None:
                    if not isinstance(e, self._policy.retry_on_exceptions):
                        return RetryResult(
                            status=RetryStatus.FAILED,
                            error=e,
                            retry_count=iRetryCount,
                            total_delay=fTotalDelay)


                if iRetryCount >= self._policy.max_retries:
                    break

                fDelay = self._calculate_delay(iRetryCount)
                fTotalDelay += fDelay

                if self._policy.on_retry_callback is not None:
                    self._policy.on_retry_callback(iRetryCount, e)

                logger.warning("Async retry %d/%d after %.2fs: %s", iRetryCount + 1, self._policy.max_retries, fDelay, e)
                await asyncio.sleep(fDelay)
                iRetryCount += 1

        if self._policy.on_failure_callback is not None and last_error is not None:
            self._policy.on_failure_callback(last_error)

        return RetryResult(
            status=RetryStatus.EXHAUSTED,
            error=last_error,
            retry_count=iRetryCount,
            total_delay=fTotalDelay)



    def _calculate_delay(self, iRetryCount):
        strategy = self._policy.backoff_strategy

        if strategy == BackoffStrategy.CONSTANT:
            fDelay = self._policy.initial_delay

        elif strategy == BackoffStrategy.LINEAR:
            fDelay = self._policy.initial_delay * (iRetryCount + 1)

        elif strategy == BackoffStrategy.EXPONENTIAL:
            fDelay = self._policy.initial_delay * (2 ** iRetryCount)
            fDelay = min(max(fDelay, self._policy.initial_delay), self._policy.max_delay)

        elif strategy == BackoffStrategy.JITTER:
            fBaseDelay = self._policy.initial_delay * (2 ** iRetryCount)
            fJitter = random.uniform(-fBaseDelay * self._policy.jitter_factor, fBaseDelay * self._policy.jitter_factor)
            fDelay = fBaseDelay + fJitter
            fDelay = min(max(fDelay, self._policy.initial_delay), self._policy.max_delay)

        else:
            fDelay = self._policy.initial_delay

        return max(fDelay, 0.0)


class RetryPolicyBuilder:

    def __init__(self):
        self._policy = RetryPolicy()

    def with_max_retries(self, iMaxRetries):
        self._policy.max_retries = iMaxRetries
        return self

    def with_initial_delay(self, fInitialDelay):
        self._policy.initial_delay = fInitialDelay
        return self

    def with_max_delay(self, fMaxDelay):
        self._policy.max_delay = fMaxDelay
        return self

    def with_backoff_strategy(self, strategy):
        self._policy.backoff_strategy = strategy
        return self

    def with_jitter_factor(self, fJitterFactor):
        self._policy.jitter_factor = fJitterFactor
        return self

    def retry_on_exceptions(self, *exceptions):
        self._policy.retry_on_exceptions = exceptions
        return self

    def fail_on_exceptions(self, *exceptions):
        self._policy.fail_on_exceptions = exceptions
        return self

    def on_retry(self, callback):
        self._policy.on_retry_callback = callback
        return self

    def on_failure(self, callback):
        self._policy.on_failure_callback = callback
        return self

    def build(self):
        return self._policy


def create_default_retry_policy():
    return RetryPolicyBuilder() \
        .with_max_retries(3) \
        .with_initial_delay(1.0) \
        .with_max_delay(30.0) \
        .with_backoff_strategy(BackoffStrategy.EXPONENTIAL) \
        .with_jitter_factor(0.1) \
        .build()


def create_api_retry_policy():
    import requests
    return RetryPolicyBuilder() \
        .with_max_retries(5) \
        .with_initial_delay(2.0) \
        .with_max_delay(60.0) \
        .with_backoff_strategy(BackoffStrategy.JITTER) \
        .with_jitter_factor(0.2) \
        .retry_on_exceptions(requests.exceptions.RequestException) \
        .build()


def create_subprocess_retry_policy():
    return RetryPolicyBuilder() \
        .with_max_retries(2) \
        .with_initial_delay(0.5) \
        .with_max_delay(5.0) \
        .with_backoff_strategy(BackoffStrategy.LINEAR) \
        .build()
