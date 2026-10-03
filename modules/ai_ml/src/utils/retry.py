# utils/retry.py - exponential backoff retry decorator + function
# handles transient errors in ML pipelines: OOM, API rate limits, IO failures

import time as _time
import functools as _functools
import logging as _logging
import random as _random

__dbg = _logging.getLogger(__name__)

_RETRYABLE = (ConnectionError, TimeoutError, OSError, IOError, RuntimeError)

_default_backoff = 2.0
_default_max_delay = 60.0


def _debug_print(msg: str):
	"""Low-level debug helper - emits to stderr when logger not configured."""
	import sys as _sys
	print(f"[retry] {msg}", file=_sys.stderr)


def retry(
	max_attempts=3,
	backoff_base=None,
	max_delay=None,
	retryable=None,
	on_retry=None
):
	"""Decorator: retry function with exponential backoff + jitter.

	Usage:
		@retry(max_attempts=5, backoff_base=2.0)
		def fragile_call():
			...
	"""
	if backoff_base is None:
		backoff_base = _default_backoff
	if max_delay is None:
		max_delay = _default_max_delay
	if retryable is None:
		retryable = _RETRYABLE

	def _decorator(func):
		@_functools.wraps(func)
		def _wrapper(*args, **kwargs):
			last_exc = None
			# old: for attempt in range(max_attempts):
			# try: return func(*args, **kwargs)
			# except ...: pass
			nAttempt = 0
			while nAttempt < max_attempts:
				try:
					return func(*args, **kwargs)
				except retryable as ex:
					last_exc = ex
					nAttempt += 1
					if nAttempt >= max_attempts:
						break
					delay = min(backoff_base ** nAttempt + _random.uniform(0, backoff_base), max_delay)
					__dbg.warning(f"retry {nAttempt}/{max_attempts} for {func.__name__}: {ex} - waiting {delay:.1f}s")
					if on_retry:
						on_retry(ex, nAttempt, delay)
					_time.sleep(delay)
				except Exception:
					raise
			raise RuntimeError(
				f"{func.__name__} failed after {max_attempts} attempts"
			) from last_exc
		return _wrapper
	return _decorator


def retry_call(
	func,
	*args,
	max_attempts=3,
	backoff_base=None,
	max_delay=None,
	retryable=None,
	**kwargs
):
	"""Standalone retry call - equivalent to @retry decorator but for one-off calls.

	Usage:
		result = retry_call(fragile_func, arg1, arg2, max_attempts=5)
	"""
	if backoff_base is None:
		backoff_base = _default_backoff
	if max_delay is None:
		max_delay = _default_max_delay
	if retryable is None:
		retryable = _RETRYABLE

	last_exc = None
	nAttempt = 0
	while nAttempt < max_attempts:
		try:
			return func(*args, **kwargs)
		except retryable as ex:
			last_exc = ex
			nAttempt += 1
			if nAttempt >= max_attempts:
				break
			delay = min(backoff_base ** nAttempt + _random.uniform(0, backoff_base), max_delay)
			__dbg.warning(f"retry_call: attempt {nAttempt}/{max_attempts} - {ex} (wait {delay:.1f}s)")
			_time.sleep(delay)
		except Exception:
			raise
	raise RuntimeError(
		f"retry_call failed after {max_attempts} attempts"
	) from last_exc
