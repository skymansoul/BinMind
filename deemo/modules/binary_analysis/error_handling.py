"""Error categorization, context propagation, and retry helpers."""
from __future__ import annotations
import time as _time
import functools as _functools
import logging as _logging
from typing import Callable, Any, Dict, Optional, Tuple
from enum import Enum

_log = _logging.getLogger(__name__)


class ErrorCategory(Enum):
    ANALYSIS = "analysis"
    PLUGIN = "plugin"
    SCHEDULER = "scheduler"
    CONFIG = "config"
    RECOVERABLE = "recoverable"
    FATAL = "fatal"
    TRANSIENT = "transient"
    VALIDATION = "validation"
    TIMEOUT = "timeout"

class ErrorSeverity(Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ErrorRecord:
    __slots__ = ('exception', 'category', 'severity', 'context', 'timestamp',
                 'error_id', 'stack_trace')

    def __init__(self, exception=None, category=ErrorCategory.FATAL,
                 severity=ErrorSeverity.CRITICAL, context=None,
                 error_id="", stack_trace=""):
        self.exception = exception
        self.category = category
        self.severity = severity
        self.context = context or {}
        self.timestamp = _time.time()
        self.error_id = error_id
        self.stack_trace = stack_trace


class ErrorContext:
    def __init__(self, task_id="", analyzer_name="", binary_path="",
                 function_name="", **kwargs):
        self.task_id = task_id
        self.analyzer_name = analyzer_name
        self.binary_path = binary_path
        self.function_name = function_name
        self.error = None
        self.trace: list = []
        self.metadata: Dict[str, Any] = dict(kwargs)

    def capture(self, exc, **kwargs):
        self.error = exc
        self.metadata.update(kwargs)

    def to_dict(self):
        return {"error": str(self.error), "metadata": self.metadata}


class ErrorHandler:
    def __init__(self):
        self.records: list = []
        self._handlers: Dict[ErrorCategory, list] = {
            cat: [] for cat in ErrorCategory
        }

    def handle(self, error, category=ErrorCategory.FATAL, context=None):
        rec = ErrorRecord(error, category,
                          ErrorSeverity.HIGH if category == ErrorCategory.FATAL else ErrorSeverity.MEDIUM,
                          context)
        self.records.append(rec)
        _log.error("[%s] %s", category.value, str(error)[:200])
        for cb in self._handlers.get(category, []):
            try:
                cb(rec)
            except Exception:
                pass
        if category == ErrorCategory.FATAL:
            raise error
        return rec

    def register_handler(self, category: ErrorCategory, callback):
        self._handlers.setdefault(category, []).append(callback)

    def classify(self, exc: Exception) -> ErrorCategory:
        cls_name = type(exc).__name__.lower()
        if isinstance(exc, (TimeoutError, ConnectionError)):
            return ErrorCategory.TIMEOUT
        if isinstance(exc, (ValueError, TypeError)):
            return ErrorCategory.VALIDATION
        if "retry" in cls_name or "transient" in cls_name or "temporary" in cls_name:
            return ErrorCategory.TRANSIENT
        if isinstance(exc, (IOError, OSError, BrokenPipeError)):
            return ErrorCategory.RECOVERABLE
        return ErrorCategory.FATAL


# -- retry decorator ----------------------------------------------

def retry(max_attempts: int = 3, delay: float = 0.5,
          backoff: float = 2.0, retryable: Optional[Tuple] = None):
    if retryable is None:
        retryable = (IOError, OSError, TimeoutError, ConnectionError)

    def decorator(fn: Callable):
        @_functools.wraps(fn)
        def wrapper(*args, **kwargs):
            wait = delay
            last_exc = None
            for attempt in range(1, max_attempts + 1):
                try:
                    return fn(*args, **kwargs)
                except retryable as e:
                    last_exc = e
                    if attempt < max_attempts:
                        _log.warning("retry %d/%d for %s: %s",
                                     attempt, max_attempts, fn.__name__, str(e)[:100])
                        _time.sleep(wait)
                        wait *= backoff
            raise last_exc
        return wrapper
    return decorator


class RetryHandler:
    def __init__(self, max_attempts=3, delay=0.5, backoff=2.0):
        self.max_attempts = max_attempts
        self.delay = delay
        self.backoff = backoff

    def execute(self, fn, *args, **kwargs):
        wrapped = retry(self.max_attempts, self.delay, self.backoff)(fn)
        return wrapped(*args, **kwargs)


# -- safe execution context ---------------------------------------

class SafeExecution:
    def __init__(self, error_handler=None):
        self.error_handler = error_handler or ErrorHandler()

    def run(self, fn, *args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as exc:
            cat = self.error_handler.classify(exc)
            self.error_handler.handle(exc, category=cat)
            return None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, _tb):
        if exc_type is not None and exc_val is not None:
            cat = self.error_handler.classify(exc_val)
            self.error_handler.handle(exc_val, category=cat)
            return cat != ErrorCategory.FATAL
        return False


def get_error_handler():
    return ErrorHandler()


module: str = ""
