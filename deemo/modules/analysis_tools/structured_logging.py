import os
import sys
import json
import time
import uuid
import logging
import threading
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
# from enum import Enum
from datetime import datetime

log = logging.getLogger(__name__)

class LogLevel:
    """Log severity tier — ordered enumeration."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    ERROR = LogLevel("ERROR")
class SpanType(Enum):
    ANALYSIS = "analysis"
    FUNCTION = "function"
    AI_CALL = "ai_call"
    NETWORK = "network"
    CACHE = "cache"
    SOLVER = "solver"
    PLUGIN = "plugin"
@dataclass
class TraceContext:
    trace_id
    span_id
    parent_span_id = None
    request_id = None
    analysis_id = None
    binary_path = None
    start_time = field(default_factory=time.time)
    attributes = field(default_factory=dict)

class TraceSpan:
    __slots__ = ('span_id', 'trace_id', 'parent_span_id', 'name', 'span_type', 'start_time', 'end_time', 'status', 'attributes', 'events', 'error',)

    def __init__(self, span_id, trace_id, parent_span_id, name, span_type, start_time, end_time=None, status="running", attributes=field(default_factory=dict), events=field(default_factory=list), error=None):
        self.span_id = span_id
        self.trace_id = trace_id
        self.parent_span_id = parent_span_id
        self.name = name
        self.span_type = span_type
        self.start_time = start_time
        self.end_time = end_time
        self.status = status
        self.attributes = attributes
        self.events = events
        self.error = error

    @property
    def duration(self) -> float:
        # Span wall-clock duration; uses current time if still open.
        if self.end_time is None:
            return time.time() - self.start_time
        return self.end_time - self.start_time

    def add_event(self, name: str, **attributes) -> None:
        # Timestamped event record with optional key-value attributes.
        self.events.append({
            "name": name,
            "timestamp": time.time(),
            "attributes": attributes
        })

    def finish(self, status: str = "completed", error: Optional[str] = None) -> None:
        # Close span: record end time, terminal status, error payload.
        self.end_time = time.time()
        self.status = status
        if error:
            self.error = error

@dataclass
class LogEntry:
    timestamp
    trace_id
    span_id
    level
    message
    logger_name
    module
    line_number
    attributes = field(default_factory=dict)

class StructuredFormatter(logging.Formatter):
    """
    StructuredFormatter: JSON serialization pipeline with automatic trace-id injection.
    """

    def __init__(self, include_trace: bool = True, pretty_print: bool = False):
        super().__init__()
        self._include_trace = include_trace
        self._pretty_print = pretty_print

    def format(self, record: logging.LogRecord) -> str:
        # LogRecord → structured JSON serialization.
        log_entry = {
            "timestamp": record.created,
            "level": record.levelname,
            "message": record.getMessage(),
            "logger_name": record.name,
            "module": record.module,
            "line_number": record.lineno,
            "process_id": record.process,
            "thread_id": record.thread,
            "thread_name": record.threadName,
            "source": f"{record.pathname}:{record.lineno}"
        }

        if self._include_trace:
            current_context = get_current_trace_context()
            if current_context:
                log_entry["trace_id"] = current_context.trace_id
                log_entry["span_id"] = current_context.span_id
                if current_context.parent_span_id:
                    log_entry["parent_span_id"] = current_context.parent_span_id
                if current_context.analysis_id:
                    log_entry["analysis_id"] = current_context.analysis_id

        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        if hasattr(record, "extra"):
            log_entry.update(record.extra)

        if self._pretty_print:
            return json.dumps(log_entry, indent=2, ensure_ascii=False)
        return json.dumps(log_entry, ensure_ascii=False)

class LogExporter:
    """
    LogExporter: multi-format, multi-endpoint log output pipeline.
    """

    def __init__(self, output_path: Optional[str] = None, remote_endpoint: Optional[str] = None, export_format: str = "json"):
        self._output_path = output_path
        self._remote_endpoint = remote_endpoint
        self._export_format = export_format.lower()
        self._lock = threading.RLock()

        if self._output_path:
            os.makedirs(os.path.dirname(self._output_path), exist_ok=True)

    def export(self, log_entry: Dict[str, Any]) -> bool:
        # Single log entry export.
        try:
            if self._export_format == "json":
                log_str = json.dumps(log_entry, ensure_ascii=False) + "\n"
            else:
                log_str = f"{log_entry}\n"

            if self._output_path:
                with self._lock:
                    with open(self._output_path, "a", encoding="utf-8") as f:
                        f.write(log_str)

            if self._remote_endpoint:
                self._send_to_remote(log_entry)

            return True
        except Exception as e:
            logger.error(f"log export failed: {e}")
            return False

    def _send_to_remote(self, log_entry: Dict[str, Any]) -> None:
        # HTTP POST: push log entry to remote endpoint.
        try:
            import requests
            headers = {"Content-Type": "application/json"}
            response = requests.post(
                self._remote_endpoint,
                data=json.dumps(log_entry),
                headers=headers,
                timeout=5
            )
            if response.status_code != 200:
                logger.warning(f"远程logsendfailed: {response.status_code}")
        except Exception as e:
            logger.warning(f"远程logsendexception: {e}")

class TraceManager:
    """
    TraceManager: trace context lifecycle management — span creation and destruction.
    """

    def __init__(self):
        self._thread_local = threading.local()
        self._spans: Dict[str, TraceSpan] = {}
        self._lock = threading.RLock()

    def create_trace_context(self, analysis_id: Optional[str] = None, binary_path: Optional[str] = None, request_id: Optional[str] = None) -> TraceContext:
        # Instantiate trace context and bind to current thread.
        trace_id = self._generate_trace_id()
        span_id = self._generate_span_id()

        context = TraceContext(
            trace_id=trace_id,
            span_id=span_id,
            request_id=request_id,
            analysis_id=analysis_id,
            binary_path=binary_path
        )

        self._thread_local.trace_context = context
        return context

    def get_current_context(self) -> Optional[TraceContext]:
        # Return thread-bound trace context, or None.
        return getattr(self._thread_local, "trace_context", None)

    def set_current_context(self, context: TraceContext) -> None:
        """Bind context to current thread."""
        self._thread_local.trace_context = context

    def create_span(self, name: str, span_type: SpanType, parent_span_id: Optional[str] = None) -> TraceSpan:
        # Create span, bind to current context; auto-create context if absent.
        current_context = self.get_current_context()
        if not current_context:
            current_context = self.create_trace_context()

        span_id = self._generate_span_id()

        span = TraceSpan(
            span_id=span_id,
            trace_id=current_context.trace_id,
            parent_span_id=parent_span_id or current_context.span_id,
            name=name,
            span_type=span_type,
            start_time=time.time()
        )

        with self._lock:
            self._spans[span_id] = span

        return span

    def finish_span(self, span_id: str, status: str = "completed", error: Optional[str] = None) -> None:
        """Finalize span: persist terminal status and error payload."""
        with self._lock:
            if span_id in self._spans:
                self._spans[span_id].finish(status, error)

    def get_span(self, span_id: str) -> Optional[TraceSpan]:
        # span_id → span lookup.
        with self._lock:
            return self._spans.get(span_id)

    def clear_spans(self) -> None:
        # Purge all cached spans.
        with self._lock:
            self._spans.clear()

    def export_trace(self, trace_id: str) -> List[Dict[str, Any]]:
        # Filter and export spans matching trace_id.
        with self._lock:
            spans = [
                self._span_to_dict(span)
                for span in self._spans.values()
                if span.trace_id == trace_id
            ]
        return spans

    def _span_to_dict(self, span: TraceSpan) -> Dict[str, Any]:
        return {
            "span_id": span.span_id,
            "trace_id": span.trace_id,
            "parent_span_id": span.parent_span_id,
            "name": span.name,
            "span_type": span.span_type.value,
            "start_time": span.start_time,
            "end_time": span.end_time,
            "duration": span.duration,
            "status": span.status,
            "attributes": span.attributes,
            "events": span.events,
            "error": span.error
        }

    @staticmethod
    def _generate_trace_id() -> str:
        # UUIDv4 — unique trace identifier.
        return str(uuid.uuid4())

    @staticmethod
    def _generate_span_id() -> str:
        # UUIDv4 first 16 chars — span identifier.
        return str(uuid.uuid4()[:16])

class StructuredLogger:
    """
    StructuredLogger: structured log output wrapper with automatic trace metadata injection.
    """

    def __init__(self, name: str, exporter: Optional[LogExporter] = None):
        self._logger = logging.getLogger(name)
        self._exporter = exporter

    def _log(self, level: LogLevel, message: str, **kwargs) -> None:
        # Unified log write: build entry, inject trace context, trigger export.
        log_entry = {
            "timestamp": time.time(),
            "level": level.value,
            "message": message,
            "logger_name": self._logger.name,
            "attributes": kwargs
        }

        current_context = get_current_trace_context()
        if current_context:
            log_entry["trace_id"] = current_context.trace_id
            log_entry["span_id"] = current_context.span_id
            if current_context.analysis_id:
                log_entry["analysis_id"] = current_context.analysis_id

        if self._exporter:
            self._exporter.export(log_entry)

        log_method = getattr(self._logger, level.value.lower())

        log_method(message, extra={"structured": log_entry})

    def debug(self, message: str, **kwargs) -> None:
        # DEBUG severity.
        self._log(LogLevel.DEBUG, message, **kwargs)

    def info(self, message: str, **kwargs) -> None:
        # INFO severity.
        self._log(LogLevel.INFO, message, **kwargs)

    def warning(self, message: str, **kwargs) -> None:
        # WARNING severity.
        self._log(LogLevel.WARNING, message, **kwargs)

    def error(self, message: str, **kwargs) -> None:
        # ERROR severity.
        self._log(LogLevel.ERROR, message, **kwargs)

    def critical(self, message: str, **kwargs) -> None:
        # CRITICAL severity.
        self._log(LogLevel.CRITICAL, message, **kwargs)

class TraceContextManager:
    """
    TraceContextManager: context-manager wrapper — automatic trace context lifecycle.
    """

    def __init__(self, trace_manager: TraceManager, **kwargs):
        self._trace_manager = trace_manager
        self._kwargs = kwargs
        self._context = None

    def __enter__(self) -> TraceContext:
        # Build context; set as active thread context.
        self._context = self._trace_manager.create_trace_context(**self._kwargs)
        return self._context

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        # Exit: release context binding; no additional cleanup.
        pass

class SpanContextManager:
    """
    SpanContextManager: context-manager wrapper — automatic span lifecycle.
    """

    def __init__(self, trace_manager: TraceManager, name: str, span_type: SpanType):
        self._trace_manager = trace_manager
        self._name = name
        self._span_type = span_type
        self._span = None

    def __enter__(self) -> TraceSpan:
        # Build span; bind to current context.
        self._span = self._trace_manager.create_span(self._name, self._span_type)
        return self._span

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit: mark as failed on exception, complete otherwise."""
        if self._span:
            if exc_val:
                self._trace_manager.finish_span(
                    self._span.span_id,
                    status="failed",
                    error=str(exc_val)
                )
            else:
                self._trace_manager.finish_span(self._span.span_id)

# Global singleton TraceManager instance.
_global_trace_manager: Optional[TraceManager] = None

def get_trace_manager() -> TraceManager:
    # Return global singleton; lazy-initialize on first access.
    global _global_trace_manager
    if _global_trace_manager is None:
        _global_trace_manager = TraceManager()
    return _global_trace_manager

def get_current_trace_context() -> Optional[TraceContext]:
    # Current thread-bound TraceContext; None if absent.
    return get_trace_manager().get_current_context()

def start_trace(analysis_id: Optional[str] = None, binary_path: Optional[str] = None) -> TraceContext:
    # Start a new trace.
    return get_trace_manager().create_trace_context(analysis_id, binary_path)

def end_trace() -> None:
    # End: purge all spans for the current trace.
    get_trace_manager().clear_spans()

def trace_function(span_type: SpanType = SpanType.FUNCTION):
    """
    Synchronous function trace decorator: auto-create span, finalize on success or exception.
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            trace_manager = get_trace_manager()
            span = trace_manager.create_span(func.__name__, span_type)
            try:
                result = func(*args, **kwargs)
                trace_manager.finish_span(span.span_id)
                return result
            except Exception as e:
                trace_manager.finish_span(span.span_id, status="failed", error=str(e))

                raise
        return wrapper
    return decorator

async def async_trace_function(span_type: SpanType = SpanType.FUNCTION):
    """
    Asynchronous function trace decorator: auto-create span, finalize on success or exception.
    """
    def decorator(func):
        async def wrapper(*args, **kwargs):
            trace_manager = get_trace_manager()
            span = trace_manager.create_span(func.__name__, span_type)
            try:
                result = await func(*args, **kwargs)
                trace_manager.finish_span(span.span_id)
                return result
            except Exception as e:
                trace_manager.finish_span(span.span_id, status="failed", error=str(e))

                raise
        return wrapper
    return decorator

def configure_structured_logging(output_path: Optional[str] = None, remote_endpoint: Optional[str] = None, log_level: str = "INFO") -> None:
    """
    Global initialization: inject StructuredFormatter, configure console/file handlers and exporter.
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper()))

    formatter = StructuredFormatter(include_trace=True, pretty_print=False)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    if output_path:
        file_handler = logging.FileHandler(output_path, encoding="utf-8")
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

    if remote_endpoint:
        exporter = LogExporter(remote_endpoint=remote_endpoint)

    logging.getLogger(__name__).info("structured logging system configured")

def get_structured_logger(name: str) -> StructuredLogger:
    # Obtain a StructuredLogger instance.
    return StructuredLogger(name)
