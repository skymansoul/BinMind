#!/usr/bin/env python3
import os, sys, json, time, uuid, logging, threading
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from enum import Enum

log = logging.getLogger(__name__)

class LogLevel(str, Enum): DEBUG = "DEBUG"; INFO = "INFO"; WARNING = "WARNING"; ERROR = "ERROR"; CRITICAL = "CRITICAL"
class SpanType(Enum): ANALYSIS="analysis"; FUNCTION="function"; AI_CALL="ai_call"; NETWORK="network"; CACHE="cache"; SOLVER="solver"; PLUGIN="plugin"

@dataclass
class TraceContext:
    trace_id: str = ""; span_id: str = ""
    parent_span_id: Optional[str] = None; request_id: Optional[str] = None
    analysis_id: Optional[str] = None; binary_path: Optional[str] = None
    start_time: float = field(default_factory=time.time)
    attributes: dict = field(default_factory=dict)

class TraceSpan:
    __slots__ = ('span_id','trace_id','parent_span_id','name','span_type','start_time',
                 'end_time','status','attributes','events','error',)
    def __init__(self, span_id, trace_id, parent_span_id, name, span_type,
                 start_time, end_time=None, status="running",
                 attributes=None, events=None, error=None):
        self.span_id = span_id; self.trace_id = trace_id
        self.parent_span_id = parent_span_id; self.name = name
        self.span_type = span_type; self.start_time = start_time
        self.end_time = end_time; self.status = status
        self.attributes = attributes if attributes is not None else {}
        self.events = events if events is not None else []; self.error = error
    @property
    def duration(self) -> float:
        if self.end_time is None: return time.time() - self.start_time
        return self.end_time - self.start_time
    def add_event(self, name: str, **attributes):
        self.events.append({"name": name, "timestamp": time.time(), "attributes": attributes})
    def finish(self, status: str = "completed", error: Optional[str] = None):
        self.end_time = time.time(); self.status = status
        if error: self.error = error

class StructuredFormatter(logging.Formatter):
    def __init__(self, include_trace: bool = True, pretty_print: bool = False):
        super().__init__(); self._include_trace = include_trace; self._pretty_print = pretty_print
    def format(self, record: logging.LogRecord) -> str:
        entry = {"timestamp": record.created, "level": record.levelname,
                 "message": record.getMessage(), "logger_name": record.name,
                 "module": record.module, "line_number": record.lineno,
                 "process_id": record.process, "thread_id": record.thread,
                 "source": f"{record.pathname}:{record.lineno}"}
        if self._include_trace:
            ctx = get_current_trace_context()
            if ctx:
                entry["trace_id"] = ctx.trace_id; entry["span_id"] = ctx.span_id
                if ctx.parent_span_id: entry["parent_span_id"] = ctx.parent_span_id
                if ctx.analysis_id: entry["analysis_id"] = ctx.analysis_id
        if record.exc_info: entry["exception"] = self.formatException(record.exc_info)
        if self._pretty_print: return json.dumps(entry, indent=2, ensure_ascii=False)
        return json.dumps(entry, ensure_ascii=False)

class LogExporter:
    def __init__(self, output_path=None, remote_endpoint=None, export_format="json"):
        self._output_path = output_path; self._remote_endpoint = remote_endpoint
        self._export_format = export_format.lower(); self._lock = threading.RLock()
        self._success_count = 0; self._fail_count = 0
        if self._output_path: os.makedirs(os.path.dirname(self._output_path), exist_ok=True)

    def export(self, log_entry: Dict[str, Any]) -> bool:
        try:
            log_str = json.dumps(log_entry, ensure_ascii=False) + "\n" if self._export_format == "json" else f"{log_entry}\n"
            if self._output_path:
                with self._lock:
                    with open(self._output_path, "a", encoding="utf-8") as f: f.write(log_str)
            self._success_count += 1; return True
        except Exception as e:
            self._fail_count += 1; return False

    def stats(self) -> Dict[str, int]:
        return {'success': self._success_count, 'fail': self._fail_count}

class TraceManager:
    def __init__(self):
        self._thread_local = threading.local(); self._spans: Dict[str, TraceSpan] = {}
        self._lock = threading.RLock()
    def create_trace_context(self, **kwargs) -> TraceContext:
        ctx = TraceContext(trace_id=str(uuid.uuid4()), span_id=str(uuid.uuid4())[:16], **kwargs)
        self._thread_local.trace_context = ctx; return ctx
    def get_current_context(self) -> Optional[TraceContext]:
        return getattr(self._thread_local, "trace_context", None)
    def create_span(self, name: str, span_type: SpanType, parent_span_id=None) -> TraceSpan:
        ctx = self.get_current_context()
        if not ctx: ctx = self.create_trace_context()
        span = TraceSpan(span_id=str(uuid.uuid4())[:16], trace_id=ctx.trace_id,
                         parent_span_id=parent_span_id or ctx.span_id,
                         name=name, span_type=span_type, start_time=time.time())
        with self._lock: self._spans[span.span_id] = span
        return span
    def finish_span(self, span_id: str, status="completed", error=None):
        with self._lock:
            if span_id in self._spans: self._spans[span_id].finish(status, error)
    def clear_spans(self):
        with self._lock: self._spans.clear()
    def export_otel_trace(self, trace_id: str) -> List[Dict]:
        """导出为 OpenTelemetry 兼容格式——span 属性映射到 OTel semantic conventions。"""
        with self._lock:
            otel_spans = []
            for span in self._spans.values():
                if span.trace_id != trace_id: continue
                otel_spans.append({
                    "traceId": span.trace_id, "spanId": span.span_id,
                    "parentSpanId": span.parent_span_id or "",
                    "name": span.name, "kind": "INTERNAL",
                    "startTimeUnixNano": str(int(span.start_time * 1e9)),
                    "endTimeUnixNano": str(int((span.end_time or span.start_time) * 1e9)),
                    "status": {"code": 1 if span.error else 0,
                               "message": span.error or ""},
                    "attributes": [{"key": k, "value": {"stringValue": str(v)}}
                                   for k, v in span.attributes.items()],
                })
            return otel_spans

_global_trace_manager: Optional[TraceManager] = None

def get_trace_manager() -> TraceManager:
    global _global_trace_manager
    if _global_trace_manager is None: _global_trace_manager = TraceManager()
    return _global_trace_manager

def get_current_trace_context() -> Optional[TraceContext]:
    return get_trace_manager().get_current_context()

def configure_structured_logging(output_path=None, log_level="INFO"):
    root_logger = logging.getLogger(); root_logger.setLevel(getattr(logging, log_level.upper()))
    formatter = StructuredFormatter(include_trace=True, pretty_print=False)
    ch = logging.StreamHandler(sys.stdout); ch.setFormatter(formatter); root_logger.addHandler(ch)
    if output_path:
        fh = logging.FileHandler(output_path, encoding="utf-8")
        fh.setFormatter(formatter); root_logger.addHandler(fh)
