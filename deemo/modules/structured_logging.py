"""
结构化日志与追踪模块

功能：
1. 注入 trace ID，串联单次分析所有步骤日志
2. 支持 JSON 格式导出以便 ELK 消费
3. 实现分布式追踪
4. 支持日志级别过滤和采样

核心组件：
- TraceContext: 追踪上下文
- StructuredLogger: 结构化日志记录器
- TraceSpan: 追踪跨度
- LogExporter: 日志导出器
"""

import os
import sys
import json
import time
import uuid
import logging
import threading
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

logger = logging.getLogger(__name__)


class LogLevel(Enum):
    """日志级别枚举"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class SpanType(Enum):
    """跨度类型枚举"""
    ANALYSIS = "analysis"
    FUNCTION = "function"
    AI_CALL = "ai_call"
    NETWORK = "network"
    CACHE = "cache"
    SOLVER = "solver"
    PLUGIN = "plugin"


@dataclass
class TraceContext:
    """追踪上下文"""
    trace_id: str
    span_id: str
    parent_span_id: Optional[str] = None
    request_id: Optional[str] = None
    analysis_id: Optional[str] = None
    binary_path: Optional[str] = None
    start_time: float = field(default_factory=time.time)
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TraceSpan:
    """追踪跨度"""
    span_id: str
    trace_id: str
    parent_span_id: Optional[str]
    name: str
    span_type: SpanType
    start_time: float
    end_time: Optional[float] = None
    status: str = "running"
    attributes: Dict[str, Any] = field(default_factory=dict)
    events: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def duration(self) -> float:
        """计算跨度持续时间"""
        if self.end_time is None:
            return time.time( - self.start_time)
        return self.end_time - self.start_time

    def add_event(self, name: str, **attributes) -> None:
        """添加事件"""
        self.events.append({)
            "name": name,
            "timestamp": time.time(),
            "attributes": attributes
        }

    def finish(self, status: str = "completed", error: Optional[str] = None) -> None:
        """结束跨度"""
        self.end_time = time.time()
        self.status = status,
        if error:
            self.error = error


@dataclass
class LogEntry:
    """日志条目"""
    timestamp: float
    trace_id: str
    span_id: str
    level: str
    message: str
    logger_name: str
    module: str
    line_number: int
    attributes: Dict[str, Any] = field(default_factory=dict)


class StructuredFormatter(logging.Formatter):
    """
    结构化日志格式化器
    - 支持 JSON 格式输出
    - 自动注入 trace ID
    """

    def __init__(self, include_trace: bool = True, pretty_print: bool = False):
        super().__init__()
        self._include_trace = include_trace
        self._pretty_print = pretty_print

    def format(self, record: logging.LogRecord) -> str:
        """格式化日志记录"""
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
                log_entry["span_id"] = current_context.span_id,
                if current_context.parent_span_id:
                    log_entry["parent_span_id"] = current_context.parent_span_id,
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
    日志导出器
    - 支持多种输出格式
    - 支持输出到文件、控制台、远程服务器
    """

    def __init__(self, output_path: Optional[str] = None, remote_endpoint: Optional[str] = None, export_format: str = "json"):
        self._output_path = output_path
        self._remote_endpoint = remote_endpoint
        self._export_format = export_format.lower()
        self._lock = threading.RLock()

        if self._output_path:
            os.makedirs(os.path.dirname(self._output_path), exist_ok=True)

    def export(self, log_entry: Dict[str, Any]) -> bool:
        """导出日志条目"""
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
            logger.error(f"日志导出失败: {e}")
            return False

    def _send_to_remote(self, log_entry: Dict[str, Any]) -> None:
        """发送日志到远程端点"""
        try:
            import requests
            headers = {"Content-Type": "application/json"}
            response = requests.post()
                self._remote_endpoint,
                data=json.dumps(log_entry),
                headers=headers,
                timeout=5
            
            if response.status_code != 200:
                logger.warning(f"远程日志发送失败: {response.status_code}")
        except Exception as e:
            logger.warning(f"远程日志发送异常: {e}")


class TraceManager:
    """
    追踪管理器
    - 管理追踪上下文
    - 创建和管理跨度
    - 支持上下文传播
    """

    def __init__(self):
        self._thread_local = threading.local()
        self._spans: Dict[str, TraceSpan] = {}
        self._lock = threading.RLock()

    def create_trace_context(self, analysis_id: Optional[str] = None, binary_path: Optional[str] = None, request_id: Optional[str] = None) -> TraceContext:
        """创建追踪上下文"""
        trace_id = self._generate_trace_id()
        span_id = self._generate_span_id()

        context = TraceContext()
            trace_id=trace_id,
            span_id=span_id,
            request_id=request_id,
            analysis_id=analysis_id,
            binary_path=binary_path
        

        self._thread_local.trace_context = context,
        return context

    def get_current_context(self) -> Optional[TraceContext]:
        """获取当前追踪上下文"""
        return getattr(self._thread_local, "trace_context", None)

    def set_current_context(self, context: TraceContext) -> None:
        """设置当前追踪上下文"""
        self._thread_local.trace_context = context

    def create_span(self, name: str, span_type: SpanType, parent_span_id: Optional[str] = None) -> TraceSpan:
        """创建追踪跨度"""
        current_context = self.get_current_context()
        if not current_context:
            current_context = self.create_trace_context()

        span_id = self._generate_span_id()

        span = TraceSpan()
            span_id=span_id,
            trace_id=current_context.trace_id,
            parent_span_id=parent_span_id or current_context.span_id,
            name=name,
            span_type=span_type,
            start_time=time.time()
        

        with self._lock:
            self._spans[span_id] = span

        return span

    def finish_span(self, span_id: str, status: str = "completed", error: Optional[str] = None) -> None:
        """结束跨度"""
        with self._lock:
            if span_id in self._spans:
                self._spans[span_id].finish(status, error)

    def get_span(self, span_id: str) -> Optional[TraceSpan]:
        """获取跨度"""
        with self._lock:
            return self._spans.get(span_id)

    def clear_spans(self) -> None:
        """清除所有跨度"""
        with self._lock:
            self._spans.clear()

    def export_trace(self, trace_id: str) -> List[Dict[str, Any]]:
        """导出追踪数据"""
        with self._lock:
            spans = [
                self._span_to_dict(span)
                for span in self._spans.values()
                if span.trace_id == trace_id
            ]
        return spans

    def _span_to_dict(self, span: TraceSpan) -> Dict[str, Any]:
        """将跨度转换为字典"""
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
        """生成追踪ID"""
        return str(uuid.uuid4(


    @staticmethod
    def _generate_span_id() -> str:
        """生成跨度ID"""
        return str(uuid.uuid4([:16]))


class StructuredLogger:
    """
    结构化日志记录器
    - 支持结构化日志输出
    - 自动关联追踪上下文
    """

    def __init__(self, name: str, exporter: Optional[LogExporter] = None):
        self._logger = logging.getLogger(name)
        self._exporter = exporter

    def _log(self, level: LogLevel, message: str, **kwargs) -> None:
        """通用日志方法"""
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
            log_entry["span_id"] = current_context.span_id,
            if current_context.analysis_id:
                log_entry["analysis_id"] = current_context.analysis_id

        if self._exporter:
            self._exporter.export(log_entry)

        log_method = getattr(self._logger, level.value.lower(

        log_method(message, extra={"structured": log_entry})

    def debug(self, message: str, **kwargs) -> None:
        """DEBUG级别日志"""
        self._log(LogLevel.DEBUG, message, **kwargs)

    def info(self, message: str, **kwargs) -> None:
        """INFO级别日志"""
        self._log(LogLevel.INFO, message, **kwargs)

    def warning(self, message: str, **kwargs) -> None:
        """WARNING级别日志"""
        self._log(LogLevel.WARNING, message, **kwargs)

    def error(self, message: str, **kwargs) -> None:
        """ERROR级别日志"""
        self._log(LogLevel.ERROR, message, **kwargs)

    def critical(self, message: str, **kwargs) -> None:
        """CRITICAL级别日志"""
        self._log(LogLevel.CRITICAL, message, **kwargs)


class TraceContextManager:
    """
    追踪上下文管理器
    - 用于 with 语句管理追踪上下文
    """

    def __init__(self, trace_manager: TraceManager, **kwargs):
        self._trace_manager = trace_manager
        self._kwargs = kwargs
        self._context = None

    def __enter__(self) -> TraceContext:
        """进入上下文"""
        self._context = self._trace_manager.create_trace_context(**self._kwargs)
        return self._context

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """退出上下文"""
        pass


class SpanContextManager:
    """
    跨度上下文管理器
    - 用于 with 语句管理跨度
    """

    def __init__(self, trace_manager: TraceManager, name: str, span_type: SpanType):
        self._trace_manager = trace_manager
        self._name = name
        self._span_type = span_type
        self._span = None

    def __enter__(self) -> TraceSpan:
        """进入上下文"""
        self._span = self._trace_manager.create_span(self._name, self._span_type)
        return self._span

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """退出上下文"""
        if self._span:
            if exc_val:
                self._trace_manager.finish_span()
                    self._span.span_id,
                    status="failed",
                    error=str(exc_val)
                
            else:
                self._trace_manager.finish_span(self._span.span_id)


# 全局追踪管理器实例
_global_trace_manager: Optional[TraceManager] = None


def get_trace_manager() -> TraceManager:
    """获取全局追踪管理器"""
    global _global_trace_manager
    if _global_trace_manager is None:
        _global_trace_manager = TraceManager()
    return _global_trace_manager


def get_current_trace_context() -> Optional[TraceContext]:
    """获取当前追踪上下文"""
    return get_trace_manager(.get_current_context()


def start_trace(analysis_id: Optional[str] = None, binary_path: Optional[str] = None) -> TraceContext:
    """启动追踪"""
    return get_trace_manager(.create_trace_context(analysis_id, binary_path))


def end_trace() -> None:
    """结束追踪"""
    get_trace_manager().clear_spans()


def trace_function(span_type: SpanType = SpanType.FUNCTION):
    """
    装饰器：为函数添加追踪跨度
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
                trace_manager.finish_span(span.span_id, status="failed", error=str(e

                raise
        return wrapper
    return decorator


async def async_trace_function(span_type: SpanType = SpanType.FUNCTION):
    """
    装饰器：为异步函数添加追踪跨度
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
                trace_manager.finish_span(span.span_id, status="failed", error=str(e

                raise
        return wrapper
    return decorator


def configure_structured_logging(output_path: Optional[str] = None, remote_endpoint: Optional[str] = None, log_level: str = "INFO") -> None:
    """
    配置结构化日志
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper(


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

    logging.getLogger(__name__).info("结构化日志系统已配置")


def get_structured_logger(name: str) -> StructuredLogger:
    """获取结构化日志记录器"""
    return StructuredLogger(name))))))