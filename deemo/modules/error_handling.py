import logging
import traceback
import sys
import json
from datetime import datetime
from typing import Dict, Any, Optional, Callable, Type, Tuple, List
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps

logger = logging.getLogger(__name__)


class ErrorSeverity(Enum):
    """错误严重程度枚举"""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class ErrorCategory(Enum):
    """错误分类枚举"""
    ANALYSIS = "analysis"
    PLUGIN = "plugin"
    SCHEDULER = "scheduler"
    CONFIG = "config"
    NETWORK = "network"
    RUNTIME = "runtime"
    SECURITY = "security"
    OTHER = "other"


@dataclass
class ErrorContext:
    """错误上下文信息"""
    task_id: Optional[str] = None
    analyzer_name: Optional[str] = None
    binary_path: Optional[str] = None
    function_name: Optional[str] = None
    arguments: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    severity: ErrorSeverity = ErrorSeverity.ERROR
    category: ErrorCategory = ErrorCategory.OTHER
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "analyzer_name": self.analyzer_name,
            "binary_path": self.binary_path,
            "function_name": self.function_name,
            "arguments": self.arguments,
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity.value,
            "category": self.category.value
        }


@dataclass
class ErrorRecord:
    """错误记录"""
    error_id: str
    exception: Exception
    context: ErrorContext
    stack_trace: str
    handled: bool = False
    recovery_action: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "error_id": self.error_id,
            "exception_type": type(self.exception).__name__,
            "exception_message": str(self.exception),
            "stack_trace": self.stack_trace,
            "context": self.context.to_dict(),
            "handled": self.handled,
            "recovery_action": self.recovery_action
        }


class ErrorHandler:
    """
    全局错误处理器
    
    负责：
    1. 捕获和记录异常
    2. 提供错误上下文信息
    3. 实现安全降级策略
    4. 支持错误恢复和重试
    """
    
    def __init__(self, max_errors: int = 1000):
        """
        初始化错误处理器
        
        Args:
            max_errors: 最大错误记录数
        """
        self.errors: Dict[str, ErrorRecord] = {}
        self.max_errors = max_errors
        self.error_count = 0
    
    def capture_exception(
        self,
        exception: Exception,
        context: Optional[ErrorContext] = None,
        handled: bool = False,
        recovery_action: Optional[str] = None
    ) -> str:
        """
        捕获异常并记录
        
        Args:
            exception: 异常对象
            context: 错误上下文
            handled: 是否已处理
            recovery_action: 恢复操作描述
            
        Returns:
            错误ID
        """
        error_id = self._generate_error_id()
        
        stack_trace = traceback.format_exc()
        
        if context is None:
            context = ErrorContext()
        
        record = ErrorRecord(
            error_id=error_id,
            exception=exception,
            context=context,
            stack_trace=stack_trace,
            handled=handled,
            recovery_action=recovery_action
        )
        
        self.errors[error_id] = record
        self.error_count += 1
        
        if self.error_count > self.max_errors:
            self._cleanup_old_errors()
        
        self._log_error(record)
        
        return error_id
    
    def _generate_error_id(self) -> str:
        """生成唯一错误ID"""
        timestamp = datetime.now().isoformat()
        import hashlib
        return hashlib.sha256(f"{timestamp}_{self.error_count}".encode()).hexdigest()[:16]
    
    def _cleanup_old_errors(self) -> None:
        """清理旧错误记录"""
        if len(self.errors) <= self.max_errors:
            return
        
        sorted_errors = sorted(
            self.errors.items(),
            key=lambda x: x[1].context.timestamp
        )
        
        to_remove = [error_id for error_id, _ in sorted_errors[:-self.max_errors]]
        
        for error_id in to_remove:
            del self.errors[error_id]
    
    def _log_error(self, record: ErrorRecord) -> None:
        """记录错误日志"""
        severity = record.context.severity
        
        log_message = f"[Error {record.error_id}] {type(record.exception).__name__}: {record.exception}"
        
        if record.context.task_id:
            log_message += f" | Task: {record.context.task_id}"
        if record.context.analyzer_name:
            log_message += f" | Analyzer: {record.context.analyzer_name}"
        if record.context.binary_path:
            log_message += f" | Binary: {record.context.binary_path}"
        
        if severity == ErrorSeverity.CRITICAL:
            logger.critical(log_message)
        elif severity == ErrorSeverity.ERROR:
            logger.error(log_message)
        elif severity == ErrorSeverity.WARNING:
            logger.warning(log_message)
        elif severity == ErrorSeverity.INFO:
            logger.info(log_message)
        else:
            logger.debug(log_message)
        
        if not record.handled:
            logger.debug(f"Stack trace:\n{record.stack_trace}")
    
    def get_error(self, error_id: str) -> Optional[ErrorRecord]:
        """获取错误记录"""
        return self.errors.get(error_id)
    
    def get_errors_by_category(self, category: ErrorCategory) -> List[ErrorRecord]:
        """按分类获取错误记录"""
        return [
            record for record in self.errors.values()
            if record.context.category == category
        ]
    
    def get_errors_by_severity(self, severity: ErrorSeverity) -> List[ErrorRecord]:
        """按严重程度获取错误记录"""
        return [
            record for record in self.errors.values()
            if record.context.severity == severity
        ]
    
    def get_unhandled_errors(self) -> List[ErrorRecord]:
        """获取未处理的错误"""
        return [
            record for record in self.errors.values()
            if not record.handled
        ]
    
    def mark_as_handled(self, error_id: str, recovery_action: Optional[str] = None) -> bool:
        """标记错误为已处理"""
        if error_id in self.errors:
            self.errors[error_id].handled = True
            if recovery_action:
                self.errors[error_id].recovery_action = recovery_action
            return True
        return False
    
    def generate_report(self) -> str:
        """生成错误报告"""
        lines = [
            "# 错误报告",
            "",
            f"**生成时间**: {datetime.now().isoformat()}",
            f"**总错误数**: {self.error_count}",
            f"**当前记录数**: {len(self.errors)}",
            "",
            "## 错误统计",
            ""
        ]
        
        category_counts = {}
        severity_counts = {}
        
        for record in self.errors.values():
            category = record.context.category.value
            severity = record.context.severity.value
            
            category_counts[category] = category_counts.get(category, 0) + 1
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        lines.append("### 按分类统计")
        lines.append("")
        lines.append("| 分类 | 数量 |")
        lines.append("|------|------|")
        for category, count in category_counts.items():
            lines.append(f"| {category} | {count} |")
        
        lines.append("")
        lines.append("### 按严重程度统计")
        lines.append("")
        lines.append("| 严重程度 | 数量 |")
        lines.append("|----------|------|")
        for severity, count in severity_counts.items():
            lines.append(f"| {severity} | {count} |")
        
        unhandled_count = len(self.get_unhandled_errors())
        lines.append("")
        lines.append(f"**未处理错误**: {unhandled_count}")
        
        return "\n".join(lines)
    
    def export_errors(self, path: str) -> bool:
        """导出错误记录到文件"""
        try:
            errors_data = {
                error_id: record.to_dict()
                for error_id, record in self.errors.items()
            }
            
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(errors_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"错误记录已导出到: {path}")
            return True
        except Exception as e:
            logger.error(f"导出错误记录失败: {e}")
            return False


def error_handler_decorator(
    category: ErrorCategory = ErrorCategory.OTHER,
    severity: ErrorSeverity = ErrorSeverity.ERROR,
    handle_errors: bool = True,
    recovery_action: Optional[str] = None
) -> Callable:
    """
    错误处理装饰器
    
    Args:
        category: 错误分类
        severity: 错误严重程度
        handle_errors: 是否自动处理错误
        recovery_action: 默认恢复操作
    
    Returns:
        装饰后的函数
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            handler = get_error_handler()
            
            context = ErrorContext(
                severity=severity,
                category=category
            )
            
            try:
                return func(*args, **kwargs)
            except Exception as e:
                error_id = handler.capture_exception(
                    e,
                    context=context,
                    handled=handle_errors,
                    recovery_action=recovery_action
                )
                
                if handle_errors:
                    logger.warning(f"自动处理错误 {error_id}: {e}")
                    
                    if recovery_action:
                        logger.info(f"执行恢复操作: {recovery_action}")
                    
                    return None
                else:
                    raise
        
        return wrapper
    return decorator


def with_error_context(**context_kwargs) -> Callable:
    """
    设置错误上下文装饰器
    
    Args:
        **context_kwargs: 上下文参数
    
    Returns:
        装饰后的函数
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            handler = get_error_handler()
            
            context = ErrorContext(**context_kwargs)
            
            try:
                return func(*args, **kwargs)
            except Exception as e:
                handler.capture_exception(e, context=context)
                raise
        
        return wrapper
    return decorator


class ErrorHandlingContext:
    """
    错误处理上下文管理器
    
    提供上下文感知的错误捕获
    """
    
    def __init__(self, **context_kwargs):
        self.context = ErrorContext(**context_kwargs)
        self.error_handler = get_error_handler()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self.error_handler.capture_exception(
                exc_val,
                context=self.context,
                handled=True
            )
            return True
        return False


def get_error_handler() -> ErrorHandler:
    """获取全局错误处理器实例"""
    global _error_handler
    if _error_handler is None:
        _error_handler = ErrorHandler()
    return _error_handler


# Global error handler instance (Python 3.7 compatible - no type annotation on global)
_error_handler = None  # type: Optional[ErrorHandler]


class SafeExecution:
    """
    安全执行包装器
    
    提供安全降级策略，确保单个任务失败不会影响整个分析流程
    """
    
    @staticmethod
    def execute(
        func: Callable,
        *args,
        fallback: Any = None,
        context: Optional[ErrorContext] = None,
        **kwargs
    ) -> Tuple[Any, bool]:
        """
        安全执行函数
        
        Args:
            func: 要执行的函数
            *args: 位置参数
            fallback: 降级返回值
            context: 错误上下文
            **kwargs: 关键字参数
            
        Returns:
            (结果, 是否成功)
        """
        try:
            result = func(*args, **kwargs)
            return result, True
        except Exception as e:
            handler = get_error_handler()
            
            if context is None:
                context = ErrorContext(
                    severity=ErrorSeverity.ERROR,
                    category=ErrorCategory.RUNTIME
                )
            
            handler.capture_exception(e, context=context, handled=True)
            
            logger.warning(f"安全降级: {func.__name__} 失败，使用降级值")
            
            return fallback, False
    
    @staticmethod
    async def execute_async(
        func: Callable,
        *args,
        fallback: Any = None,
        context: Optional[ErrorContext] = None,
        **kwargs
    ) -> Tuple[Any, bool]:
        """
        异步安全执行函数
        
        Args:
            func: 要执行的异步函数
            *args: 位置参数
            fallback: 降级返回值
            context: 错误上下文
            **kwargs: 关键字参数
            
        Returns:
            (结果, 是否成功)
        """
        try:
            result = await func(*args, **kwargs)
            return result, True
        except Exception as e:
            handler = get_error_handler()
            
            if context is None:
                context = ErrorContext(
                    severity=ErrorSeverity.ERROR,
                    category=ErrorCategory.RUNTIME
                )
            
            handler.capture_exception(e, context=context, handled=True)
            
            logger.warning(f"安全降级(异步): {func.__name__} 失败，使用降级值")
            
            return fallback, False


class RetryHandler:
    """
    重试处理器
    
    支持带退避策略的重试机制
    """
    
    def __init__(
        self,
        max_retries: int = 3,
        backoff_factor: float = 1.0,
        retry_on_exceptions: Tuple[Type[Exception], ...] = (Exception,)
    ):
        """
        初始化重试处理器
        
        Args:
            max_retries: 最大重试次数
            backoff_factor: 退避因子
            retry_on_exceptions: 需要重试的异常类型
        """
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.retry_on_exceptions = retry_on_exceptions
    
    def execute(
        self,
        func: Callable,
        *args,
        context: Optional[ErrorContext] = None,
        **kwargs
    ) -> Tuple[Any, bool]:
        """
        执行带重试的函数
        
        Args:
            func: 要执行的函数
            *args: 位置参数
            context: 错误上下文
            **kwargs: 关键字参数
            
        Returns:
            (结果, 是否成功)
        """
        import time
        
        last_exception = None
        
        for attempt in range(self.max_retries + 1):
            try:
                result = func(*args, **kwargs)
                if attempt > 0:
                    logger.info(f"重试成功: {func.__name__} (尝试 {attempt})")
                return result, True
            except Exception as e:
                last_exception = e
                
                if not isinstance(e, self.retry_on_exceptions):
                    raise
                
                if attempt < self.max_retries:
                    delay = self.backoff_factor * (2 ** attempt)
                    logger.warning(f"{func.__name__} 失败 (尝试 {attempt}/{self.max_retries})，{delay:.1f}秒后重试: {e}")
                    time.sleep(delay)
                else:
                    logger.error(f"{func.__name__} 最终失败: {e}")
        
        handler = get_error_handler()
        if context is None:
            context = ErrorContext()
        
        handler.capture_exception(last_exception, context=context, handled=True)
        
        return None, False
