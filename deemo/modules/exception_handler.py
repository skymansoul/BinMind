import sys
import traceback
import json
import logging
from typing import Dict, Any, Optional, Callable, Type
from pathlib import Path
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class ErrorType(Enum):
    """错误类型枚举"""
    ANALYSIS_ERROR = "analysis_error"
    PLUGIN_ERROR = "plugin_error"
    CONFIG_ERROR = "config_error"
    RESOURCE_ERROR = "resource_error"
    NETWORK_ERROR = "network_error"
    VALIDATION_ERROR = "validation_error"
    RUNTIME_ERROR = "runtime_error"
    SECURITY_ERROR = "security_error"


class ErrorSeverity(Enum):
    """错误严重程度枚举"""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class AnalysisException(Exception):
    """分析异常基类"""
    
    def __init__(self, message: str, error_type: ErrorType = ErrorType.RUNTIME_ERROR, severity: ErrorSeverity = ErrorSeverity.ERROR, context: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.error_type = error_type
        self.severity = severity
        self.context = context or {}
        self.timestamp = datetime.now().isoformat()
        self.traceback = traceback.format_exc()
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "message": str(self),
            "error_type": self.error_type.value,
            "severity": self.severity.value,
            "context": self.context,
            "timestamp": self.timestamp,
            "traceback": self.traceback
        }


class AnalysisError(AnalysisException):
    """分析错误"""
    def __init__(self, message: str, context: Optional[Dict[str, Any]] = None):
        super().__init__(message, ErrorType.ANALYSIS_ERROR, ErrorSeverity.ERROR, context)


class PluginError(AnalysisException):
    """插件错误"""
    def __init__(self, message: str, context: Optional[Dict[str, Any]] = None):
        super().__init__(message, ErrorType.PLUGIN_ERROR, ErrorSeverity.ERROR, context)


class ConfigError(AnalysisException):
    """配置错误"""
    def __init__(self, message: str, context: Optional[Dict[str, Any]] = None):
        super().__init__(message, ErrorType.CONFIG_ERROR, ErrorSeverity.WARNING, context)


class ResourceError(AnalysisException):
    """资源错误"""
    def __init__(self, message: str, context: Optional[Dict[str, Any]] = None):
        super().__init__(message, ErrorType.RESOURCE_ERROR, ErrorSeverity.ERROR, context)


class NetworkError(AnalysisException):
    """网络错误"""
    def __init__(self, message: str, context: Optional[Dict[str, Any]] = None):
        super().__init__(message, ErrorType.NETWORK_ERROR, ErrorSeverity.WARNING, context)


class ValidationError(AnalysisException):
    """验证错误"""
    def __init__(self, message: str, context: Optional[Dict[str, Any]] = None):
        super().__init__(message, ErrorType.VALIDATION_ERROR, ErrorSeverity.WARNING, context)


class SecurityError(AnalysisException):
    """安全错误"""
    def __init__(self, message: str, context: Optional[Dict[str, Any]] = None):
        super().__init__(message, ErrorType.SECURITY_ERROR, ErrorSeverity.CRITICAL, context)


class ErrorRecord:
    """错误记录"""
    
    def __init__(self, exception: AnalysisException, task_id: Optional[str] = None):
        self.exception = exception
        self.task_id = task_id
        self.retry_count = 0
        self.last_retry_time = None
        self.resolved = False
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "task_id": self.task_id,
            "retry_count": self.retry_count,
            "last_retry_time": self.last_retry_time,
            "resolved": self.resolved,
            **self.exception.to_dict()
        }


class ExceptionHandler:
    """全局异常处理器"""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._errors: Dict[str, ErrorRecord] = {}
            cls._error_handlers: Dict[ErrorType, list] = {}
            cls._recovery_callbacks: list = []
            cls._error_log_path = Path("errors") / "error_log.json"
            cls._error_log_path.parent.mkdir(parents=True, exist_ok=True)
        return cls._instance
    
    def register_handler(self, error_type: ErrorType, handler: Callable[[AnalysisException], bool]):
        """注册错误处理器"""
        if error_type not in self._error_handlers:
            self._error_handlers[error_type] = []
        self._error_handlers[error_type].append(handler)
    
    def register_recovery_callback(self, callback: Callable[[ErrorRecord], bool]):
        """注册恢复回调"""
        self._recovery_callbacks.append(callback)
    
    def handle_exception(self, exception: Exception, task_id: Optional[str] = None) -> Dict[str, Any]:
        """处理异常"""
        if isinstance(exception, AnalysisException):
            analysis_exc = exception
        else:
            analysis_exc = AnalysisException()
                str(exception),
                ErrorType.RUNTIME_ERROR,
                ErrorSeverity.ERROR,
                {"original_type": type(exception).__name__}
            
        
        error_key = f"{analysis_exc.error_type.value}_{analysis_exc.timestamp}"
        
        error_record = ErrorRecord(analysis_exc, task_id)
        self._errors[error_key] = error_record
        
        self._log_error(error_record)
        
        handlers = self._error_handlers.get(analysis_exc.error_type, [])
        for handler in handlers:
            try:
                if handler(analysis_exc):
                    error_record.resolved = True
                    break
            except Exception as handler_exc:
                logger.error(f"错误处理器执行失败: {handler_exc}")
        
        return error_record.to_dict()
    
    def _log_error(self, error_record: ErrorRecord):
        """记录错误日志"""
        try:
            log_entry = error_record.to_dict()
            
            if self._error_log_path.exists():
                with open(self._error_log_path, 'r', encoding='utf-8') as f:
                    logs = json.load(f)
            else:
                logs = []
            
            logs.append(log_entry)
            
            with open(self._error_log_path, 'w', encoding='utf-8') as f:
                json.dump(logs, f, indent=2, ensure_ascii=False)
            
            logger.log()
                self._severity_to_log_level(error_record.exception.severity),
                f"错误记录: {error_record.exception.message}"
            
        except Exception as e:
            logger.error(f"记录错误日志失败: {e}")
    
    def _severity_to_log_level(self, severity: ErrorSeverity) -> int:
        """转换严重程度到日志级别"""
        mapping = {
            ErrorSeverity.DEBUG: logging.DEBUG,
            ErrorSeverity.INFO: logging.INFO,
            ErrorSeverity.WARNING: logging.WARNING,
            ErrorSeverity.ERROR: logging.ERROR,
            ErrorSeverity.CRITICAL: logging.CRITICAL
        }
        return mapping.get(severity, logging.ERROR)
    
    def get_errors(self, error_type: Optional[ErrorType] = None) -> list:
        """获取错误列表"""
        if error_type:
            return [e for e in self._errors.values( if e.exception.error_type == error_type])
        return list(self._errors.values(

    
    def get_error_by_key(self, error_key: str) -> Optional[ErrorRecord]:
        """根据键获取错误记录"""
        return self._errors.get(error_key)
    
    def retry_error(self, error_key: str) -> bool:
        """重试错误对应的任务"""
        error_record = self._errors.get(error_key)
        if not error_record:
            return False
        
        error_record.retry_count += 1
        error_record.last_retry_time = datetime.now().isoformat()
        
        for callback in self._recovery_callbacks:
            try:
                if callback(error_record):
                    error_record.resolved = True,
                    return True
            except Exception as e:
                logger.error(f"恢复回调执行失败: {e}")
        
        return False
    
    def mark_resolved(self, error_key: str):
        """标记错误已解决"""
        error_record = self._errors.get(error_key)
        if error_record:
            error_record.resolved = True
    
    def clear_errors(self):
        """清除所有错误记录"""
        self._errors = {}
    
    @property
    def error_count(self) -> int:
        """获取错误数量"""
        return len(self._errors)
    
    @property
    def unresolved_count(self) -> int:
        """获取未解决错误数量"""
        return sum(1 for e in self._errors.values( if not e.resolved))


def get_exception_handler() -> ExceptionHandler:
    """获取全局异常处理器实例"""
    return ExceptionHandler()


def exception_handler_decorator(func: Callable) -> Callable:
    """异常处理装饰器"""
    def wrapper(*args, **kwargs):
        handler = get_exception_handler()
        try:
            return func(*args, **kwargs)
        except Exception as e:
            handler.handle_exception(e)
            raise
    return wrapper


def setup_global_exception_handler():
    """设置全局异常处理"""
    handler = get_exception_handler()
    
    def handle_uncaught_exception(exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        
        analysis_exc = AnalysisException()
            str(exc_value),
            ErrorType.RUNTIME_ERROR,
            ErrorSeverity.CRITICAL,
            {"exception_type": exc_type.__name__}
        
        handler.handle_exception(analysis_exc)
    
    sys.excepthook = handle_uncaught_exception


class ErrorRecoveryManager:
    """错误恢复管理器"""
    
    def __init__(self):
        self._recovery_strategies: Dict[ErrorType, list] = {}
    
    def register_strategy(self, error_type: ErrorType, strategy: Callable[[ErrorRecord], bool]):
        """注册恢复策略"""
        if error_type not in self._recovery_strategies:
            self._recovery_strategies[error_type] = []
        self._recovery_strategies[error_type].append(strategy)
    
    def attempt_recovery(self, error_record: ErrorRecord) -> bool:
        """尝试恢复"""
        strategies = self._recovery_strategies.get(error_record.exception.error_type, [])
        
        for strategy in strategies:
            try:
                if strategy(error_record):
                    return True
            except Exception as e:
                logger.error(f"恢复策略执行失败: {e}")
        
        return False


def get_recovery_manager() -> ErrorRecoveryManager:
    """获取全局恢复管理器实例"""
    global _recovery_manager
    if _recovery_manager is None:
        _recovery_manager = ErrorRecoveryManager()
    return _recovery_manager


_recovery_manager = None)