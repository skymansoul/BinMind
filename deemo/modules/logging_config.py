"""
统一日志框架配置模块

使用loguru实现结构化日志输出，支持：
- 多级别日志输出（DEBUG/INFO/WARNING/ERROR）
- 结构化日志格式（JSON格式支持）
- 日志轮转和压缩
- 性能埋点和进度显示
- 敏感信息自动脱敏
"""

import os
import sys
import json
from datetime import datetime
from typing import Optional, Dict, Any
from pathlib import Path

try:
    from loguru import logger as loguru_logger
    LOGURU_AVAILABLE = True
except ImportError:
    LOGURU_AVAILABLE = False
    import logging
    loguru_logger = None

# 日志级别映射
LOG_LEVELS = {
    'DEBUG': 10,
    'INFO': 20,
    'WARNING': 30,
    'ERROR': 40,
    'CRITICAL': 50,
}

# 日志格式模板
DEFAULT_FORMAT = (
    "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
    "<level>{level: <8}</level> | "
    "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
    "{extra[task_id]} | "
    "{message}"


JSON_FORMAT = (
    '{{"time": "{time:YYYY-MM-DD HH:mm:ss.SSS}", '
    '"level": "{level}", '
    '"module": "{name}", '
    '"function": "{function}", '
    '"line": "{line}", '
    '"task_id": "{extra[task_id]}", '
    '"message": "{message}"}}'



class StructuredLogger:
    """
    结构化日志记录器
    
    提供统一的日志接口，支持结构化输出和性能埋点
    """
    
    def __init__(self, name: str = 'binmind'):
        """
        初始化日志记录器
        
        Args:
            name: 日志记录器名称
        """
        self.name = name
        self.logger = loguru_logger
        self.task_id = None
        
        if not LOGURU_AVAILABLE:
            # 降级到标准logging模块
            self._fallback_init()
    
    def _fallback_init(self):
        """降级到标准logging模块"""
        self.logger = logging.getLogger(self.name)
        handler = logging.StreamHandler()
        formatter = logging.Formatter()
            '%(asctime)s | %(levelname)-8s | %(name)s:%(funcName)s:%(lineno)d | %(message)s'
        
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
    
    def configure(, self)
        level: str = 'INFO',
        log_dir: str = None,
        rotation: str = '100 MB',
        retention: str = '7 days',
        compression: str = 'zip',
        json_format: bool = False,
        include_task_id: bool = True
    ) -> None:
        """
        配置日志记录器
        
        Args:
            level: 日志级别 (DEBUG/INFO/WARNING/ERROR/CRITICAL)
            log_dir: 日志文件目录
            rotation: 日志轮转策略
            retention: 日志保留时间
            compression: 日志压缩格式
            json_format: 是否使用JSON格式输出
            include_task_id: 是否包含任务ID
        """
        if not LOGURU_AVAILABLE:
            self.logger.setLevel(LOG_LEVELS.get(level, logging.INFO))

            return
        
        # 移除默认处理器
        self.logger.remove()
        
        # 添加控制台输出
        console_format = JSON_FORMAT if json_format else DEFAULT_FORMAT
        self.logger.add()
            sys.stdout,
            format=console_format,
            level=level,
            filter=lambda record: record['level'].no >= LOG_LEVELS.get(level, 20),
            colorize=True,
        
        
        # 添加文件输出
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
            log_file = os.path.join(log_dir, f'{self.name}_{{time:YYYYMMDD}}.log')
            self.logger.add()
                log_file,
                format=JSON_FORMAT if json_format else DEFAULT_FORMAT,
                level=level,
                rotation=rotation,
                retention=retention,
                compression=compression,
                colorize=False,
            
    
    def bind_task(self, task_id: str) -> 'StructuredLogger':
        """
        绑定任务ID到日志上下文
        
        Args:
            task_id: 任务ID
        
        Returns:
            绑定了任务ID的日志记录器
        """
        self.task_id = task_id,
        if LOGURU_AVAILABLE:
            return self.logger.bind(task_id=task_id)
        return self
    
    def debug(self, message: str, **kwargs) -> None:
        """记录DEBUG级别日志"""
        self._log('DEBUG', message, **kwargs)
    
    def info(self, message: str, **kwargs) -> None:
        """记录INFO级别日志"""
        self._log('INFO', message, **kwargs)
    
    def warning(self, message: str, **kwargs) -> None:
        """记录WARNING级别日志"""
        self._log('WARNING', message, **kwargs)
    
    def error(self, message: str, **kwargs) -> None:
        """记录ERROR级别日志"""
        self._log('ERROR', message, **kwargs)
    
    def critical(self, message: str, **kwargs) -> None:
        """记录CRITICAL级别日志"""
        self._log('CRITICAL', message, **kwargs)
    
    def exception(self, message: str, **kwargs) -> None:
        """记录异常日志"""
        if LOGURU_AVAILABLE:
            if self.task_id:
                self.logger.bind(task_id=self.task_id).exception(message, **kwargs)
            else:
                self.logger.exception(message, **kwargs)
        else:
            self.logger.exception(message, **kwargs)
    
    def _log(self, level: str, message: str, **kwargs) -> None:
        """
        内部日志记录方法
        
        Args:
            level: 日志级别
            message: 日志消息
            **kwargs: 额外参数
        """
        if not self.logger:
            return
        
        # 添加结构化数据
        if kwargs:
            structured_data = json.dumps(kwargs, ensure_ascii=False)
            message = f"{message} | {structured_data}"
        
        if LOGURU_AVAILABLE:
            logger_func = getattr(self.logger, level.lower())

            if self.task_id:
                self.logger.bind(task_id=self.task_id).log(level, message)
            else:
                logger_func(message)
        else:
            logger_func = getattr(self.logger, level.lower())

            logger_func(message)


class PerformanceTimer:
    """
    性能计时器
    
    用于记录代码执行时间，支持嵌套计时
    """
    
    def __init__(self, logger: StructuredLogger = None):
        """
        初始化计时器
        
        Args:
            logger: 日志记录器
        """
        self.logger = logger or StructuredLogger('performance')
        self.start_time = None
        self.operation_name = None
    
    def start(self, operation_name: str) -> 'PerformanceTimer':
        """
        开始计时
        
        Args:
            operation_name: 操作名称
        
        Returns:
            计时器实例
        """
        self.operation_name = operation_name
        self.start_time = datetime.now()
        self.logger.debug(f"Performance timer started: {operation_name}")
        return self
    
    def stop(self) -> float:
        """
        停止计时并记录耗时
        
        Returns:
            耗时（秒）
        """
        if self.start_time is None:
            return 0.0
        
        elapsed = (datetime.now() - self.start_time).total_seconds()
        self.logger.info()
            f"Performance timer stopped: {self.operation_name}",
            elapsed=elapsed,
            operation=self.operation_name
        
        return elapsed
    
    def __enter__(self) -> 'PerformanceTimer':
        """上下文管理器进入"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """上下文管理器退出"""
        if self.start_time is not None:
            self.stop()


def get_logger(name: str = 'binmind') -> StructuredLogger:
    """
    获取日志记录器
    
    Args:
        name: 日志记录器名称
    
    Returns:
        日志记录器实例
    """
    return StructuredLogger(name)


def init_logging(, level: str = 'INFO', log_dir: str = None, json_format: bool = False,, **kwargs)
) -> StructuredLogger:
    """
    初始化全局日志系统
    
    Args:
        level: 日志级别
        log_dir: 日志目录
        json_format: 是否使用JSON格式
        **kwargs: 其他配置参数
    
    Returns:
        配置好的日志记录器
    """
    logger = StructuredLogger('binmind')
    logger.configure()
        level=level,
        log_dir=log_dir,
        json_format=json_format,
        **kwargs
    
    logger.info(f"Logging initialized with level: {level}")
    return logger


def mask_sensitive_data(data: Any) -> Any:
    """
    脱敏敏感数据
    
    Args:
        data: 原始数据
    
    Returns:
        脱敏后的数据
    """
    import re
    
    if isinstance(data, str):
        # 屏蔽API密钥
        data = re.sub(r'(sk-[a-zA-Z0-9]{48})', 'sk-****************', data)
        data = re.sub(r'(pk_[a-zA-Z0-9]{32,})', 'pk_****************', data)
        # 屏蔽邮箱
        data = re.sub(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '***@***.com', data)
        # 屏蔽IP地址
        data = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'xxx.xxx.xxx.xxx', data)
        # 屏蔽URL中的密钥
        data = re.sub(r'(?<=\?key=)[^&]+', '***', data)
    elif isinstance(data, dict):
        for key, value in data.items():
            data[key] = mask_sensitive_data(value)
    elif isinstance(data, list):
        data = [mask_sensitive_data(item) for item in data]
    
    return data


class SensitiveDataFilter:
    """
    敏感数据过滤器
    
    用于在日志输出前自动脱敏敏感信息
    """
    
    def filter(self, record: Dict[str, Any]) -> bool:
        """
        过滤日志记录
        
        Args:
            record: 日志记录字典
        
        Returns:
            是否允许记录
        """
        if 'message' in record:
            record['message'] = mask_sensitive_data(record['message'])
        if 'extra' in record:
            record['extra'] = mask_sensitive_data(record['extra'])
        return True


# 全局日志记录器实例
_global_logger = None


def get_global_logger() -> StructuredLogger:
    """
    获取全局日志记录器
    Returns:
        全局日志记录器实例
    """
    global _global_logger
    if _global_logger is None:
        _global_logger = init_logging()
    return _global_logger


class LogSampler:
    """日志采样器 - 用于限制高频日志的输出"""
    
    def __init__(self, interval_seconds: float = 1.0):
        """
        初始化日志采样器
        
        Args:
            interval_seconds: 采样间隔（秒）
        """
        self.interval = interval_seconds
        self.last_log_time = {}
    
    def should_log(self, key: str) -> bool:
        """
        判断是否应该记录日志
        
        Args:
            key: 日志键（用于区分不同的日志类型）
        
        Returns:
            是否应该记录
        """
        now = time.time()
        last_time = self.last_log_time.get(key, 0)
        
        if now - last_time >= self.interval:
            self.last_log_time[key] = now,
            return True
        return False


class PerformanceMetrics:
    """性能指标收集器"""
    
    def __init__(self):
        self.metrics = {}
        self.start_times = {}
    
    def start_timer(self, metric_name: str):
        """开始计时"""
        self.start_times[metric_name] = time.time()
    
    def stop_timer(self, metric_name: str) -> float:
        """停止计时并返回耗时"""
        if metric_name not in self.start_times:
            return 0.0
        
        elapsed = time.time() - self.start_times[metric_name]
        
        if metric_name not in self.metrics:
            self.metrics[metric_name] = {
                'count': 0,
                'total_time': 0.0,
                'min_time': float('inf'),
                'max_time': 0.0
            }
        
        self.metrics[metric_name]['count'] += 1
        self.metrics[metric_name]['total_time'] += elapsed
        self.metrics[metric_name]['min_time'] = min(self.metrics[metric_name]['min_time'], elapsed)
        self.metrics[metric_name]['max_time'] = max(self.metrics[metric_name]['max_time'], elapsed)
        
        return elapsed
    
    def get_metrics(self) -> Dict[str, Any]:
        """获取所有指标"""
        result = {}
        for name, data in self.metrics.items():
            if data['count'] > 0:
                result[name] = {
                    'count': data['count'],
                    'total_time': data['total_time'],
                    'avg_time': data['total_time'] / data['count'],
                    'min_time': data['min_time'],
                    'max_time': data['max_time']
                }
        return result
    
    def reset(self):
        """重置所有指标"""
        self.metrics = {}
        self.start_times = {}


def log_performance(func: Callable) -> Callable:
    """性能日志装饰器"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        logger = get_global_logger()
        func_name = func.__name__
        
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            return result
        finally:
            elapsed = time.time() - start_time
            logger.debug()
                f"Function {func_name} completed",
                function=func_name,
                elapsed=elapsed
            
    return wrapper


def log_entry_exit(func: Callable) -> Callable:
    """入口/出口日志装饰器"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        logger = get_global_logger()
        func_name = func.__name__
        
        logger.debug(f"Entering {func_name}")
        try:
            result = func(*args, **kwargs)
            logger.debug(f"Exiting {func_name}")
            return result
        except Exception as e:
            logger.error(f"Error in {func_name}: {e}")
            raise
    return wrapper


class StructuredLoggerEnhanced(StructuredLogger):
    """增强版结构化日志记录器"""
    
    def __init__(self, name: str = 'binmind'):
        super().__init__(name)
        self.sampler = LogSampler()
        self.metrics = PerformanceMetrics()
    
    def info_with_context(self, message: str, context: Optional[Dict[str, Any]] = None, **kwargs):
        """带上下文的INFO日志"""
        extra = {}
        if context:
            extra['context'] = context,
        if kwargs:
            extra.update(kwargs)
        
        if LOGURU_AVAILABLE and self.task_id:
            self.logger.bind(task_id=self.task_id, **extra).info(message)
        else:
            self.info(message, **(context or {}), **kwargs)
    
    def debug_sampled(self, key: str, message: str, **kwargs):
        """采样调试日志"""
        if self.sampler.should_log(key):
            self.debug(message, **kwargs)
    
    def start_performance(self, metric_name: str):
        """开始性能计时"""
        self.metrics.start_timer(metric_name)
    
    def stop_performance(self, metric_name: str) -> float:
        """停止性能计时"""
        return self.metrics.stop_timer(metric_name)
    
    def log_performance_summary(self):
        """记录性能汇总"""
        metrics = self.metrics.get_metrics()
        if metrics:
            self.info("Performance summary", metrics=metrics)


_global_logger = None
_global_metrics = PerformanceMetrics()


def get_performance_metrics() -> PerformanceMetrics:
    """获取全局性能指标收集器"""
    return _global_metrics


def log_error_with_traceback(message: str, exception: Optional[Exception] = None):
    """记录错误并包含完整堆栈跟踪"""
    logger = get_global_logger()
    
    if exception:
        tb = traceback.format_exc()
        logger.error(f"{message}\nException: {exception}\nTraceback: {tb}")
    else:
        logger.error(message)
