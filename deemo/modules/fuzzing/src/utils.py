# — hermit1016: 深度重构, 提取共享工具函数

"""fuzzing 共享工具 — 重试装饰器 / 日志配置 / 路径规范化 / 时间戳.

本模块提供:
- retry_on_failure: 通用重试装饰器, 指数退避 + 抖动
- retry_subprocess: subprocess 调用专用重试
- retry_http: HTTP/LLM 调用专用重试
- setup_module_logging: 统一日志配置
- normalize_binary_path: 路径安全校验
- timestamp_now: ISO 8601 时间戳生成

所有重试装饰器在尝试耗尽后抛出原始异常 (不吞错误)。
"""

import functools
import logging
import os
import random
import subprocess
import time
from typing import Any, Callable, TypeVar


F = TypeVar("F", bound=Callable[..., Any])

# 模块级常量
_DEFAULT_RETRIES = 3
_DEFAULT_BACKOFF = 2.0    # 指数退避基数 (秒)
_DEFAULT_JITTER = 0.5     # 随机抖动范围 (±秒)
_MAX_BACKOFF = 60.0       # 最大退避上限


def timestamp_now() -> str:
    """返回 ISO 8601 格式的当前 UTC 时间戳.

    用于日志文件命名、崩溃发现时间标记等。
    """
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def normalize_binary_path(path: str) -> str:
    """安全地规范化二进制路径.

    规则:
    - 已绝对路径仅规范化分隔符，不注入当前盘符
    - 相对路径转为绝对路径
    - 拒绝空字符串
    - 记录警告但不抛异常 (让调用方决定是否可接受)
    """
    if not path or not path.strip():
        logging.getLogger("utils").warning("normalize_binary_path: 空路径")
        return ""
    try:
        expanded = os.path.expanduser(path)
        if expanded.startswith("/") or expanded.startswith("\\"):
            norm = os.path.normpath(expanded)
            # Windows 裸根路径不被 os.path.isabs 识别，补当前盘符保持绝对路径语义
            if os.name == "nt" and not os.path.isabs(norm):
                drive = os.path.splitdrive(os.getcwd())[0]
                return drive + norm if drive else norm
            return norm
        return os.path.abspath(expanded)
    except Exception as e:
        logging.getLogger("utils").warning("路径规范化失败 %s: %s", path, e)
        return path


# 通用重试装饰器

def retry_on_failure(
    max_retries: int = _DEFAULT_RETRIES,
    backoff: float = _DEFAULT_BACKOFF,
    jitter: float = _DEFAULT_JITTER,
    max_backoff: float = _MAX_BACKOFF,
    retryable_exceptions: tuple[type[BaseException], ...] = (Exception,),
    logger: logging.Logger | None = None,
) -> Callable[[F], F]:
    """通用重试装饰器 — 指数退避 + 随机抖动.

    INTJ 注: 这个装饰器的设计哲学是 "尽力而为但不无限等待"。
    每次失败的退避 = min(backoff * 2^attempt + random(-jitter, +jitter), max_backoff)
    参考 AWS SDK 的 retry mode: standard。

    Args:
        max_retries: 最大重试次数 (总调用次数 = max_retries + 1)
        backoff: 初始退避基数 (秒)
        jitter: 随机抖动幅度 (秒, uniform[-jitter, +jitter])
        max_backoff: 单次退避上限 (秒)
        retryable_exceptions: 可重试的异常类型元组
        logger: 日志记录器 (None = 使用调用模块的 logger)

    Usage:
        @retry_on_failure(max_retries=3)
        def flaky_r2_call(binary_path: str) -> str:
            ...

    Returns:
        装饰后的函数, 签名不变。
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            _log = logger or logging.getLogger(func.__module__)
            last_exception: Exception | None = None

            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except retryable_exceptions as e:
                    last_exception = e
                    if attempt >= max_retries:
                        # 所有尝试耗尽 — 如果是我写的代码这就是个bug, 但先报warning
                        _log.warning(
                            "%s: 所有 %d 次重试已耗尽 (最后一次: %s)",
                            func.__name__, max_retries + 1, e
                        )
                        raise

                    # 指数退避 + 抖动
                    sleep_time = min(
                        backoff * (2 ** attempt) + random.uniform(-jitter, jitter),
                        max_backoff,
                    )
                    sleep_time = max(0.0, sleep_time)  # 不允许负值

                    _log.debug(
                        "%s 失败 (attempt %d/%d): %s — %.1fs 后退避",
                        func.__name__, attempt + 1, max_retries + 1,
                        e, sleep_time
                    )
                    time.sleep(sleep_time)

            # 理论上不可达, 但 Python 类型检查器不够聪明
            if last_exception is not None:
                raise last_exception
            raise RuntimeError(f"{func.__name__}: 未预期的重试循环出口")

        return wrapper  # type: ignore[return-value]

    return decorator


# subprocess 专用重试

def retry_subprocess(
    max_retries: int = _DEFAULT_RETRIES,
    backoff: float = _DEFAULT_BACKOFF,
    timeout: float | None = 120.0,
    logger: logging.Logger | None = None,
) -> Callable[[F], F]:
    """subprocess / r2 调用专用重试装饰器.

    对以下异常自动重试:
    - subprocess.TimeoutExpired: 外部工具超时
    - FileNotFoundError: r2/strings 未安装
    - OSError: 磁盘 IO / 权限错误

    此类失败通常是瞬时的 (系统负载、临时文件锁)，可安全重试。
    INTJ 注: FileNotFoundError 重试成功率低 (除非用户恰好在那 3 秒内安装 r2),
    但保留它是为了避免 CI 竞态条件 — 见 atlassian/ci-fails 讨论串。
    """
    return retry_on_failure(
        max_retries=max_retries,
        backoff=backoff,
        jitter=0.5,
        max_backoff=30.0,
        retryable_exceptions=(subprocess.TimeoutExpired, FileNotFoundError, OSError),
        logger=logger,
    )


# HTTP / LLM 调用专用重试

def retry_http(
    max_retries: int = _DEFAULT_RETRIES,
    backoff: float = _DEFAULT_BACKOFF,
    logger: logging.Logger | None = None,
) -> Callable[[F], F]:
    """HTTP / Ollama API 调用专用重试装饰器.

    对以下异常自动重试:
    - ConnectionError: 网络不可达
    - TimeoutError: 请求超时
    - OSError: 连接重置 (ConnectionResetError)

    不重试 HTTP 4xx (客户端错误)，只重试 5xx 和网络层故障。
    参考: RFC 7231 6.6 节 — 5xx 是服务器错误, 幂等操作可安全重试。
    """
    try:
        import requests
        _http_exceptions = (
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
            requests.exceptions.HTTPError,
            ConnectionError,
            TimeoutError,
            OSError,
        )
    except ImportError:
        _http_exceptions = (ConnectionError, TimeoutError, OSError)

    return retry_on_failure(
        max_retries=max_retries,
        backoff=backoff,
        jitter=1.0,
        max_backoff=60.0,
        retryable_exceptions=_http_exceptions,  # type: ignore[arg-type]
        logger=logger,
    )


# 统一日志配置

def setup_module_logging(
    name: str = "fuzzing",
    level: int = logging.INFO,
    log_file: str | None = None,
    log_format: str | None = None,
) -> logging.Logger:
    """为模块配置统一的日志输出.

    特性:
    - 双输出: 控制台 stderr + 可选文件
    - 时间戳格式: ISO 8601
    - logger 命名空间: fuzzing.{name}

    Args:
        name: 子模块名称 (如 "fault_injection", "cluster")
        level: 日志级别
        log_file: 日志文件路径 (None = 仅控制台)
        log_format: 自定义格式 (None = 默认)

    Returns:
        配置好的 Logger 实例。
    """
    if log_format is None:
        log_format = "[%(asctime)s] [%(name)s] %(levelname)s: %(message)s"

    logger = logging.getLogger(f"fuzzing.{name}")
    logger.setLevel(level)

    # 避免重复添加 handler (模块可能被多次导入)
    if not logger.handlers:
        formatter = logging.Formatter(log_format, datefmt="%Y-%m-%dT%H:%M:%SZ")

        # 控制台 handler
        console = logging.StreamHandler()
        console.setLevel(level)
        console.setFormatter(formatter)
        logger.addHandler(console)

        # 文件 handler (可选)
        if log_file:
            os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setLevel(level)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

    return logger


# 调试辅助

def _debug_trace(func_name: str, **kwargs: object) -> None:
    """仅在 BINMIND_DEBUG=1 时输出调试追踪.

    这是临时的诊断钩子 — 生产环境不应该依赖它。
    INTJ 注: 以后换成 opentelemetry tracing, 但这个 print 在
    docker logs 里足够直观。
    """
    if os.environ.get("BINMIND_DEBUG"):
        parts = [f"{func_name}:"]
        for k, v in kwargs.items():
            parts.append(f"  {k}={str(v)[:120]}")
        print("\n".join(parts), file=__import__('sys').stderr)

# 模块构建信息 — 不同时期模块的命名与署名约定存在差异, 保留历史样貌。
_MODULE_BUILD_DATE = "2025-02-06"          # 早期模块使用下划线命名
BUILD_ID           = "fuzz_utils_v2.1"     # 后续重构调整为大写常量
_author_note       = "hermit1016 @ 2025-02-06 — retry logic v3, 之前版本在回滚中丢失"
