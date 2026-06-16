"""
性能与资源控制系统

功能：
1. 超时控制
2. 内存限制
3. 沙箱隔离
4. 增量分析缓存增强
"""

import os
import sys
import time
import json
import hashlib
import logging
import tempfile
import subprocess
import multiprocessing

# resource 模块仅在 Unix/Linux 系统上可用
if sys.platform == 'linux':
    import resource
else:
    resource = None
from pathlib import Path
from typing import Dict, Any, Optional, Callable, Tuple, List
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, TimeoutError
from contextlib import contextmanager

logger = logging.getLogger(__name__)


class SandboxType(Enum):
    """沙箱类型枚举"""
    NONE = "none"
    SUBPROCESS = "subprocess"
    DOCKER = "docker"
    GVISO = "gviso"
    CUSTOM = "custom"


@dataclass
class ResourceLimits:
    """资源限制配置"""
    timeout: int = 300
    memory_limit: int = 2048
    cpu_limit: int = 100
    disk_limit: int = 10240
    network_enabled: bool = False
    filesystem_readonly: bool = True
    max_processes: int = 10


@dataclass
class ExecutionResult:
    """执行结果"""
    success: bool
    output: str
    error: Optional[str] = None
    return_code: int = 0
    execution_time: float = 0.0
    memory_peak: int = 0
    killed: bool = False
    kill_reason: Optional[str] = None


class ResourceMonitor:
    """
    资源监控器
    
    监控进程的资源使用情况
    """
    
    def __init__(self, pid: Optional[int] = None):
        self.pid = pid or os.getpid()
        self._start_time = time.time()
        self._start_memory = self._get_memory_usage()
    
    def _get_memory_usage(self) -> int:
        """获取内存使用（字节）"""
        try:
            if sys.platform == 'linux':
                with open(f'/proc/{self.pid}/status', 'r') as f:
                    for line in f:
                        if line.startswith('VmRSS:'):
                            return int(line.split()[1]) * 1024
            elif sys.platform == 'darwin':
                import psutil
                process = psutil.Process(self.pid)
                return process.memory_info().rss
        except Exception:
            pass
        return 0
    
    def get_current_memory(self) -> int:
        """获取当前内存使用"""
        return self._get_memory_usage()
    
    def get_peak_memory(self) -> int:
        """获取峰值内存使用"""
        current = self._get_memory_usage()
        return max(current, self._start_memory)
    
    def get_execution_time(self) -> float:
        """获取执行时间"""
        return time.time() - self._start_time


class TimeoutExecutor:
    """
    超时执行器
    
    支持超时控制的函数执行
    """
    
    def __init__(self, timeout: int = 300, default_result: Any = None):
        """
        初始化超时执行器
        
        Args:
            timeout: 默认超时时间（秒）
            default_result: 超时时的默认返回值
        """
        self.timeout = timeout
        self.default_result = default_result
    
    def execute(
        self,
        func: Callable,
        *args,
        timeout: Optional[int] = None,
        **kwargs
    ) -> Tuple[Any, bool]:
        """
        执行函数（带超时控制）
        
        Args:
            func: 要执行的函数
            *args: 位置参数
            timeout: 超时时间（秒）
            **kwargs: 关键字参数
            
        Returns:
            (结果, 是否成功)
        """
        timeout = timeout or self.timeout
        
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(func, *args, **kwargs)
            
            try:
                result = future.result(timeout=timeout)
                return result, True
            except TimeoutError:
                logger.warning(f"函数 {func.__name__} 执行超时 ({timeout}s)")
                return self.default_result, False
            except Exception as e:
                logger.error(f"函数 {func.__name__} 执行失败: {e}")
                return self.default_result, False
    
    def execute_with_result(
        self,
        func: Callable,
        *args,
        timeout: Optional[int] = None,
        **kwargs
    ) -> Tuple[Any, ExecutionResult]:
        """
        执行函数并返回详细结果
        
        Args:
            func: 要执行的函数
            *args: 位置参数
            timeout: 超时时间（秒）
            **kwargs: 关键字参数
            
        Returns:
            (结果, ExecutionResult)
        """
        timeout = timeout or self.timeout
        start_time = time.time()
        
        monitor = ResourceMonitor()
        
        try:
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(func, *args, **kwargs)
                
                result = future.result(timeout=timeout)
                
                execution_time = time.time() - start_time
                
                return result, ExecutionResult(
                    success=True,
                    output=str(result)[:1000],
                    execution_time=execution_time,
                    memory_peak=monitor.get_peak_memory()
                )
                
        except TimeoutError:
            execution_time = time.time() - start_time
            return self.default_result, ExecutionResult(
                success=False,
                output="",
                error="执行超时",
                killed=True,
                kill_reason="timeout",
                execution_time=execution_time
            )
        except Exception as e:
            execution_time = time.time() - start_time
            return self.default_result, ExecutionResult(
                success=False,
                output="",
                error=str(e),
                execution_time=execution_time
            )


class MemoryLimiter:
    """
    内存限制器
    
    限制进程可以使用的内存量
    """
    
    @staticmethod
    @contextmanager
    def limit_memory(max_bytes: int):
        """
        上下文管理器：限制内存使用
        
        Args:
            max_bytes: 最大内存（字节）
        """
        if sys.platform == 'linux':
            try:
                def raise_oom(signum, frame):
                    raise MemoryError("内存使用超过限制")
                
                import signal
                old_handler = signal.signal(signal.SIGSEGV, raise_oom)
                
                resource.setrlimit(resource.RLIMIT_AS, (max_bytes, max_bytes))
                
                yield
            except Exception as e:
                logger.warning(f"内存限制设置失败: {e}")
                yield
            finally:
                if sys.platform == 'linux':
                    resource.setrlimit(resource.RLIMIT_AS, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
                    signal.signal(signal.SIGSEGV, old_handler)
        else:
            yield
    
    @staticmethod
    def check_memory_available(required_bytes: int) -> bool:
        """
        检查是否有足够的可用内存
        
        Args:
            required_bytes: 需要的内存（字节）
            
        Returns:
            是否有足够的内存
        """
        try:
            if sys.platform == 'linux':
                with open('/proc/meminfo', 'r') as f:
                    for line in f:
                        if line.startswith('MemAvailable:'):
                            available_kb = int(line.split()[1])
                            available_bytes = available_kb * 1024
                            return available_bytes >= required_bytes
            elif sys.platform == 'darwin':
                import psutil
                vm = psutil.virtual_memory()
                return vm.available >= required_bytes
        except Exception as e:
            logger.warning(f"检查可用内存失败: {e}")
        
        return True
    
    @staticmethod
    def get_system_memory_info() -> Dict[str, int]:
        """
        获取系统内存信息
        
        Returns:
            内存信息字典
        """
        info = {
            "total": 0,
            "available": 0,
            "used": 0,
            "percent": 0
        }
        
        try:
            if sys.platform == 'linux':
                with open('/proc/meminfo', 'r') as f:
                    for line in f:
                        if line.startswith('MemTotal:'):
                            info["total"] = int(line.split()[1]) * 1024
                        elif line.startswith('MemAvailable:'):
                            info["available"] = int(line.split()[1]) * 1024
            elif sys.platform == 'darwin':
                import psutil
                vm = psutil.virtual_memory()
                info["total"] = vm.total
                info["available"] = vm.available
                info["used"] = vm.used
                info["percent"] = vm.percent
        except Exception as e:
            logger.warning(f"获取系统内存信息失败: {e}")
        
        info["used"] = info["total"] - info["available"]
        if info["total"] > 0:
            info["percent"] = (info["used"] / info["total"]) * 100
        
        return info


class SandboxExecutor:
    """
    沙箱执行器
    
    在隔离环境中执行代码
    """
    
    def __init__(
        self,
        sandbox_type: SandboxType = SandboxType.SUBPROCESS,
        limits: Optional[ResourceLimits] = None
    ):
        """
        初始化沙箱执行器
        
        Args:
            sandbox_type: 沙箱类型
            limits: 资源限制
        """
        self.sandbox_type = sandbox_type
        self.limits = limits or ResourceLimits()
    
    def execute(
        self,
        command: List[str],
        input_data: Optional[bytes] = None,
        timeout: Optional[int] = None,
        working_dir: Optional[str] = None,
        env: Optional[Dict[str, str]] = None
    ) -> ExecutionResult:
        """
        在沙箱中执行命令
        
        Args:
            command: 命令列表
            input_data: 输入数据
            timeout: 超时时间
            working_dir: 工作目录
            env: 环境变量
            
        Returns:
            ExecutionResult
        """
        timeout = timeout or self.limits.timeout
        
        if self.sandbox_type == SandboxType.SUBPROCESS:
            return self._execute_subprocess(
                command, input_data, timeout, working_dir, env
            )
        elif self.sandbox_type == SandboxType.DOCKER:
            return self._execute_docker(
                command, input_data, timeout, working_dir, env
            )
        else:
            return self._execute_direct(
                command, input_data, timeout, working_dir, env
            )
    
    def _execute_subprocess(
        self,
        command: List[str],
        input_data: Optional[bytes],
        timeout: int,
        working_dir: Optional[str],
        env: Optional[Dict[str, str]]
    ) -> ExecutionResult:
        """使用 subprocess 执行"""
        start_time = time.time()
        
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE if input_data else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=working_dir,
                env=env,
                preexec_fn=self._setup_preexec_fn() if sys.platform == 'linux' else None
            )
            
            stdout, stderr = process.communicate(
                input=input_data,
                timeout=timeout
            )
            
            execution_time = time.time() - start_time
            
            return ExecutionResult(
                success=process.returncode == 0,
                output=stdout.decode('utf-8', errors='replace')[:5000],
                error=stderr.decode('utf-8', errors='replace')[:1000] if stderr else None,
                return_code=process.returncode,
                execution_time=execution_time
            )
            
        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            return ExecutionResult(
                success=False,
                output="",
                error="执行超时",
                killed=True,
                kill_reason="timeout",
                execution_time=execution_time
            )
        except Exception as e:
            execution_time = time.time() - start_time
            return ExecutionResult(
                success=False,
                output="",
                error=str(e),
                execution_time=execution_time
            )
    
    def _execute_docker(
        self,
        command: List[str],
        input_data: Optional[bytes],
        timeout: int,
        working_dir: Optional[str],
        env: Optional[Dict[str, str]]
    ) -> ExecutionResult:
        """使用 Docker 执行"""
        start_time = time.time()
        
        docker_command = [
            "docker", "run",
            "--rm",
            "--network=none" if not self.limits.network_enabled else "",
            "--read-only" if self.limits.filesystem_readonly else "",
            "-m", f"{self.limits.memory_limit}m",
            "-c", str(self.limits.cpu_limit),
            "--pids-limit", str(self.limits.max_processes)
        ]
        
        if working_dir:
            docker_command.extend(["-w", working_dir])
        
        docker_command.extend(["binary_analysis_sandbox"])
        docker_command.extend(command)
        
        return self._execute_subprocess(docker_command, input_data, timeout, None, env)
    
    def _execute_direct(
        self,
        command: List[str],
        input_data: Optional[bytes],
        timeout: int,
        working_dir: Optional[str],
        env: Optional[Dict[str, str]]
    ) -> ExecutionResult:
        """直接执行（无沙箱）"""
        start_time = time.time()
        
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE if input_data else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=working_dir,
                env=env
            )
            
            stdout, stderr = process.communicate(
                input=input_data,
                timeout=timeout
            )
            
            execution_time = time.time() - start_time
            
            return ExecutionResult(
                success=process.returncode == 0,
                output=stdout.decode('utf-8', errors='replace')[:5000],
                error=stderr.decode('utf-8', errors='replace')[:1000] if stderr else None,
                return_code=process.returncode,
                execution_time=execution_time
            )
            
        except subprocess.TimeoutExpired:
            process.kill()
            execution_time = time.time() - start_time
            return ExecutionResult(
                success=False,
                output="",
                error="执行超时",
                killed=True,
                kill_reason="timeout",
                execution_time=execution_time
            )
        except Exception as e:
            execution_time = time.time() - start_time
            return ExecutionResult(
                success=False,
                output="",
                error=str(e),
                execution_time=execution_time
            )
    
    def _setup_preexec_fn(self) -> Optional[Callable]:
        """设置进程前的执行函数"""
        if sys.platform != 'linux':
            return None
        
        def set_limits():
            try:
                resource.setrlimit(resource.RLIMIT_AS, (
                    self.limits.memory_limit * 1024 * 1024,
                    self.limits.memory_limit * 1024 * 1024
                ))
                resource.setrlimit(resource.RLIMIT_CPU, (
                    self.limits.cpu_limit,
                    self.limits.cpu_limit
                ))
                resource.setrlimit(resource.RLIMIT_NPROC, (
                    self.limits.max_processes,
                    self.limits.max_processes
                ))
                if self.limits.disk_limit > 0:
                    resource.setrlimit(resource.RLIMIT_FSIZE, (
                        self.limits.disk_limit * 1024 * 1024,
                        self.limits.disk_limit * 1024 * 1024
                    ))
            except Exception as e:
                logger.warning(f"设置资源限制失败: {e}")
        
        return set_limits


class IncrementalAnalysisCache:
    """
    增量分析缓存增强版
    
    基于内容哈希的增量分析，避免重复分析相同二进制
    """
    
    def __init__(self, cache_dir: str = "data/incremental_cache"):
        """
        初始化增量分析缓存
        
        Args:
            cache_dir: 缓存目录
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        self._memory_cache: Dict[str, Any] = {}
        self._max_memory_entries = 100
    
    def compute_content_hash(
        self,
        content: bytes,
        algorithm: str = "sha256"
    ) -> str:
        """
        计算内容哈希
        
        Args:
            content: 内容字节
            algorithm: 哈希算法
            
        Returns:
            哈希值
        """
        if algorithm == "sha256":
            return hashlib.sha256(content).hexdigest()
        elif algorithm == "sha512":
            return hashlib.sha512(content).hexdigest()
        elif algorithm == "md5":
            return hashlib.md5(content).hexdigest()
        else:
            raise ValueError(f"不支持的哈希算法: {algorithm}")
    
    def compute_binary_hash(self, binary_path: str) -> str:
        """
        计算二进制文件哈希
        
        Args:
            binary_path: 二进制文件路径
            
        Returns:
            哈希值
        """
        hasher = hashlib.sha256()
        
        with open(binary_path, 'rb') as f:
            chunk = f.read(8192)
            while chunk:
                hasher.update(chunk)
                chunk = f.read(8192)
        
        return hasher.hexdigest()
    
    def get_from_cache(self, cache_key: str) -> Optional[Any]:
        """
        从缓存获取结果
        
        Args:
            cache_key: 缓存键
            
        Returns:
            缓存的结果，如果不存在返回 None
        """
        if cache_key in self._memory_cache:
            logger.debug(f"缓存命中（内存）: {cache_key}")
            return self._memory_cache[cache_key]
        
        cache_file = self.cache_dir / f"{cache_key}.json"
        if cache_file.exists():
            try:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    result = json.load(f)
                
                self._add_to_memory_cache(cache_key, result)
                logger.debug(f"缓存命中（磁盘）: {cache_key}")
                return result
            except Exception as e:
                logger.warning(f"读取缓存失败 {cache_key}: {e}")
        
        return None
    
    def save_to_cache(self, cache_key: str, result: Any) -> None:
        """
        保存结果到缓存
        
        Args:
            cache_key: 缓存键
            result: 要缓存的结果
        """
        self._add_to_memory_cache(cache_key, result)
        
        cache_file = self.cache_dir / f"{cache_key}.json"
        try:
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, default=str, ensure_ascii=False)
            logger.debug(f"缓存已保存: {cache_key}")
        except Exception as e:
            logger.error(f"保存缓存失败 {cache_key}: {e}")
    
    def _add_to_memory_cache(self, key: str, value: Any) -> None:
        """添加到内存缓存"""
        if len(self._memory_cache) >= self._max_memory_entries:
            oldest_key = next(iter(self._memory_cache))
            del self._memory_cache[oldest_key]
        
        self._memory_cache[key] = value
    
    def invalidate_cache(self, cache_key: Optional[str] = None) -> None:
        """
        失效缓存
        
        Args:
            cache_key: 缓存键，如果为 None 则清除所有缓存
        """
        if cache_key:
            if cache_key in self._memory_cache:
                del self._memory_cache[cache_key]
            
            cache_file = self.cache_dir / f"{cache_key}.json"
            if cache_file.exists():
                cache_file.unlink()
        else:
            self._memory_cache.clear()
            
            for cache_file in self.cache_dir.glob("*.json"):
                cache_file.unlink()
    
    def is_cache_valid(
        self,
        cache_key: str,
        binary_path: Optional[str] = None,
        max_age_days: int = 30
    ) -> bool:
        """
        检查缓存是否有效
        
        Args:
            cache_key: 缓存键
            binary_path: 二进制文件路径（用于验证文件是否修改）
            max_age_days: 最大有效期（天）
            
        Returns:
            缓存是否有效
        """
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        if not cache_file.exists():
            return False
        
        cache_time = cache_file.stat().st_mtime
        age_days = (time.time() - cache_time) / 86400
        
        if age_days > max_age_days:
            return False
        
        if binary_path:
            binary_mtime = os.path.getmtime(binary_path)
            if binary_mtime > cache_time:
                return False
        
        return True


class ResourceController:
    """
    资源控制器
    
    整合超时、内存限制和沙箱功能
    """
    
    def __init__(self, limits: Optional[ResourceLimits] = None):
        """
        初始化资源控制器
        
        Args:
            limits: 资源限制
        """
        self.limits = limits or ResourceLimits()
        self.timeout_executor = TimeoutExecutor(self.limits.timeout)
        self.memory_limiter = MemoryLimiter()
        self.sandbox = SandboxExecutor(SandboxType.SUBPROCESS, self.limits)
        self.cache = IncrementalAnalysisCache()
    
    def execute_with_limits(
        self,
        func: Callable,
        *args,
        use_memory_limit: bool = True,
        use_cache: bool = False,
        cache_key: Optional[str] = None,
        **kwargs
    ) -> Tuple[Any, ExecutionResult]:
        """
        带资源限制执行函数
        
        Args:
            func: 要执行的函数
            *args: 位置参数
            use_memory_limit: 是否使用内存限制
            use_cache: 是否使用缓存
            cache_key: 缓存键
            **kwargs: 关键字参数
            
        Returns:
            (结果, ExecutionResult)
        """
        if use_cache and cache_key:
            cached_result = self.cache.get_from_cache(cache_key)
            if cached_result:
                return cached_result, ExecutionResult(
                    success=True,
                    output="[cached]",
                    execution_time=0.0
                )
        
        start_time = time.time()
        monitor = ResourceMonitor()
        
        try:
            if use_memory_limit:
                max_bytes = self.limits.memory_limit * 1024 * 1024
                
                if not self.memory_limiter.check_memory_available(max_bytes):
                    return None, ExecutionResult(
                        success=False,
                        output="",
                        error="可用内存不足",
                        execution_time=time.time() - start_time
                    )
                
                with self.memory_limiter.limit_memory(max_bytes):
                    result, execution_result = self.timeout_executor.execute_with_result(
                        func, *args, timeout=self.limits.timeout, **kwargs
                    )
            else:
                result, execution_result = self.timeout_executor.execute_with_result(
                    func, *args, timeout=self.limits.timeout, **kwargs
                )
            
            execution_result.memory_peak = monitor.get_peak_memory()
            
            if use_cache and cache_key and execution_result.success:
                self.cache.save_to_cache(cache_key, result)
            
            return result, execution_result
            
        except Exception as e:
            return None, ExecutionResult(
                success=False,
                output="",
                error=str(e),
                execution_time=time.time() - start_time
            )
    
    def get_resource_stats(self) -> Dict[str, Any]:
        """
        获取资源统计信息
        
        Returns:
            资源统计信息
        """
        memory_info = self.memory_limiter.get_system_memory_info()
        
        return {
            "memory": memory_info,
            "cpu_count": multiprocessing.cpu_count(),
            "current_limits": {
                "timeout": self.limits.timeout,
                "memory_limit_mb": self.limits.memory_limit,
                "cpu_limit": self.limits.cpu_limit,
                "network_enabled": self.limits.network_enabled
            },
            "cache_entries": len(self.cache._memory_cache),
            "cache_dir": str(self.cache.cache_dir)
        }
