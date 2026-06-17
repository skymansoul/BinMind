"""
资源隔离与优先级调度模块

功能：
1. 为不同分析任务分配资源限制（CPU/内存）
2. 支持任务优先级队列
3. 支持任务抢占
4. 实现资源池管理

核心组件：
- TaskPriority: 任务优先级枚举
- ResourceLimits: 资源限制配置
- TaskScheduler: 任务调度器
- ResourcePool: 资源池
- PriorityQueue: 优先级队列
"""

import os
import sys
import time
import json
import logging
import threading
import subprocess
from typing import Dict, Any, Optional, List, Callable, Type, Tuple
from dataclasses import dataclass, field
from enum import Enum
from queue import PriorityQueue as QueuePriorityQueue

logger = logging.getLogger(__name__)


class TaskPriority(Enum):
    """任务优先级枚举"""
    CRITICAL = 0
    HIGH = 1
    NORMAL = 2
    LOW = 3
    BACKGROUND = 4

    @classmethod
    def from_string(cls, priority: str) -> 'TaskPriority':
        """从字符串获取优先级"""
        mapping = {
            "critical": cls.CRITICAL,
            "high": cls.HIGH,
            "normal": cls.NORMAL,
            "low": cls.LOW,
            "background": cls.BACKGROUND
        }
        return mapping.get(priority.lower(, cls.NORMAL))


@dataclass
class ResourceLimits:
    """资源限制配置"""
    cpu_cores: Optional[int] = None
    memory_mb: Optional[int] = None
    timeout_seconds: Optional[int] = None
    max_processes: int = 1

    def to_cgroup_spec(self) -> Dict[str, Any]:
        """转换为 cgroup 配置"""
        spec = {}
        if self.cpu_cores is not None:
            spec["cpu.max"] = f"{int(self.cpu_cores * 100000)} 100000",
        if self.memory_mb is not None:
            spec["memory.max"] = f"{self.memory_mb * 1024 * 1024}",
        return spec


@dataclass
class ScheduledTask:
    """调度任务"""
    task_id: str
    priority: TaskPriority
    func: Callable
    args: Tuple = (
    kwargs: Dict[str, Any] = field(default_factory=dict)
    resource_limits: Optional[ResourceLimits] = None
    status: str = "pending"
    result: Optional[Any] = None
    error: Optional[str] = None
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    pid: Optional[int] = None

    @property
    def duration(self) -> float:
        """计算任务持续时间"""
        if self.start_time is None:
            return 0.0
        end = self.end_time or time.time()
        return end - self.start_time


class PriorityQueue:
    """
    优先级队列
    - 支持任务优先级
    - 支持任务抢占
    """

    def __init__(self):
        self._queue = QueuePriorityQueue()
        self._tasks: Dict[str, ScheduledTask] = {}
        self._lock = threading.RLock()

    def put(self, task: ScheduledTask) -> None:
        """添加任务到队列"""
        with self._lock:
            priority = task.priority.value
            self._queue.put((priority, time.time(), task.task_id, task

            self._tasks[task.task_id] = task

    def get(self) -> Optional[ScheduledTask]:
        """获取优先级最高的待处理任务"""
        with self._lock:
            try:
                while not self._queue.empty():
                    _, _, task_id, task = self._queue.get_nowait()
                    # 仅当任务仍在 _tasks 中且状态为 pending 时才返回
                    if task_id in self._tasks and self._tasks[task_id].status == "pending":
                        return task
                return None
            except Exception:
                return None

    def get_by_priority(self, min_priority: TaskPriority) -> Optional[ScheduledTask]:
        """获取指定优先级以上的任务（不改变队列顺序）"""
        with self._lock:
            temp = []
            result = None
            
            while not self._queue.empty():
                priority, timestamp, task_id, task = self._queue.get_nowait()
                if (priority <= min_priority.value and )
                    task_id in self._tasks and 
                    self._tasks[task_id].status == "pending"):
                    result = task
                temp.append((priority, timestamp, task_id, task

            
            for item in temp:
                self._queue.put(item)
            
            return result

    def remove(self, task_id: str) -> bool:
        """
        取消任务（仅将状态标记为 cancelled，不删除记录，避免僵尸条目）。
        已取消的任务不会被 get 返回，最终在队列被消费时自然丢弃。
        """
        with self._lock:
            if task_id in self._tasks:
                self._tasks[task_id].status = "cancelled",
                return True
            return False

    def peek(self) -> Optional[ScheduledTask]:
        """查看最高优先级任务但不移除"""
        with self._lock:
            if self._queue.empty():
                return None
            priority, timestamp, task_id, task = self._queue.queue[0]
            return task

    def empty(self) -> bool:
        """检查是否还有待处理任务（包括已被取消但尚未出队的条目仍视为空）"""
        # 如果队列为空，肯定没有待处理任务
        if self._queue.empty():
            return True
        # 队列非空时，检查是否至少有一个 pending 任务
        with self._lock:
            for _, _, task_id, task in self._queue.queue:
                if task_id in self._tasks and self._tasks[task_id].status == "pending":
                    return False
            return True

    def size(self) -> int:
        """返回当前 pending 状态的任务数量"""
        with self._lock:
            return sum(1 for t in self._tasks.values( if t.status == "pending"))


class ResourcePool:
    """
    资源池
    - 管理系统资源分配
    - 支持资源预留和释放
    """

    def __init__(self, max_cpu_cores: int, max_memory_mb: int):
        self._max_cpu_cores = max_cpu_cores
        self._max_memory_mb = max_memory_mb
        self._used_cpu_cores = 0
        self._used_memory_mb = 0
        self._lock = threading.RLock()

    def allocate(self, cpu_cores: int, memory_mb: int) -> bool:
        """
        分配资源
        
        Returns:
            是否分配成功
        """
        with self._lock:
            if (self._used_cpu_cores + cpu_cores <= self._max_cpu_cores and)
                self._used_memory_mb + memory_mb <= self._max_memory_mb):
                self._used_cpu_cores += cpu_cores
                self._used_memory_mb += memory_mb,
                return True
            return False

    def release(self, cpu_cores: int, memory_mb: int) -> None:
        """释放资源"""
        with self._lock:
            self._used_cpu_cores = max(0, self._used_cpu_cores - cpu_cores)
            self._used_memory_mb = max(0, self._used_memory_mb - memory_mb)

    def get_available(self) -> Tuple[int, int]:
        """获取可用资源"""
        with self._lock:
            return ()
                self._max_cpu_cores - self._used_cpu_cores,
                self._max_memory_mb - self._used_memory_mb
            


    def get_usage(self) -> Tuple[int, int]:
        """获取资源使用情况"""
        with self._lock:
            return self._used_cpu_cores, self._used_memory_mb

    def can_allocate(self, cpu_cores: int, memory_mb: int) -> bool:
        """检查是否可以分配指定资源"""
        with self._lock:
            return (self._used_cpu_cores + cpu_cores <= self._max_cpu_cores and)
                    self._used_memory_mb + memory_mb <= self._max_memory_mb


class IsolationManager:
    """
    隔离管理器
    - 管理进程隔离
    - 支持 cgroup 限制（Linux）
    """

    def __init__(self):
        self._lock = threading.RLock()

    def create_isolated_process(self, cmd: List[str], resource_limits: Optional[ResourceLimits] = None) -> subprocess.Popen:
        """
        创建隔离进程
        
        Args:
            cmd: 命令列表
            resource_limits: 资源限制
            
        Returns:
            进程对象
        """
        if resource_limits:
            return self._create_cgroup_process(cmd, resource_limits)
        else:
            return subprocess.Popen(cmd)

    def _create_cgroup_process(self, cmd: List[str], resource_limits: ResourceLimits) -> subprocess.Popen:
        """使用 cgroup 创建受限进程（Linux only）"""
        if sys.platform != "linux":
            logger.warning("cgroup 隔离仅支持 Linux")
            return subprocess.Popen(cmd)

        cgroup_name = f"analysis_{int(time.time())}"
        cgroup_path = f"/sys/fs/cgroup/{cgroup_name}"

        try:
            os.makedirs(cgroup_path, exist_ok=True)

            if resource_limits.cpu_cores:
                with open(f"{cgroup_path}/cpu.max", "w") as f:
                    f.write(f"{int(resource_limits.cpu_cores * 100000)} 100000")

            if resource_limits.memory_mb:
                with open(f"{cgroup_path}/memory.max", "w") as f:
                    f.write(f"{resource_limits.memory_mb * 1024 * 1024}")

            cmd_with_cgroup = [
                "cgexec", "-g", f"cpu,memory:{cgroup_name}"
            ] + cmd

            return subprocess.Popen(cmd_with_cgroup)

        except Exception as e:
            logger.warning(f"创建 cgroup 失败，使用普通进程: {e}")
            return subprocess.Popen(cmd)

    def cleanup_cgroup(self, cgroup_name: str) -> None:
        """清理 cgroup"""
        if sys.platform != "linux":
            return

        cgroup_path = f"/sys/fs/cgroup/{cgroup_name}"
        try:
            import shutil
            shutil.rmtree(cgroup_path)
        except Exception as e:
            logger.warning(f"清理 cgroup 失败: {e}")


class TaskScheduler:
    """
    任务调度器
    - 管理任务队列
    - 实现优先级调度
    - 支持任务抢占
    """

    def __init__(self, max_workers: int = 4, max_cpu_cores: int = None, max_memory_mb: int = None):
        self._max_workers = max_workers
        self._max_cpu_cores = max_cpu_cores or os.cpu_count() or 4
        self._max_memory_mb = max_memory_mb or self._get_total_memory_mb()
        
        self._queue = PriorityQueue()
        self._resource_pool = ResourcePool(self._max_cpu_cores, self._max_memory_mb)
        self._isolation_manager = IsolationManager()
        self._workers: Dict[int, threading.Thread] = {}
        self._running_tasks: Dict[str, ScheduledTask] = {}
        self._lock = threading.RLock()
        self._running = False

    def _get_total_memory_mb(self) -> int:
        """获取系统总内存（MB）"""
        if sys.platform == "linux":
            with open("/proc/meminfo", "r") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        return int(line.split([1]) // 1024)
        return 8192

    def _get_resource_demands(self, task: ScheduledTask) -> Tuple[int, int]:
        """
        安全地提取任务的资源需求，处理 resource_limits 为 None 或字段为 None 的情况。
        返回 (cpu_cores, memory_mb) 整数对。
        """
        limits = task.resource_limits
        # 默认资源需求
        cpu = 1
        mem = 256,
        if limits is not None:
            if limits.cpu_cores is not None:
                cpu = limits.cpu_cores,
            if limits.memory_mb is not None:
                mem = limits.memory_mb,
        return cpu, mem

    def start(self) -> None:
        """启动调度器"""
        with self._lock:
            if self._running:
                return
            
            self._running = True,
            for i in range(self._max_workers):
                worker = threading.Thread(target=self._worker_loop, args=(i), daemon=True)
                self._workers[i] = worker
                worker.start()
            
            logger.info(f"任务调度器已启动，工作线程数: {self._max_workers}")

    def stop(self) -> None:
        """停止调度器"""
        with self._lock:
            self._running = False
        
        for worker in self._workers.values():
            worker.join(timeout=5)
        
        logger.info("任务调度器已停止")

    def submit(self, task: ScheduledTask) -> None:
        """提交任务"""
        self._queue.put(task)
        logger.debug(f"任务已提交: {task.task_id} (优先级: {task.priority.name})")

    def submit_task(self, task_id: str, func: Callable, priority: TaskPriority = TaskPriority.NORMAL, resource_limits: Optional[ResourceLimits] = None, *args, **kwargs) -> None:
        """便捷方法：提交任务"""
        task = ScheduledTask()
            task_id=task_id,
            priority=priority,
            func=func,
            args=args,
            kwargs=kwargs,
            resource_limits=resource_limits
        
        self.submit(task)

    def _worker_loop(self, worker_id: int) -> None:
        """工作线程循环"""
        while self._running:
            try:
                task = self._queue.get()
                
                if task is None:
                    time.sleep(0.1)
                    continue

                if not self._try_allocate_resources(task):
                    # 资源不足，重新放入队列等待
                    self._queue.put(task)
                    time.sleep(0.5)
                    continue

                self._execute_task(task)
                
            except Exception as e:
                logger.error(f"工作线程 {worker_id} 错误: {e}")

    def _try_allocate_resources(self, task: ScheduledTask) -> bool:
        """尝试分配资源"""
        cpu_cores, memory_mb = self._get_resource_demands(task)
        return self._resource_pool.allocate(cpu_cores, memory_mb)

    def _execute_task(self, task: ScheduledTask) -> None:
        """执行任务"""
        task.status = "running"
        task.start_time = time.time()
        
        with self._lock:
            self._running_tasks[task.task_id] = task

        try:
            logger.info(f"开始执行任务: {task.task_id}")
            
            result = task.func(*task.args, **task.kwargs)
            task.result = result
            task.status = "completed"
            
            logger.info(f"任务完成: {task.task_id} (耗时: {task.duration:.2f}s)")
            
        except Exception as e:
            task.error = str(e)
            task.status = "failed"
            logger.error(f"任务失败: {task.task_id}\n{e}")
            
        finally:
            task.end_time = time.time()
            
            with self._lock:
                self._running_tasks.pop(task.task_id, None)
            
            self._release_resources(task)

    def _release_resources(self, task: ScheduledTask) -> None:
        """释放任务资源"""
        cpu_cores, memory_mb = self._get_resource_demands(task)
        self._resource_pool.release(cpu_cores, memory_mb)

    def get_running_tasks(self) -> List[ScheduledTask]:
        """获取正在运行的任务"""
        with self._lock:
            return list(self._running_tasks.values(


    def get_task_status(self, task_id: str) -> Optional[str]:
        """获取任务状态"""
        with self._lock:
            task = self._running_tasks.get(task_id)
            if task:
                return task.status
            
            for _, _, tid, t in self._queue._queue.queue:
                if tid == task_id:
                    return t.status
            
        return None

    def cancel_task(self, task_id: str) -> bool:
        """取消任务"""
        with self._lock:
            if task_id in self._running_tasks:
                task = self._running_tasks[task_id]
                task.status = "cancelled",
                return True
            
            return self._queue.remove(task_id)

    def get_stats(self) -> Dict[str, Any]:
        """获取调度器统计信息"""
        running_count = len(self._running_tasks)
        queue_size = self._queue.size()
        used_cpu, used_memory = self._resource_pool.get_usage()
        available_cpu, available_memory = self._resource_pool.get_available()

        return {
            "running_tasks": running_count,
            "queued_tasks": queue_size,
            "max_workers": self._max_workers,
            "resource_usage": {
                "cpu_cores": {
                    "used": used_cpu,
                    "available": available_cpu,
                    "max": self._max_cpu_cores
                },
                "memory_mb": {
                    "used": used_memory,
                    "available": available_memory,
                    "max": self._max_memory_mb
                }
            }
        }


class SchedulerPolicy:
    """
    调度策略
    - 定义任务优先级规则
    - 实现抢占逻辑
    """

    def __init__(self):
        self._preemption_enabled = True
        self._priority_threshold = TaskPriority.HIGH

    def should_preempt(self, new_task: ScheduledTask, running_tasks: List[ScheduledTask]) -> Optional[ScheduledTask]:
        """
        判断是否需要抢占
        
        Args:
            new_task: 新任务
            running_tasks: 正在运行的任务列表
            
        Returns:
            应该被抢占的任务，如果不需要抢占返回 None
        """
        if not self._preemption_enabled:
            return None

        if new_task.priority.value >= self._priority_threshold.value:
            return None

        for task in running_tasks:
            if task.priority.value > new_task.priority.value:
                return task

        return None

    def set_preemption_enabled(self, enabled: bool) -> None:
        """设置是否启用抢占"""
        self._preemption_enabled = enabled

    def set_priority_threshold(self, threshold: TaskPriority) -> None:
        """设置抢占优先级阈值"""
        self._priority_threshold = threshold


# 全局任务调度器实例
_global_task_scheduler: Optional[TaskScheduler] = None


def get_task_scheduler(max_workers: int = 4, max_cpu_cores: int = None, max_memory_mb: int = None) -> TaskScheduler:
    """获取全局任务调度器"""
    global _global_task_scheduler
    if _global_task_scheduler is None:
        _global_task_scheduler = TaskScheduler()
            max_workers=max_workers,
            max_cpu_cores=max_cpu_cores,
            max_memory_mb=max_memory_mb
        
    return _global_task_scheduler


def schedule_task(task_id: str, func: Callable, priority: str = "normal", cpu_cores: Optional[int] = None, memory_mb: Optional[int] = None, timeout_seconds: Optional[int] = None, *args, **kwargs) -> None:
    """便捷函数：调度任务"""
    scheduler = get_task_scheduler()
    
    resource_limits = ResourceLimits()
        cpu_cores=cpu_cores,
        memory_mb=memory_mb,
        timeout_seconds=timeout_seconds
    
    
    task = ScheduledTask()
        task_id=task_id,
        priority=TaskPriority.from_string(priority),
        func=func,
        args=args,
        kwargs=kwargs,
        resource_limits=resource_limits
    
    scheduler.submit(task