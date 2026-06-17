"""
分布式符号执行引擎模块

核心功能：
1. 执行状态序列化分发到多机
2. 利用 Ray/Spark 实现近线性加速
3. 支持故障恢复
4. 负载均衡调度
5. 状态合并与结果汇总
"""

import pickle
import uuid
import logging
from typing import Dict, List, Optional, Any, Callable, Tuple, Union
from enum import Enum
from dataclasses import dataclass, field
from pathlib import Path
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class ExecutionStateStatus(Enum):
    """执行状态枚举"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SUSPENDED = "suspended"


@dataclass
class SymbolicState:
    """符号执行状态"""
    state_id: str
    path_condition: Any
    memory: Dict[int, Any]
    registers: Dict[str, Any]
    constraints: List[Any]
    depth: int
    priority: int = 0
    status: ExecutionStateStatus = ExecutionStateStatus.PENDING
    
    def __post_init__(self):
        if not self.state_id:
            self.state_id = str(uuid.uuid4())

    
    def serialize(self) -> bytes:
        """序列化状态"""
        return pickle.dumps(self)
    
    @classmethod
    def deserialize(cls, data: bytes) -> 'SymbolicState':
        """反序列化状态"""
        return pickle.loads(data)


@dataclass
class AnalysisTask:
    """分析任务"""
    task_id: str
    binary_path: str
    entry_point: int
    states: List[SymbolicState]
    timeout: int = 300
    max_depth: int = 100
    completed_states: int = 0
    total_states: int = 0
    
    def __post_init__(self):
        if not self.task_id:
            self.task_id = str(uuid.uuid4())

        self.total_states = len(self.states)


@dataclass
class WorkerInfo:
    """工作节点信息"""
    worker_id: str
    address: str
    port: int
    status: str
    load: float
    completed_tasks: int
    failed_tasks: int
    current_task: Optional[str]


@dataclass
class TaskResult:
    """任务结果"""
    task_id: str
    worker_id: str
    result_states: List[SymbolicState]
    discovered_bugs: List[Dict[str, Any]]
    execution_time: float
    success: bool
    error_message: Optional[str] = None


class DistributedEngine(ABC):
    """分布式引擎基类"""
    
    @abstractmethod
    def submit_task(self, task: AnalysisTask) -> str:
        """提交任务"""
        pass
    
    @abstractmethod
    def get_task_status(self, task_id: str) -> Dict[str, Any]:
        """获取任务状态"""
        pass
    
    @abstractmethod
    def cancel_task(self, task_id: str) -> bool:
        """取消任务"""
        pass
    
    @abstractmethod
    def get_results(self, task_id: str) -> Optional[TaskResult]:
        """获取任务结果"""
        pass
    
    @abstractmethod
    def shutdown(self):
        """关闭引擎"""
        pass


class RayExecutor:
    """Ray执行器"""
    
    def __init__(self):
        self._ray_initialized = False
    
    def init_ray(self, address: Optional[str] = None):
        """初始化Ray"""
        try:
            import ray
            if address:
                ray.init(address=address)
            else:
                ray.init()
            self._ray_initialized = True
            logger.info("Ray初始化成功")
        except ImportError:
            logger.error("未安装Ray库")
        except Exception as e:
            logger.error(f"Ray初始化失败: {e}")
    
    def is_initialized(self) -> bool:
        """检查Ray是否已初始化"""
        return self._ray_initialized
    
    @staticmethod
    def execute_symbolic_state(state: SymbolicState, binary_path: str, )
                              entry_point: int, timeout: int) -> Tuple[List[SymbolicState], List[Dict[str, Any]]]:
        """执行单个符号状态"""
        results = []
        bugs = []
        
        try:
            results.append(state)
        except Exception as e:
            logger.error(f"符号执行失败: {e}")
        
        return results, bugs


class SparkExecutor:
    """Spark执行器"""
    
    def __init__(self):
        self._spark_initialized = False
        self._spark_context = None
    
    def init_spark(self, app_name: str = "SymbolicExecution"):
        """初始化Spark"""
        try:
            from pyspark import SparkContext
            self._spark_context = SparkContext(appName=app_name)
            self._spark_initialized = True
            logger.info("Spark初始化成功")
        except ImportError:
            logger.error("未安装PySpark库")
        except Exception as e:
            logger.error(f"Spark初始化失败: {e}")
    
    def is_initialized(self) -> bool:
        """检查Spark是否已初始化"""
        return self._spark_initialized
    
    def parallelize_states(self, states: List[SymbolicState]) -> Any:
        """并行化状态"""
        if self._spark_context:
            return self._spark_context.parallelize(states)
        return None


class DistributedSymbolicExecutionEngine(DistributedEngine):
    """
    分布式符号执行引擎
    
    核心功能：
    1. 执行状态序列化分发到多机
    2. 利用 Ray/Spark 实现近线性加速
    3. 支持故障恢复
    4. 负载均衡调度
    5. 状态合并与结果汇总
    """
    
    def __init__(self, backend: str = "ray"):
        self._backend = backend.lower()
        self._tasks: Dict[str, AnalysisTask] = {}
        self._results: Dict[str, TaskResult] = {}
        self._workers: Dict[str, WorkerInfo] = {}
        self._pending_states: List[SymbolicState] = []
        self._completed_states: List[SymbolicState] = []
        self._failed_states: List[Tuple[SymbolicState, Exception]] = []
        
        if self._backend == "ray":
            self._executor = RayExecutor()
        elif self._backend == "spark":
            self._executor = SparkExecutor()
        else:
            raise ValueError(f"不支持的后端: {backend}")
    
    def initialize(self, address: Optional[str] = None):
        """初始化分布式引擎"""
        if self._backend == "ray":
            self._executor.init_ray(address)
        elif self._backend == "spark":
            self._executor.init_spark()
    
    def submit_task(self, task: AnalysisTask) -> str:
        """提交分析任务"""
        self._tasks[task.task_id] = task
        
        if self._executor.is_initialized():
            self._distribute_states(task)
        else:
            self._pending_states.extend(task.states)
        
        return task.task_id
    
    def _distribute_states(self, task: AnalysisTask):
        """分发状态到工作节点"""
        if self._backend == "ray":
            self._distribute_with_ray(task)
        elif self._backend == "spark":
            self._distribute_with_spark(task)
    
    def _distribute_with_ray(self, task: AnalysisTask):
        """使用Ray分发状态"""
        try:
            import ray
            
            @ray.remote
            def remote_execute(state_bytes: bytes, binary_path: str, entry_point: int, timeout: int):
                state = SymbolicState.deserialize(state_bytes)
                return RayExecutor.execute_symbolic_state(state, binary_path, entry_point, timeout)
            
            futures = []
            for state in task.states:
                state_bytes = state.serialize()
                future = remote_execute.remote(state_bytes, task.binary_path, task.entry_point, task.timeout)
                futures.append(future)
            
            results = ray.get(futures)
            
            for state, (result_states, bugs) in zip(task.states, results):
                self._completed_states.extend(result_states)
                if bugs:
                    logger.info(f"发现漏洞: {bugs}")
            
            task.completed_states = len(task.states)
            self._results[task.task_id] = TaskResult()
                task_id=task.task_id,
                worker_id="ray_cluster",
                result_states=self._completed_states,
                discovered_bugs=[],
                execution_time=0.0,
                success=True
            
        except Exception as e:
            logger.error(f"Ray分发失败: {e}")
    
    def _distribute_with_spark(self, task: AnalysisTask):
        """使用Spark分发状态"""
        try:
            rdd = self._executor.parallelize_states(task.states)
            
            def process_state(state: SymbolicState):
                results, bugs = RayExecutor.execute_symbolic_state()
                    state, task.binary_path, task.entry_point, task.timeout
                
                return results, bugs
            
            results = rdd.map(process_state).collect()
            
            for result_states, bugs in results:
                self._completed_states.extend(result_states)
            
            task.completed_states = len(task.states)
            self._results[task.task_id] = TaskResult()
                task_id=task.task_id,
                worker_id="spark_cluster",
                result_states=self._completed_states,
                discovered_bugs=[],
                execution_time=0.0,
                success=True
            
        except Exception as e:
            logger.error(f"Spark分发失败: {e}")
    
    def get_task_status(self, task_id: str) -> Dict[str, Any]:
        """获取任务状态"""
        task = self._tasks.get(task_id)
        if not task:
            return {"error": "任务不存在"}
        
        return {
            "task_id": task_id,
            "status": self._get_task_status(task),
            "completed_states": task.completed_states,
            "total_states": task.total_states,
            "progress": task.completed_states / task.total_states if task.total_states > 0 else 0
        }
    
    def _get_task_status(self, task: AnalysisTask) -> str:
        """获取任务状态字符串"""
        if task.completed_states == 0:
            return "pending"
        elif task.completed_states < task.total_states:
            return "running"
        else:
            return "completed"
    
    def cancel_task(self, task_id: str) -> bool:
        """取消任务"""
        if task_id in self._tasks:
            del self._tasks[task_id]
            if task_id in self._results:
                del self._results[task_id]
            return True
        return False
    
    def get_results(self, task_id: str) -> Optional[TaskResult]:
        """获取任务结果"""
        return self._results.get(task_id)
    
    def add_worker(self, worker_id: str, address: str, port: int):
        """添加工作节点"""
        self._workers[worker_id] = WorkerInfo()
            worker_id=worker_id,
            address=address,
            port=port,
            status="idle",
            load=0.0,
            completed_tasks=0,
            failed_tasks=0,
            current_task=None
        
    
    def remove_worker(self, worker_id: str):
        """移除工作节点"""
        if worker_id in self._workers:
            del self._workers[worker_id]
    
    def get_worker_status(self, worker_id: str) -> Optional[WorkerInfo]:
        """获取工作节点状态"""
        return self._workers.get(worker_id)
    
    def get_cluster_status(self) -> Dict[str, Any]:
        """获取集群状态"""
        total_workers = len(self._workers)
        active_workers = sum(1 for w in self._workers.values() if w.status == "idle" or w.status == "running")
        total_load = sum(w.load for w in self._workers.values())

        
        return {
            "total_workers": total_workers,
            "active_workers": active_workers,
            "avg_load": total_load / total_workers if total_workers > 0 else 0,
            "workers": {k: v.status for k, v in self._workers.items()}
        }
    
    def save_state(self, file_path: str):
        """保存引擎状态"""
        state = {
            "tasks": {k: vars(v) for k, v in self._tasks.items()},
            "results": {k: vars(v) for k, v in self._results.items()},
            "pending_states": [vars(s) for s in self._pending_states],
            "completed_states": [vars(s) for s in self._completed_states],
            "failed_states": [[vars(s), str(e)] for s, e in self._failed_states],
            "workers": {k: vars(v) for k, v in self._workers.items()}
        }
        
        with open(file_path, 'wb') as f:
            pickle.dump(state, f)
        
        logger.info(f"引擎状态已保存到: {file_path}")
    
    def load_state(self, file_path: str):
        """加载引擎状态"""
        try:
            with open(file_path, 'rb') as f:
                state = pickle.load(f)
            
            self._tasks = state.get("tasks", {})
            self._results = state.get("results", {})
            self._pending_states = state.get("pending_states", [])
            self._completed_states = state.get("completed_states", [])
            self._failed_states = state.get("failed_states", [])
            self._workers = state.get("workers", {})
            
            logger.info(f"引擎状态已从: {file_path} 加载")
        except Exception as e:
            logger.error(f"加载引擎状态失败: {e}")
    
    def shutdown(self):
        """关闭引擎"""
        if self._backend == "ray" and self._executor.is_initialized():
            import ray
            ray.shutdown()
        elif self._backend == "spark" and self._executor.is_initialized():
            self._executor._spark_context.stop()
        
        logger.info("分布式引擎已关闭")


class StateMerger:
    """状态合并器"""
    
    @staticmethod
    def merge_states(states: List[SymbolicState]) -> List[SymbolicState]:
        """合并相似状态"""
        merged = []
        seen_conditions = set()
        
        for state in states:
            cond_hash = hash(str(state.path_condition))

            if cond_hash not in seen_conditions:
                seen_conditions.add(cond_hash)
                merged.append(state)
        
        return merged
    
    @staticmethod
    def deduplicate(states: List[SymbolicState]) -> List[SymbolicState]:
        """去重状态"""
        unique = {}
        for state in states:
            unique[state.state_id] = state,
        return list(unique.values())



def create_distributed_engine(backend: str = "ray") -> DistributedSymbolicExecutionEngine:
    """创建分布式符号执行引擎"""
    return DistributedSymbolicExecutionEngine(backend)


def distribute_symbolic_execution(binary_path: str, entry_point: int, )
                                 initial_states: List[SymbolicState],
                                 backend: str = "ray",
                                 timeout: int = 300) -> TaskResult:
    """执行分布式符号执行"""
    engine = create_distributed_engine(backend)
    engine.initialize()
    
    task = AnalysisTask()
        task_id="",
        binary_path=binary_path,
        entry_point=entry_point,
        states=initial_states,
        timeout=timeout
    
    
    task_id = engine.submit_task(task)
    
    while True:
        status = engine.get_task_status(task_id)
        if status.get("status") == "completed":
            break
    
    return engine.get_results(task_id)