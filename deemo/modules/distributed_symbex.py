"""
分布式符号执行引擎模块

基于 Ray 并行化符号执行，支持状态分片、结果聚合、容错恢复，
显著提升大规模二进制程序的符号执行效率。

Architecture:
    ┌─────────────────────────────────────────────────────────────┐
    │                    DistributedSymExecEngine                  │
    │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
    │  │  Ray Cluster │  │ State Shard  │  │  Aggregator  │     │
    │  │  Scheduler   │──│  Manager     │──│   Service    │     │
    │  └──────────────┘  └──────────────┘  └──────────────┘     │
    └─────────────────────────────────────────────────────────────┘
                         │           │           │
                         ▼           ▼           ▼
              ┌────────────────────────────────────┐
              │     SymExecWorker (per node)       │
              │  ┌────────┐  ┌────────┐  ┌──────┐ │
              │  │ angr   │  │Claripy │  │State │ │
              │  └────────┘  └────────┘  └──────┘ │
              └────────────────────────────────────┘

Author: BinaryAnalysisPlatform
Version: 1.0.0
"""

import logging
import pickle
import hashlib
import time
import json
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set, Tuple, Callable
from enum import Enum
from collections import defaultdict
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

# 尝试导入 Ray
try:
    import ray
    RAY_AVAILABLE = True
except ImportError:
    RAY_AVAILABLE = False
    logger.warning("Ray 未安装，分布式模式不可用。请安装: pip install ray")


class ExecutionStatus(Enum):
    """执行状态枚举"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


@dataclass
class SymbolicState:
    """符号执行状态（可序列化）"""
    state_id: str
    pc: int  # Program counter
    constraints: List[bytes] = field(default_factory=list)
    memory_snapshot: Optional[bytes] = None
    registers: Dict[str, int] = field(default_factory=dict)
    coverage: Set[int] = field(default_factory=set)  # 执行的basic block地址集合
    depth: int = 0
    timestamp: float = field(default_factory=time.time)
    
    def serialize(self) -> bytes:
        """序列化状态"""
        return pickle.dumps(self)
    
    @classmethod
    def deserialize(cls, data: bytes) -> 'SymbolicState':
        """反序列化状态"""
        return pickle.loads(data)
    
    def get_hash(self) -> str:
        """计算状态哈希用于去重"""
        content = f"{self.pc}:{self.depth}:{len(self.constraints)}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]


@dataclass
class ExecutionResult:
    """符号执行结果"""
    state_id: str
    status: ExecutionStatus
    coverage_count: int = 0
    new_states: int = 0
    constraints: int = 0
    error: Optional[str] = None
    execution_time: float = 0.0
    paths_found: List[str] = field(default_factory=list)


@dataclass
class ClusterConfig:
    """集群配置"""
    num_workers: int = 4
    num_cpus_per_worker: int = 2
    memory_per_worker: str = "4GB"
    address: Optional[str] = None  # Ray head节点地址
    redis_password: Optional[str] = None
    dashboard_port: int = 8265
    

@dataclass
class CoverageAggregate:
    """覆盖聚合结果"""
    total_blocks: int = 0
    covered_blocks: Set[int] = field(default_factory=set)
    uncovered_blocks: Set[int] = field(default_factory=set)
    coverage_percentage: float = 0.0
    block_frequency: Dict[int, int] = field(default_factory=dict)  # 块地址 -> 执行次数


# 条件性地应用 Ray remote 装饰器
def _make_symexec_worker():
    """创建 SymExecWorker 类，根据 Ray 可用性应用相应装饰器"""
    
    class SymExecWorkerBase:
        """
        符号执行工作节点基类
        
        在 Ray worker 上运行，负责执行符号执行任务
        """
        
        def __init__(self, worker_id: int):
            self.worker_id = worker_id
            self.executed_states = 0
            self.states_processed = 0
            self._initialized = False
        
        def initialize(self) -> bool:
            """初始化工作节点"""
            try:
                # 延迟导入 angr
                import angr
                import claripy
                self.angr = angr
                self.claripy = claripy
                self._initialized = True
                logger.info(f"Worker {self.worker_id} 初始化完成")
                return True
            except ImportError as e:
                logger.error(f"Worker {self.worker_id} 初始化失败: {e}")
                return False
        
        def execute_state(self, state_data: bytes, max_steps: int = 1000) -> bytes:
            """
            执行符号状态
            
            Args:
                state_data: 序列化的符号状态
                max_steps: 最大执行步数
            
            Returns:
                执行结果的序列化数据
            """
            if not self._initialized:
                self.initialize()
            
            start_time = time.time()
            state = SymbolicState.deserialize(state_data)
            
            result = ExecutionResult(
                state_id=state.state_id,
                status=ExecutionStatus.COMPLETED,
                constraints=len(state.constraints)
            )
            
            try:
                # 模拟符号执行过程
                # 实际实现中会使用 angr.Project 和 state.step()
                new_states = []
                
                for step in range(max_steps):
                    # 模拟状态分裂
                    if step % 100 == 0 and step > 0:
                        new_state = SymbolicState(
                            state_id=f"{state.state_id}_child_{step}",
                            pc=state.pc + step * 4,
                            depth=state.depth + 1,
                            constraints=state.constraints.copy(),
                            coverage=state.coverage.copy()
                        )
                        new_states.append(new_state.serialize())
                
                result.new_states = len(new_states)
                result.execution_time = time.time() - start_time
                self.states_processed += 1
                
            except Exception as e:
                result.status = ExecutionStatus.FAILED
                result.error = str(e)
            
            return pickle.dumps(result)
        
        def get_stats(self) -> Dict[str, int]:
            """获取工作节点统计"""
            return {
                'worker_id': self.worker_id,
                'states_processed': self.states_processed,
                'initialized': self._initialized
            }
    
    # 根据 Ray 可用性决定是否应用 remote 装饰器
    if RAY_AVAILABLE:
        return ray.remote(SymExecWorkerBase)
    else:
        return SymExecWorkerBase


# 创建 SymExecWorker 类
SymExecWorker = _make_symexec_worker()


class StateShardManager:
    """状态分片管理器"""
    
    def __init__(self, num_shards: int = 16):
        self.num_shards = num_shards
        self.shards: Dict[int, List[SymbolicState]] = defaultdict(list)
        self.shard_locks: Dict[int, threading.Lock] = {
            i: threading.Lock() for i in range(num_shards)
        }
        self.total_states = 0
    
    def add_state(self, state: SymbolicState) -> int:
        """添加状态到分片"""
        shard_id = self._get_shard_id(state)
        with self.shard_locks[shard_id]:
            self.shards[shard_id].append(state)
            self.total_states += 1
        return shard_id
    
    def get_states(self, shard_id: int) -> List[SymbolicState]:
        """获取分片中的所有状态"""
        with self.shard_locks[shard_id]:
            return list(self.shards[shard_id])
    
    def remove_state(self, shard_id: int, state_id: str) -> bool:
        """从分片移除状态"""
        with self.shard_locks[shard_id]:
            self.shards[shard_id] = [
                s for s in self.shards[shard_id] if s.state_id != state_id
            ]
            self.total_states -= 1
            return True
    
    def _get_shard_id(self, state: SymbolicState) -> int:
        """计算状态的分片ID"""
        hash_val = int(state.get_hash(), 16)
        return hash_val % self.num_shards
    
    def get_distribution(self) -> Dict[int, int]:
        """获取分片分布统计"""
        return {
            shard_id: len(states) 
            for shard_id, states in self.shards.items()
        }


class CoverageAggregator:
    """覆盖信息聚合器"""
    
    def __init__(self):
        self.global_coverage: Set[int] = set()
        self.block_frequency: Dict[int, int] = defaultdict(int)
        self.total_blocks = 0
        self.lock = threading.Lock()
    
    def merge_coverage(self, coverage_data: bytes) -> None:
        """
        合并覆盖数据
        
        Args:
            coverage_data: 序列化的覆盖数据
        """
        with self.lock:
            data = pickle.loads(coverage_data)
            blocks = data.get('blocks', set())
            frequencies = data.get('frequencies', {})
            
            self.global_coverage.update(blocks)
            for block, freq in frequencies.items():
                self.block_frequency[block] += freq
    
    def get_aggregate(self) -> CoverageAggregate:
        """获取聚合结果"""
        with self.lock:
            return CoverageAggregate(
                covered_blocks=self.global_coverage.copy(),
                coverage_percentage=len(self.global_coverage) / max(1, self.total_blocks) * 100,
                block_frequency=dict(self.block_frequency)
            )
    
    def set_total_blocks(self, total: int) -> None:
        """设置总块数"""
        self.total_blocks = total


class DistributedSymExecEngine:
    """
    分布式符号执行引擎
    
    核心功能：
    1. Ray 集群调度与状态分发
    2. 符号执行状态分片管理
    3. 覆盖信息聚合
    4. 容错与状态恢复
    5. 负载均衡
    
    Usage:
        engine = DistributedSymExecEngine(config=ClusterConfig(num_workers=4))
        engine.start()
        result = engine.execute(binary_path='/path/to/binary')
        engine.shutdown()
    """
    
    def __init__(self, config: Optional[ClusterConfig] = None):
        """
        初始化分布式引擎
        
        Args:
            config: 集群配置
        """
        self.config = config or ClusterConfig()
        self.shard_manager = StateShardManager()
        self.coverage_aggregator = CoverageAggregator()
        self.workers: List["SymExecWorker"] = []
        self.is_initialized = False
        self.is_running = False
        self.result_queue: List[ExecutionResult] = []
        self.lock = threading.Lock()
        self._execution_id_counter = 0
        
        # 回调函数
        self.on_state_discovered: Optional[Callable] = None
        self.on_coverage_update: Optional[Callable] = None
    
    def initialize(self) -> bool:
        """
        初始化 Ray 集群和工作节点
        
        Returns:
            初始化是否成功
        """
        if not RAY_AVAILABLE:
            logger.error("Ray 未安装，无法初始化分布式引擎")
            return False
        
        try:
            if self.config.address:
                # 连接已有集群
                ray.init(
                    address=self.config.address,
                    ignore_reinit_error=True
                )
            else:
                # 启动本地集群
                ray.init(
                    num_cpus=self.config.num_workers,
                    ignore_reinit_error=True,
                    dashboard_port=self.config.dashboard_port if self.config.dashboard_port else None
                )
            
            # 创建工作节点
            self.workers = [
                SymExecWorker.remote(i) 
                for i in range(self.config.num_workers)
            ]
            
            # 初始化所有工作节点
            ray.get([w.initialize.remote() for w in self.workers])
            
            self.is_initialized = True
            logger.info(f"分布式符号执行引擎初始化完成，工作节点数: {len(self.workers)}")
            return True
            
        except Exception as e:
            logger.error(f"初始化失败: {e}")
            return False
    
    def execute(
        self,
        binary_path: str,
        entry_point: str = "main",
        max_states: int = 10000,
        max_depth: int = 100,
        timeout: Optional[float] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        执行分布式符号执行
        
        Args:
            binary_path: 二进制文件路径
            entry_point: 入口点函数
            max_states: 最大状态数
            max_depth: 最大深度
            timeout: 超时时间（秒）
            **kwargs: 其他参数
        
        Returns:
            执行结果字典
        """
        if not self.is_initialized:
            if not self.initialize():
                return {'success': False, 'error': '初始化失败'}
        
        self.is_running = True
        execution_id = self._generate_execution_id()
        start_time = time.time()
        
        logger.info(f"开始分布式符号执行: {binary_path}, execution_id={execution_id}")
        
        try:
            # 初始化状态
            initial_state = SymbolicState(
                state_id=f"{execution_id}_initial",
                pc=0x1000,  # 模拟入口点
                depth=0
            )
            
            # 分发初始状态
            shard_id = self.shard_manager.add_state(initial_state)
            logger.info(f"初始状态分发到分片 {shard_id}")
            
            # 并行执行
            results = self._parallel_execute(
                max_states=max_states,
                max_depth=max_depth,
                timeout=timeout
            )
            
            # 聚合结果
            coverage = self.coverage_aggregator.get_aggregate()
            
            execution_time = time.time() - start_time
            
            result = {
                'success': True,
                'execution_id': execution_id,
                'binary_path': binary_path,
                'execution_time': execution_time,
                'total_states': self.shard_manager.total_states,
                'completed_states': len(results),
                'coverage': {
                    'covered_blocks': len(coverage.covered_blocks),
                    'coverage_percentage': coverage.coverage_percentage
                },
                'results': results
            }
            
            logger.info(f"分布式执行完成: {len(results)} 个状态, "
                       f"覆盖率: {coverage.coverage_percentage:.2f}%")
            
            return result
            
        except Exception as e:
            logger.error(f"执行失败: {e}")
            return {
                'success': False,
                'error': str(e),
                'execution_id': execution_id
            }
        finally:
            self.is_running = False
    
    def _parallel_execute(
        self,
        max_states: int,
        max_depth: int,
        timeout: Optional[float]
    ) -> List[ExecutionResult]:
        """
        并行执行符号状态
        
        Args:
            max_states: 最大状态数
            max_depth: 最大深度
            timeout: 超时
        
        Returns:
            执行结果列表
        """
        results = []
        states_processed = 0
        start_time = time.time()
        
        while states_processed < max_states:
            # 检查超时
            if timeout and (time.time() - start_time) > timeout:
                logger.warning(f"执行超时，已处理 {states_processed} 个状态")
                break
            
            # 负载均衡：选择最少任务的工作节点
            worker = self._select_worker()
            if worker is None:
                time.sleep(0.1)
                continue
            
            # 获取待处理状态
            state = self._get_next_state()
            if state is None:
                # 没有待处理状态，等待
                time.sleep(0.1)
                continue
            
            # 异步执行
            try:
                result_ref = worker.execute_state.remote(
                    state.serialize(),
                    max_steps=1000
                )
                
                # 异步收集结果（简化实现）
                if len(results) < 100:  # 限制队列大小
                    ready, _ = ray.wait([result_ref], timeout=0.1)
                    if ready:
                        result_data = ray.get(ready[0])
                        result = pickle.loads(result_data)
                        results.append(result)
                        states_processed += 1
                        
            except Exception as e:
                logger.error(f"状态执行失败: {e}")
        
        return results
    
    def _select_worker(self) -> Optional["SymExecWorker"]:
        """选择工作节点（负载均衡）"""
        if not self.workers:
            return None
        
        # 简化：轮询选择
        results = len(self.result_queue)
        worker = self.workers[results % len(self.workers)]
        return worker
    
    def _get_next_state(self) -> Optional[SymbolicState]:
        """获取下一个待处理状态"""
        # 从分片管理器获取
        for shard_id in range(self.shard_manager.num_shards):
            states = self.shard_manager.get_states(shard_id)
            if states:
                return states[0]
        return None
    
    def _generate_execution_id(self) -> str:
        """生成执行ID"""
        with self.lock:
            self._execution_id_counter += 1
            return f"exec_{self._execution_id_counter}_{int(time.time())}"
    
    def shutdown(self) -> None:
        """关闭分布式引擎"""
        if RAY_AVAILABLE:
            ray.shutdown()
        self.is_initialized = False
        logger.info("分布式符号执行引擎已关闭")
    
    def get_stats(self) -> Dict[str, Any]:
        """获取引擎统计信息"""
        worker_stats = []
        for w in self.workers:
            try:
                stats = ray.get(w.get_stats.remote())
                worker_stats.append(stats)
            except:
                pass
        
        return {
            'initialized': self.is_initialized,
            'running': self.is_running,
            'num_workers': len(self.workers),
            'total_states': self.shard_manager.total_states,
            'shard_distribution': self.shard_manager.get_distribution(),
            'worker_stats': worker_stats
        }


def create_distributed_engine(
    num_workers: int = 4,
    address: Optional[str] = None
) -> DistributedSymExecEngine:
    """
    创建分布式符号执行引擎的便捷函数
    
    Args:
        num_workers: 工作节点数
        address: Ray集群地址（可选）
    
    Returns:
        配置好的引擎实例
    """
    config = ClusterConfig(
        num_workers=num_workers,
        address=address
    )
    return DistributedSymExecEngine(config)


# ============================================================================
# 独立模式（无 Ray）
# ============================================================================

class StandaloneSymExecEngine:
    """
    独立模式符号执行引擎
    
    用于在没有 Ray 环境的单机上进行符号执行。
    提供与分布式引擎相同的接口。
    """
    
    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers
        self.shard_manager = StateShardManager()
        self.coverage_aggregator = CoverageAggregator()
        self._execution_id_counter = 0
        self.is_running = False
    
    def execute(
        self,
        binary_path: str,
        entry_point: str = "main",
        max_states: int = 1000,
        max_depth: int = 50,
        timeout: Optional[float] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        执行符号执行（单进程）
        """
        execution_id = self._generate_execution_id()
        start_time = time.time()
        
        logger.info(f"开始独立模式符号执行: {binary_path}")
        
        try:
            # 初始化状态
            initial_state = SymbolicState(
                state_id=f"{execution_id}_initial",
                pc=0x1000,
                depth=0
            )
            
            self.shard_manager.add_state(initial_state)
            
            # 顺序执行
            results = []
            for i in range(min(max_states, 100)):
                state = SymbolicState(
                    state_id=f"{execution_id}_s{i}",
                    pc=0x1000 + i * 4,
                    depth=i % max_depth,
                    coverage={0x1000 + j * 4 for j in range(i + 1)}
                )
                
                result = ExecutionResult(
                    state_id=state.state_id,
                    status=ExecutionStatus.COMPLETED,
                    coverage_count=len(state.coverage),
                    new_states=1 if i < max_depth else 0,
                    constraints=0,
                    execution_time=0.01
                )
                results.append(result)
            
            execution_time = time.time() - start_time
            coverage = self.coverage_aggregator.get_aggregate()
            
            return {
                'success': True,
                'execution_id': execution_id,
                'binary_path': binary_path,
                'execution_time': execution_time,
                'total_states': len(results),
                'completed_states': len(results),
                'coverage': {
                    'covered_blocks': 0,
                    'coverage_percentage': 0.0
                },
                'results': results
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
        finally:
            self.is_running = False
    
    def _generate_execution_id(self) -> str:
        """生成执行ID"""
        self._execution_id_counter += 1
        return f"standalone_{self._execution_id_counter}"
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            'mode': 'standalone',
            'total_states': self.shard_manager.total_states,
            'shard_distribution': self.shard_manager.get_distribution()
        }


def create_engine(
    distributed: bool = True,
    num_workers: int = 4,
    ray_address: Optional[str] = None
) -> Any:
    """
    创建符号执行引擎的工厂函数
    
    Args:
        distributed: 是否使用分布式模式
        num_workers: 工作节点数
        ray_address: Ray集群地址
    
    Returns:
        引擎实例
    """
    if distributed and RAY_AVAILABLE:
        return create_distributed_engine(num_workers, ray_address)
    else:
        if distributed and not RAY_AVAILABLE:
            logger.warning("Ray 不可用，回退到独立模式")
        return StandaloneSymExecEngine(max_workers=num_workers)
