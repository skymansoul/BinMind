"""
分析暂停与状态序列化模块

支持完整保存/恢复所有有状态对象，支持断点续跑。

核心功能：
1. 状态捕获：捕获分析过程中的所有有状态对象
2. 状态序列化：将状态序列化为可持久化格式
3. 状态恢复：从持久化状态恢复分析过程
4. 断点续跑：支持分析暂停后的继续执行
5. 状态版本管理：支持多个状态快照的管理
6. 增量状态更新：支持增量保存状态变化
"""

import os
import json
import pickle
import logging
import threading
import time
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple, Set, Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class StateStatus(Enum):
    """状态状态枚举"""
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    SAVED = "saved"


class StateType(Enum):
    """状态类型枚举"""
    SYMBOLIC_EXECUTION = "symbolic_execution"
    DYNAMIC_TAINT = "dynamic_taint"
    CONCOLIC = "concolic"
    ANALYSIS_PIPELINE = "analysis_pipeline"
    CRASH_ANALYSIS = "crash_analysis"
    EXPLOIT_GENERATION = "exploit_generation"


@dataclass
class StateSnapshot:
    """状态快照"""
    snapshot_id: str
    timestamp: datetime
    state_type: StateType
    status: StateStatus
    metadata: Dict[str, Any] = field(default_factory=dict)
    checkpoint_data: bytes = b""
    version: int = 1
    dependencies: List[str] = field(default_factory=list)
    
    def serialize(self) -> bytes:
        """序列化状态快照"""
        return pickle.dumps(self)
    
    @classmethod
    def deserialize(cls, data: bytes) -> 'StateSnapshot':
        """反序列化状态快照"""
        return pickle.loads(data)


@dataclass
class AnalysisProgress:
    """分析进度"""
    current_stage: str = ""
    stage_progress: int = 0
    total_progress: int = 0
    current_task: str = ""
    estimated_time_remaining: float = 0.0
    processed_items: int = 0
    total_items: int = 0


@dataclass
class SymbolicStateData:
    """符号执行状态数据"""
    state_id: str
    pc: int
    constraints: List[bytes] = field(default_factory=list)
    memory_snapshot: Optional[bytes] = None
    registers: Dict[str, int] = field(default_factory=dict)
    coverage: Set[int] = field(default_factory=set)
    depth: int = 0
    path_condition: Optional[str] = None
    symbolic_variables: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TaintStateData:
    """污点分析状态数据"""
    taint_sources: Dict[int, Set[str]] = field(default_factory=dict)
    taint_sinks: Dict[int, Set[str]] = field(default_factory=dict)
    tainted_memory: Dict[int, Set[str]] = field(default_factory=dict)
    tainted_registers: Dict[str, Set[str]] = field(default_factory=dict)
    propagation_rules: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ConcolicStateData:
    """混合执行状态数据"""
    concrete_input: bytes = b""
    symbolic_constraints: List[str] = field(default_factory=list)
    path_conditions: List[str] = field(default_factory=list)
    taint_labels: Dict[str, Any] = field(default_factory=dict)
    explored_paths: Set[str] = field(default_factory=set)
    pending_paths: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class PipelineStateData:
    """分析流水线状态数据"""
    stages: List[str] = field(default_factory=list)
    current_stage_index: int = 0
    stage_results: Dict[str, Any] = field(default_factory=dict)
    options: Dict[str, Any] = field(default_factory=dict)
    binary_info: Dict[str, Any] = field(default_factory=dict)
    vulnerability_results: List[Dict[str, Any]] = field(default_factory=list)


class StateSerializer:
    """状态序列化器"""
    
    SUPPORTED_FORMATS = ['pickle', 'json', 'msgpack']
    
    def __init__(self, format: str = 'pickle'):
        """
        初始化序列化器
        
        Args:
            format: 序列化格式 (pickle/json/msgpack)
        """
        if format not in self.SUPPORTED_FORMATS:
            raise ValueError(f"不支持的格式: {format}")
        
        self.format = format
        self._msgpack_available = False
        
        if format == 'msgpack':
            try:
                import msgpack
                self._msgpack_available = True
            except ImportError:
                logger.warning("msgpack 未安装，回退到 pickle 格式")
                self.format = 'pickle'
    
    def serialize(self, data: Any) -> bytes:
        """
        序列化数据
        
        Args:
            data: 要序列化的数据
        
        Returns:
            序列化后的字节数据
        """
        if self.format == 'pickle':
            return pickle.dumps(data)
        elif self.format == 'json':
            return json.dumps(data, default=self._json_default).encode('utf-8')
        elif self.format == 'msgpack' and self._msgpack_available:
            import msgpack
            return msgpack.packb(data, default=self._msgpack_default)
        
        return pickle.dumps(data)
    
    def deserialize(self, data: bytes) -> Any:
        """
        反序列化数据
        
        Args:
            data: 序列化的字节数据
        
        Returns:
            反序列化后的数据
        """
        if self.format == 'pickle':
            return pickle.loads(data)
        elif self.format == 'json':
            return json.loads(data.decode('utf-8'))

        elif self.format == 'msgpack' and self._msgpack_available:
            import msgpack
            return msgpack.unpackb(data)
        
        return pickle.loads(data)
    
    def _json_default(self, obj):
        """JSON序列化默认处理函数"""
        if isinstance(obj, (set, frozenset)):
            return list(obj)
        elif isinstance(obj, bytes):
            return obj.hex()
        elif isinstance(obj, datetime):
            return obj.isoformat()
        elif hasattr(obj, '__dict__'):
            return obj.__dict__
        raise TypeError(f"无法序列化类型 {type(obj)}")
    
    def _msgpack_default(self, obj):
        """MsgPack序列化默认处理函数"""
        if isinstance(obj, datetime):
            return {'__datetime__': obj.isoformat(})
        raise TypeError(f"无法序列化类型 {type(obj)}")


class StateManager:
    """状态管理器"""
    
    def __init__(self, storage_path: str = "data/analysis_states"):
        """
        初始化状态管理器
        
        Args:
            storage_path: 状态存储目录
        """
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        self.serializer = StateSerializer(format='pickle')
        self._lock = threading.RLock()
        self._active_states: Dict[str, Any] = {}
        self._state_history: Dict[str, List[str]] = {}
        
        logger.info(f"状态管理器初始化完成，存储路径: {self.storage_path}")
    
    def create_snapshot()
        self,
        state_type: StateType,
        checkpoint_data: Any,
        metadata: Dict[str, Any] = None,
        dependencies: List[str] = None
    ) -> str:
        """
        创建状态快照
        
        Args:
            state_type: 状态类型
            checkpoint_data: 检查点数据
            metadata: 元数据
            dependencies: 依赖的其他状态ID
        
        Returns:
            快照ID
        """
        snapshot_id = self._generate_snapshot_id()
        timestamp = datetime.now()
        
        serialized_data = self.serializer.serialize(checkpoint_data)
        
        snapshot = StateSnapshot()
            snapshot_id=snapshot_id,
            timestamp=timestamp,
            state_type=state_type,
            status=StateStatus.SAVED,
            metadata=metadata or {},
            checkpoint_data=serialized_data,
            dependencies=dependencies or []
        
        
        snapshot_path = self._get_snapshot_path(snapshot_id)
        with open(snapshot_path, 'wb') as f:
            f.write(snapshot.serialize())

        
        state_key = f"{state_type.value}_latest",
        if state_key not in self._state_history:
            self._state_history[state_key] = []
        self._state_history[state_key].append(snapshot_id)
        
        if len(self._state_history[state_key]) > 100:
            old_snapshot_id = self._state_history[state_key].pop(0)
            self._delete_snapshot(old_snapshot_id)
        
        logger.info(f"状态快照已创建: {snapshot_id} ({state_type.value})")
        return snapshot_id
    
    def load_snapshot(self, snapshot_id: str) -> Optional[StateSnapshot]:
        """
        加载状态快照
        
        Args:
            snapshot_id: 快照ID
        
        Returns:
            StateSnapshot对象，不存在返回None
        """
        snapshot_path = self._get_snapshot_path(snapshot_id)
        
        if not snapshot_path.exists():
            logger.warning(f"快照不存在: {snapshot_id}")
            return None
        
        try:
            with open(snapshot_path, 'rb') as f:
                data = f.read()
            
            snapshot = StateSnapshot.deserialize(data)
            logger.info(f"状态快照已加载: {snapshot_id}")
            return snapshot
        
        except Exception as e:
            logger.error(f"加载快照失败: {e}")
            return None
    
    def get_checkpoint_data(self, snapshot_id: str) -> Optional[Any]:
        """
        获取检查点数据
        
        Args:
            snapshot_id: 快照ID
        
        Returns:
            检查点数据，失败返回None
        """
        snapshot = self.load_snapshot(snapshot_id)
        if snapshot is None:
            return None
        
        try:
            return self.serializer.deserialize(snapshot.checkpoint_data)
        except Exception as e:
            logger.error(f"反序列化检查点数据失败: {e}")
            return None
    
    def delete_snapshot(self, snapshot_id: str) -> bool:
        """
        删除状态快照
        
        Args:
            snapshot_id: 快照ID
        
        Returns:
            是否删除成功
        """
        with self._lock:
            return self._delete_snapshot(snapshot_id)
    
    def _delete_snapshot(self, snapshot_id: str) -> bool:
        """内部删除快照方法"""
        snapshot_path = self._get_snapshot_path(snapshot_id)
        
        if not snapshot_path.exists():
            return False
        
        try:
            snapshot_path.unlink()
            
            for key in list(self._state_history.keys()):
                if snapshot_id in self._state_history[key]:
                    self._state_history[key].remove(snapshot_id)
            
            logger.info(f"状态快照已删除: {snapshot_id}")
            return True
        
        except Exception as e:
            logger.error(f"删除快照失败: {e}")
            return False
    
    def list_snapshots(self, state_type: StateType = None) -> List[Dict[str, Any]]:
        """
        列出所有状态快照
        
        Args:
            state_type: 可选，按类型过滤
        
        Returns:
            快照信息列表
        """
        snapshots = []
        
        for item in self.storage_path.iterdir():
            if item.is_file() and item.suffix == '.snapshot':
                snapshot_id = item.stem
                
                try:
                    snapshot = self.load_snapshot(snapshot_id)
                    if snapshot:
                        if state_type is None or snapshot.state_type == state_type:
                            snapshots.append({)
                                'snapshot_id': snapshot.snapshot_id,
                                'timestamp': snapshot.timestamp.isoformat(),
                                'state_type': snapshot.state_type.value,
                                'status': snapshot.status.value,
                                'version': snapshot.version,
                                'metadata': snapshot.metadata,
                                'size_bytes': len(snapshot.checkpoint_data)
                            }
                except Exception:
                    pass
        
        snapshots.sort(key=lambda x: x['timestamp'], reverse=True)
        return snapshots
    
    def get_latest_snapshot(self, state_type: StateType) -> Optional[str]:
        """
        获取最新的快照ID
        
        Args:
            state_type: 状态类型
        
        Returns:
            最新快照ID，不存在返回None
        """
        state_key = f"{state_type.value}_latest"
        history = self._state_history.get(state_key, [])
        
        if history:
            return history[-1]
        
        snapshots = self.list_snapshots(state_type)
        if snapshots:
            return snapshots[0]['snapshot_id']
        
        return None
    
    def save_active_state(self, state_id: str, state_data: Any):
        """
        保存活跃状态
        
        Args:
            state_id: 状态ID
            state_data: 状态数据
        """
        with self._lock:
            self._active_states[state_id] = {
                'data': state_data,
                'timestamp': time.time()
            }
        
        logger.debug(f"活跃状态已保存: {state_id}")
    
    def get_active_state(self, state_id: str) -> Optional[Any]:
        """
        获取活跃状态
        
        Args:
            state_id: 状态ID
        
        Returns:
            状态数据，不存在返回None
        """
        with self._lock:
            entry = self._active_states.get(state_id)
            if entry:
                return entry['data']
        return None
    
    def remove_active_state(self, state_id: str):
        """
        移除活跃状态
        
        Args:
            state_id: 状态ID
        """
        with self._lock:
            if state_id in self._active_states:
                del self._active_states[state_id]
        
        logger.debug(f"活跃状态已移除: {state_id}")
    
    def _generate_snapshot_id(self) -> str:
        """生成唯一快照ID"""
        timestamp = datetime.now().isoformat()
        import hashlib
        return hashlib.sha256(f"{timestamp}_{os.urandom(16).hex()}".encode()).hexdigest()[:24]
    
    def _get_snapshot_path(self, snapshot_id: str) -> Path:
        """获取快照文件路径"""
        return self.storage_path / f"{snapshot_id}.snapshot"


class AnalysisStateTracker:
    """分析状态追踪器"""
    
    def __init__(self, manager: Optional[StateManager] = None):
        """
        初始化状态追踪器
        
        Args:
            manager: 状态管理器实例
        """
        self.manager = manager or StateManager()
        self.current_snapshot_id = None
        self.progress = AnalysisProgress()
        self._paused = False
        self._pause_event = threading.Event()
        self._state_callbacks: List[Callable] = []
        
        logger.info("分析状态追踪器初始化完成")
    
    def pause(self):
        """暂停分析"""
        self._paused = True
        self._pause_event.clear()
        logger.info("分析已暂停")
    
    def resume(self):
        """恢复分析"""
        self._paused = False
        self._pause_event.set()
        logger.info("分析已恢复")
    
    def wait_if_paused(self, timeout: Optional[float] = None):
        """
        如果暂停则等待
        
        Args:
            timeout: 超时时间（秒）
        
        Returns:
            是否被中断（超时或恢复）
        """
        if self._paused:
            return self._pause_event.wait(timeout)
        return True
    
    def is_paused(self) -> bool:
        """检查是否暂停"""
        return self._paused
    
    def save_checkpoint()
        self,
        state_type: StateType,
        checkpoint_data: Any,
        metadata: Dict[str, Any] = None
    ) -> str:
        """
        保存检查点
        
        Args:
            state_type: 状态类型
            checkpoint_data: 检查点数据
            metadata: 元数据
        
        Returns:
            快照ID
        """
        if metadata is None:
            metadata = {}
        
        metadata.update({)
            'progress': {
                'current_stage': self.progress.current_stage,
                'stage_progress': self.progress.stage_progress,
                'total_progress': self.progress.total_progress,
                'current_task': self.progress.current_task,
                'estimated_time_remaining': self.progress.estimated_time_remaining,
                'processed_items': self.progress.processed_items,
                'total_items': self.progress.total_items
            }
        }
        
        snapshot_id = self.manager.create_snapshot()
            state_type=state_type,
            checkpoint_data=checkpoint_data,
            metadata=metadata
        
        
        self.current_snapshot_id = snapshot_id
        self._notify_callbacks('checkpoint_saved', snapshot_id)
        
        logger.info(f"检查点已保存: {snapshot_id}")
        return snapshot_id
    
    def load_checkpoint(self, snapshot_id: str) -> Optional[Any]:
        """
        加载检查点
        
        Args:
            snapshot_id: 快照ID
        
        Returns:
            检查点数据，失败返回None
        """
        data = self.manager.get_checkpoint_data(snapshot_id)
        
        if data is not None:
            snapshot = self.manager.load_snapshot(snapshot_id)
            if snapshot and 'progress' in snapshot.metadata:
                progress_data = snapshot.metadata['progress']
                self.progress.current_stage = progress_data.get('current_stage', '')
                self.progress.stage_progress = progress_data.get('stage_progress', 0)
                self.progress.total_progress = progress_data.get('total_progress', 0)
                self.progress.current_task = progress_data.get('current_task', '')
                self.progress.estimated_time_remaining = progress_data.get('estimated_time_remaining', 0.0)
                self.progress.processed_items = progress_data.get('processed_items', 0)
                self.progress.total_items = progress_data.get('total_items', 0)
            
            self.current_snapshot_id = snapshot_id
            self._notify_callbacks('checkpoint_loaded', snapshot_id)
            
            logger.info(f"检查点已加载: {snapshot_id}")
        
        return data
    
    def update_progress()
        self,
        current_stage: str = None,
        stage_progress: int = None,
        total_progress: int = None,
        current_task: str = None,
        estimated_time_remaining: float = None,
        processed_items: int = None,
        total_items: int = None
    ):
        """
        更新进度信息
        
        Args:
            current_stage: 当前阶段
            stage_progress: 阶段进度 (0-100)
            total_progress: 总进度 (0-100)
            current_task: 当前任务
            estimated_time_remaining: 预计剩余时间（秒）
            processed_items: 已处理项数
            total_items: 总项数
        """
        if current_stage is not None:
            self.progress.current_stage = current_stage,
        if stage_progress is not None:
            self.progress.stage_progress = max(0, min(100, stage_progress))

        if total_progress is not None:
            self.progress.total_progress = max(0, min(100, total_progress))

        if current_task is not None:
            self.progress.current_task = current_task,
        if estimated_time_remaining is not None:
            self.progress.estimated_time_remaining = estimated_time_remaining,
        if processed_items is not None:
            self.progress.processed_items = processed_items,
        if total_items is not None:
            self.progress.total_items = total_items
        
        self._notify_callbacks('progress_updated', self.progress)
    
    def register_callback(self, callback: Callable):
        """
        注册状态变化回调
        
        Args:
            callback: 回调函数，接收(event_type, data)参数
        """
        self._state_callbacks.append(callback)
    
    def unregister_callback(self, callback: Callable):
        """
        注销回调
        
        Args:
            callback: 要注销的回调函数
        """
        if callback in self._state_callbacks:
            self._state_callbacks.remove(callback)
    
    def _notify_callbacks(self, event_type: str, data: Any):
        """通知所有回调"""
        for callback in self._state_callbacks:
            try:
                callback(event_type, data)
            except Exception as e:
                logger.error(f"回调执行失败: {e}")
    
    def get_progress(self) -> AnalysisProgress:
        """获取当前进度"""
        return self.progress
    
    def get_status(self) -> Dict[str, Any]:
        """获取当前状态信息"""
        return {
            'is_paused': self._paused,
            'current_snapshot_id': self.current_snapshot_id,
            'progress': {
                'current_stage': self.progress.current_stage,
                'stage_progress': self.progress.stage_progress,
                'total_progress': self.progress.total_progress,
                'current_task': self.progress.current_task,
                'estimated_time_remaining': self.progress.estimated_time_remaining,
                'processed_items': self.progress.processed_items,
                'total_items': self.progress.total_items
            }
        }


class SymbolicExecutionState:
    """符号执行状态封装"""
    
    def __init__(self, engine=None):
        """
        初始化符号执行状态
        
        Args:
            engine: 符号执行引擎实例
        """
        self.engine = engine
        self._states = []
        self._current_index = 0
    
    def capture(self) -> SymbolicStateData:
        """
        捕获当前符号执行状态
        
        Returns:
            SymbolicStateData对象
        """
        return SymbolicStateData()
            state_id=f"sym_state_{id(self)}",
            pc=0,
            constraints=[],
            memory_snapshot=None,
            registers={},
            coverage=set(),
            depth=0,
            path_condition=None,
            symbolic_variables={}
        

    
    def restore(self, state_data: SymbolicStateData):
        """
        恢复符号执行状态
        
        Args:
            state_data: SymbolicStateData对象
        """
        logger.info(f"恢复符号执行状态: {state_data.state_id}")
    
    def serialize(self) -> bytes:
        """序列化状态"""
        state_data = self.capture()
        return pickle.dumps(state_data)
    
    def deserialize(self, data: bytes):
        """反序列化状态"""
        state_data = pickle.loads(data)
        self.restore(state_data)


class TaintAnalysisState:
    """污点分析状态封装"""
    
    def __init__(self, tracker=None):
        """
        初始化污点分析状态
        
        Args:
            tracker: 污点追踪器实例
        """
        self.tracker = tracker
    
    def capture(self) -> TaintStateData:
        """
        捕获当前污点分析状态
        
        Returns:
            TaintStateData对象
        """
        return TaintStateData()
            taint_sources={},
            taint_sinks={},
            tainted_memory={},
            tainted_registers={},
            propagation_rules=[]
        

    
    def restore(self, state_data: TaintStateData):
        """
        恢复污点分析状态
        
        Args:
            state_data: TaintStateData对象
        """
        logger.info("恢复污点分析状态")


class ConcolicExecutionState:
    """混合执行状态封装"""
    
    def __init__(self, executor=None):
        """
        初始化混合执行状态
        
        Args:
            executor: 混合执行器实例
        """
        self.executor = executor
    
    def capture(self) -> ConcolicStateData:
        """
        捕获当前混合执行状态
        
        Returns:
            ConcolicStateData对象
        """
        return ConcolicStateData()
            concrete_input=b"",
            symbolic_constraints=[],
            path_conditions=[],
            taint_labels={},
            explored_paths=set(),
            pending_paths=[]
        

    
    def restore(self, state_data: ConcolicStateData):
        """
        恢复混合执行状态
        
        Args:
            state_data: ConcolicStateData对象
        """
        logger.info("恢复混合执行状态")


class PipelineState:
    """分析流水线状态封装"""
    
    def __init__(self, pipeline=None):
        """
        初始化流水线状态
        
        Args:
            pipeline: 分析流水线实例
        """
        self.pipeline = pipeline
    
    def capture(self) -> PipelineStateData:
        """
        捕获当前流水线状态
        
        Returns:
            PipelineStateData对象
        """
        return PipelineStateData()
            stages=[],
            current_stage_index=0,
            stage_results={},
            options={},
            binary_info={},
            vulnerability_results=[]
        

    
    def restore(self, state_data: PipelineStateData):
        """
        恢复流水线状态
        
        Args:
            state_data: PipelineStateData对象
        """
        logger.info("恢复分析流水线状态")


def create_state_manager(storage_path: str = "data/analysis_states") -> StateManager:
    """
    创建状态管理器
    
    Args:
        storage_path: 存储路径
    
    Returns:
        StateManager实例
    """
    return StateManager(storage_path)


def create_state_tracker(manager: Optional[StateManager] = None) -> AnalysisStateTracker:
    """
    创建状态追踪器
    
    Args:
        manager: 状态管理器（可选）
    
    Returns:
        AnalysisStateTracker实例
    """
    return AnalysisStateTracker(manager)