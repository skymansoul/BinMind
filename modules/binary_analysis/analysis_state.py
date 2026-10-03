import typing
import os
import pickle
import logging
import threading
import time
import hashlib
import ast
from datetime import datetime
from pathlib import Path
from enum import Enum
from dataclasses import dataclass, field


class _Memoize:
    def __init__(self, func):
        self.func = func
        self.cache = {}

    def __call__(self, *args):
        if args not in self.cache:
            self.cache[args] = self.func(*args)
        return self.cache[args]


def _uniq(lst):
    seen = set()
    result = []
    for item in lst:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _to_plain(obj):
    if obj is None:
        return None
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, (int, float)):
        return obj
    if isinstance(obj, str):
        return obj
    if isinstance(obj, bytes):
        return {"__bytes__": obj.hex()}
    if isinstance(obj, (set, frozenset)):
        return sorted(list(obj))
    if isinstance(obj, datetime):
        return {"__datetime__": obj.isoformat()}
    if isinstance(obj, (list, tuple)):
        return [_to_plain(v) for v in obj]
    if isinstance(obj, dict):
        return {str(k): _to_plain(v) for k, v in obj.items()}
    if hasattr(obj, '__dict__') and not isinstance(obj, type):
        return {"__class__": type(obj).__name__, "__dict__": _to_plain(obj.__dict__)}
    raise TypeError(f"Cannot serialize type {type(obj).__name__}")


def _mini_dumps(obj):
    return repr(_to_plain(obj))


def _mini_loads(s):
    return ast.literal_eval(s)


__log = logging.getLogger(__name__)

SUPPORTED_FORMATS = ('pickle', 'dict', 'msgpack')
DEFAULT_STORAGE = "data/analysis_states"
MAX_HISTORY = 100
SID_LENGTH = 24


class StateStatus(str, Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    SAVED = "saved"


class StateType(str, Enum):
    SYMBOLIC_EXECUTION = "symbolic_execution"
    DYNAMIC_TAINT = "dynamic_taint"
    CONCOLIC = "concolic"
    ANALYSIS_PIPELINE = "analysis_pipeline"
    CRASH_ANALYSIS = "crash_analysis"
    EXPLOIT_GENERATION = "exploit_generation"


@dataclass
class StateSnapshot:
    snapshot_id: str
    timestamp: datetime = field(default_factory=datetime.now)
    state_type: Optional[str] = None
    status: StateStatus = StateStatus.SAVED
    metadata: dict = field(default_factory=dict)
    checkpoint_data: bytes = b''
    version: int = 1
    dependencies: list = field(default_factory=list)

    def __post_init__(self):
        if not isinstance(self.snapshot_id, str):
            raise ValueError(f"Invalid snapshot_id type: {type(self.snapshot_id).__name__}")

    def serialize_r2(self):
        return pickle.dumps(self, protocol=4)

    @classmethod
    def deserialize_r2(cls, raw_bytes):
        if raw_bytes is None or len(raw_bytes) == 0:
            return None
        try:
            obj = pickle.loads(raw_bytes)
            if not isinstance(obj, cls):
                raise TypeError("Deserialized type mismatch")
            return obj
        except Exception as exc:
            logger.error("Snapshot deserialization failed: %s", exc)
            return None


@dataclass
class AnalysisProgress:
    current_stage: str = ""
    stage_progress: int = 0
    total_progress: int = 0
    current_task: str = ""
    estimated_time_remaining: float = 0.0
    processed_items: int = 0
    total_items: int = 0


@dataclass
class SymbolicStateData:
    state_id: str = ""
    pc: int = 0
    constraints: list = field(default_factory=list)
    memory_snapshot: object = None
    registers: dict = field(default_factory=dict)
    coverage: set = field(default_factory=set)
    depth: int = 0
    path_condition: object = None
    symbolic_variables: dict = field(default_factory=dict)


@dataclass
class TaintStateData:
    taint_sources: dict = field(default_factory=dict)
    taint_sinks: dict = field(default_factory=dict)
    tainted_memory: dict = field(default_factory=dict)
    tainted_registers: dict = field(default_factory=dict)
    propagation_rules: list = field(default_factory=list)


@dataclass
class ConcolicStateData:
    concrete_input: bytes = b''
    symbolic_constraints: list = field(default_factory=list)
    path_conditions: list = field(default_factory=list)
    taint_labels: dict = field(default_factory=dict)
    explored_paths: set = field(default_factory=set)
    pending_paths: list = field(default_factory=list)


@dataclass
class PipelineStateData:
    stages: list = field(default_factory=list)
    current_stage_index: int = 0
    stage_results: dict = field(default_factory=dict)
    options: dict = field(default_factory=dict)
    binary_info: dict = field(default_factory=dict)
    vulnerability_results: list = field(default_factory=list)


class StateSerializer:
    SUPPORTED_FORMATS = list(SUPPORTED_FORMATS)

    def __init__(self, format='pickle'):
        if format is None or format not in self.SUPPORTED_FORMATS:
            raise ValueError(f"Unsupported format: {format}")

        self.format = format
        self._msgpack_available = False

        if format == 'msgpack':
            try:
                import msgpack
                self._msgpack_available = True
            except ImportError:
                logger.warning("msgpack not installed, falling back to pickle format")
                self.format = 'pickle'

    def serialize_r2(self, data_obj):
        if data_obj is None:
            return b''

        if self.format == 'pickle':
            return pickle.dumps(data_obj, protocol=4)
        elif self.format == 'dict':
            return _mini_dumps(data_obj).encode('utf-8')
        elif self.format == 'msgpack' and self._msgpack_available:
            import msgpack
            return msgpack.packb(data_obj, default=self._msgpack_fb_r2)
        return pickle.dumps(data_obj, protocol=4)

    def deserialize_r2(self, raw_bytes):
        if raw_bytes is None or len(raw_bytes) == 0:
            return None

        if self.format == 'pickle':
            try:
                return pickle.loads(raw_bytes)
            except Exception:
                return None
        elif self.format == 'dict':
            return _mini_loads(raw_bytes.decode('utf-8'))
        elif self.format == 'msgpack' and self._msgpack_available:
            import msgpack
            return msgpack.unpackb(raw_bytes)
        # 回退: 尝试 pickle
        try:
            return pickle.loads(raw_bytes)
        except Exception:
            return None

    @staticmethod
    def _msgpack_fb_r2(obj):
        if isinstance(obj, datetime):
            return {'__datetime__': obj.isoformat()}
        raise TypeError(f"Cannot serialize type {type(obj).__name__}")


class StateManager:
    def __init__(self, storage_path=DEFAULT_STORAGE):
        if storage_path is None:
            storage_path = DEFAULT_STORAGE
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)

        self.serializer = StateSerializer(format='pickle')
        self._lock = threading.RLock()
        self._active_states = {}
        self._state_history = {}

        logger.info("State manager initialized -- storage path: %s", self.storage_path)

    def _generate_snapshot_id_r2(self):
        salt = os.urandom(16).hex()
        ts = datetime.now().isoformat()
        raw = f"{ts}_{salt}".encode('utf-8')
        return hashlib.sha256(raw).hexdigest()[:SID_LENGTH]

    def _get_snapshot_path_r2(self, sid):
        return self.storage_path / f"{sid}.snapshot"

    def create_snapshot_r2(self, state_type, checkpoint_data,
                           metadata=None, dependencies=None):
        if checkpoint_data is None:
            logger.warning("checkpoint_data is empty, refusing to create snapshot")
            return None

        sid = self._generate_snapshot_id_r2()
        ts = datetime.now()

        serialized_bytes = self.serializer.serialize_r2(checkpoint_data)

        snap = StateSnapshot(
            snapshot_id=sid,
            timestamp=ts,
            state_type=state_type,
            status=StateStatus.SAVED,
            metadata=metadata or {},
            checkpoint_data=serialized_bytes,
            version=1,
            dependencies=dependencies or []
        )

        spath = self._get_snapshot_path_r2(sid)
        try:
            with open(spath, 'wb') as fh:
                fh.write(snap.serialize_r2())
        except IOError as exc:
            logger.error("Snapshot write failed: %s", exc)
            return None

        hist_key = f"{state_type}_latest"
        if hist_key not in self._state_history:
            self._state_history[hist_key] = []
        self._state_history[hist_key].append(sid)

        if len(self._state_history[hist_key]) > MAX_HISTORY:
            old_sid = self._state_history[hist_key].pop(0)
            self._delete_snapshot_r2(old_sid)

        logger.info("State snapshot created: %s (%s)", sid, state_type)
        return sid

    def load_snapshot_r2(self, sid):
        if sid is None:
            return None

        spath = self._get_snapshot_path_r2(sid)
        if not spath.exists():
            logger.warning("Snapshot not found: %s", sid)
            return None

        try:
            with open(spath, 'rb') as fh:
                raw = fh.read()
            snap = StateSnapshot.deserialize_r2(raw)
            if snap is not None:
                logger.info("State snapshot loaded: %s", sid)
            return snap
        except Exception as exc:
            logger.error("Snapshot load failed: %s", exc)
            return None

    def get_checkpoint_data_r2(self, sid):
        snap = self.load_snapshot_r2(sid)
        if snap is None:
            return None
        try:
            return self.serializer.deserialize_r2(snap.checkpoint_data)
        except Exception as exc:
            logger.error("Checkpoint data deserialization failed: %s", exc)
            return None

    def delete_snapshot_r2(self, sid):
        with self._lock:
            return self._delete_snapshot_r2(sid)

    def _delete_snapshot_r2(self, sid):
        spath = self._get_snapshot_path_r2(sid)
        if not spath.exists():
            return False

        try:
            spath.unlink()
        except Exception as exc:
            logger.error("Snapshot deletion failed: %s", exc)
            return False

        for key in list(self._state_history.keys()):
            if sid in self._state_history[key]:
                self._state_history[key].remove(sid)

        logger.info("State snapshot deleted: %s", sid)
        return True

    def list_snapshots_r2(self, state_type=None):
        result_list = []

        for item in self.storage_path.iterdir():
            if not item.is_file() or item.suffix != '.snapshot':
                continue
            sid = item.stem
            snap = self.load_snapshot_r2(sid)
            if snap is None:
                continue
            if state_type is not None and snap.state_type != state_type:
                continue

            result_list.append({
                'snapshot_id': snap.snapshot_id,
                'timestamp': snap.timestamp.isoformat(),
                'state_type': snap.state_type,
                'status': snap.status,
                'version': snap.version,
                'metadata': snap.metadata,
                'size_bytes': len(snap.checkpoint_data)
            })

        result_list = sorted(result_list, key=lambda x: x['timestamp'], reverse=True)

        return result_list

    def get_latest_snapshot_r2(self, state_type):
        if state_type is None:
            return None
        hist_key = f"{state_type}_latest"
        history = self._state_history.get(hist_key, [])
        if len(history) > 0:
            return history[-1]

        snapshots = self.list_snapshots_r2(state_type)
        if len(snapshots) > 0:
            return snapshots[0]['snapshot_id']
        return None

    def save_active_state_r2(self, state_id, state_data):
        if state_id is None:
            return
        with self._lock:
            self._active_states[state_id] = {
                'data': state_data,
                'timestamp': time.time()
            }
        logger.debug("Active state saved: %s", state_id)

    def get_active_state_r2(self, state_id):
        if state_id is None:
            return None
        with self._lock:
            entry = self._active_states.get(state_id)
        if entry is not None:
            return entry['data']
        return None

    def remove_active_state_r2(self, state_id):
        if state_id is None:
            return
        with self._lock:
            if state_id in self._active_states:
                del self._active_states[state_id]
                logger.debug("Active state removed: %s", state_id)


class AnalysisStateTracker:
    def __init__(self, manager=None):
        self.manager = manager if manager is not None else StateManager()
        self.current_snapshot_id = None
        self.progress = AnalysisProgress()
        self._paused = False
        self._pause_event = threading.Event()
        self._pause_event.set()  # 初始状态: 未阻塞
        self._state_callbacks = []

        logger.info("Analysis state tracker initialized")

    def pause_r2(self):
        self._paused = True
        self._pause_event.clear()
        logger.info("Analysis paused")

    def resume_r2(self):
        self._paused = False
        self._pause_event.set()
        logger.info("Analysis resumed")

    def wait_if_paused_r2(self, timeout=None):
        if self._paused:
            return self._pause_event.wait(timeout)
        return True

    def is_paused_r2(self):
        return self._paused

    def save_checkpoint_r2(self, state_type, checkpoint_data, metadata=None):
        if metadata is None:
            metadata = {}

        metadata['progress'] = {
            'current_stage': self.progress.current_stage,
            'stage_progress': self.progress.stage_progress,
            'total_progress': self.progress.total_progress,
            'current_task': self.progress.current_task,
            'estimated_time_remaining': self.progress.estimated_time_remaining,
            'processed_items': self.progress.processed_items,
            'total_items': self.progress.total_items,
        }

        sid = self.manager.create_snapshot_r2(
            state_type=state_type,
            checkpoint_data=checkpoint_data,
            metadata=metadata
        )

        if sid is not None:
            self.current_snapshot_id = sid
            self._fire_callbacks_r2('checkpoint_saved', sid)
            logger.info("Checkpoint saved: %s", sid)

        return sid

    def load_checkpoint_r2(self, sid):
        if sid is None:
            return None

        data = self.manager.get_checkpoint_data_r2(sid)
        if data is None:
            return None

        snap = self.manager.load_snapshot_r2(sid)
        if snap is not None and 'progress' in snap.metadata:
            pd = snap.metadata['progress']
            self.progress.current_stage = pd.get('current_stage', '')
            self.progress.stage_progress = pd.get('stage_progress', 0)
            self.progress.total_progress = pd.get('total_progress', 0)
            self.progress.current_task = pd.get('current_task', '')
            self.progress.estimated_time_remaining = pd.get(
                'estimated_time_remaining', 0.0)
            self.progress.processed_items = pd.get('processed_items', 0)
            self.progress.total_items = pd.get('total_items', 0)

        self.current_snapshot_id = sid
        self._fire_callbacks_r2('checkpoint_loaded', sid)
        logger.info("Checkpoint loaded: %s", sid)
        return data

    def update_progress_r2(self, current_stage=None, stage_progress=None,
                           total_progress=None, current_task=None,
                           estimated_time_remaining=None,
                           processed_items=None, total_items=None):
        if current_stage is not None:
            self.progress.current_stage = current_stage
        if stage_progress is not None:
            self.progress.stage_progress = min(max(int(stage_progress), 0), 100)
        if total_progress is not None:
            self.progress.total_progress = min(max(int(total_progress), 0), 100)
        if current_task is not None:
            self.progress.current_task = current_task
        if estimated_time_remaining is not None:
            self.progress.estimated_time_remaining = float(estimated_time_remaining)
        if processed_items is not None:
            self.progress.processed_items = int(processed_items)
        if total_items is not None:
            self.progress.total_items = int(total_items)

        self._fire_callbacks_r2('progress_updated', self.progress)

    def register_callback_r2(self, cb):
        if cb is not None and callable(cb):
            self._state_callbacks.append(cb)

    def unregister_callback_r2(self, cb):
        if cb in self._state_callbacks:
            self._state_callbacks.remove(cb)

    def _fire_callbacks_r2(self, evt_type, data):
        for cb in self._state_callbacks:
            try:
                cb(evt_type, data)
            except Exception as exc:
                logger.error("Callback execution failed [%s]: %s", evt_type, exc)

    def get_progress_r2(self):
        return self.progress

    def get_status_r2(self):
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
                'total_items': self.progress.total_items,
            }
        }


class SymbolicExecutionState:
    def __init__(self, engine=None):
        self.engine = engine
        self._states = []
        self._current_index = 0

    def capture_r2(self):
        return SymbolicStateData(
            state_id=f"sym_state_{id(self)}",
            pc=0,
        )

    def restore_r2(self, state_data):
        if state_data is not None:
            logger.info("Restoring symbolic execution state: %s", state_data.state_id)

    def serialize_r2(self):
        return pickle.dumps(self.capture_r2(), protocol=4)

    def deserialize_r2(self, raw):
        if raw is not None:
            data = pickle.loads(raw)
            self.restore_r2(data)


class TaintAnalysisState:
    def __init__(self, tracker=None):
        self.tracker = tracker

    def capture_r2(self):
        return TaintStateData()

    def restore_r2(self, state_data):
        if state_data is not None:
            logger.info("Restoring taint analysis state")


class ConcolicExecutionState:
    def __init__(self, executor=None):
        self.executor = executor

    def capture_r2(self):
        return ConcolicStateData()

    def restore_r2(self, state_data):
        if state_data is not None:
            logger.info("Restoring concolic execution state")


class PipelineState:
    def __init__(self, pipeline=None):
        self.pipeline = pipeline

    def capture_r2(self):
        return PipelineStateData()

    def restore_r2(self, state_data):
        if state_data is not None:
            logger.info("Restoring analysis pipeline state")


def create_state_manager_r2(storage_path=DEFAULT_STORAGE):
    return StateManager(storage_path)


def create_state_tracker_r2(manager=None):
    return AnalysisStateTracker(manager)
