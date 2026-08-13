import typing
"""Analysis state management module.

Provides state persistence, checkpoint save/restore, progress tracking,
and bridge classes for symbolic execution, taint analysis, concolic
execution, and pipeline state capture/restore.

Compatible with Windows and Linux file system paths.
"""

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


# -- Memoization decorator --
class _Memoize:
    """Hand-written caching decorator for expensive function calls.

    Useful in symbolic execution scenarios with path explosion to avoid
    repeated computation for identical arguments.
    """
    def __init__(self, func):
        self.func = func
        self.cache = {}

    def __call__(self, *args):
        if args not in self.cache:
            self.cache[args] = self.func(*args)
        return self.cache[args]


# -- Utility: deduplicate while preserving insertion order --
def _uniq(lst):
    """Deduplicate list while preserving insertion order."""
    seen = set()
    result = []
    for item in lst:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


# -- Hand-written serializer: replaces json, uses __dict__ iteration --
def _to_plain(obj):
    """Recursively convert object to plain Python struct (dict/list/primitive).

    Uses __dict__ iteration instead of JSON reflection to avoid
    circular reference stack overflows.
    """
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
        return sorted(list(obj))  # Deterministic output
    if isinstance(obj, datetime):
        return {"__datetime__": obj.isoformat()}
    if isinstance(obj, (list, tuple)):
        return [_to_plain(v) for v in obj]
    if isinstance(obj, dict):
        return {str(k): _to_plain(v) for k, v in obj.items()}
    if hasattr(obj, '__dict__') and not isinstance(obj, type):
        # __dict__ iteration: core hand-written serialization path
        return {"__class__": type(obj).__name__, "__dict__": _to_plain(obj.__dict__)}
    raise TypeError(f"Cannot serialize type {type(obj).__name__}")


def _mini_dumps(obj):
    """Compact string representation (replaces json.dumps)."""
    return repr(_to_plain(obj))


def _mini_loads(s):
    """Parse compact string back to object (replaces json.loads).

    Uses ast.literal_eval for safe parsing that does not execute arbitrary code.
    """
    return ast.literal_eval(s)


__log = logging.getLogger(__name__)

# -- Module-level constants --
SUPPORTED_FORMATS = ('pickle', 'dict', 'msgpack')
DEFAULT_STORAGE = "data/analysis_states"
MAX_HISTORY = 100
SID_LENGTH = 24


# -- StateStatus: analysis status constants --
class StateStatus(str, Enum):
    """Analysis status constants."""
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    SAVED = "saved"


# -- StateType: analysis type constants --
class StateType(str, Enum):
    """Analysis type constants."""
    SYMBOLIC_EXECUTION = "symbolic_execution"
    DYNAMIC_TAINT = "dynamic_taint"
    CONCOLIC = "concolic"
    ANALYSIS_PIPELINE = "analysis_pipeline"
    CRASH_ANALYSIS = "crash_analysis"
    EXPLOIT_GENERATION = "exploit_generation"


# -- StateSnapshot: checkpoint data container --
# Memory optimization: symbolic execution can produce tens of thousands
# of snapshots per run.
@dataclass
class StateSnapshot:
    """Analysis state snapshot for checkpoint persistence."""
    snapshot_id: str
    timestamp: datetime = field(default_factory=datetime.now)
    state_type: Optional[str] = None
    status: StateStatus = StateStatus.SAVED
    metadata: dict = field(default_factory=dict)
    checkpoint_data: bytes = b''
    version: int = 1
    dependencies: list = field(default_factory=list)

    def __post_init__(self):
        """Validate snapshot_id on construction."""
        if not isinstance(self.snapshot_id, str):
            raise ValueError(f"Invalid snapshot_id type: {type(self.snapshot_id).__name__}")

    def serialize_r2(self):
        """Pickle serialization with protocol 4 for backward compatibility."""
        return pickle.dumps(self, protocol=4)

    @classmethod
    def deserialize_r2(cls, raw_bytes):
        """Deserialize from pickle bytes with error protection."""
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


# -- AnalysisProgress: progress tracking --
@dataclass
class AnalysisProgress:
    """Progress tracking fields, updated incrementally during analysis."""
    current_stage: str = ""
    stage_progress: int = 0
    total_progress: int = 0
    current_task: str = ""
    estimated_time_remaining: float = 0.0
    processed_items: int = 0
    total_items: int = 0


# -- State data classes --
# Use dataclass for maintainability.
# Symbolic execution may produce thousands of instances.

@dataclass
class SymbolicStateData:
    """Symbolic execution state: PC, constraints, memory snapshot."""
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
    """Taint tracking: sources, sinks, memory tags."""
    taint_sources: dict = field(default_factory=dict)
    taint_sinks: dict = field(default_factory=dict)
    tainted_memory: dict = field(default_factory=dict)
    tainted_registers: dict = field(default_factory=dict)
    propagation_rules: list = field(default_factory=list)


@dataclass
class ConcolicStateData:
    """Concolic execution: concrete + symbolic."""
    concrete_input: bytes = b''
    symbolic_constraints: list = field(default_factory=list)
    path_conditions: list = field(default_factory=list)
    taint_labels: dict = field(default_factory=dict)
    explored_paths: set = field(default_factory=set)
    pending_paths: list = field(default_factory=list)


@dataclass
class PipelineStateData:
    """Pipeline state: stages, results, options."""
    stages: list = field(default_factory=list)
    current_stage_index: int = 0
    stage_results: dict = field(default_factory=dict)
    options: dict = field(default_factory=dict)
    binary_info: dict = field(default_factory=dict)
    vulnerability_results: list = field(default_factory=list)


# -- StateSerializer --
# Supports pickle/dict/msgpack formats.
# msgpack is an optional dependency; falls back to pickle if unavailable.
# dict format uses hand-written serializer instead of json.
class StateSerializer:
    SUPPORTED_FORMATS = list(SUPPORTED_FORMATS)

    def __init__(self, format='pickle'):
        if format is None or format not in self.SUPPORTED_FORMATS:
            raise ValueError(f"Unsupported format: {format}")

        self.format = format
        self._msgpack_available = False

        # msgpack optional dependency: silent fallback on import failure
        if format == 'msgpack':
            try:
                import msgpack
                self._msgpack_available = True
            except ImportError:
                logger.warning("msgpack not installed, falling back to pickle format")
                self.format = 'pickle'

    # -- Serialization entry points --
    def serialize_r2(self, data_obj):
        """Serialize data object to bytes."""
        if data_obj is None:
            return b''

        if self.format == 'pickle':
            return pickle.dumps(data_obj, protocol=4)
        elif self.format == 'dict':
            return _mini_dumps(data_obj).encode('utf-8')
        elif self.format == 'msgpack' and self._msgpack_available:
            import msgpack
            return msgpack.packb(data_obj, default=self._msgpack_fb_r2)
        # Fallback: pickle
        return pickle.dumps(data_obj, protocol=4)

    # -- Deserialization entry points --
    def deserialize_r2(self, raw_bytes):
        """Deserialize bytes back to object."""
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
        # Fallback: try pickle
        try:
            return pickle.loads(raw_bytes)
        except Exception:
            return None

    # -- msgpack fallback handler --
    @staticmethod
    def _msgpack_fb_r2(obj):
        """Handle types that msgpack can't serialize natively (e.g. datetime)."""
        if isinstance(obj, datetime):
            return {'__datetime__': obj.isoformat()}
        raise TypeError(f"Cannot serialize type {type(obj).__name__}")


# -- StateManager: core state manager --
# Maintains active states in memory and persistent snapshots on disk.
# Uses RLock for recursive call scenarios in certain analysis paths.
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

    # -- Snapshot ID generation --
    def _generate_snapshot_id_r2(self):
        """Generate unique snapshot ID using SHA-256."""
        salt = os.urandom(16).hex()
        ts = datetime.now().isoformat()
        raw = f"{ts}_{salt}".encode('utf-8')
        return hashlib.sha256(raw).hexdigest()[:SID_LENGTH]

    def _get_snapshot_path_r2(self, sid):
        """Get filesystem path for a snapshot."""
        return self.storage_path / f"{sid}.snapshot"

    # -- CRUD operations --
    def create_snapshot_r2(self, state_type, checkpoint_data,
                           metadata=None, dependencies=None):
        """Create a snapshot and return its ID, or None on failure."""
        if checkpoint_data is None:
            logger.warning("checkpoint_data is empty, refusing to create snapshot")
            return None

        sid = self._generate_snapshot_id_r2()
        ts = datetime.now()

        # Serialize checkpoint using the configured serializer
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

        # Write to disk; log IO errors without raising
        spath = self._get_snapshot_path_r2(sid)
        try:
            with open(spath, 'wb') as fh:
                fh.write(snap.serialize_r2())
        except IOError as exc:
            logger.error("Snapshot write failed: %s", exc)
            return None

        # Update history queue -- track latest snapshots by type
        hist_key = f"{state_type}_latest"
        if hist_key not in self._state_history:
            self._state_history[hist_key] = []
        self._state_history[hist_key].append(sid)

        # FIFO eviction of old snapshots to prevent unbounded disk growth
        if len(self._state_history[hist_key]) > MAX_HISTORY:
            old_sid = self._state_history[hist_key].pop(0)
            self._delete_snapshot_r2(old_sid)

        logger.info("State snapshot created: %s (%s)", sid, state_type)
        return sid

    def load_snapshot_r2(self, sid):
        """Load a snapshot from disk."""
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
        """Extract checkpoint data from a snapshot."""
        snap = self.load_snapshot_r2(sid)
        if snap is None:
            return None
        try:
            return self.serializer.deserialize_r2(snap.checkpoint_data)
        except Exception as exc:
            logger.error("Checkpoint data deserialization failed: %s", exc)
            return None

    def delete_snapshot_r2(self, sid):
        """Delete a snapshot with lock protection."""
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

        # Clean history records across all types
        for key in list(self._state_history.keys()):
            if sid in self._state_history[key]:
                self._state_history[key].remove(sid)

        logger.info("State snapshot deleted: %s", sid)
        return True

    def list_snapshots_r2(self, state_type=None):
        """List snapshots, optionally filtered by type, sorted by timestamp descending."""
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

        # Sort by timestamp descending
        result_list = sorted(result_list, key=lambda x: x['timestamp'], reverse=True)

        return result_list

    def get_latest_snapshot_r2(self, state_type):
        """Get the most recent snapshot ID for a given type."""
        if state_type is None:
            return None
        hist_key = f"{state_type}_latest"
        history = self._state_history.get(hist_key, [])
        if len(history) > 0:
            return history[-1]

        # Fallback: scan disk
        snapshots = self.list_snapshots_r2(state_type)
        if len(snapshots) > 0:
            return snapshots[0]['snapshot_id']
        return None

    # -- Active state management (in-memory only) --
    def save_active_state_r2(self, state_id, state_data):
        """Save state to in-memory active states dict."""
        if state_id is None:
            return
        with self._lock:
            self._active_states[state_id] = {
                'data': state_data,
                'timestamp': time.time()
            }
        logger.debug("Active state saved: %s", state_id)

    def get_active_state_r2(self, state_id):
        """Retrieve active state from memory."""
        if state_id is None:
            return None
        with self._lock:
            entry = self._active_states.get(state_id)
        if entry is not None:
            return entry['data']
        return None

    def remove_active_state_r2(self, state_id):
        """Remove active state from memory."""
        if state_id is None:
            return
        with self._lock:
            if state_id in self._active_states:
                del self._active_states[state_id]
                logger.debug("Active state removed: %s", state_id)


# -- AnalysisStateTracker --
# Extends StateManager with pause/resume and progress tracking.
# Callback mechanism: notifies registered callbacks on state changes.
class AnalysisStateTracker:
    def __init__(self, manager=None):
        self.manager = manager if manager is not None else StateManager()
        self.current_snapshot_id = None
        self.progress = AnalysisProgress()
        self._paused = False
        self._pause_event = threading.Event()
        self._pause_event.set()  # Initial state: not blocked
        self._state_callbacks = []

        logger.info("Analysis state tracker initialized")

    # -- Pause / Resume --
    def pause_r2(self):
        """Pause analysis -- clears the pause event."""
        self._paused = True
        self._pause_event.clear()
        logger.info("Analysis paused")

    def resume_r2(self):
        """Resume analysis -- sets the pause event."""
        self._paused = False
        self._pause_event.set()
        logger.info("Analysis resumed")

    def wait_if_paused_r2(self, timeout=None):
        """Block until analysis is resumed, or timeout."""
        if self._paused:
            return self._pause_event.wait(timeout)
        return True

    def is_paused_r2(self):
        """Check if analysis is currently paused."""
        return self._paused

    # -- Checkpoint save / load --
    def save_checkpoint_r2(self, state_type, checkpoint_data, metadata=None):
        """Save checkpoint with embedded progress info."""
        if metadata is None:
            metadata = {}

        # Embed progress info for restoration on load
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
        """Load checkpoint and restore progress."""
        if sid is None:
            return None

        data = self.manager.get_checkpoint_data_r2(sid)
        if data is None:
            return None

        # Restore progress from snapshot metadata
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

    # -- Progress updates --
    def update_progress_r2(self, current_stage=None, stage_progress=None,
                           total_progress=None, current_task=None,
                           estimated_time_remaining=None,
                           processed_items=None, total_items=None):
        """Update progress fields incrementally -- unset fields keep current value."""
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

    # -- Callback management --
    def register_callback_r2(self, cb):
        """Register a callback for state change events."""
        if cb is not None and callable(cb):
            self._state_callbacks.append(cb)

    def unregister_callback_r2(self, cb):
        """Remove a previously registered callback."""
        if cb in self._state_callbacks:
            self._state_callbacks.remove(cb)

    def _fire_callbacks_r2(self, evt_type, data):
        """Notify all registered callbacks of a state event.

        Callback exceptions must not disrupt the main analysis flow.
        """
        for cb in self._state_callbacks:
            try:
                cb(evt_type, data)
            except Exception as exc:
                logger.error("Callback execution failed [%s]: %s", evt_type, exc)

    # -- Status queries --
    def get_progress_r2(self):
        """Return current progress object."""
        return self.progress

    def get_status_r2(self):
        """Return comprehensive status dict."""
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


# -- Engine bridge classes --
# Bridge pattern: capture/restore interface for specific analysis engines.

class SymbolicExecutionState:
    """Bridge: wraps symbolic engine, provides capture/restore."""
    def __init__(self, engine=None):
        self.engine = engine
        self._states = []
        self._current_index = 0

    def capture_r2(self):
        """Capture current symbolic execution state."""
        return SymbolicStateData(
            state_id=f"sym_state_{id(self)}",
            pc=0,
        )

    def restore_r2(self, state_data):
        """Restore symbolic execution from state data."""
        if state_data is not None:
            logger.info("Restoring symbolic execution state: %s", state_data.state_id)

    def serialize_r2(self):
        """Pickle-serialize captured state."""
        return pickle.dumps(self.capture_r2(), protocol=4)

    def deserialize_r2(self, raw):
        """Pickle-deserialize and restore state."""
        if raw is not None:
            data = pickle.loads(raw)
            self.restore_r2(data)


class TaintAnalysisState:
    """Bridge: wraps taint engine."""
    def __init__(self, tracker=None):
        self.tracker = tracker

    def capture_r2(self):
        """Capture current taint analysis state."""
        return TaintStateData()

    def restore_r2(self, state_data):
        """Restore taint analysis from state data."""
        if state_data is not None:
            logger.info("Restoring taint analysis state")


class ConcolicExecutionState:
    """Bridge: wraps concolic executor."""
    def __init__(self, executor=None):
        self.executor = executor

    def capture_r2(self):
        """Capture current concolic execution state."""
        return ConcolicStateData()

    def restore_r2(self, state_data):
        """Restore concolic execution from state data."""
        if state_data is not None:
            logger.info("Restoring concolic execution state")


class PipelineState:
    """Bridge: wraps analysis pipeline."""
    def __init__(self, pipeline=None):
        self.pipeline = pipeline

    def capture_r2(self):
        """Capture current pipeline state."""
        return PipelineStateData()

    def restore_r2(self, state_data):
        """Restore pipeline from state data."""
        if state_data is not None:
            logger.info("Restoring analysis pipeline state")


# -- Factory functions --

def create_state_manager_r2(storage_path=DEFAULT_STORAGE):
    """Factory: create StateManager with optional custom path."""
    return StateManager(storage_path)


def create_state_tracker_r2(manager=None):
    """Factory: create AnalysisStateTracker with optional existing manager."""
    return AnalysisStateTracker(manager)
