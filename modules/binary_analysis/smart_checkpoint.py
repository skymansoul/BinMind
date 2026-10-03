import logging
import os
import json
import time
import pickle
import hashlib
import threading
from collections import deque
from typing import Dict, Any
from typing import List, Optional

logger = logging.getLogger(__name__)


from enum import Enum


class CheckpointPhase(Enum):
    STARTED = "started"
    INFO_COLLECT = "info_collect"
    DECOMP = "decomp"
    SYMBEX = "symbex"
    TAINT = "taint"
    EXPLOIT = "exploit"
    REPORT = "report"
    FINISHED = "finished"


class Checkpoint:
    __slots__ = ('checkpoint_id', 'phase', 'timestamp', 'binary_path',
                 'step_index', 'state', 'metadata', 'parent_id',)

    def __init__(self, checkpoint_id, phase, timestamp, binary_path,
                 step_index, state, metadata=None, parent_id=None):
        if checkpoint_id is None:
            checkpoint_id = ""
        if phase is None:
            phase = CheckpointPhase.STARTED
        if timestamp is None:
            timestamp = 0.0
        if binary_path is None:
            binary_path = ""
        if step_index is None:
            step_index = 0
        if state is None:
            state = {}
        if metadata is None:
            metadata = {}
        self.checkpoint_id = checkpoint_id
        self.phase = phase
        self.timestamp = timestamp
        self.binary_path = binary_path
        self.step_index = step_index
        self.state = state
        self.metadata = metadata
        self.parent_id = parent_id


class CheckpointConfig:
    __slots__ = ('checkpoint_dir', 'save_every_steps', 'save_every_seconds',
                 'max_checkpoints', 'compress',)

    def __init__(self, checkpoint_dir="", save_every_steps=5,
                 save_every_seconds=60.0, max_checkpoints=20, compress=False):
        if checkpoint_dir is None:
            checkpoint_dir = ""
        if save_every_steps is None:
            save_every_steps = 5
        if save_every_seconds is None:
            save_every_seconds = 60.0
        if max_checkpoints is None:
            max_checkpoints = 20
        if compress is None:
            compress = False
        self.checkpoint_dir = checkpoint_dir
        self.save_every_steps = save_every_steps
        self.save_every_seconds = save_every_seconds
        self.max_checkpoints = max_checkpoints
        self.compress = compress


class CheckpointStore:
    def __init__(self, config):
        if config is None:
            config = CheckpointConfig()
        if config.checkpoint_dir is None or len(config.checkpoint_dir) == 0:
            config.checkpoint_dir = os.path.join(
                os.path.dirname(__file__), '..', 'data', 'checkpoints'
            )
        self.config = config
        os.makedirs(config.checkpoint_dir, exist_ok=True)
        self._lock = threading.Lock()
        self._index = deque(maxlen=min(max(config.max_checkpoints * 2, 2), 200))
        self._load_index()

    def _load_index(self):
        m_path = os.path.join(self.config.checkpoint_dir, "index.json")
        if os.path.exists(m_path):
            try:
                with open(m_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                self._index = deque(data, maxlen=min(max(self.config.max_checkpoints * 2, 2), 200))
            except Exception as e:
                logger.warning("loadcheck点indexfailed: {}".format(e))

    def _save_index(self):
        m_path = os.path.join(self.config.checkpoint_dir, "index.json")
        try:
            with open(m_path, 'w', encoding='utf-8') as f:
                json.dump(list(self._index), f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.warning("savecheck点indexfailed: {}".format(e))

    def _path(self, checkpoint_id):
        return os.path.join(self.config.checkpoint_dir,
                            "{}.pkl".format(checkpoint_id))

    def _meta_path(self, checkpoint_id):
        return os.path.join(self.config.checkpoint_dir,
                            "{}.meta.json".format(checkpoint_id))

    def save(self, checkpoint):
        if checkpoint is None:
            return False
        with self._lock:
            try:
                m_state_path = self._path(checkpoint.checkpoint_id)
                with open(m_state_path, 'wb') as f:
                    pickle.dump(checkpoint.state, f,
                                protocol=pickle.HIGHEST_PROTOCOL)

                m_phase_val = checkpoint.phase.value if hasattr(
                    checkpoint.phase, 'value') else str(checkpoint.phase)
                m_state_json = json.dumps(
                    checkpoint.state, default=str, sort_keys=True)
                m_state_hash = hashlib.sha256(
                    m_state_json.encode()).hexdigest()[:16]
                m_state_size = os.path.getsize(m_state_path)

                meta = {
                    'checkpoint_id': checkpoint.checkpoint_id,
                    'phase': m_phase_val,
                    'timestamp': checkpoint.timestamp,
                    'binary_path': checkpoint.binary_path,
                    'step_index': checkpoint.step_index,
                    'parent_id': checkpoint.parent_id,
                    'metadata': checkpoint.metadata,
                    'state_hash': m_state_hash,
                    'state_size': m_state_size
                }

                m_meta_path = self._meta_path(checkpoint.checkpoint_id)
                with open(m_meta_path, 'w', encoding='utf-8') as f:
                    json.dump(meta, f, ensure_ascii=False, indent=2)

                self._index.append(meta)
                self._enforce_retention()
                self._save_index()

                logger.info("[checkpoint] save {} phase={} size={}".format(
                    checkpoint.checkpoint_id, m_phase_val, m_state_size))
                return True
            except Exception as e:
                logger.warning("savecheck点failed: {}".format(e))
                return False

    def _enforce_retention(self):
        if len(self._index) <= self.config.max_checkpoints:
            return

        m_count = len(self._index) - self.config.max_checkpoints

        k = 0
        while k < m_count:
            try:
                meta = self._index.popleft()
                m_state_p = self._path(meta.get('checkpoint_id', ''))
                m_meta_p = self._meta_path(meta.get('checkpoint_id', ''))
                for p in (m_state_p, m_meta_p):
                    if os.path.exists(p):
                        try:
                            os.remove(p)
                        except OSError:
                            logger.debug(
                                "sanitize旧check点filefailed, 可能已被delete: {}".format(p))
            except IndexError:
                break
            k = k + 1

    def load(self, checkpoint_id):
        if checkpoint_id is None:
            return None
        with self._lock:
            m_meta_p = self._meta_path(checkpoint_id)
            m_state_p = self._path(checkpoint_id)
            if not (os.path.exists(m_meta_p) and os.path.exists(m_state_p)):
                return None
            try:
                with open(m_meta_p, 'r', encoding='utf-8') as f:
                    meta = json.load(f)
                with open(m_state_p, 'rb') as f:
                    state = pickle.load(f)
                return Checkpoint(
                    checkpoint_id=meta.get('checkpoint_id', ''),
                    phase=CheckpointPhase(meta.get('phase', 'started')),
                    timestamp=meta.get('timestamp', 0.0),
                    binary_path=meta.get('binary_path', ''),
                    step_index=meta.get('step_index', 0),
                    state=state,
                    metadata=meta.get('metadata', {}),
                    parent_id=meta.get('parent_id')
                )
            except Exception as e:
                logger.warning("loadcheck点failed: {}".format(e))
                return None

    def latest(self, binary_path=None):
        with self._lock:
            m_candidates = []
            k = 0
            while k < len(self._index):
                m = self._index[k]
                if binary_path is None or m.get('binary_path') == binary_path:
                    m_candidates.append(m)
                k = k + 1

        if len(m_candidates) == 0:
            return None

        m_sorted = sorted(
            m_candidates, key=lambda m: m.get('timestamp', 0.0))
        latest_meta = m_sorted[-1]
        return self.load(latest_meta.get('checkpoint_id', ''))

    def list(self, binary_path=None, limit=50):
        if limit is None or limit <= 0:
            limit = 50
        m_limit = min(max(limit, 1), 200)
        with self._lock:
            m_results = []
            k = 0
            while k < len(self._index):
                m = self._index[k]
                if binary_path is None or m.get('binary_path') == binary_path:
                    m_results.append(m)
                k = k + 1

        m_results = sorted(
            m_results, key=lambda m: m.get('timestamp', 0.0))
        m_results.reverse()
        m_out = []
        k = 0
        while k < len(m_results) and k < m_limit:
            m_out.append(m_results[k])
            k = k + 1
        return m_out


class SmartCheckpointer:
    def __init__(self, config=None, phase=None):
        if config is None:
            config = CheckpointConfig()
        if phase is None:
            phase = CheckpointPhase.STARTED
        self.config = config
        self.store = CheckpointStore(self.config)
        self.current_phase = phase
        self.step_index = 0
        self._last_save_ts = time.time()
        self._lock = threading.Lock()

    def set_phase(self, phase):
        if phase is not None:
            self.current_phase = phase

    def _should_save(self):
        m_save_every = min(max(self.config.save_every_steps, 1), 10000)
        if self.step_index % m_save_every == 0:
            return True
        m_now = time.time()
        m_every_sec = min(max(self.config.save_every_seconds, 1.0), 3600.0)
        if (m_now - self._last_save_ts) > m_every_sec:
            return True
        return False

    def maybe_checkpoint(self, binary_path, state, metadata=None):
        if binary_path is None:
            binary_path = ""
        if state is None:
            state = {}
        if metadata is None:
            metadata = {}
        with self._lock:
            if not self._should_save():
                self.step_index = self.step_index + 1
                return None
            cid = self._make_id(binary_path)
            cp = Checkpoint(
                checkpoint_id=cid,
                phase=self.current_phase,
                timestamp=time.time(),
                binary_path=binary_path,
                step_index=self.step_index,
                state=dict(state),
                metadata=metadata,
                parent_id=None
            )
            ok = self.store.save(cp)
            self._last_save_ts = time.time()
            self.step_index = self.step_index + 1
            return cid if ok else None

    def force_checkpoint(self, binary_path, state, metadata=None):
        if binary_path is None:
            binary_path = ""
        if state is None:
            state = {}
        if metadata is None:
            metadata = {}
        cid = self._make_id(binary_path)
        cp = Checkpoint(
            checkpoint_id=cid,
            phase=self.current_phase,
            timestamp=time.time(),
            binary_path=binary_path,
            step_index=self.step_index,
            state=dict(state),
            metadata=metadata
        )
        self.store.save(cp)
        self._last_save_ts = time.time()
        self.step_index = self.step_index + 1
        return cid

    def _make_id(self, binary_path):
        if binary_path is None:
            binary_path = ""
        m_phase_val = self.current_phase.value if hasattr(
            self.current_phase, 'value') else str(self.current_phase)
        h = hashlib.sha256()
        h.update(binary_path.encode("utf-8"))
        h.update(b"\x00")
        h.update(m_phase_val.encode("utf-8"))
        h.update(b"\x00")
        h.update(str(self.step_index).encode("utf-8"))
        h.update(b"\x00")
        h.update(str(time.time()).encode("utf-8"))
        return h.hexdigest()[:24]

    def recover_latest(self, binary_path):
        if binary_path is None:
            binary_path = ""
        return self.store.latest(binary_path=binary_path)

    def recover_by_id(self, checkpoint_id):
        if checkpoint_id is None:
            return None
        return self.store.load(checkpoint_id)

    def list(self, binary_path=None):
        return self.store.list(binary_path=binary_path)


def create_smart_checkpointer(checkpoint_dir=None,
                              save_every_steps=5,
                              save_every_seconds=60.0):
    if save_every_steps is None:
        save_every_steps = 5
    if save_every_seconds is None:
        save_every_seconds = 60.0
    cfg = CheckpointConfig(
        checkpoint_dir=checkpoint_dir if checkpoint_dir else "",
        save_every_steps=save_every_steps,
        save_every_seconds=save_every_seconds
    )
    return SmartCheckpointer(cfg)
