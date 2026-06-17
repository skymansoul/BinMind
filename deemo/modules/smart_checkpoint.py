"""
智能检查点与增量恢复模块

功能:
    1. 长时间分析任务 (深度符号执行/大型固件解包) 自动保存检查点 (项目状态/内存快照)
    2. 支持从任意步骤恢复, 避免因中断造成前功尽弃

核心技术:
    - 周期性快照 (基于步数/时间)
    - 检查点目录管理 (versioned)
    - 状态机持久化
    - 恢复接口 (指定 checkpoint_id)
"""

import logging
import os
import json
import time
import pickle
import hashlib
import threading
import shutil
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import deque

logger = logging.getLogger(__name__)


class CheckpointPhase(Enum):
    """检查点阶段"""
    STARTED = "started"
    INFO_COLLECT = "info_collect"
    DECOMP = "decomp"
    SYMBEX = "symbex"
    TAINT = "taint"
    EXPLOIT = "exploit"
    REPORT = "report"
    FINISHED = "finished"


@dataclass
class Checkpoint:
    """检查点"""
    checkpoint_id: str
    phase: CheckpointPhase
    timestamp: float
    binary_path: str
    step_index: int
    state: Dict[str, Any]
    metadata: Dict[str, Any] = field(default_factory=dict)
    parent_id: Optional[str] = None


@dataclass
class CheckpointConfig:
    """检查点配置"""
    checkpoint_dir: str = ""
    save_every_steps: int = 5
    save_every_seconds: float = 60.0
    max_checkpoints: int = 20
    compress: bool = False


class CheckpointStore:
    """检查点存储 (本地 + 可选 S3)"""

    def __init__(self, config: CheckpointConfig):
        if not config.checkpoint_dir:
            config.checkpoint_dir = os.path.join(
                os.path.dirname(__file__), '..', 'data', 'checkpoints'
            )
        self.config = config
        os.makedirs(config.checkpoint_dir, exist_ok=True)
        self._lock = threading.Lock()
        self._index: deque = deque(maxlen=config.max_checkpoints * 2)
        self._load_index()

    def _load_index(self):
        index_path = os.path.join(self.config.checkpoint_dir, "index.json")
        if os.path.exists(index_path):
            try:
                with open(index_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                self._index = deque(data, maxlen=self.config.max_checkpoints * 2)
            except Exception as e:
                logger.warning(f"加载检查点索引失败: {e}")

    def _save_index(self):
        index_path = os.path.join(self.config.checkpoint_dir, "index.json")
        try:
            with open(index_path, 'w', encoding='utf-8') as f:
                json.dump(list(self._index), f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.warning(f"保存检查点索引失败: {e}")

    def _path(self, checkpoint_id: str) -> str:
        return os.path.join(self.config.checkpoint_dir,
                            f"{checkpoint_id}.pkl")

    def _meta_path(self, checkpoint_id: str) -> str:
        return os.path.join(self.config.checkpoint_dir,
                            f"{checkpoint_id}.meta.json")

    def save(self, checkpoint: Checkpoint) -> bool:
        with self._lock:
            try:
                # 保存 state
                with open(self._path(checkpoint.checkpoint_id), 'wb') as f:
                    pickle.dump(checkpoint.state, f,
                                protocol=pickle.HIGHEST_PROTOCOL)
                # 保存元数据
                meta = {
                    'checkpoint_id': checkpoint.checkpoint_id,
                    'phase': checkpoint.phase.value,
                    'timestamp': checkpoint.timestamp,
                    'binary_path': checkpoint.binary_path,
                    'step_index': checkpoint.step_index,
                    'parent_id': checkpoint.parent_id,
                    'metadata': checkpoint.metadata,
                    'state_hash': hashlib.sha256(
                        json.dumps(checkpoint.state,
                                   default=str, sort_keys=True).encode()
                    ).hexdigest()[:16],
                    'state_size': os.path.getsize(self._path(checkpoint.checkpoint_id))
                }
                with open(self._meta_path(checkpoint.checkpoint_id),
                          'w', encoding='utf-8') as f:
                    json.dump(meta, f, ensure_ascii=False, indent=2)
                self._index.append(meta)
                self._enforce_retention()
                self._save_index()
                logger.info(f"[checkpoint] 保存 {checkpoint.checkpoint_id} "
                            f"phase={checkpoint.phase.value} "
                            f"size={meta['state_size']}")
                return True
            except Exception as e:
                logger.warning(f"保存检查点失败: {e}")
                return False

    def _enforce_retention(self):
        if len(self._index) <= self.config.max_checkpoints:
            return
        # 删除最早的
        to_remove = len(self._index) - self.config.max_checkpoints
        for _ in range(to_remove):
            meta = self._index.popleft()
            for p in (self._path(meta['checkpoint_id']),
                      self._meta_path(meta['checkpoint_id'])):
                try:
                    if os.path.exists(p):
                        os.remove(p)
                except OSError:
                    pass

    def load(self, checkpoint_id: str) -> Optional[Checkpoint]:
        with self._lock:
            meta_p = self._meta_path(checkpoint_id)
            state_p = self._path(checkpoint_id)
            if not (os.path.exists(meta_p) and os.path.exists(state_p)):
                return None
            try:
                with open(meta_p, 'r', encoding='utf-8') as f:
                    meta = json.load(f)
                with open(state_p, 'rb') as f:
                    state = pickle.load(f)
                return Checkpoint(
                    checkpoint_id=meta['checkpoint_id'],
                    phase=CheckpointPhase(meta['phase']),
                    timestamp=meta['timestamp'],
                    binary_path=meta['binary_path'],
                    step_index=meta['step_index'],
                    state=state,
                    metadata=meta.get('metadata', {}),
                    parent_id=meta.get('parent_id')
                )
            except Exception as e:
                logger.warning(f"加载检查点失败: {e}")
                return None

    def latest(self, binary_path: Optional[str] = None) -> Optional[Checkpoint]:
        with self._lock:
            candidates = [m for m in self._index
                          if binary_path is None or m.get('binary_path') == binary_path]
        if not candidates:
            return None
        latest_meta = max(candidates, key=lambda m: m['timestamp'])
        return self.load(latest_meta['checkpoint_id'])

    def list(self, binary_path: Optional[str] = None,
             limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            results = [m for m in self._index
                       if binary_path is None or m.get('binary_path') == binary_path]
        results.sort(key=lambda m: m['timestamp'], reverse=True)
        return results[:limit]


class SmartCheckpointer:
    """
    智能检查点 (自动按步数/时间触发)
    """

    def __init__(self,
                 config: Optional[CheckpointConfig] = None,
                 phase: CheckpointPhase = CheckpointPhase.STARTED):
        self.config = config or CheckpointConfig()
        self.store = CheckpointStore(self.config)
        self.current_phase = phase
        self.step_index = 0
        self._last_save_ts = time.time()
        self._lock = threading.Lock()

    def set_phase(self, phase: CheckpointPhase):
        self.current_phase = phase

    def _should_save(self) -> bool:
        if self.step_index % self.config.save_every_steps == 0:
            return True
        if (time.time() - self._last_save_ts) > self.config.save_every_seconds:
            return True
        return False

    def maybe_checkpoint(self, binary_path: str,
                         state: Dict[str, Any],
                         metadata: Optional[Dict[str, Any]] = None) -> Optional[str]:
        with self._lock:
            if not self._should_save():
                self.step_index += 1
                return None
            cid = self._make_id(binary_path)
            cp = Checkpoint(
                checkpoint_id=cid,
                phase=self.current_phase,
                timestamp=time.time(),
                binary_path=binary_path,
                step_index=self.step_index,
                state=dict(state),
                metadata=metadata or {},
                parent_id=None
            )
            ok = self.store.save(cp)
            self._last_save_ts = time.time()
            self.step_index += 1
            return cid if ok else None

    def force_checkpoint(self, binary_path: str,
                         state: Dict[str, Any],
                         metadata: Optional[Dict[str, Any]] = None) -> str:
        cid = self._make_id(binary_path)
        cp = Checkpoint(
            checkpoint_id=cid,
            phase=self.current_phase,
            timestamp=time.time(),
            binary_path=binary_path,
            step_index=self.step_index,
            state=dict(state),
            metadata=metadata or {}
        )
        self.store.save(cp)
        self._last_save_ts = time.time()
        self.step_index += 1
        return cid

    def _make_id(self, binary_path: str) -> str:
        h = hashlib.sha256()
        h.update(binary_path.encode("utf-8"))
        h.update(b"\x00")
        h.update(self.current_phase.value.encode("utf-8"))
        h.update(b"\x00")
        h.update(str(self.step_index).encode("utf-8"))
        h.update(b"\x00")
        h.update(str(time.time()).encode("utf-8"))
        return h.hexdigest()[:24]

    def recover_latest(self, binary_path: str
                        ) -> Optional[Checkpoint]:
        return self.store.latest(binary_path=binary_path)

    def recover_by_id(self, checkpoint_id: str) -> Optional[Checkpoint]:
        return self.store.load(checkpoint_id)

    def list(self, binary_path: Optional[str] = None) -> List[Dict[str, Any]]:
        return self.store.list(binary_path=binary_path)


def create_smart_checkpointer(
    checkpoint_dir: Optional[str] = None,
    save_every_steps: int = 5,
    save_every_seconds: float = 60.0
) -> SmartCheckpointer:
    cfg = CheckpointConfig(
        checkpoint_dir=checkpoint_dir or "",
        save_every_steps=save_every_steps,
        save_every_seconds=save_every_seconds
    )
    return SmartCheckpointer(cfg)
