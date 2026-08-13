# main interface: CheckpointType等4class。
# dependency: import time; import hashlib
import logging
import time
import hashlib
import json
import threading
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from enum import StrEnum

logger = logging.getLogger(__name__)


class CheckpointType(StrEnum):
    MANUAL = "manual"
    AUTOMATIC = "automatic"
    PERIODIC = "periodic"
    EVENT_TRIGGERED = "event_triggered"

class CheckpointStatus(StrEnum):
    CREATED = "created"
    VALIDATED = "validated"
    RESTORED = "restored"
    CORRUPTED = "corrupted"
    DELETED = "deleted"


@dataclass
class Checkpoint:
    checkpoint_id: str
    type: CheckpointType
    timestamp: float = 0.0
    status: CheckpointStatus = CheckpointStatus.CREATED
    data: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)
    hash: Optional[str] = None

    def compute_hash(self):
        """计算check点hash"""
        data_str = json.dumps(self.data, sort_keys=True)
        self.hash = hashlib.sha256(data_str.encode()).hexdigest()


@dataclass
class AuditLogEntry:
    timestamp: float = 0.0
    action: str = ""
    checkpoint_id: str = ""
    user: str = ""
    details: dict = field(default_factory=dict)


class CheckpointStorage:
    """check点存储"""

    def __init__(self, storage_path: str = "./checkpoints"):
        self._storage_path = storage_path
        self._checkpoints: Dict[str, Checkpoint] = {}
        self._audit_log: List[AuditLogEntry] = []
        self._lock = threading.RLock()

    def save(self, checkpoint: Checkpoint):
        with self._lock:
            checkpoint.compute_hash()
            self._checkpoints[checkpoint.checkpoint_id] = checkpoint
            self._audit_log.append(AuditLogEntry(
                timestamp=time.time(),
                action="save_checkpoint",
                checkpoint_id=checkpoint.checkpoint_id,
                details={"type": checkpoint.type.value}
            ))

    def load(self, checkpoint_id: str) -> Optional[Checkpoint]:
        with self._lock:
            checkpoint = self._checkpoints.get(checkpoint_id)
            if checkpoint:
                self._audit_log.append(AuditLogEntry(
                    timestamp=time.time(),
                    action="load_checkpoint",
                    checkpoint_id=checkpoint_id
                ))
            return checkpoint

    def delete(self, checkpoint_id: str):
        with self._lock:
            if checkpoint_id in self._checkpoints:
                self._checkpoints[checkpoint_id].status = CheckpointStatus.DELETED
                del self._checkpoints[checkpoint_id]
                self._audit_log.append(AuditLogEntry(
                    timestamp=time.time(),
                    action="delete_checkpoint",
                    checkpoint_id=checkpoint_id
                ))

    def list(self) -> List[Checkpoint]:
        with self._lock:
            return list(self._checkpoints.values())

    def validate(self, checkpoint_id: str) -> bool:
        with self._lock:
            checkpoint = self._checkpoints.get(checkpoint_id)
            if not checkpoint:
                return False

            expected_hash = checkpoint.hash
            checkpoint.compute_hash()
            if checkpoint.hash != expected_hash:
                checkpoint.status = CheckpointStatus.CORRUPTED
                return False

            checkpoint.status = CheckpointStatus.VALIDATED
            return True

    def get_audit_log(self) -> List[AuditLogEntry]:
        with self._lock:
            return list(self._audit_log)


class CheckpointManager:
    """check点管理器"""

    def __init__(self):
        self._storage = CheckpointStorage()
        self._periodic_interval = 300
        self._running = False
        self._timer = None
        self._current_state = {}

    def start(self):
        if self._running:
            return
        self._running = True
        self._schedule_periodic_checkpoint()

    def stop(self):
        self._running = False
        if self._timer:
            self._timer.cancel()

    def _schedule_periodic_checkpoint(self):
        if not self._running:
            return

        self.create_checkpoint(CheckpointType.PERIODIC)
        self._timer = threading.Timer(self._periodic_interval, self._schedule_periodic_checkpoint)
        self._timer.start()

    def create_checkpoint(self, checkpoint_type: CheckpointType,
                          data: Optional[Dict[str, Any]] = None,
                          metadata: Optional[Dict[str, Any]] = None) -> str:
        checkpoint_id = hashlib.sha256(f"{time.time()}_{checkpoint_type.value}".encode()).hexdigest()[:16]

        checkpoint = Checkpoint(
            checkpoint_id=checkpoint_id,
            type=checkpoint_type,
            timestamp=time.time(),
            data=data or self._current_state.copy(),
            metadata=metadata or {}
        )

        self._storage.save(checkpoint)
        return checkpoint_id

    def restore_checkpoint(self, checkpoint_id: str) -> bool:
        checkpoint = self._storage.load(checkpoint_id)
        if not checkpoint:
            return False

        if not self._storage.validate(checkpoint_id):
            return False

        self._current_state = checkpoint.data.copy()
        checkpoint.status = CheckpointStatus.RESTORED
        self._storage.save(checkpoint)
        return True

    def delete_checkpoint(self, checkpoint_id: str):
        self._storage.delete(checkpoint_id)

    def update_state(self, key: str, value: Any):
        self._current_state[key] = value

    def get_state(self) -> Dict[str, Any]:
        return self._current_state.copy()

    def list_checkpoints(self) -> List[Dict[str, Any]]:
        """列出check点"""
        checkpoints = self._storage.list()
        return [{
            'checkpoint_id': c.checkpoint_id,
            'type': c.type.value,
            'timestamp': c.timestamp,
            'status': c.status.value,
            'hash': c.hash
        } for c in checkpoints]

    def validate_checkpoint(self, checkpoint_id: str) -> bool:
        return self._storage.validate(checkpoint_id)

    def generate_audit_report(self) -> Dict[str, Any]:
        log = self._storage.get_audit_log()
        checkpoints = self._storage.list()

        report = {
            'generated_at': time.time(),
            'total_checkpoints': len(checkpoints),
            'checkpoint_summary': {
                'manual': sum(1 for c in checkpoints if c.type == CheckpointType.MANUAL),
                'automatic': sum(1 for c in checkpoints if c.type == CheckpointType.AUTOMATIC),
                'periodic': sum(1 for c in checkpoints if c.type == CheckpointType.PERIODIC),
                'event_triggered': sum(1 for c in checkpoints if c.type == CheckpointType.EVENT_TRIGGERED)
            },
            'status_summary': {
                'created': sum(1 for c in checkpoints if c.status == CheckpointStatus.CREATED),
                'validated': sum(1 for c in checkpoints if c.status == CheckpointStatus.VALIDATED),
                'restored': sum(1 for c in checkpoints if c.status == CheckpointStatus.RESTORED),
                'corrupted': sum(1 for c in checkpoints if c.status == CheckpointStatus.CORRUPTED)
            },
            'audit_events': len(log),
            'recent_events': [
                {
                    'timestamp': e.timestamp,
                    'action': e.action,
                    'checkpoint_id': e.checkpoint_id,
                    'details': e.details
                }
                for e in log[-10:]
            ]
        }

        return report

    def set_periodic_interval(self, interval: int):
        self._periodic_interval = interval
        if self._running:
            self.stop()
            self.start()


class AuditCheckpointService:
    """审计check点service"""

    def __init__(self):
        self._manager = CheckpointManager()
        self._hooks: List[Callable] = []

    def start(self):
        self._manager.start()

    def stop(self):
        self._manager.stop()

    def create_checkpoint(self, data: Dict[str, Any], checkpoint_type: str = "manual") -> Dict[str, Any]:
        try:
            type_enum = CheckpointType(checkpoint_type.lower())
        except ValueError:
            type_enum = CheckpointType.MANUAL

        checkpoint_id = self._manager.create_checkpoint(type_enum, data)
        return {'success': True, 'checkpoint_id': checkpoint_id}

    def restore_checkpoint(self, checkpoint_id: str) -> Dict[str, Any]:
        success = self._manager.restore_checkpoint(checkpoint_id)
        return {'success': success, 'checkpoint_id': checkpoint_id}

    def delete_checkpoint(self, checkpoint_id: str) -> Dict[str, Any]:
        self._manager.delete_checkpoint(checkpoint_id)
        return {'success': True, 'checkpoint_id': checkpoint_id}

    def list_checkpoints(self) -> Dict[str, Any]:
        checkpoints = self._manager.list_checkpoints()
        return {'success': True, 'checkpoints': checkpoints}

    def validate_checkpoint(self, checkpoint_id: str) -> Dict[str, Any]:
        valid = self._manager.validate_checkpoint(checkpoint_id)
        return {'success': valid, 'checkpoint_id': checkpoint_id}

    def generate_report(self) -> Dict[str, Any]:
        report = self._manager.generate_audit_report()
        return {'success': True, 'report': report}

    def set_auto_save_interval(self, seconds: int) -> Dict[str, Any]:
        self._manager.set_periodic_interval(seconds)
        return {'success': True, 'interval': seconds}


def create_audit_checkpoint(data: Dict[str, Any]) -> Dict[str, Any]:
    """convenience entry point"""
    service = AuditCheckpointService()
    service.start()
    try:
        result = service.create_checkpoint(data)
        result['report'] = service.generate_report()
        return result
    finally:
        service.stop()
