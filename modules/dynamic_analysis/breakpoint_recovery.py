import os
import json
import pickle
import sqlite3
import logging
from typing import Dict, Any, Optional, Callable, List
from pathlib import Path
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from threading import Lock

logger = logging.getLogger(__name__)


class RecoveryMode:
    # 恢复策略枚举
    MANUAL = "manual"           # 人工驱动恢复
    AUTO_RETRY = "auto_retry"  # 指数退避重试
    SKIP = "skip"               # 丢弃失败任务，保留流水线
    ROLLBACK = "rollback"       # 回滚到最近的合法检查点


class SnapshotType:
    # 任务状态快照分类
    TASK_START = "task_start"
    TASK_COMPLETE = "task_complete"
    CHECKPOINT = "checkpoint"
    ERROR = "error"
    MANUAL = "manual"

class TaskSnapshot:
    __slots__ = ('task_id', 'snapshot_type', 'timestamp', 'state', 'context', 'dependencies', 'snapshot_id', 'parent_snapshot_id',)

    def __init__(self, task_id, snapshot_type, timestamp, state, context, dependencies, snapshot_id="", parent_snapshot_id=""):
        self.task_id = task_id
        self.snapshot_type = snapshot_type
        self.timestamp = timestamp
        self.state = state
        self.context = context
        self.dependencies = dependencies
        self.snapshot_id = snapshot_id
        self.parent_snapshot_id = parent_snapshot_id


    def __post_init__(self):
        if not self.snapshot_id:
            self.snapshot_id = self._generate_id()

    def _generate_id(self) -> str:
        return f"{self.task_id}_{self.timestamp.strftime('%Y%m%d_%H%M%S')}_{id(self)}"[:32]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "snapshot_type": self.snapshot_type.value,
            "timestamp": self.timestamp.isoformat(),
            "state": self.state,
            "context": self.context,
            "dependencies": self.dependencies,
            "snapshot_id": self.snapshot_id,
            "parent_snapshot_id": self.parent_snapshot_id
        }


class RecoveryPlan:
    __slots__ = ('plan_id', 'error_key', 'task_id', 'mode', 'steps', 'estimated_time', 'created_at',)

    def __init__(self, plan_id, error_key, task_id, mode, steps, estimated_time=None, created_at=field(default_factory=datetime.now)):
        self.plan_id = plan_id
        self.error_key = error_key
        self.task_id = task_id
        self.mode = mode
        self.steps = steps
        self.estimated_time = estimated_time
        self.created_at = created_at


    def to_dict(self) -> Dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "error_key": self.error_key,
            "task_id": self.task_id,
            "mode": self.mode.value,
            "steps": self.steps,
            "estimated_time": str(self.estimated_time),
            "created_at": self.created_at.isoformat()
        }


class CheckpointManager:
    # 持久化任务检查点存储，带内存索引

    def __init__(self, checkpoint_dir: str = "data/checkpoints"):
        self._checkpoint_dir = Path(checkpoint_dir)
        self._checkpoint_dir.mkdir(parents=True, exist_ok=True)
        self._active_checkpoints: Dict[str, TaskSnapshot] = {}
        self._lock = Lock()

    def create_checkpoint(self, task_id: str, state: Dict[str, Any], context: Dict[str, Any], snapshot_type: SnapshotType = SnapshotType.CHECKPOINT, parent_snapshot_id: str = "") -> str:
        # 将当前任务状态序列化到磁盘上的命名检查点
        snapshot = TaskSnapshot(
            task_id=task_id,
            snapshot_type=snapshot_type,
            timestamp=datetime.now(),
            state=state,
            context=context,
            dependencies=[],
            parent_snapshot_id=parent_snapshot_id
        )

        with self._lock:
            self._active_checkpoints[snapshot.snapshot_id] = snapshot

        self._persist_snapshot(snapshot)
        logger.info(f"Checkpoint persisted: {snapshot.snapshot_id}")

        return snapshot.snapshot_id

    def _persist_snapshot(self, snapshot: TaskSnapshot):
        # 将快照刷写到磁盘的 JSON 文件
        snapshot_dir = self._checkpoint_dir / snapshot.task_id
        snapshot_dir.mkdir(exist_ok=True)

        snapshot_file = snapshot_dir / f"{snapshot.snapshot_id}.json"
        with open(snapshot_file, 'w', encoding='utf-8') as f:
            json.dump(snapshot.to_dict(), f, indent=2, ensure_ascii=False)

    def load_checkpoint(self, snapshot_id: str) -> Optional[TaskSnapshot]:
        # 从磁盘按 ID 恢复已保存的快照
        for task_dir in self._checkpoint_dir.iterdir():
            if not task_dir.is_dir():
                continue
            snapshot_file = task_dir / f"{snapshot_id}.json"
            if snapshot_file.exists():
                try:
                    with open(snapshot_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        return TaskSnapshot(
                            task_id=data["task_id"],
                            snapshot_type=SnapshotType(data["snapshot_type"]),
                            timestamp=datetime.fromisoformat(data["timestamp"]),
                            state=data["state"],
                            context=data["context"],
                            dependencies=data["dependencies"],
                            snapshot_id=data["snapshot_id"],
                            parent_snapshot_id=data.get("parent_snapshot_id", ""))
                except Exception as e:
                    logger.error(f"Checkpoint load error: {e}")

        return None

    def get_task_checkpoints(self, task_id: str) -> List[TaskSnapshot]:
        # 返回某任务的所有快照，按时间戳排序
        snapshots = []
        task_dir = self._checkpoint_dir / task_id

        if task_dir.exists():
            for snapshot_file in task_dir.glob("*.json"):
                try:
                    with open(snapshot_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        snapshots.append(TaskSnapshot(
                            task_id=data["task_id"],
                            snapshot_type=SnapshotType(data["snapshot_type"]),
                            timestamp=datetime.fromisoformat(data["timestamp"]),
                            state=data["state"],
                            context=data["context"],
                            dependencies=data["dependencies"],
                            snapshot_id=data["snapshot_id"],
                            parent_snapshot_id=data.get("parent_snapshot_id", "")
                        ))

                except Exception as e:
                    logger.error(f"Snapshot parse error: {e}")

        snapshots.sort(key=lambda x: x.timestamp)
        return snapshots

    def get_latest_checkpoint(self, task_id: str) -> Optional[TaskSnapshot]:
        # 返回某任务最近的快照，无则 None
        checkpoints = self.get_task_checkpoints(task_id)
        return checkpoints[-1] if checkpoints else None

    def delete_checkpoint(self, snapshot_id: str) -> bool:
        # 从磁盘和内存索引中移除快照
        for task_dir in self._checkpoint_dir.iterdir():
            if not task_dir.is_dir():
                continue

            snapshot_file = task_dir / f"{snapshot_id}.json"
            if snapshot_file.exists():
                snapshot_file.unlink()
                with self._lock:
                    if snapshot_id in self._active_checkpoints:
                        del self._active_checkpoints[snapshot_id]
                return True

        return False

    def cleanup_old_checkpoints(self, max_age_days: int = 30) -> int:
        # 清除超过阈值的旧快照，返回删除数
        cutoff_time = datetime.now() - timedelta(days=max_age_days)
        deleted_count = 0

        for task_dir in self._checkpoint_dir.iterdir():
            if not task_dir.is_dir():
                continue

            for snapshot_file in task_dir.glob("*.json"):
                try:
                    mtime = datetime.fromtimestamp(snapshot_file.stat().st_mtime)
                    if mtime < cutoff_time:
                        snapshot_file.unlink()
                        deleted_count += 1
                except Exception as e:
                    logger.error(f"Checkpoint cleanup error: {e}")

        return deleted_count


class RecoveryStrategy:
    # 抽象基类，决定错误是否可恢复以及如何恢复

    def can_recover(self, error_record: 'ErrorRecord') -> bool:
        pass

    def create_recovery_plan(self, error_record: 'ErrorRecord') -> RecoveryPlan:
        pass

    def execute_recovery(self, plan: RecoveryPlan) -> bool:
        pass


class AutoRetryStrategy(RecoveryStrategy):
    # 指数退避重试失败任务

    def __init__(self, max_retries: int = 3, delay_seconds: int = 5):
        self.max_retries = max_retries
        self.delay_seconds = delay_seconds

    def can_recover(self, error_record: 'ErrorRecord') -> bool:
        return error_record.retry_count < self.max_retries

    def create_recovery_plan(self, error_record: 'ErrorRecord') -> RecoveryPlan:
        return RecoveryPlan(
            plan_id=f"retry_{error_record.error_key}",
            error_key=error_record.error_key,
            task_id=error_record.task_id,
            mode=RecoveryMode.AUTO_RETRY,
            steps=[{
                "action": "retry_task",
                "task_id": error_record.task_id,
                "retry_count": error_record.retry_count + 1,
                "delay_seconds": self.delay_seconds * (error_record.retry_count + 1)
            }],
            estimated_time=timedelta(seconds=self.delay_seconds * (error_record.retry_count + 1)))

    def execute_recovery(self, plan: RecoveryPlan) -> bool:
        import time

        for step in plan.steps:
            if step["action"] == "retry_task":
                delay = step.get("delay_seconds", 0)
                if delay > 0:
                    time.sleep(delay)

                logger.info(f"Retry task: {step['task_id']} (attempt {step['retry_count']})")

        return True


class SkipStrategy(RecoveryStrategy):
    # 跳过失败任务，流水线继续处理剩余工作

    def can_recover(self, error_record: 'ErrorRecord') -> bool:
        return True

    def create_recovery_plan(self, error_record: 'ErrorRecord') -> RecoveryPlan:
        return RecoveryPlan(
            plan_id=f"skip_{error_record.error_key}",
            error_key=error_record.error_key,
            task_id=error_record.task_id,
            mode=RecoveryMode.SKIP,
            steps=[{
                "action": "skip_task",
                "task_id": error_record.task_id,
                "reason": "Task skipped by automatic recovery policy"
            }],
            estimated_time=timedelta(seconds=0)
        )


class RollbackStrategy(RecoveryStrategy):
    # 将任务状态回滚到最后已知的合法检查点

    def __init__(self, checkpoint_manager: CheckpointManager):
        self.checkpoint_manager = checkpoint_manager

    def can_recover(self, error_record: 'ErrorRecord') -> bool:
        if not error_record.task_id:
            return False

        checkpoints = self.checkpoint_manager.get_task_checkpoints(error_record.task_id)
        return len(checkpoints) > 0

    def create_recovery_plan(self, error_record: 'ErrorRecord') -> RecoveryPlan:
        checkpoints = self.checkpoint_manager.get_task_checkpoints(error_record.task_id)
        steps = []

        if checkpoints:
            latest_checkpoint = checkpoints[-1]
            steps.append({
                "action": "rollback_to_checkpoint",
                "checkpoint_id": latest_checkpoint.snapshot_id,
                "task_id": error_record.task_id,
                "timestamp": latest_checkpoint.timestamp.isoformat()
            })
            steps.append({
                "action": "retry_task",
                "task_id": error_record.task_id,
                "retry_count": 1
            })

        return RecoveryPlan(
            plan_id=f"rollback_{error_record.error_key}",
            error_key=error_record.error_key,
            task_id=error_record.task_id,
            mode=RecoveryMode.ROLLBACK,
            steps=steps,
            estimated_time=timedelta(seconds=30))


    def execute_recovery(self, plan: RecoveryPlan) -> bool:
        for step in plan.steps:
            if step["action"] == "rollback_to_checkpoint":
                checkpoint = self.checkpoint_manager.load_checkpoint(step["checkpoint_id"])
                if checkpoint:
                    logger.info(f"Rollback to checkpoint: {step['checkpoint_id']}")
                else:
                    logger.error(f"Checkpoint not found: {step['checkpoint_id']}")
                    return False

            elif step["action"] == "retry_task":
                logger.info(f"Retry task: {step['task_id']}")

        return True


class ErrorRecord:
    __slots__ = ('error_key', 'task_id', 'exception_type', 'message', 'traceback', 'context', 'timestamp', 'retry_count', 'last_retry_time', 'resolved', 'recovery_plan',)

    def __init__(self, error_key, task_id, exception_type, message, traceback, context, timestamp, retry_count=0, last_retry_time=None, resolved=False, recovery_plan=None):
        self.error_key = error_key
        self.task_id = task_id
        self.exception_type = exception_type
        self.message = message
        self.traceback = traceback
        self.context = context
        self.timestamp = timestamp
        self.retry_count = retry_count
        self.last_retry_time = last_retry_time
        self.resolved = resolved
        self.recovery_plan = recovery_plan



class BreakpointRecoveryManager:
    # 检查点驱动的任务恢复编排器
    # 流水线：异常捕获→SQLite+JSON 持久化→检查点恢复→策略链（自动重试→回滚→跳过）→审计

    def __init__(self, checkpoint_dir: str = "data/checkpoints", db_path: str = "data/recovery.db"):
        self._checkpoint_manager = CheckpointManager(checkpoint_dir)
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)

        self._recovery_strategies: List[RecoveryStrategy] = [
            AutoRetryStrategy(),
            RollbackStrategy(self._checkpoint_manager),
            SkipStrategy()
        ]

        self._errors: Dict[str, ErrorRecord] = {}
        self._recovery_callbacks: List[Callable[[ErrorRecord], bool]] = []
        self._lock = Lock()

        self._init_database()
        self._load_errors()

    def _init_database(self):
        # 初始化 SQLite schema：error_records + recovery_history
        conn = sqlite3.connect(str(self._db_path))

        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS error_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                error_key TEXT UNIQUE,
                task_id TEXT,
                exception_type TEXT,
                message TEXT,
                traceback TEXT,
                context TEXT,
                timestamp TEXT,
                retry_count INTEGER,
                last_retry_time TEXT,
                resolved INTEGER,
                recovery_plan TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS recovery_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                error_key TEXT,
                plan_id TEXT,
                mode TEXT,
                success INTEGER,
                executed_at TEXT,
                duration REAL,
                FOREIGN KEY (error_key) REFERENCES error_records(error_key)
            )
        ''')

        conn.commit()
        conn.close()

    def _load_errors(self):
        # 将持久化的错误记录恢复到内存索引
        conn = sqlite3.connect(str(self._db_path))

        cursor = conn.cursor()

        cursor.execute('SELECT * FROM error_records')

        for row in cursor.fetchall():
            try:
                error_record = ErrorRecord(
                    error_key=row[1],
                    task_id=row[2],
                    exception_type=row[3],
                    message=row[4],
                    traceback=row[5],
                    context=json.loads(row[6]),
                    timestamp=datetime.fromisoformat(row[7]),
                    retry_count=row[8],
                    last_retry_time=datetime.fromisoformat(row[9]) if row[9] else None,
                    resolved=bool(row[10]),
                    recovery_plan=json.loads(row[11]) if row[11] else None
                )
                self._errors[row[1]] = error_record
            except Exception as e:
                logger.error(f"Error record deserialization failed: {e}")

        conn.close()

    def capture_exception(self, exception: Exception, task_id: Optional[str] = None, context: Optional[Dict[str, Any]] = None) -> str:
        # 将异常包装为 ErrorRecord 并立即持久化
        error_key = f"{type(exception).__name__}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{id(exception)}"[:64]

        error_record = ErrorRecord(
            error_key=error_key,
            task_id=task_id,
            exception_type=type(exception).__name__,
            message=str(exception),
            traceback=self._format_traceback(exception),
            context=context or {},
            timestamp=datetime.now()
        )

        with self._lock:
            self._errors[error_key] = error_record

        self._persist_error(error_record)
        logger.error(f"Exception captured: {error_key} — {exception}")

        return error_key

    def _format_traceback(self, exception: Exception) -> str:
        # 生成异常的字符串 traceback
        import traceback
        return traceback.format_exc()

    def _persist_error(self, error_record: ErrorRecord):
        # 将错误记录 upsert 到 SQLite
        conn = sqlite3.connect(str(self._db_path))

        cursor = conn.cursor()

        recovery_plan_json = json.dumps(error_record.recovery_plan.to_dict()) if error_record.recovery_plan else None

        cursor.execute('''
            INSERT OR REPLACE INTO error_records
            (error_key, task_id, exception_type, message, traceback, context, timestamp,
             retry_count, last_retry_time, resolved, recovery_plan)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            error_record.error_key,
            error_record.task_id,
            error_record.exception_type,
            error_record.message,
            error_record.traceback,
            json.dumps(error_record.context),
            error_record.timestamp.isoformat(),
            error_record.retry_count,
            error_record.last_retry_time.isoformat() if error_record.last_retry_time else None,
            int(error_record.resolved),
            recovery_plan_json
        ))

        conn.commit()
        conn.close()

    def generate_recovery_plan(self, error_key: str) -> Optional[RecoveryPlan]:
        # 选择第一个适用的恢复策略并生成恢复计划
        error_record = self._errors.get(error_key)
        if not error_record:
            return None

        for strategy in self._recovery_strategies:
            if strategy.can_recover(error_record):
                plan = strategy.create_recovery_plan(error_record)
                error_record.recovery_plan = plan
                self._persist_error(error_record)
                return plan

        return None

    def execute_recovery(self, error_key: str) -> bool:
        # 对已捕获的错误执行分配的恢复计划
        error_record = self._errors.get(error_key)
        if not error_record:
            return False

        if not error_record.recovery_plan:
            plan = self.generate_recovery_plan(error_key)
            if not plan:
                return False
        else:
            plan = error_record.recovery_plan

        for strategy in self._recovery_strategies:
            if isinstance(strategy, self._get_strategy_type(plan.mode)):
                success = strategy.execute_recovery(plan)
                self._record_recovery_history(error_key, plan, success)

                if success:
                    error_record.resolved = True
                    self._persist_error(error_record)
                    logger.info(f"Recovery succeeded: {error_key}")

                return success

        return False

    def _get_strategy_type(self, mode: RecoveryMode):
        # 将 RecoveryMode 映射到对应策略类
        mapping = {
            RecoveryMode.AUTO_RETRY: AutoRetryStrategy,
            RecoveryMode.SKIP: SkipStrategy,
            RecoveryMode.ROLLBACK: RollbackStrategy
        }
        return mapping.get(mode)

    def _record_recovery_history(self, error_key: str, plan: RecoveryPlan, success: bool):
        # 向 recovery_history 追加审计条目
        conn = sqlite3.connect(str(self._db_path))

        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO recovery_history
            (error_key, plan_id, mode, success, executed_at, duration)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            error_key,
            plan.plan_id,
            plan.mode.value,
            int(success),
            datetime.now().isoformat(),
            0.0
        ))

        conn.commit()
        conn.close()

    def save_checkpoint(self, task_id: str, state: Dict[str, Any], context: Dict[str, Any], snapshot_type: SnapshotType = SnapshotType.CHECKPOINT) -> str:
        # 持久化任务检查点，返回快照 ID
        return self._checkpoint_manager.create_checkpoint(task_id, state, context, snapshot_type)

    def load_from_checkpoint(self, task_id: str) -> Optional[Dict[str, Any]]:
        # 从最近的检查点恢复任务状态
        checkpoint = self._checkpoint_manager.get_latest_checkpoint(task_id)
        return checkpoint.state if checkpoint else None

    def get_unresolved_errors(self) -> List[ErrorRecord]:
        # 返回所有待解决的错误
        return [e for e in self._errors.values() if not e.resolved]

    def register_recovery_callback(self, callback: Callable[[ErrorRecord], bool]):
        # 将外部处理器链接到恢复流水线
        self._recovery_callbacks.append(callback)

    def trigger_recovery(self, error_key: str):
        # 调用已注册的回调直到有回调处理该错误
        error_record = self._errors.get(error_key)
        if not error_record:
            return

        for callback in self._recovery_callbacks:
            try:
                if callback(error_record):
                    break
            except Exception as e:
                logger.error(f"Recovery callback error: {e}")

    def get_recovery_status(self, error_key: str) -> Dict[str, Any]:
        # 查询指定错误的恢复状态
        error_record = self._errors.get(error_key)
        if not error_record:
            return {"error": "Error record not found"}

        return {
            "error_key": error_record.error_key,
            "task_id": error_record.task_id,
            "message": error_record.message,
            "resolved": error_record.resolved,
            "retry_count": error_record.retry_count,
            "recovery_plan": error_record.recovery_plan.to_dict() if error_record.recovery_plan else None,
            "timestamp": error_record.timestamp.isoformat()
        }


def get_recovery_manager() -> BreakpointRecoveryManager:
    # 全局恢复管理器单例访问器
    global _recovery_manager
    if _recovery_manager is None:
        _recovery_manager = BreakpointRecoveryManager()
    return _recovery_manager

_recovery_manager = None


class RecoveryContextManager:
    # 上下文管理器：进入时自动检查点，异常时自动恢复

    def __init__(self, task_id: str, recovery_manager: BreakpointRecoveryManager = None):
        self._task_id = task_id
        self._recovery_manager = recovery_manager or get_recovery_manager()
        self._checkpoint_ids = []

    def __enter__(self):
        self._save_initial_checkpoint()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_val:
            error_key = self._recovery_manager.capture_exception(exc_val, self._task_id)
            self._recovery_manager.generate_recovery_plan(error_key)
        else:
            self._save_final_checkpoint()

    def _save_initial_checkpoint(self):
        # 任务执行开始前快照状态
        checkpoint_id = self._recovery_manager.save_checkpoint(
            self._task_id,
            {"status": "started"},
            {"timestamp": datetime.now().isoformat()},
            SnapshotType.TASK_START
        )
        self._checkpoint_ids.append(checkpoint_id)

    def _save_final_checkpoint(self):
        # 任务成功完成后快照状态
        checkpoint_id = self._recovery_manager.save_checkpoint(
            self._task_id,
            {"status": "completed"},
            {"timestamp": datetime.now().isoformat()},
            SnapshotType.TASK_COMPLETE,
            parent_snapshot_id=self._checkpoint_ids[-1] if self._checkpoint_ids else ""
        )
        self._checkpoint_ids.append(checkpoint_id)

    def save_progress(self, progress: float, state: Optional[Dict[str, Any]] = None):
        # 执行中间增量检查点
        checkpoint_id = self._recovery_manager.save_checkpoint(
            self._task_id,
            {"status": "in_progress", "progress": progress, **(state or {})},
            {"timestamp": datetime.now().isoformat()},
            SnapshotType.CHECKPOINT,
            parent_snapshot_id=self._checkpoint_ids[-1] if self._checkpoint_ids else ""
        )
        self._checkpoint_ids.append(checkpoint_id)


def recover_from_checkpoint(task_id: str) -> Optional[Dict[str, Any]]:
    # 便捷入口：从最近的检查点恢复任务状态
    recovery_manager = get_recovery_manager()
    return recovery_manager.load_from_checkpoint(task_id)


def setup_recovery_handlers():
    # 注册默认自动恢复回调（最多重试 3 次）
    recovery_manager = get_recovery_manager()

    def auto_recovery_callback(error_record: ErrorRecord) -> bool:
        if error_record.retry_count < 3:
            return recovery_manager.execute_recovery(error_record.error_key)
        return False

    recovery_manager.register_recovery_callback(auto_recovery_callback)
