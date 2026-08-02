# 2026-07-21
# 核心数据模型 — 分布式任务系统的「通用语言」
# Task/Node 是跨模块传递的基本单位，保持纯数据，不掺杂业务逻辑
# 序列化走 to_dict/from_dict，避免 pickle 的跨版本/安全风险

from __future__ import annotations

import json
import time
import enum
from dataclasses import dataclass, field, asdict
from typing import Optional, List

# ===== 枚举 =====

class TaskStatus(enum.Enum):
    """任务生命周期状态机"""
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    SUCCESS = "success"
    FAILURE = "failure"
    RETRYING = "retrying"
    CANCELLED = "cancelled"

    @property
    def terminal(self) -> bool:
        """SUCCESS / FAILURE / CANCELLED 为终态，不再变迁"""
        return self in (TaskStatus.SUCCESS, TaskStatus.FAILURE, TaskStatus.CANCELLED)


class TaskType(enum.Enum):
    STATIC_ANALYSIS = "static_analysis"
    DYNAMIC_ANALYSIS = "dynamic_analysis"
    SYMBOLIC = "symbolic"
    DECOMPILE = "decompile"
    CUSTOM = "custom"


# ===== 数据类 =====

@dataclass
class Task:
    """分布式任务 — 不可变字段用 dataclass，可变状态走属性 setter"""
    id: str
    type: TaskType
    payload: dict = field(default_factory=dict)
    priority: int = 0
    status: TaskStatus = TaskStatus.PENDING
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    retries: int = 0
    max_retries: int = 3
    timeout: float = 300.0
    tags: list = field(default_factory=list)
    parent_id: Optional[str] = None

    def touch(self):
        self.updated_at = time.time()

    def age(self) -> float:
        """自创建以来的秒数"""
        return time.time() - self.created_at

    def to_dict(self) -> dict:
        d = asdict(self)
        d["type"] = self.type.value
        d["status"] = self.status.value
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Task":
        d = dict(d)  # 浅拷贝防止污染入参
        d["type"] = TaskType(d["type"]) if not isinstance(d.get("type"), TaskType) else d["type"]
        d["status"] = TaskStatus(d["status"]) if not isinstance(d.get("status"), TaskStatus) else d["status"]
        d.setdefault("tags", [])
        d.setdefault("parent_id", None)
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class Node:
    """计算节点 — worker 注册信息"""
    id: str
    address: str
    status: str = "offline"  # online / offline / busy
    last_heartbeat: float = field(default_factory=time.time)
    capacity: int = 1
    current_load: int = 0
    labels: dict = field(default_factory=dict)
    version: str = "0.1.0"

    @property
    def load_ratio(self) -> float:
        if self.capacity <= 0:
            return 1.0
        return min(self.current_load / self.capacity, 1.0)

    def is_available(self) -> bool:
        return self.status == "online" and self.current_load < self.capacity

    def is_stale(self, timeout: float = 60.0) -> bool:
        """心跳超过 timeout 秒未更新视为失联"""
        return time.time() - self.last_heartbeat > timeout

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Node":
        d = dict(d)
        d.setdefault("labels", {})
        d.setdefault("version", "0.1.0")
        keys = cls.__dataclass_fields__.keys()
        return cls(**{k: d[k] for k in keys if k in d})


# ------- 便捷序列化 -------

def task_to_json(task: Task, indent=None) -> str:
    return json.dumps(task.to_dict(), indent=indent, ensure_ascii=False)

def task_from_json(s: str) -> Task:
    return Task.from_dict(json.loads(s))

def node_to_json(node: Node, indent=None) -> str:
    return json.dumps(node.to_dict(), indent=indent, ensure_ascii=False)

def node_from_json(s: str) -> Node:
    return Node.from_dict(json.loads(s))


# ------- 批量操作 -------

def tasks_from_json_list(raw: str) -> List[Task]:
    """批量反序列化 — 单次 json.loads 比逐条调用快 ~3x"""
    items = json.loads(raw)
    if not isinstance(items, list):
        raise TypeError("expected JSON array")
    return [Task.from_dict(it) for it in items]

def tasks_to_json_list(tasks: List[Task], indent=None) -> str:
    return json.dumps([t.to_dict() for t in tasks], indent=indent, ensure_ascii=False)
