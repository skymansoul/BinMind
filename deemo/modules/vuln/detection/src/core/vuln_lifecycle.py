# 漏洞生命周期状态机
# 状态迁移白名单、审计追踪、SLA跟踪
# FIXME: SLA阈值按严重级别可配置
# 同状态迁移返回False，不写审计日志

from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import uuid
import hashlib
import json as _json
import os
from collections import deque

from vuln_detection.src.logger import get_logger

json = _json
_log = get_logger("vuln_detection.lifecycle")


class VulnStatus(Enum):
    NEW = "new"
    CONFIRMED = "confirmed"
    TRIAGED = "triaged"
    IN_PROGRESS = "in_progress"
    FIXING = "fixing"
    FIXED = "fixed"
    CLOSED = "closed"
    WONT_FIX = "wont_fix"
    FALSE_POSITIVE = "false_positive"


class VulnSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# 合法状态迁移映射
# FIXED重开须经CONFIRMED；FALSE_POSITIVE仅退回NEW
_VALID_TRANSITIONS: Dict[VulnStatus, List[VulnStatus]] = {
    VulnStatus.NEW: [VulnStatus.CONFIRMED, VulnStatus.FALSE_POSITIVE, VulnStatus.WONT_FIX],
    VulnStatus.CONFIRMED: [VulnStatus.TRIAGED, VulnStatus.IN_PROGRESS,
                           VulnStatus.WONT_FIX, VulnStatus.FALSE_POSITIVE],
    VulnStatus.TRIAGED: [VulnStatus.IN_PROGRESS, VulnStatus.FIXING,
                         VulnStatus.WONT_FIX, VulnStatus.CONFIRMED],
    VulnStatus.IN_PROGRESS: [VulnStatus.FIXING, VulnStatus.WONT_FIX,
                             VulnStatus.CONFIRMED],
    VulnStatus.FIXING: [VulnStatus.FIXED, VulnStatus.IN_PROGRESS,
                        VulnStatus.WONT_FIX],
    VulnStatus.FIXED: [VulnStatus.CLOSED, VulnStatus.CONFIRMED],
    VulnStatus.CLOSED: [VulnStatus.CONFIRMED],
    VulnStatus.WONT_FIX: [VulnStatus.CONFIRMED],
    VulnStatus.FALSE_POSITIVE: [VulnStatus.NEW],
}

_SEVERITY_SCORES = {
    VulnSeverity.CRITICAL: 9.0,
    VulnSeverity.HIGH: 7.0,
    VulnSeverity.MEDIUM: 4.0,
    VulnSeverity.LOW: 1.0,
    VulnSeverity.INFO: 0.0,
}

# SLA时限（小时），阶梯化
_SLA_HOURS = {
    VulnSeverity.CRITICAL: 24,
    VulnSeverity.HIGH: 72,
    VulnSeverity.MEDIUM: 168,
    VulnSeverity.LOW: 720,
    VulnSeverity.INFO: 2160,
}


@dataclass
class VulnRecord:
    vuln_id: str
    cve_id: str = ""
    title: str = ""
    description: str = ""
    severity: VulnSeverity = VulnSeverity.INFO
    status: VulnStatus = VulnStatus.NEW
    cvss_score: float = 0.0
    affected_component: str = ""
    affected_version: str = ""
    file_path: str = ""
    line_number: int = 0
    function_name: str = ""
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""
    sla_deadline: str = ""

    @property
    def is_open(self) -> bool:
        return self.status not in (VulnStatus.FIXED, VulnStatus.CLOSED,
                                    VulnStatus.WONT_FIX, VulnStatus.FALSE_POSITIVE)

    severity_score = property(lambda self: _SEVERITY_SCORES.get(self.severity, 0.0))


@dataclass
class StatusChange:
    from_status: VulnStatus
    to_status: VulnStatus
    timestamp: str
    reason: str = ""
    changed_by: str = "system"


class VulnLifecycle:
    """漏洞生命周期管理：状态机、审计追踪、持久化。

    约束：
    - transition() 先验证再迁移
    - 同状态迁移返回False
    - update() 禁止修改status，强制经transition保证审计完整性
    - SLA按严重级别阶梯自动计算
    """

    def __init__(self, storage_path: str = ""):
        self._records: Dict[str, VulnRecord] = {}
        self._history: Dict[str, deque] = {}
        self._storage_path = storage_path
        self._dirty = False
        if storage_path and os.path.exists(storage_path):
            self._load()

    @classmethod
    def _generate_id(cls, cve_id: str = "", function_name: str = "") -> str:
        raw = f"{cve_id}{function_name}{uuid.uuid4()}"
        return "VULN-" + hashlib.sha256(raw.encode()).hexdigest()[:12].upper()

    @classmethod
    def _compute_sla(cls, severity: VulnSeverity) -> str:
        hours = _SLA_HOURS.get(severity, 168)
        deadline = datetime.now() + timedelta(hours=hours)
        return deadline.isoformat()

# 增删改查

    def create(self, **kwargs) -> VulnRecord:
        now = datetime.now().isoformat()
        if "vuln_id" not in kwargs:
            kwargs["vuln_id"] = self._generate_id(
                kwargs.get("cve_id", ""), kwargs.get("function_name", ""))
        severity = kwargs.pop("severity", VulnSeverity.INFO)
        rec = VulnRecord(
            vuln_id=kwargs.pop("vuln_id"),
            cve_id=kwargs.pop("cve_id", ""),
            title=kwargs.pop("title", ""),
            description=kwargs.pop("description", ""),
            severity=severity,
            status=VulnStatus.NEW,
            cvss_score=kwargs.pop("cvss_score", 0.0),
            affected_component=kwargs.pop("affected_component", ""),
            affected_version=kwargs.pop("affected_version", ""),
            file_path=kwargs.pop("file_path", ""),
            line_number=kwargs.pop("line_number", 0),
            function_name=kwargs.pop("function_name", ""),
            tags=kwargs.pop("tags", []) if isinstance(kwargs.get("tags"), list) else [],
            references=kwargs.pop("references", []) if isinstance(kwargs.get("references"), list) else [],
            created_at=now, updated_at=now,
            sla_deadline=self._compute_sla(severity),
        )
        self._records[rec.vuln_id] = rec
        self._history[rec.vuln_id] = deque([
            StatusChange(from_status=VulnStatus.NEW, to_status=VulnStatus.NEW,
                         timestamp=now, reason="Record created")
        ])
        self._dirty = True
        return rec

    def read(self, vuln_id: str) -> Optional[VulnRecord]:
        return self._records.get(vuln_id)

    def update(self, vuln_id: str, **kwargs) -> Optional[VulnRecord]:
        rec = self._records.get(vuln_id)
        if rec is None:
            return None
        kwargs.pop("status", None)
        kwargs.pop("vuln_id", None)
        for k, v in kwargs.items():
            if hasattr(rec, k):
                setattr(rec, k, v)
        rec.updated_at = datetime.now().isoformat()
        self._dirty = True
        return rec

    def delete(self, vuln_id: str) -> bool:
        if vuln_id in self._records:
            del self._records[vuln_id]
            self._history.pop(vuln_id, None)
            self._dirty = True
            return True
        return False

    def list_all(self, status: Optional[VulnStatus] = None,
                 severity: Optional[VulnSeverity] = None) -> List[VulnRecord]:
        results = list(self._records.values())
        if status:
            results = [r for r in results if r.status == status]
        if severity:
            results = [r for r in results if r.severity == severity]
        return sorted(results, key=lambda r: _SEVERITY_SCORES.get(r.severity, 0),
                      reverse=True)

    def search(self, query: str) -> List[VulnRecord]:
        q = query.lower()
        results = []
        for r in self._records.values():
            if q in r.cve_id.lower(): results.append(r); continue
            if q in r.title.lower(): results.append(r); continue
            if q in r.function_name.lower(): results.append(r); continue
            if q in r.affected_component.lower(): results.append(r); continue
            if q in r.description.lower(): results.append(r); continue
        return results

# 状态流转

    def transition(self, vuln_id: str, new_status: VulnStatus,
                   reason: str = "", changed_by: str = "system") -> bool:
        rec = self._records.get(vuln_id)
        if rec is None:
            return False
        if rec.status == new_status:
            return False
        allowed = _VALID_TRANSITIONS.get(rec.status, [])
        if new_status not in allowed:
            _log.warning("illegal transition: %s -> %s for %s",
                         rec.status.value, new_status.value, vuln_id)
            return False
        old = rec.status
        rec.status = new_status
        rec.updated_at = datetime.now().isoformat()
        change = StatusChange(
            from_status=old, to_status=new_status,
            timestamp=rec.updated_at, reason=reason,
            changed_by=changed_by)
        self._history.setdefault(vuln_id, deque()).append(change)
        self._dirty = True
        return True

    def get_history(self, vuln_id: str) -> List[StatusChange]:
        return list(self._history.get(vuln_id, []))

    def get_valid_transitions(self, vuln_id: str) -> List[VulnStatus]:
        rec = self._records.get(vuln_id)
        if rec is None:
            return []
        return _VALID_TRANSITIONS.get(rec.status, [])

    def transition_batch(self, vuln_ids: List[str], new_status: VulnStatus,
                         reason: str = "") -> Dict[str, bool]:
        results = {}
        for vid in vuln_ids:
            results[vid] = self.transition(vid, new_status, reason)
        return results

# 检索

    def _find_by_cve(self, cve_id: str) -> List[VulnRecord]:
        return [r for r in self._records.values()
                if r.cve_id.upper() == cve_id.upper()]

    def _find_by_component(self, component: str) -> List[VulnRecord]:
        q = component.lower()
        return [r for r in self._records.values()
                if q in r.affected_component.lower()]

    def _fetch_sla_breaches(self) -> List[VulnRecord]:
        now = datetime.now()
        return [r for r in self._records.values()
                if r.is_open and r.sla_deadline
                and datetime.fromisoformat(r.sla_deadline) < now]

# 统计

    def stats(self) -> Dict[str, Any]:
        by_status: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        for r in self._records.values():
            by_status[r.status.value] = by_status.get(r.status.value, 0) + 1
            by_severity[r.severity.value] = by_severity.get(r.severity.value, 0) + 1
        return {
            "total": len(self._records),
            "by_status": by_status,
            "by_severity": by_severity,
            "open_count": sum(1 for r in self._records.values() if r.is_open),
            "sla_breaches": len(self._fetch_sla_breaches()),
        }

# 持久化

    def save(self, path: str = "") -> str:
        p = path or self._storage_path or "vuln_lifecycle.json"
        data = {"records": [], "history": {}}
        for rec in self._records.values():
            d = {
                "vuln_id": rec.vuln_id, "cve_id": rec.cve_id,
                "title": rec.title, "description": rec.description,
                "severity": rec.severity.value, "status": rec.status.value,
                "cvss_score": rec.cvss_score,
                "affected_component": rec.affected_component,
                "affected_version": rec.affected_version,
                "file_path": rec.file_path, "line_number": rec.line_number,
                "function_name": rec.function_name,
                "tags": rec.tags, "references": rec.references,
                "created_at": rec.created_at, "updated_at": rec.updated_at,
                "sla_deadline": rec.sla_deadline,
            }
            data["records"].append(d)

        for vid, changes in self._history.items():
            data["history"][vid] = [
                {"from": c.from_status.value, "to": c.to_status.value,
                 "timestamp": c.timestamp, "reason": c.reason,
                 "changed_by": c.changed_by}
                for c in changes
            ]

        os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        self._dirty = False
        return os.path.abspath(p)

    def _load(self) -> None:
        try:
            with open(self._storage_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for d in data.get("records", []):
                rec = VulnRecord(
                    vuln_id=d["vuln_id"], cve_id=d.get("cve_id", ""),
                    title=d.get("title", ""),
                    description=d.get("description", ""),
                    severity=VulnSeverity(d.get("severity", "info")),
                    status=VulnStatus(d.get("status", "new")),
                    cvss_score=d.get("cvss_score", 0.0),
                    affected_component=d.get("affected_component", ""),
                    affected_version=d.get("affected_version", ""),
                    file_path=d.get("file_path", ""),
                    line_number=d.get("line_number", 0),
                    function_name=d.get("function_name", ""),
                    tags=d.get("tags", []), references=d.get("references", []),
                    created_at=d.get("created_at", ""),
                    updated_at=d.get("updated_at", ""),
                    sla_deadline=d.get("sla_deadline", ""),
                )
                self._records[rec.vuln_id] = rec
            for vid, changes in data.get("history", {}).items():
                self._history[vid] = deque()
                for c in changes:
                    self._history[vid].append(StatusChange(
                        from_status=VulnStatus(c["from"]),
                        to_status=VulnStatus(c["to"]),
                        timestamp=c.get("timestamp", ""),
                        reason=c.get("reason", ""),
                        changed_by=c.get("changed_by", "system"),
                    ))
        except Exception:
            pass

    def close(self) -> None:
        if self._dirty and self._storage_path:
            self.save()
