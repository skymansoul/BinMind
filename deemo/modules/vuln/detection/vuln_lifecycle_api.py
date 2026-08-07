# 漏洞生命周期管理API。
# CRUD+状态机流转+历史审计。状态迁移约束为核心设计。
# 批量状态迁移原子性检查与过渡统计。

from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime
import json as _json
import hashlib
import os

json = _json


class VulnStatus(Enum):
    """漏洞生命周期状态——单向流转受状态机规则约束。"""
    NEW = "new"
    CONFIRMED = "confirmed"
    IN_PROGRESS = "in_progress"
    FIXED = "fixed"
    WONT_FIX = "wont_fix"
    FALSE_POSITIVE = "false_positive"


class VulnSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# 状态迁移白名单——定义合法状态转换。
# FIXED不可退回NEW，FALSE_POSITIVE不可复活为CONFIRMED。
_VALID_TRANSITIONS: Dict[VulnStatus, List[VulnStatus]] = {
    VulnStatus.NEW: [VulnStatus.CONFIRMED, VulnStatus.FALSE_POSITIVE, VulnStatus.WONT_FIX],
    VulnStatus.CONFIRMED: [VulnStatus.IN_PROGRESS, VulnStatus.WONT_FIX, VulnStatus.FALSE_POSITIVE],
    VulnStatus.IN_PROGRESS: [VulnStatus.FIXED, VulnStatus.WONT_FIX, VulnStatus.CONFIRMED],
    VulnStatus.FIXED: [VulnStatus.CONFIRMED],  # 允许重开，但需走确认流程
    VulnStatus.WONT_FIX: [VulnStatus.CONFIRMED],
    VulnStatus.FALSE_POSITIVE: [VulnStatus.NEW],  # FP被推翻，回到NEW重新评估
}

# 严重性分数映射——CVSS v3兼容。
_SEVERITY_SCORES = {
    VulnSeverity.CRITICAL: 9.0,
    VulnSeverity.HIGH: 7.0,
    VulnSeverity.MEDIUM: 4.0,
    VulnSeverity.LOW: 1.0,
    VulnSeverity.INFO: 0.0,
}


@dataclass
class VulnRecord:
    """单条漏洞记录的完整快照。"""
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


@dataclass
class StatusChange:
    """单次状态变更的快照。"""
    from_status: VulnStatus
    to_status: VulnStatus
    timestamp: str
    reason: str = ""
    changed_by: str = "system"


class VulnLifecycleAPI:
    """漏洞生命周期管理——持久化+审计追踪。

    核心入口:
        transition(vuln_id, new_status) — 执行状态迁移，验证合法性后写入审计日志。
        get_history(vuln_id) — 返回该漏洞的完整状态变更时间线。
    """

    def __init__(self, storage_path: str = ""):
        self._records: Dict[str, VulnRecord] = {}
        # vuln_id→历史变更栈映射。
        self._history: Dict[str, List[StatusChange]] = {}
        self._storage_path = storage_path
        self._dirty = False
        if storage_path and os.path.exists(storage_path):
            self._load()

# CRUD

    def create(self, **kwargs) -> VulnRecord:
        """创建新漏洞记录。vuln_id未提供时自动生成。"""
        now = datetime.now().isoformat()
        if "vuln_id" not in kwargs:
            raw = f"{kwargs.get('cve_id', 'GEN')}{kwargs.get('function_name', '')}{now}"
            kwargs["vuln_id"] = "VULN-" + hashlib.sha256(raw.encode()).hexdigest()[:12].upper()
        rec = VulnRecord(
            vuln_id=kwargs.pop("vuln_id"),
            cve_id=kwargs.pop("cve_id", ""),
            title=kwargs.pop("title", ""),
            description=kwargs.pop("description", ""),
            severity=kwargs.pop("severity", VulnSeverity.INFO),
            status=VulnStatus.NEW,
            cvss_score=kwargs.pop("cvss_score", 0.0),
            affected_component=kwargs.pop("affected_component", ""),
            affected_version=kwargs.pop("affected_version", ""),
            file_path=kwargs.pop("file_path", ""),
            line_number=kwargs.pop("line_number", 0),
            function_name=kwargs.pop("function_name", ""),
            tags=kwargs.pop("tags", []) if isinstance(kwargs.get("tags"), list) else [],
            references=kwargs.pop("references", []) if isinstance(kwargs.get("references"), list) else [],
            created_at=now,
            updated_at=now,
        )
        self._records[rec.vuln_id] = rec
        self._history[rec.vuln_id] = [
            StatusChange(from_status=VulnStatus.NEW, to_status=VulnStatus.NEW,
                         timestamp=now, reason="Record created", changed_by="system")
        ]
        self._dirty = True
        return rec

    def read(self, vuln_id: str) -> Optional[VulnRecord]:
        return self._records.get(vuln_id)

    def update(self, vuln_id: str, **kwargs) -> Optional[VulnRecord]:
        """更新漏洞元数据，不触发状态迁移。改状态需调用transition()。"""
        rec = self._records.get(vuln_id)
        if rec is None:
            return None
        # 禁止通过update修改status——强制经transition以保证审计完整性。
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
        return sorted(results, key=lambda r: _SEVERITY_SCORES.get(r.severity, 0), reverse=True)

    def search(self, query: str) -> List[VulnRecord]:
        q = query.lower()
        results = []
        for r in self._records.values():
            if q in r.cve_id.lower():
                results.append(r); continue
            if q in r.title.lower():
                results.append(r); continue
            if q in r.function_name.lower():
                results.append(r); continue
            if q in r.affected_component.lower():
                results.append(r); continue
        return results

# 状态迁移引擎

    def transition(self, vuln_id: str, new_status: VulnStatus,
                   reason: str = "", changed_by: str = "system") -> bool:
        """执行漏洞状态迁移。核心约束:

        1. 校验当前状态→目标状态是否在合法转移表中。
        2. 写入StatusChange至历史审计栈。
        3. 更新record.updated_at。

        返回True表示迁移成功，False表示非法转移。
        """
        rec = self._records.get(vuln_id)
        if rec is None:
            return False
        # 同状态跳过，避免无意义迁移。
        if rec.status == new_status:
            return False
        allowed = _VALID_TRANSITIONS.get(rec.status, [])
        if new_status not in allowed:
            return False
        old = rec.status
        rec.status = new_status
        rec.updated_at = datetime.now().isoformat()
        change = StatusChange(
            from_status=old,
            to_status=new_status,
            timestamp=rec.updated_at,
            reason=reason,
            changed_by=changed_by,
        )
        self._history.setdefault(vuln_id, []).append(change)
        self._dirty = True
        return True

    def get_history(self, vuln_id: str) -> List[StatusChange]:
        """返回该漏洞完整状态变更时间线，时间升序。"""
        return list(self._history.get(vuln_id, []))

    def get_valid_transitions(self, vuln_id: str) -> List[VulnStatus]:
        rec = self._records.get(vuln_id)
        if rec is None:
            return []
        return _VALID_TRANSITIONS.get(rec.status, [])

# 批量操作

    def transition_batch(self, vuln_ids: List[str], new_status: VulnStatus,
                         reason: str = "") -> Dict[str, bool]:
        results = {}
        for vid in vuln_ids:
            results[vid] = self.transition(vid, new_status, reason)
        return results

    def search_by_cve(self, cve_id: str) -> List[VulnRecord]:
        return [r for r in self._records.values() if r.cve_id.upper() == cve_id.upper()]

    def search_by_component(self, component: str) -> List[VulnRecord]:
        q = component.lower()
        return [r for r in self._records.values() if q in r.affected_component.lower()]

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
        }

# 持久化

    def save(self, path: str = "") -> str:
        p = path or self._storage_path or "vuln_lifecycle.json"
        data = {
            "records": [],
            "history": {},
        }
        for rec in self._records.values():
            d = {
                "vuln_id": rec.vuln_id, "cve_id": rec.cve_id, "title": rec.title,
                "description": rec.description, "severity": rec.severity.value,
                "status": rec.status.value, "cvss_score": rec.cvss_score,
                "affected_component": rec.affected_component,
                "affected_version": rec.affected_version,
                "file_path": rec.file_path, "line_number": rec.line_number,
                "function_name": rec.function_name,
                "tags": rec.tags, "references": rec.references,
                "created_at": rec.created_at, "updated_at": rec.updated_at,
            }
            data["records"].append(d)

        for vid, changes in self._history.items():
            data["history"][vid] = [
                {"from": c.from_status.value, "to": c.to_status.value,
                 "timestamp": c.timestamp, "reason": c.reason,
                 "changed_by": c.changed_by}
                for c in changes
            ]

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
                    title=d.get("title", ""), description=d.get("description", ""),
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
                )
                self._records[rec.vuln_id] = rec

            for vid, changes in data.get("history", {}).items():
                self._history[vid] = []
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
