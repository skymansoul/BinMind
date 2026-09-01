import logging
from typing import Dict, Any, List, Optional
import time
from enum import Enum

logger = logging.getLogger(__name__)


class VulnStatus(Enum):
    NEW = "new"
    CONFIRMED = "confirmed"
    TRIAGED = "triaged"
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


class VulnRecord:
    __slots__ = ('vuln_id', 'title', 'status', 'severity', 'assignee', 'created_at', 'updated_at', 'sla_days', 'sla_deadline', 'comments',)

    def __init__(self, vuln_id, title, status=VulnStatus.NEW, severity=VulnSeverity.MEDIUM, assignee="", created_at=0.0, updated_at=0.0, sla_days=30, sla_deadline=0.0, comments=None):
        self.vuln_id = vuln_id
        self.title = title
        self.status = status
        self.severity = severity
        self.assignee = assignee
        self.created_at = created_at
        self.updated_at = updated_at
        self.sla_days = sla_days
        self.sla_deadline = sla_deadline
        self.comments = comments if comments is not None else []

    def to_dict(self) -> Dict[str, Any]:
        return {
            'vuln_id': self.vuln_id,
            'title': self.title,
            'status': self.status.value,
            'severity': self.severity.value,
            'assignee': self.assignee,
            'sla_days': self.sla_days
        }


class VulnerabilityLifecycleAPI:
    """漏洞生命周期状态机, create->triage->fix->close, 按严重级别强制执行SLA。"""

    VALID_TRANSITIONS = {
        VulnStatus.NEW: [VulnStatus.CONFIRMED, VulnStatus.FALSE_POSITIVE],
        VulnStatus.CONFIRMED: [VulnStatus.TRIAGED, VulnStatus.WONT_FIX],
        VulnStatus.TRIAGED: [VulnStatus.FIXING],
        VulnStatus.FIXING: [VulnStatus.FIXED],
        VulnStatus.FIXED: [VulnStatus.CLOSED],
        VulnStatus.CLOSED: [],
        VulnStatus.WONT_FIX: [],
        VulnStatus.FALSE_POSITIVE: [],
    }

    SLA_BY_SEVERITY = {
        VulnSeverity.CRITICAL: 3,
        VulnSeverity.HIGH: 14,
        VulnSeverity.MEDIUM: 30,
        VulnSeverity.LOW: 90,
    }

    def __init__(self):
        self._vulns: Dict[str, VulnRecord] = {}
        self._counter = 0

    def _next_id(self) -> str:
        self._counter += 1
        return f"VL-{self._counter:06d}"

    def create(self, title: str, severity: str = "medium",
               assignee: str = "") -> VulnRecord:
        try:
            sev = VulnSeverity(severity)
        except ValueError:
            sev = VulnSeverity.MEDIUM

        sla_days = self.SLA_BY_SEVERITY.get(sev, 30)
        now = time.time()
        record = VulnRecord(
            vuln_id=self._next_id(), title=title,
            severity=sev, assignee=assignee,
            created_at=now, updated_at=now,
            sla_days=sla_days, sla_deadline=now + sla_days * 86400)
        self._vulns[record.vuln_id] = record
        return record

    def transition(self, vuln_id: str, new_status: str) -> Optional[VulnRecord]:
        record = self._vulns.get(vuln_id)
        if not record:
            return None
        try:
            ns = VulnStatus(new_status)
        except ValueError:
            return None

        if ns not in self.VALID_TRANSITIONS.get(record.status, []):
            logger.warning(f"invalid transition: {record.status.value} -> {ns.value}")
            return None

        record.status = ns
        record.updated_at = time.time()
        if ns in (VulnStatus.CLOSED, VulnStatus.FALSE_POSITIVE, VulnStatus.WONT_FIX):
            record.sla_deadline = 0
        return record

    def get_sla_breaches(self) -> List[VulnRecord]:
        now = time.time()
        return [v for v in self._vulns.values()
               if v.sla_deadline > 0 and now > v.sla_deadline]

    def analyze(self, vulnerabilities: Optional[List[Dict[str, Any]]] = None,
                **kwargs) -> Dict[str, Any]:
        if vulnerabilities:
            for v in vulnerabilities:
                record = self.create(
                    v.get('title', 'untitled'),
                    v.get('severity', 'medium'),
                    v.get('assignee', ''))
                if 'status' in v:
                    self.transition(record.vuln_id, v['status'])

        by_status = {}
        for v in self._vulns.values():
            by_status[v.status.value] = by_status.get(v.status.value, 0) + 1

        by_severity = {}
        for v in self._vulns.values():
            by_severity[v.severity.value] = by_severity.get(v.severity.value, 0) + 1

        sla_breaches = self.get_sla_breaches()

        return {
            'success': True,
            'total_vulnerabilities': len(self._vulns),
            'by_status': by_status,
            'by_severity': by_severity,
            'sla_breaches': len(sla_breaches),
            'breaches': [v.to_dict() for v in sla_breaches[:20]],
            'valid_transitions': {
                f.value: [t.value for t in trans]
                for f, trans in self.VALID_TRANSITIONS.items()
            }
        }


def manage_vuln_lifecycle(vulnerabilities: List[Dict[str, Any]],
                           **kwargs) -> Dict[str, Any]:
    api = VulnerabilityLifecycleAPI()
    return api.analyze(vulnerabilities=vulnerabilities)


__all__ = ["VulnerabilityLifecycleAPI", "VulnRecord", "VulnStatus",
           "VulnSeverity", "manage_vuln_lifecycle"]
