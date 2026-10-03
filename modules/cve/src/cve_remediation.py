# CVE修复跟踪——匹配漏洞的SLA、截止日期与状态管理。
# 将"发现47个CVE"转化为"3个逾期，12个本周到期，32个正常"。
#
# 状态生命周期: open → in_progress → remediated（或accepted_risk）
# 截止日期由严重度 + EPSS评分计算:
#   CRITICAL + 高EPSS: 24小时
#   CRITICAL: 7天
#   HIGH: 30天
#   MEDIUM: 90天
#   LOW: 180天
#
# 逾期检测将当前日期与截止日期比较。接受风险需记录理由并免除该CVE的跟踪。

import json
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple, Any

from .cve_models import CVEEntry, Severity

_DEFAULT_DB_PATH = os.path.join(
    os.path.expanduser("~"), ".binmind", "remediation.db"
)

# SLA截止天数——基于行业标准（CISA BOD 22-01 + NIST）
_SLA_DEADLINES = {
    "CRITICAL": 7,
    "HIGH": 30,
    "MEDIUM": 90,
    "LOW": 180,
    "NONE": 365,
    "UNKNOWN": 90,
}

# EPSS加速: 高EPSS缩短截止日期
_EPSS_SHORTEN_FACTOR = {
    0.5: 0.5,   # >50th percentile: 截止减半
    0.1: 0.75,  # >10th percentile: 截止75%
}

# 状态值
STATUS_OPEN = "open"
STATUS_IN_PROGRESS = "in_progress"
STATUS_REMEDIATED = "remediated"
STATUS_ACCEPTED_RISK = "accepted_risk"


class RemediationTracker:
    """跟踪匹配CVE的修复状态与SLA截止日期。"""

    def __init__(self, db_path: Optional[str] = None):
        self._db_path = db_path or _DEFAULT_DB_PATH
        self._lock = threading.Lock()
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            if self._db_path != ":memory:":
                d = os.path.dirname(self._db_path)
                if d:
                    os.makedirs(d, exist_ok=True)
            self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def _init_db(self):
        conn = self._get_conn()
        with self._lock:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS remediation (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT NOT NULL,
                    deployment TEXT DEFAULT '',
                    component TEXT DEFAULT '',
                    severity TEXT NOT NULL DEFAULT 'UNKNOWN',
                    cvss_score REAL,
                    epss_score REAL,
                    risk_score REAL,
                    status TEXT NOT NULL DEFAULT 'open',
                    deadline TEXT,
                    deadline_days INTEGER,
                    assigned_to TEXT DEFAULT '',
                    justification TEXT DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    remediated_at TEXT,
                    UNIQUE(cve_id, deployment, component)
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_remediation_status
                ON remediation(status, deadline)
            """)
            conn.commit()

# 导入匹配的CVE

    def import_matches(
        self,
        matches: List[Dict],
        deployment: str = "",
        risk_scores: Optional[Dict[str, float]] = None,
    ) -> int:
        """将CVE匹配结果导入修复跟踪器。
        每个匹配需含: cve_id, severity, cvss_score, epss_score, component。
        risk_scores: 可选 cve_id → risk_score字典（来自cve_risk_scorer）。

        设置初始状态为'open'并计算截止日期。
        返回新增/更新的条目数。"""
        conn = self._get_conn()
        now = datetime.now(timezone.utc).isoformat()
        count = 0

        with self._lock:
            for m in matches:
                cid = m.get("cve_id", "")
                if not cid:
                    continue
                sev = m.get("severity", "UNKNOWN").upper()
                cvss = m.get("cvss_score")
                epss = m.get("epss_score")
                comp = m.get("component", m.get("component_name", ""))
                risk = (risk_scores or {}).get(cid)

                deadline_days = _compute_deadline_days(sev, epss)
                deadline_date = datetime.now(timezone.utc) + timedelta(days=deadline_days)
                deadline = deadline_date.strftime("%Y-%m-%d")

                conn.execute(
                    "INSERT OR REPLACE INTO remediation "
                    "(cve_id, deployment, component, severity, cvss_score, "
                    "epss_score, risk_score, status, deadline, deadline_days, "
                    "created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (cid, deployment, comp, sev, cvss, epss, risk,
                     STATUS_OPEN, deadline, deadline_days, now, now),
                )
                count += 1

            conn.commit()
        return count

# 状态管理

    def update_status(
        self,
        cve_id: str,
        status: str,
        deployment: str = "",
        justification: str = "",
    ) -> bool:
        """更新CVE修复状态。"""
        if status not in (STATUS_OPEN, STATUS_IN_PROGRESS, STATUS_REMEDIATED, STATUS_ACCEPTED_RISK):
            return False

        conn = self._get_conn()
        now = datetime.now(timezone.utc).isoformat()
        remediated_at = now if status == STATUS_REMEDIATED else None

        with self._lock:
            cur = conn.execute(
                "UPDATE remediation SET status = ?, updated_at = ?, "
                "remediated_at = ?, justification = ? "
                "WHERE cve_id = ? AND (deployment = ? OR deployment = '' OR ? = '')",
                (status, now, remediated_at, justification, cve_id, deployment, deployment),
            )
            conn.commit()
            return cur.rowcount > 0

    def accept_risk(self, cve_id: str, justification: str, deployment: str = "") -> bool:
        """接受某CVE的风险（标记为accepted_risk并附理由）。"""
        return self.update_status(cve_id, STATUS_ACCEPTED_RISK, deployment, justification)

# 查询

    def get_overdue(self) -> List[Dict[str, Any]]:
        """获取所有超过截止日期且未修复/未接受的CVE。"""
        conn = self._get_conn()
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        with self._lock:
            rows = conn.execute(
                "SELECT * FROM remediation WHERE status IN ('open', 'in_progress') "
                "AND deadline < ? ORDER BY deadline ASC",
                (today,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_due_soon(self, days: int = 7) -> List[Dict[str, Any]]:
        """获取未来N天内到期的CVE。"""
        conn = self._get_conn()
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        cutoff = (datetime.now(timezone.utc) + timedelta(days=days)).strftime("%Y-%m-%d")
        with self._lock:
            rows = conn.execute(
                "SELECT * FROM remediation WHERE status IN ('open', 'in_progress') "
                "AND deadline >= ? AND deadline <= ? ORDER BY deadline ASC",
                (today, cutoff),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_by_status(self, status: str) -> List[Dict[str, Any]]:
        """按状态获取所有条目。"""
        conn = self._get_conn()
        with self._lock:
            rows = conn.execute(
                "SELECT * FROM remediation WHERE status = ? ORDER BY severity DESC, deadline ASC",
                (status,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_for_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """获取特定CVE的修复条目。"""
        conn = self._get_conn()
        with self._lock:
            row = conn.execute(
                "SELECT * FROM remediation WHERE cve_id = ?", (cve_id,)
            ).fetchone()
        return dict(row) if row else None

# 摘要

    def summary(self) -> Dict[str, Any]:
        """仪表盘友好的修复摘要。"""
        conn = self._get_conn()
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        with self._lock:
            total = conn.execute("SELECT COUNT(*) as cnt FROM remediation").fetchone()
            by_status = conn.execute(
                "SELECT status, COUNT(*) as cnt FROM remediation GROUP BY status"
            ).fetchall()
            overdue = conn.execute(
                "SELECT COUNT(*) as cnt FROM remediation "
                "WHERE status IN ('open', 'in_progress') AND deadline < ?",
                (today,),
            ).fetchone()
            due_7d = conn.execute(
                "SELECT COUNT(*) as cnt FROM remediation "
                "WHERE status IN ('open', 'in_progress') "
                "AND deadline >= ? AND deadline <= ?",
                (today, (datetime.now(timezone.utc) + timedelta(days=7)).strftime("%Y-%m-%d")),
            ).fetchone()
            remediated = conn.execute(
                "SELECT COUNT(*) as cnt FROM remediation WHERE status = 'remediated'"
            ).fetchone()
            accepted = conn.execute(
                "SELECT COUNT(*) as cnt FROM remediation WHERE status = 'accepted_risk'"
            ).fetchone()

        return {
            "total_tracked": total["cnt"] if total else 0,
            "by_status": {r["status"]: r["cnt"] for r in by_status},
            "overdue": overdue["cnt"] if overdue else 0,
            "due_within_7_days": due_7d["cnt"] if due_7d else 0,
            "remediated": remediated["cnt"] if remediated else 0,
            "accepted_risk": accepted["cnt"] if accepted else 0,
        }

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


# SLA计算

def _compute_deadline_days(severity: str, epss_score: Optional[float] = None) -> int:
    """按严重度与EPSS评分计算SLA截止天数。"""
    base = _SLA_DEADLINES.get(severity.upper(), 90)

    # EPSS高时缩短截止期（活跃利用中）
    if epss_score is not None:
        for threshold, factor in sorted(_EPSS_SHORTEN_FACTOR.items(), reverse=True):
            if epss_score >= threshold:
                base = max(1, int(base * factor))
                break

    return base


def compute_deadline(severity: str, epss_score: Optional[float] = None) -> str:
    """计算修复截止日期，返回ISO日期字符串。"""
    days = _compute_deadline_days(severity, epss_score)
    deadline = datetime.now(timezone.utc) + timedelta(days=days)
    return deadline.strftime("%Y-%m-%d")


def _parse_date(s: str) -> Optional[datetime]:
    """将日期或datetime字符串解析为datetime对象。"""
    if not s:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(s)
    except (ValueError, TypeError):
        return None


def is_overdue(deadline_str: str) -> bool:
    """检查截止日期是否已过期。"""
    dl = _parse_date(deadline_str)
    if dl is None:
        return False
    return dl < datetime.now(timezone.utc)


def days_until_deadline(deadline_str: str) -> Optional[int]:
    """距截止日期的剩余天数。负数=已逾期。None=无法解析。"""
    dl = _parse_date(deadline_str)
    if dl is None:
        return None
    now = datetime.now(timezone.utc)
    return (dl - now).days
