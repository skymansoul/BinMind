# 2026-10-20 ~ 2026-10-23
# CVE Remediation Tracking — SLAs, deadlines, and status management for
# matched vulnerabilities. Turns "we found 47 CVEs" into "3 overdue, 12 due
# this week, 32 on track."
#
# Status lifecycle: open → in_progress → remediated (or accepted_risk)
# Deadlines computed from severity + EPSS score:
#   CRITICAL + high EPSS: 24 hours
#   CRITICAL: 7 days
#   HIGH: 30 days
#   MEDIUM: 90 days
#   LOW: 180 days
#
# Overdue detection compares current date against deadline. Accepting a risk
# records a justification and exempts the CVE from deadline tracking.

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

# SLA deadlines in days — based on industry standards (CISA BOD 22-01 + NIST)
_SLA_DEADLINES = {
    "CRITICAL": 7,
    "HIGH": 30,
    "MEDIUM": 90,
    "LOW": 180,
    "NONE": 365,
    "UNKNOWN": 90,
}

# EPSS boost: high EPSS shortens the deadline
_EPSS_SHORTEN_FACTOR = {
    0.5: 0.5,   # >50th percentile: half the deadline
    0.1: 0.75,  # >10th percentile: 75% of deadline
}

# status values
STATUS_OPEN = "open"
STATUS_IN_PROGRESS = "in_progress"
STATUS_REMEDIATED = "remediated"
STATUS_ACCEPTED_RISK = "accepted_risk"


class RemediationTracker:
    """Tracks remediation status and SLA deadlines for matched CVEs."""

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

    # ---- import matched CVEs ----

    def import_matches(
        self,
        matches: List[Dict],
        deployment: str = "",
        risk_scores: Optional[Dict[str, float]] = None,
    ) -> int:
        """Import CVE matches into the remediation tracker.
        Each match should have: cve_id, severity, cvss_score, epss_score, component.
        risk_scores: optional dict of cve_id → risk_score (from cve_risk_scorer).

        Sets initial status to 'open' and computes deadlines.
        Returns count of entries added/updated."""
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

    # ---- status management ----

    def update_status(
        self,
        cve_id: str,
        status: str,
        deployment: str = "",
        justification: str = "",
    ) -> bool:
        """Update remediation status for a CVE."""
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
        """Accept the risk for a CVE (mark as accepted_risk with justification)."""
        return self.update_status(cve_id, STATUS_ACCEPTED_RISK, deployment, justification)

    # ---- query ----

    def get_overdue(self) -> List[Dict[str, Any]]:
        """Get all CVEs past their deadline (not yet remediated or accepted)."""
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
        """Get CVEs due within the next N days."""
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
        """Get all entries with a given status."""
        conn = self._get_conn()
        with self._lock:
            rows = conn.execute(
                "SELECT * FROM remediation WHERE status = ? ORDER BY severity DESC, deadline ASC",
                (status,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_for_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get remediation entry for a specific CVE."""
        conn = self._get_conn()
        with self._lock:
            row = conn.execute(
                "SELECT * FROM remediation WHERE cve_id = ?", (cve_id,)
            ).fetchone()
        return dict(row) if row else None

    # ---- summary ----

    def summary(self) -> Dict[str, Any]:
        """Dashboard-friendly remediation summary."""
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


# ---- SLA computation ----

def _compute_deadline_days(severity: str, epss_score: Optional[float] = None) -> int:
    """Compute SLA deadline in days for a given severity and EPSS score."""
    base = _SLA_DEADLINES.get(severity.upper(), 90)

    # shorten deadline if EPSS is high (actively exploited)
    if epss_score is not None:
        for threshold, factor in sorted(_EPSS_SHORTEN_FACTOR.items(), reverse=True):
            if epss_score >= threshold:
                base = max(1, int(base * factor))
                break

    return base


def compute_deadline(severity: str, epss_score: Optional[float] = None) -> str:
    """Compute remediation deadline as an ISO date string."""
    days = _compute_deadline_days(severity, epss_score)
    deadline = datetime.now(timezone.utc) + timedelta(days=days)
    return deadline.strftime("%Y-%m-%d")


def _parse_date(s: str) -> Optional[datetime]:
    """Parse a date or datetime string to a datetime object."""
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
    """Check if a deadline has passed."""
    dl = _parse_date(deadline_str)
    if dl is None:
        return False
    return dl < datetime.now(timezone.utc)


def days_until_deadline(deadline_str: str) -> Optional[int]:
    """Days remaining until deadline. Negative = overdue. None = unparseable."""
    dl = _parse_date(deadline_str)
    if dl is None:
        return None
    now = datetime.now(timezone.utc)
    return (dl - now).days
