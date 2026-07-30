"""
Vulnerability database backed by SQLite. Stores findings across runs
for later comparison and CVE correlation.
"""

import json
import logging
import os
import sqlite3
import time
from typing import Dict, List, Optional

from config import DB_PATH

logger = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_ts TEXT NOT NULL,
    binary_path TEXT NOT NULL,
    binary_hash TEXT,
    function_name TEXT,
    vuln_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    cwe TEXT,
    description TEXT,
    evidence TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS analysis_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT,
    finished_at TEXT,
    binary_path TEXT,
    binary_hash TEXT,
    status TEXT,
    summary TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_binary ON findings(binary_path);
CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(vuln_type);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
"""


def _connect() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    conn = _connect()
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


def start_run(binary_path: str) -> int:
    conn = _connect()
    cur = conn.execute(
        "INSERT INTO analysis_runs (started_at, binary_path, status) VALUES (?, ?, ?)",
        (time.strftime('%Y-%m-%dT%H:%M:%S'), binary_path, 'running')
    )
    run_id = cur.lastrowid
    conn.commit()
    conn.close()
    return run_id


def finish_run(run_id: int, status: str = 'completed', summary: str = ''):
    conn = _connect()
    conn.execute(
        "UPDATE analysis_runs SET finished_at=?, status=?, summary=? WHERE id=?",
        (time.strftime('%Y-%m-%dT%H:%M:%S'), status, summary, run_id)
    )
    conn.commit()
    conn.close()


def save_finding(run_id: int, binary_path: str, binary_hash: str,
                 func_name: str, vuln_type: str, severity: str,
                 cwe: str = '', description: str = '',
                 evidence: str = '') -> int:
    conn = _connect()
    cur = conn.execute(
        """INSERT INTO findings
           (run_ts, binary_path, binary_hash, function_name,
            vuln_type, severity, cwe, description, evidence)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (time.strftime('%Y-%m-%dT%H:%M:%S'), binary_path, binary_hash,
         func_name, vuln_type, severity, cwe, description, evidence)
    )
    fid = cur.lastrowid
    conn.commit()
    conn.close()
    return fid


def search_similar(vuln_type: str = None, binary_path: str = None,
                   severity: str = None, limit: int = 50) -> List[Dict]:
    conn = _connect()
    parts = ["SELECT * FROM findings WHERE 1=1"]
    params = []
    if vuln_type:
        parts.append("AND vuln_type LIKE ?")
        params.append(f'%{vuln_type}%')
    if binary_path:
        parts.append("AND binary_path LIKE ?")
        params.append(f'%{binary_path}%')
    if severity:
        parts.append("AND severity = ?")
        params.append(severity)
    parts.append("ORDER BY created_at DESC LIMIT ?")
    params.append(limit)

    rows = conn.execute(' '.join(parts), params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def stats() -> Dict:
    conn = _connect()
    total = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    by_sev = conn.execute(
        "SELECT severity, COUNT(*) c FROM findings GROUP BY severity"
    ).fetchall()
    by_type = conn.execute(
        "SELECT vuln_type, COUNT(*) c FROM findings GROUP BY vuln_type"
    ).fetchall()
    conn.close()
    return {
        'total_findings': total,
        'by_severity': {r['severity']: r['c'] for r in by_sev},
        'by_type': {r['vuln_type']: r['c'] for r in by_type},
    }
