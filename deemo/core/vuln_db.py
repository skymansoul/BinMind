# core/vuln_db.py - SQLite 结果库 (findings / analysis_runs / step_records 三层)

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
    priority_score REAL DEFAULT NULL,
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

CREATE TABLE IF NOT EXISTS step_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL,
    step_name TEXT NOT NULL,
    start_time TEXT,
    end_time TEXT,
    input_summary TEXT,
    output_summary TEXT,
    status TEXT NOT NULL DEFAULT 'running',
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_binary ON findings(binary_path);
CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(vuln_type);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_steps_run ON step_records(run_id);
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
    try:
        conn.execute("ALTER TABLE findings ADD COLUMN priority_score REAL DEFAULT NULL")
    except sqlite3.OperationalError:
        pass  # 旧库已含该列
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


def record_step(run_id: int, step_name: str, start_ts: str = None,
                status: str = 'running', input_summary: str = '',
                output_summary: str = '', error_message: str = '') -> int:
    """
    写入一条逐步执行记录。end_time 在状态为终态时自动落当前时间。

    返回 step 记录 id，供调用方在步骤结束时二次更新。
    """
    now = time.strftime('%Y-%m-%dT%H:%M:%S')
    start_ts = start_ts or now
    end_time = now if status in ('success', 'failed', 'skipped') else None
    conn = _connect()
    cur = conn.execute(
        """INSERT INTO step_records
           (run_id, step_name, start_time, end_time, input_summary,
            output_summary, status, error_message)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (run_id, step_name, start_ts, end_time, input_summary,
         output_summary, status, error_message)
    )
    sid = cur.lastrowid
    conn.commit()
    conn.close()
    return sid


def update_step(sid: int, status: str, output_summary: str = '',
                error_message: str = ''):
    conn = _connect()
    conn.execute(
        """UPDATE step_records
           SET end_time=?, status=?, output_summary=?, error_message=?
           WHERE id=?""",
        (time.strftime('%Y-%m-%dT%H:%M:%S'), status, output_summary,
         error_message, sid)
    )
    conn.commit()
    conn.close()


def save_finding(run_id: int, binary_path: str, binary_hash: str,
                 func_name: str, vuln_type: str, severity: str,
                 cwe: str = '', description: str = '',
                 evidence: str = '', priority_score: float = None) -> int:
    conn = _connect()
    cur = conn.execute(
        """INSERT INTO findings
           (run_ts, binary_path, binary_hash, function_name,
            vuln_type, severity, cwe, description, evidence, priority_score)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (time.strftime('%Y-%m-%dT%H:%M:%S'), binary_path, binary_hash,
         func_name, vuln_type, severity, cwe, description, evidence,
         priority_score)
    )
    fid = cur.lastrowid
    conn.commit()
    conn.close()
    return fid


def get_run_findings(run_id: int) -> List[Dict]:
    """按 run 的 started_at 时间窗取该 run 落库的 findings。"""
    conn = _connect()
    run = conn.execute(
        "SELECT started_at, binary_path FROM analysis_runs WHERE id=?",
        (run_id,)
    ).fetchone()
    if run is None:
        conn.close()
        return []
    rows = conn.execute(
        "SELECT * FROM findings WHERE run_ts >= ? AND binary_path = ? ORDER BY id",
        (run['started_at'], run['binary_path'])
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


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
