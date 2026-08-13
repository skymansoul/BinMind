import logging
import os
import json
import time
import sqlite3
import hashlib
import re
import threading
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

__log = logging.getLogger(__name__)


class ChangeKind(str, Enum):
    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"
    UNCHANGED = "unchanged"


@dataclass
class FunctionSnapshot:
    binary_id: str
    version: str
    func_name: str
    fingerprint: str
    size: int
    captured_at: float
    metadata: Dict = field(default_factory=dict)


@dataclass
class FunctionChangeLog:
    func_name: str
    from_version: Optional[str]
    to_version: str
    kind: ChangeKind
    introduced_cve: List = field(default_factory=list)
    fixed_cve: List = field(default_factory=list)
    commit_id: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    notes: str = ""


@dataclass
class CVEMapping:
    cve_id: str
    func_names: List = field(default_factory=list)
    affected_versions: List = field(default_factory=list)
    fixed_version: Optional[str] = None
    description: str = ""

class FunctionHasher:
    """Function fingerprint generator."""

    def __init__(self, r2_path: str = "r2"):
        self.r2_path = r2_path

    def list_functions(self, binary_path: str) -> List[str]:
        import subprocess
        try:
            r = subprocess.run(
                [self.r2_path, '-q', '-c', 'afl;q', binary_path],
                capture_output=True, text=True, timeout=60,
                encoding='utf-8', errors='replace'
            )
            funcs = []
            for line in r.stdout.split("\n"):
                m = re.search(r"0x[0-9a-f]+\s+\d+\s+(\S.*)", line)
                if m:
                    funcs.append(m.group(1).strip())
            return funcs
        except Exception as e:
            logger.warning(f"Failed to get function list: {e}")
            return []

    def fingerprint(self, binary_path: str, func_name: str) -> str:
        import subprocess
        try:
            r = subprocess.run(
                [self.r2_path, '-q', '-c', f'pdf @ {func_name}; q', binary_path],
                capture_output=True, text=True, timeout=60,
                encoding='utf-8', errors='replace'
            )
            return hashlib.sha256(r.stdout.encode("utf-8")).hexdigest()
        except Exception as e:
            logger.warning(f"Fingerprinting failed: {e}")
            return ""

class VersionedFuncDB:

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            db_path = os.path.join(
                os.path.dirname(__file__), '..', 'data',
                'func_version_history.sqlite3'
            )
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _conn(self):
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def _init_db(self):
        with self._lock, self._conn() as c:
            c.execute("""
                CREATE TABLE IF NOT EXISTS snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    binary_id TEXT,
                    version TEXT,
                    func_name TEXT,
                    fingerprint TEXT,
                    size INTEGER,
                    captured_at REAL,
                    metadata TEXT
                )
            """)
            c.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_snapshot_unique
                ON snapshots(binary_id, version, func_name)
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS changes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    func_name TEXT,
                    from_version TEXT,
                    to_version TEXT,
                    kind TEXT,
                    introduced_cve TEXT,
                    fixed_cve TEXT,
                    commit_id TEXT,
                    timestamp REAL,
                    notes TEXT
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS cve_map (
                    cve_id TEXT PRIMARY KEY,
                    func_names TEXT,
                    affected_versions TEXT,
                    fixed_version TEXT,
                    description TEXT
                )
            """)
            c.execute("CREATE INDEX IF NOT EXISTS idx_changes_func "
                      "ON changes(func_name)")

    def add_snapshot(self, snap: FunctionSnapshot) -> bool:
        with self._lock, self._conn() as c:
            try:
                c.execute("""
                    INSERT OR REPLACE INTO snapshots
                    (binary_id, version, func_name, fingerprint,
                     size, captured_at, metadata)
                    VALUES (?,?,?,?,?,?,?)
                """, (
                    snap.binary_id, snap.version, snap.func_name,
                    snap.fingerprint, snap.size, snap.captured_at,
                    json.dumps(snap.metadata)
                ))
                return True
            except Exception as e:
                logger.warning(f"Snapshot insert failed: {e}")
                return False

    def add_change(self, change: FunctionChangeLog) -> bool:
        with self._lock, self._conn() as c:
            try:
                c.execute("""
                    INSERT INTO changes
                    (func_name, from_version, to_version, kind,
                     introduced_cve, fixed_cve, commit_id, timestamp, notes)
                    VALUES (?,?,?,?,?,?,?,?,?)
                """, (
                    change.func_name, change.from_version, change.to_version,
                    change.kind.value,
                    json.dumps(change.introduced_cve),
                    json.dumps(change.fixed_cve),
                    change.commit_id, change.timestamp, change.notes
                ))
                return True
            except Exception as e:
                logger.warning(f"Change insert failed: {e}")
                return False

    def add_cve(self, cve: CVEMapping) -> bool:
        with self._lock, self._conn() as c:
            try:
                c.execute("""
                    INSERT OR REPLACE INTO cve_map VALUES (?,?,?,?,?)
                """, (
                    cve.cve_id, json.dumps(cve.func_names),
                    json.dumps(cve.affected_versions),
                    cve.fixed_version, cve.description
                ))
                return True
            except Exception as e:
                logger.warning(f"CVE insert failed: {e}")
                return False

    def get_history(self, binary_id: str, func_name: str) -> List[FunctionSnapshot]:
        with self._lock, self._conn() as c:
            cur = c.execute("""
                SELECT binary_id, version, func_name, fingerprint,
                       size, captured_at, metadata
                FROM snapshots
                WHERE binary_id = ? AND func_name = ?
                ORDER BY captured_at ASC
            """, (binary_id, func_name))
            rows = cur.fetchall()
        out: List[FunctionSnapshot] = []
        for r in rows:
            out.append(FunctionSnapshot(
                binary_id=r[0], version=r[1], func_name=r[2],
                fingerprint=r[3], size=r[4], captured_at=r[5],
                metadata=json.loads(r[6] or "{}")
            ))
        return out

    def get_changes(self, binary_id: Optional[str] = None,
                    func_name: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock, self._conn() as c:
            sql = "SELECT * FROM changes WHERE 1=1"
            params: List = []
            if func_name:
                sql += " AND func_name = ?"
                params.append(func_name)
            sql += " ORDER BY timestamp DESC"
            cur = c.execute(sql, params)
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, r)) for r in cur.fetchall()]


class FunctionVersionTracker:
    """Function version tracker."""

    def __init__(self, db: Optional[VersionedFuncDB] = None,
                 r2_path: str = "r2"):
        self.db = db or VersionedFuncDB()
        self.hasher = FunctionHasher(r2_path)

    def capture_version(self, binary_id: str, version: str,
                        binary_path: str,
                        metadata: Optional[Dict[str, Any]] = None) -> int:
        funcs = self.hasher.list_functions(binary_path)
        count = 0
        for fn in funcs:
            fp = self.hasher.fingerprint(binary_path, fn)
            snap = FunctionSnapshot(
                binary_id=binary_id, version=version, func_name=fn,
                fingerprint=fp, size=len(fp) // 2, captured_at=time.time(),
                metadata=metadata or {}
            )
            if self.db.add_snapshot(snap):
                count += 1
        return count

    def diff_versions(self, binary_id: str,
                      from_version: str, to_version: str,
                      to_binary_path: Optional[str] = None) -> List[FunctionChangeLog]:
        with self.db._lock, self.db._conn() as c:
            cur = c.execute("""
                SELECT func_name, fingerprint FROM snapshots
                WHERE binary_id = ? AND version = ?
            """, (binary_id, from_version))
            old = {r[0]: r[1] for r in cur.fetchall()}
            cur = c.execute("""
                SELECT func_name, fingerprint FROM snapshots
                WHERE binary_id = ? AND version = ?
            """, (binary_id, to_version))
            new = {r[0]: r[1] for r in cur.fetchall()}

        changes: List[FunctionChangeLog] = []
        old_set, new_set = set(old.keys()), set(new.keys())
        for fn in (new_set - old_set):
            changes.append(FunctionChangeLog(
                func_name=fn, from_version=from_version,
                to_version=to_version, kind=ChangeKind.ADDED
            ))
        for fn in (old_set - new_set):
            changes.append(FunctionChangeLog(
                func_name=fn, from_version=from_version,
                to_version=to_version, kind=ChangeKind.DELETED
            ))
        for fn in (old_set & new_set):
            if old[fn] != new[fn]:
                changes.append(FunctionChangeLog(
                    func_name=fn, from_version=from_version,
                    to_version=to_version, kind=ChangeKind.MODIFIED
                ))
        for c in changes:
            self.db.add_change(c)
        return changes

    def find_introducing_version(self, binary_id: str,
                                 func_name: str) -> Optional[FunctionChangeLog]:
        history = self.db.get_history(binary_id, func_name)
        if not history:
            return None
        first = history[0]
        return FunctionChangeLog(
            func_name=func_name, from_version=None,
            to_version=first.version, kind=ChangeKind.ADDED,
            timestamp=first.captured_at
        )


def track_func_version(binary_id: str, version: str,
                       binary_path: str) -> Dict[str, Any]:
    """Convenience entry point."""
    t = FunctionVersionTracker()
    n = t.capture_version(binary_id, version, binary_path)
    return {'success': True, 'binary_id': binary_id, 'version': version,
            'captured': n}
