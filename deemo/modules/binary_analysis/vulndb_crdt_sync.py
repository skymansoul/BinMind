import logging
import os
import json
import time
import hashlib
import sqlite3
import threading
import uuid
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from collections import defaultdict
from enum import Enum

logger = logging.getLogger(__name__)



class OpType(Enum):
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    TAG_ADD = "tag_add"
    TAG_REMOVE = "tag_remove"
    LINK_CVE = "link_cve"
    COMMENT = "comment"

class LamportClock:
    __slots__ = ('counter', 'node_id',)

    def __init__(self, counter=0, node_id="local"):
        self.counter = counter
        self.node_id = node_id

    def tick(self) -> int:
        self.counter += 1
        return self.counter

    def update(self, other: int):
        self.counter = max(self.counter, other) + 1

    def compare(self, other: 'LamportClock') -> int:
        if self.counter != other.counter:
            return -1 if self.counter < other.counter else 1
        if self.node_id != other.node_id:
            return -1 if self.node_id < other.node_id else 1
        return 0


class Op:
    __slots__ = ('op_id', 'op_type', 'node_id', 'clock_counter', 'timestamp', 'vuln_id', 'payload', 'prev_op_id',)

    def __init__(self, op_id, op_type, node_id, clock_counter, timestamp, vuln_id, payload=None, prev_op_id=None):
        self.op_id = op_id
        self.op_type = op_type
        self.node_id = node_id
        self.clock_counter = clock_counter
        self.timestamp = timestamp
        self.vuln_id = vuln_id
        self.payload = payload if payload is not None else {}
        self.prev_op_id = prev_op_id


class VulnerabilityRecord:
    __slots__ = ('vuln_id', 'cve_id', 'func_name', 'binary_path', 'vuln_type', 'severity', 'description', 'tags', 'metadata', 'version', 'last_modified_clock', 'last_modified_node', 'tombstone',)

    def __init__(self, vuln_id, cve_id="", func_name="", binary_path="", vuln_type="", severity="low", description="", tags=None, metadata=None, version=1, last_modified_clock=0, last_modified_node="local", tombstone=False):
        self.vuln_id = vuln_id
        self.cve_id = cve_id
        self.func_name = func_name
        self.binary_path = binary_path
        self.vuln_type = vuln_type
        self.severity = severity
        self.description = description
        self.tags = tags if tags is not None else []
        self.metadata = metadata if metadata is not None else {}
        self.version = version
        self.last_modified_clock = last_modified_clock
        self.last_modified_node = last_modified_node
        self.tombstone = tombstone


class ConflictResolution:
    __slots__ = ('vuln_id', 'winning_node', 'losing_node', 'reason', 'merged_fields', 'timestamp',)

    def __init__(self, vuln_id, winning_node, losing_node, reason, merged_fields=None, timestamp=None):
        self.vuln_id = vuln_id
        self.winning_node = winning_node
        self.losing_node = losing_node
        self.reason = reason
        self.merged_fields = merged_fields if merged_fields is not None else {}
        self.timestamp = timestamp if timestamp is not None else time.time()


class GCounter:
    """G-Counter CRDT 计数器 (按node)"""

    def __init__(self):
        self._counters: Dict[str, int] = defaultdict(int)

    def increment(self, node: str, value: int = 1):
        self._counters[node] += value

    def value(self) -> int:
        return sum(self._counters.values())

    def merge(self, other: 'GCounter'):
        for k, v in other._counters.items():
            if v > self._counters[k]:
                self._counters[k] = v


class LWWSet:

    def __init__(self):
        self._items: Dict[Any, Tuple[int, str]] = {}

    def add(self, item: Any, clock: int, node: str):
        cur = self._items.get(item)
        if cur is None or (clock, node) > cur:
            self._items[item] = (clock, node)

    def remove(self, item: Any, clock: int, node: str):
        cur = self._items.get(item)
        if cur is None or (clock, node) > cur:
            self._items.pop(item, None)

    def contains(self, item: Any) -> bool:
        return item in self._items

    def items(self) -> List[Any]:
        return list(self._items.keys())

    def merge(self, other: 'LWWSet'):
        for item, (c, n) in other._items.items():
            cur = self._items.get(item)
            if cur is None or (c, n) > cur:
                self._items[item] = (c, n)


class CRDTVulnDB:

    def __init__(self,
                 node_id: Optional[str] = None,
                 db_path: Optional[str] = None):
        if node_id is None:
            node_id = "node-" + uuid.uuid4().hex[:8]
        if db_path is None:
            db_path = os.path.join(
                os.path.dirname(__file__), '..', 'data',
                f'crdt_vulndb_{node_id}.sqlite3'
            )
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.node_id = node_id
        self.db_path = db_path
        self.clock = LamportClock(node_id=node_id)
        self._lock = threading.Lock()
        self._init_db()
        self._load_clock()

    def _conn(self):
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def _init_db(self):
        with self._lock, self._conn() as c:
            c.execute("""
                CREATE TABLE IF NOT EXISTS vulns (
                    vuln_id TEXT PRIMARY KEY,
                    record TEXT,
                    version INTEGER,
                    last_modified_clock INTEGER,
                    last_modified_node TEXT,
                    tombstone INTEGER DEFAULT 0
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS oplog (
                    op_id TEXT PRIMARY KEY,
                    op_type TEXT,
                    node_id TEXT,
                    clock_counter INTEGER,
                    timestamp REAL,
                    vuln_id TEXT,
                    payload TEXT,
                    prev_op_id TEXT
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS conflicts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    vuln_id TEXT,
                    winning_node TEXT,
                    losing_node TEXT,
                    reason TEXT,
                    merged_fields TEXT,
                    timestamp REAL
                )
            """)
            c.execute("CREATE INDEX IF NOT EXISTS idx_oplog_clock "
                      "ON oplog(clock_counter)")

    def _load_clock(self):
        with self._lock, self._conn() as c:
            cur = c.execute("SELECT MAX(clock_counter) FROM oplog")
            row = cur.fetchone()
            if row and row[0]:
                self.clock.counter = row[0]

# 操作interface

    def _record_op(self, op: Op):
        with self._lock, self._conn() as c:
            c.execute("""
                INSERT OR IGNORE INTO oplog VALUES (?,?,?,?,?,?,?,?)
            """, (
                op.op_id, op.op_type.value, op.node_id,
                op.clock_counter, op.timestamp, op.vuln_id,
                json.dumps(op.payload), op.prev_op_id
            ))

    def create(self, vuln: VulnerabilityRecord) -> str:
        with self._lock:
            counter = self.clock.tick()
            op = Op(
                op_id=uuid.uuid4().hex,
                op_type=OpType.CREATE,
                node_id=self.node_id,
                clock_counter=counter,
                timestamp=time.time(),
                vuln_id=vuln.vuln_id,
                payload=asdict(vuln)
            )
            self._record_op(op)
            with self._conn() as c:
                c.execute("""
                    INSERT OR REPLACE INTO vulns
                    (vuln_id, record, version, last_modified_clock,
                     last_modified_node, tombstone)
                    VALUES (?,?,?,?,?,?)
                """, (
                    vuln.vuln_id, json.dumps(asdict(vuln)), 1,
                    counter, self.node_id, 0
                ))
        return op.op_id

    def update(self, vuln_id: str, **fields) -> Optional[str]:
        with self._lock:
            cur = self._conn().execute(
                "SELECT record, last_modified_clock, last_modified_node "
                "FROM vulns WHERE vuln_id = ?", (vuln_id,)
            )
            row = cur.fetchone()
            if not row:
                return None
            try:
                record = json.loads(row[0])
            except Exception:
                record = {}
            record.update(fields)
            counter = self.clock.tick()
            op = Op(
                op_id=uuid.uuid4().hex,
                op_type=OpType.UPDATE,
                node_id=self.node_id,
                clock_counter=counter,
                timestamp=time.time(),
                vuln_id=vuln_id,
                payload=fields
            )
            self._record_op(op)
            with self._conn() as c:
                c.execute("""
                    UPDATE vulns SET record=?, version=version+1,
                        last_modified_clock=?, last_modified_node=?
                    WHERE vuln_id=?
                """, (
                    json.dumps(record), counter, self.node_id, vuln_id
                ))
        return op.op_id

    def delete(self, vuln_id: str) -> Optional[str]:
        """软delete (tombstone)"""
        return self.update(vuln_id, tombstone=True)

# 同步interface

    def get_operations_since(self, clock: int) -> List[Op]:
        with self._lock, self._conn() as c:
            cur = c.execute("""
                SELECT op_id, op_type, node_id, clock_counter, timestamp,
                       vuln_id, payload, prev_op_id
                FROM oplog
                WHERE clock_counter > ?
                ORDER BY clock_counter ASC
            """, (clock,))
            rows = cur.fetchall()
        ops: List[Op] = []
        for r in rows:
            try:
                payload = json.loads(r[6] or "{}")
            except Exception:
                payload = {}
            ops.append(Op(
                op_id=r[0], op_type=OpType(r[1]),
                node_id=r[2], clock_counter=r[3],
                timestamp=r[4], vuln_id=r[5],
                payload=payload, prev_op_id=r[7]
            ))
        return ops

    def apply_remote_op(self, op: Op) -> Optional[ConflictResolution]:
        """应用远端操作, 处理冲突"""
        with self._lock:
            self.clock.update(op.clock_counter)
            cur = self._conn().execute(
                "SELECT record, last_modified_clock, last_modified_node, version "
                "FROM vulns WHERE vuln_id = ?", (op.vuln_id,)
            )
            row = cur.fetchone()
            conflict: Optional[ConflictResolution] = None
            if op.op_type == OpType.CREATE:
                if row:
                    rec_a = json.loads(row[0])
                    rec_b = op.payload
                    if (op.clock_counter, op.node_id) > (row[1], row[2]):
                        winning = op.node_id
                        losing = row[2]
                        merged = rec_b
                        conflict = ConflictResolution(
                            vuln_id=op.vuln_id,
                            winning_node=winning,
                            losing_node=losing,
                            reason="create_conflict_lww",
                            merged_fields=merged
                        )
                    else:
                        winning = row[2]
                        losing = op.node_id
                        conflict = ConflictResolution(
                            vuln_id=op.vuln_id,
                            winning_node=winning,
                            losing_node=losing,
                            reason="create_conflict_local_wins"
                        )
                        return conflict
                else:
                    merged = op.payload
                self._upsert(op.vuln_id, merged, op.clock_counter, op.node_id)
            elif op.op_type == OpType.UPDATE:
                if not row:
                    return None
                rec = json.loads(row[0])
                if (op.clock_counter, op.node_id) > (row[1], row[2]):
                    rec.update(op.payload)
                    self._upsert(op.vuln_id, rec, op.clock_counter, op.node_id,
                                 version=row[3] + 1)
                else:
                    conflict = ConflictResolution(
                        vuln_id=op.vuln_id,
                        winning_node=row[2],
                        losing_node=op.node_id,
                        reason="update_conflict_local_newer"
                    )
            elif op.op_type == OpType.DELETE:
                self._upsert(op.vuln_id, {'tombstone': True},
                             op.clock_counter, op.node_id, tombstone=True)
            self._record_op(op)
            if conflict:
                with self._conn() as c:
                    c.execute("""
                        INSERT INTO conflicts
                        (vuln_id, winning_node, losing_node, reason,
                         merged_fields, timestamp)
                        VALUES (?,?,?,?,?,?)
                    """, (
                        conflict.vuln_id, conflict.winning_node,
                        conflict.losing_node, conflict.reason,
                        json.dumps(conflict.merged_fields), conflict.timestamp
                    ))
            return conflict

    def _upsert(self, vuln_id: str, record: Dict[str, Any],
                clock: int, node: str,
                version: Optional[int] = None,
                tombstone: bool = False) -> bool:
        with self._conn() as c:
            cur = c.execute(
                "SELECT version FROM vulns WHERE vuln_id=?", (vuln_id,)
            )
            row = cur.fetchone()
            if row:
                new_version = version or (row[0] + 1)
                c.execute("""
                    UPDATE vulns SET record=?, version=?, last_modified_clock=?,
                        last_modified_node=?, tombstone=?
                    WHERE vuln_id=?
                """, (
                    json.dumps(record), new_version, clock, node,
                    1 if tombstone else 0, vuln_id
                ))
            else:
                c.execute("""
                    INSERT INTO vulns
                    (vuln_id, record, version, last_modified_clock,
                     last_modified_node, tombstone)
                    VALUES (?,?,?,?,?,?)
                """, (
                    vuln_id, json.dumps(record), 1, clock, node,
                    1 if tombstone else 0
                ))
        return True

    def sync_with(self, other: 'CRDTVulnDB') -> int:
        """与另一个node同步"""
        ops = other.get_operations_since(0)
        applied = 0
        for op in ops:
            self.apply_remote_op(op)
            applied += 1
        return applied


def create_crdt_node(node_id: Optional[str] = None) -> CRDTVulnDB:
    return CRDTVulnDB(node_id=node_id)
