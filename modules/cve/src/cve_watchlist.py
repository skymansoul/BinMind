# CVE监视列表——匹配资产清单的新CVE运营监控。
# 维护需监控的产品/SBOM列表。每次检查周期搜索知识库获取新匹配，
# 并与先前状态比较（通过变更日志模块或简单时间戳跟踪）。
#
# 监视列表存储于sqlite（与其他模块模式一致）。
# 每条目为 (name, ecosystem, version, last_checked_at, last_match_count)。
# 检查时搜索该product@version的知识库，比较匹配数与last_match_count，
# 将新匹配报告为告警。
#
# 若cve_changelog可用，告警还包括对先前匹配CVE的字段级变更
# （严重度提升、新EPSS评分、KEV新增）。

import json
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any

from .cve_models import CVEEntry

_DEFAULT_WATCH_PATH = os.path.join(
    os.path.expanduser("~"), ".binmind", "watchlist.db"
)

# 尝试导入变更日志以支持富告警
try:
    from .cve_changelog import CVEChangelog, diff_entries
    _HAS_CHANGELOG = True
except ImportError:
    _HAS_CHANGELOG = False


class CVEWatchlist:
    """产品监视列表——跟踪监控目标并对新匹配发出告警。"""

    def __init__(self, db_path: Optional[str] = None):
        self._db_path = db_path or _DEFAULT_WATCH_PATH
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
                CREATE TABLE IF NOT EXISTS watchlist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    ecosystem TEXT DEFAULT '',
                    version TEXT DEFAULT '',
                    last_checked_at REAL DEFAULT 0.0,
                    last_match_count INTEGER DEFAULT 0,
                    last_match_ids TEXT DEFAULT '[]',
                    alerts_enabled INTEGER DEFAULT 1,
                    created_at REAL NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS watch_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    watch_id INTEGER NOT NULL,
                    cve_id TEXT NOT NULL,
                    alert_type TEXT NOT NULL DEFAULT 'new_match',
                    details TEXT DEFAULT '',
                    created_at REAL NOT NULL,
                    acknowledged INTEGER DEFAULT 0
                )
            """)
            conn.commit()

# 管理监视列表

    def add(
        self, name: str, ecosystem: str = "", version: str = ""
    ) -> int:
        """添加产品到监视列表。返回watch_id。"""
        conn = self._get_conn()
        now = time.time()
        with self._lock:
            cur = conn.execute(
                "INSERT INTO watchlist (name, ecosystem, version, created_at) "
                "VALUES (?, ?, ?, ?)",
                (name.lower().strip(), ecosystem.lower().strip(), version.strip(), now),
            )
            conn.commit()
            return cur.lastrowid

    def remove(self, watch_id: int) -> bool:
        """按ID移除监视条目。"""
        conn = self._get_conn()
        with self._lock:
            cur = conn.execute("DELETE FROM watchlist WHERE id = ?", (watch_id,))
            conn.commit()
            return cur.rowcount > 0

    def list_all(self) -> List[Dict[str, Any]]:
        """列出所有监视条目。"""
        conn = self._get_conn()
        with self._lock:
            rows = conn.execute(
                "SELECT * FROM watchlist ORDER BY last_checked_at ASC"
            ).fetchall()
        return [dict(r) for r in rows]

    def get(self, watch_id: int) -> Optional[Dict[str, Any]]:
        """获取单个监视条目。"""
        conn = self._get_conn()
        with self._lock:
            row = conn.execute(
                "SELECT * FROM watchlist WHERE id = ?", (watch_id,)
            ).fetchone()
        return dict(row) if row else None

# 检查新匹配

    def check_all(self, kb, min_severity: str = "LOW") -> Dict[str, Any]:
        """对照知识库检查所有监视条目。
        对每条目搜索匹配CVE并与先前状态比较。
        返回 {alerts, summary}。"""
        entries = self.list_all()
        all_alerts: List[Dict] = []
        summary_parts: List[Dict] = []

        for entry in entries:
            result = self._check_one(kb, entry, min_severity)
            all_alerts.extend(result.get("alerts", []))
            summary_parts.append({
                "watch_id": entry["id"],
                "name": entry["name"],
                "ecosystem": entry["ecosystem"],
                "version": entry["version"],
                "new_matches": result.get("new_match_count", 0),
                "total_matches": result.get("total_match_count", 0),
                "severity_changes": result.get("severity_changes", 0),
            })

        return {
            "alerts": all_alerts,
            "summary": summary_parts,
            "total_alerts": len(all_alerts),
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    def _check_one(self, kb, entry: Dict, min_severity: str) -> Dict[str, Any]:
        """检查单条监视条目。"""
        watch_id = entry["id"]
        name = entry["name"]
        eco = entry["ecosystem"]
        ver = entry["version"]

        # 搜索知识库匹配
        query = name
        if ver:
            query = f"{name} {ver}"
        kb_results, total = kb.search(query=query, limit=200) if hasattr(kb, 'search') else ([], 0)

        # 按严重度过滤
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4, "UNKNOWN": 5}
        min_sev_val = sev_order.get(min_severity.upper(), 99)
        filtered = [
            e for e in kb_results
            if sev_order.get(
                e.severity if hasattr(e, 'severity') else e.get('severity', 'UNKNOWN'),
                99
            ) <= min_sev_val
        ]
        current_ids = [e.cve_id if hasattr(e, 'cve_id') else e.get('cve_id', '') for e in filtered]
        current_count = len(current_ids)

        # 与先前状态比较
        prev_ids = json.loads(entry.get("last_match_ids", "[]"))
        prev_count = entry.get("last_match_count", 0)
        new_ids = [cid for cid in current_ids if cid not in prev_ids]

        alerts: List[Dict] = []
        now = time.time()

        # 告警: 新匹配
        for cid in new_ids:
            matched = next((e for e in filtered if (e.cve_id if hasattr(e, 'cve_id') else e.get('cve_id', '')) == cid), None)
            sev = matched.severity if matched and hasattr(matched, 'severity') else "UNKNOWN"
            alerts.append({
                "watch_id": watch_id,
                "cve_id": cid,
                "alert_type": "new_match",
                "severity": sev,
                "product": name,
                "ecosystem": eco,
            })

        # 告警: 先前匹配CVE的严重度变更
        severity_changes = 0
        if _HAS_CHANGELOG and prev_ids:
            try:
                cl = CVEChangelog(kb)
                for cid in prev_ids:
                    history = cl.get_changelog(cid, limit=5)
                    for h in history:
                        if h["field_name"] == "severity" and h["changed_at"] > entry.get("last_checked_at", 0):
                            alerts.append({
                                "watch_id": watch_id,
                                "cve_id": cid,
                                "alert_type": "severity_change",
                                "details": f"{h['old_value']} → {h['new_value']}",
                                "product": name,
                            })
                            severity_changes += 1
            except Exception:
                pass

        # 持久化告警
        conn = self._get_conn()
        with self._lock:
            for a in alerts:
                conn.execute(
                    "INSERT INTO watch_alerts (watch_id, cve_id, alert_type, details, created_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (watch_id, a["cve_id"], a["alert_type"],
                     a.get("details", ""), now),
                )
            # 更新监视状态
            conn.execute(
                "UPDATE watchlist SET last_checked_at = ?, last_match_count = ?, "
                "last_match_ids = ? WHERE id = ?",
                (now, current_count, json.dumps(current_ids), watch_id),
            )
            conn.commit()

        return {
            "alerts": alerts,
            "new_match_count": len(new_ids),
            "total_match_count": current_count,
            "severity_changes": severity_changes,
        }

# 从SBOM组件导入监视列表

    def import_from_sbom(self, components: List[Dict]) -> int:
        """将SBOM组件导入监视列表。
        每个组件需含: name, version, ecosystem（或purl_type）。
        返回新增条目数。"""
        count = 0
        for comp in components:
            name = comp.get("name", comp.get("component", ""))
            if not name:
                continue
            version = comp.get("version", "")
            eco = comp.get("ecosystem", comp.get("purl_type", ""))
            self.add(name, eco, version)
            count += 1
        return count

# 告警管理

    def get_alerts(
        self, acknowledged: Optional[bool] = None, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """获取告警，可选按确认状态过滤。"""
        conn = self._get_conn()
        with self._lock:
            if acknowledged is None:
                rows = conn.execute(
                    "SELECT * FROM watch_alerts ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            else:
                ack_val = 1 if acknowledged else 0
                rows = conn.execute(
                    "SELECT * FROM watch_alerts WHERE acknowledged = ? "
                    "ORDER BY created_at DESC LIMIT ?",
                    (ack_val, limit),
                ).fetchall()
        return [dict(r) for r in rows]

    def acknowledge_alert(self, alert_id: int):
        """将告警标记为已确认。"""
        conn = self._get_conn()
        with self._lock:
            conn.execute(
                "UPDATE watch_alerts SET acknowledged = 1 WHERE id = ?",
                (alert_id,),
            )
            conn.commit()

    def alert_stats(self) -> Dict[str, Any]:
        """告警摘要统计。"""
        conn = self._get_conn()
        with self._lock:
            total = conn.execute(
                "SELECT COUNT(*) as cnt FROM watch_alerts"
            ).fetchone()
            unack = conn.execute(
                "SELECT COUNT(*) as cnt FROM watch_alerts WHERE acknowledged = 0"
            ).fetchone()
            by_type = conn.execute(
                "SELECT alert_type, COUNT(*) as cnt FROM watch_alerts "
                "GROUP BY alert_type"
            ).fetchall()
        return {
            "total_alerts": total["cnt"] if total else 0,
            "unacknowledged": unack["cnt"] if unack else 0,
            "by_type": {r["alert_type"]: r["cnt"] for r in by_type},
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
