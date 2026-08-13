# ~ 2026-10-05
# CISA 已知被利用漏洞 (KEV) 目录同步。
# 通过基于 ETag 的条件请求获取并缓存 KEV 目录。
#
# KEV 目录是 CISA 的权威列表，收录已被实际利用的 CVE。
# 在此目录中是 SSVC 评分的最强信号:
# 覆盖所有其他利用成熟度启发式方法。
#
# 订阅源 URL: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
# 格式于 2023 年中从平面数组更改为包含 "catalogVersion"、
# "title" 和 "vulnerabilities" 键的 dict 包装。_parse() 处理两种格式。
#
# AUDIT_R4 发现与决策:
# - ETag 缓存使用 If-None-Match 头: 收到 304 时返回缓存数据。
#   普通 HTTPError (非 304) 时同样返回缓存数据。Exception
#   (连接超时、DNS 失败等) 时返回缓存数据。错误处理
#   有意不对称 — HTTPError 304 是预期且正常的 (目录未变化)，
#   但其他 HTTP 错误 (500、速率限制) 是预期外的，应触发回退到缓存。
#   通用 Exception 覆盖网络错误，在隔离或受限环境中常见。
#   三种分支，相同结果，不同原因。
# - sync_to_kb() 直接访问 kb._get_conn() (私有属性)。替代方案
#   是在 kb.py 中添加上下文连接访问器，涉及修改另一文件。
#   务实选择是使用私有属性。
# - 在缓存中存储 knownRansomwareCampaignUse。评分中尚未使用但
#   预留以备未来勒索软件感知的优先级排序。

import json
import os
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime
from typing import Dict, List, Optional, Union, Any

from .cve_models import CVEEntry

# 可选 HTTP 导入 — 允许离线操作
from ._internal_helpers import _HAS_URLLIB
try:
    from urllib.request import urlopen, Request
    from urllib.error import HTTPError, URLError
    _HAS_URLLIB = True
except ImportError:
    _HAS_URLLIB = False


# 常量
_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_DEFAULT_CACHE_DIR = os.path.join(os.path.expanduser("~"), ".binmind", "cache")


class KEVClient:
    """CISA KEV 目录客户端，含基于 ETag 的条件刷新。

    遵循与 NVD 客户端相同的缓存模式:
    - sqlite 本地缓存于 cache_dir/kev_cache.db
    - ETag 头用于条件 GET (If-None-Match)
    - 304 Not Modified 时返回缓存数据
    - 网络错误时也返回缓存数据 (离线安全)
    """

    def __init__(self, cache_dir: Optional[str] = None):
        self._cache_dir = cache_dir or _DEFAULT_CACHE_DIR
        os.makedirs(self._cache_dir, exist_ok=True)
        self._db_path = os.path.join(self._cache_dir, "kev_cache.db")
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    @contextmanager
    def _connect(self):
        """打开短期 sqlite 连接，提交后自动关闭。

        连接句柄在 Windows 上锁定缓存文件；临时目录清理依赖连接已释放，
        故所有缓存操作均使用即用即关的连接。
        """
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.commit()
            conn.close()

    def _init_db(self):
        """建立 sqlite 本地缓存 — KEV catalog is small (~2MB), sqlite is fine."""
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS kev_entries (
                    cve_id TEXT PRIMARY KEY,
                    vendor_project TEXT,
                    product TEXT,
                    vulnerability_name TEXT,
                    date_added TEXT,
                    short_description TEXT,
                    required_action TEXT,
                    due_date TEXT,
                    known_ransomware INTEGER DEFAULT 0,
                    notes TEXT,
                    raw_json TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS kev_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at TEXT
                )
            """)

    def _get_etag(self) -> Optional[str]:
        """从元数据表获取缓存的 ETag。"""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT value FROM kev_meta WHERE key = 'etag'"
            ).fetchone()
        return row["value"] if row else None

    def _set_etag(self, etag: str):
        """在元数据表中存储 ETag。"""
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO kev_meta (key, value, updated_at) VALUES (?, ?, ?)",
                ("etag", etag, datetime.now().isoformat()),
            )

    def _get_last_fetch(self) -> Optional[str]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT value FROM kev_meta WHERE key = 'last_fetch'"
            ).fetchone()
        return row["value"] if row else None

    def _set_last_fetch(self):
        with self._connect() as conn:
            now = datetime.now().isoformat()
            conn.execute(
                "INSERT OR REPLACE INTO kev_meta (key, value, updated_at) VALUES (?, ?, ?)",
                ("last_fetch", now, now),
            )

# 获取 + 解析
    def fetch_catalog(self, force: bool = False) -> List[Dict[str, Any]]:
        """从 CISA 网站获取 KEV 目录。

        使用 ETag 条件 GET 避免重新下载未变更的数据。
        返回解析后的 KEV 条目列表 (始终为 dict 列表，
        无论订阅源顶层格式如何)。

        错误处理 (AUDIT_R4 — 有意不对称):
        - HTTPError 304: 预期内, 目录未变更 → 返回缓存条目
        - HTTPError (其他): 预期外服务器错误 → 返回缓存条目
        - URLError/Exception: 网络故障 → 返回缓存条目

        三种分支均返回缓存数据，但代表语义不同的故障模式。
        不对称是有意的 — 监控系统后续可接入此处。
        """
        if not _HAS_URLLIB:
            return self._load_cached_entries()

        etag = self._get_etag() if not force else None
        headers = {"User-Agent": "BinMind/1.0 (KEV sync)"}
        if etag:
            headers["If-None-Match"] = etag

        try:
            req = Request(_KEV_URL, headers=headers)
            with urlopen(req, timeout=30) as resp:
                # 检查新 ETag
                new_etag = resp.headers.get("ETag", "")
                if new_etag:
                    self._set_etag(new_etag)

                raw = resp.read().decode("utf-8", errors="replace")
                data = json.loads(raw)
                entries = self._parse(data)
                self._store_entries(entries)
                self._set_last_fetch()
                return entries

        except HTTPError as e:
            if e.code == 304:
                # 304 Not Modified — 目录未变更，使用缓存
                # 条件请求的正常路径
                return self._load_cached_entries()
            else:
                # 意外 HTTP 错误 (500, 429 等) — 降级，使用缓存
                # 服务器返回非预期状态码，降级使用缓存
                return self._load_cached_entries()

        except Exception:
            # 网络不可达，DNS 失败，超时 — 离线模式
            # 网络不可达，使用本地缓存
            return self._load_cached_entries()

    def _parse(self, data: Any) -> List[Dict[str, Any]]:
        """将 KEV 订阅源解析为条目 dict 列表。

        处理两种格式:
        - 2023 前: 漏洞对象的平面 JSON 数组
        - 2023 后: 含 'vulnerabilities' 键的 dict 包装

        订阅源格式约 2023 年变更，当时 CISA 向顶层添加了
        元数据字段 (catalogVersion, title, lastUpdated)。
        """
        # 2023 后: dict 包装格式
        # 注意: 格式从数组变成了对象包装，需要先检查类型
        if isinstance(data, dict):
            vulns = data.get("vulnerabilities", [])
            if vulns:
                return self._normalize_entries(vulns)
            # 可能是单条目？可能性低但安全起见
            if "cveID" in data:
                return self._normalize_entries([data])
            return []

        # 2023 前: 平面数组格式
        if isinstance(data, list):
            return self._normalize_entries(data)

        return []

    def _normalize_entries(self, entries: List[Dict]) -> List[Dict[str, Any]]:
        """将原始 KEV 条目归一化为内部 dict 格式。

        每个条目含: cveID, vendorProject, product, vulnerabilityName,
        dateAdded, shortDescription, requiredAction, dueDate,
        knownRansomwareCampaignUse, notes
        """
        result = []
        for raw in entries:
            if not isinstance(raw, dict):
                continue
            cve_id = raw.get("cveID", "").upper().strip()
            if not cve_id:
                continue

            entry = {
                "cve_id": cve_id,
                "vendor_project": raw.get("vendorProject", ""),
                "product": raw.get("product", ""),
                "vulnerability_name": raw.get("vulnerabilityName", ""),
                "date_added": raw.get("dateAdded", ""),
                "short_description": raw.get("shortDescription", ""),
                "required_action": raw.get("requiredAction", ""),
                "due_date": raw.get("dueDate", ""),
                # 保存knownRansomwareCampaignUse以备将来评分使用
                "known_ransomware": bool(raw.get("knownRansomwareCampaignUse", False)),
                "notes": raw.get("notes", ""),
            }
            result.append(entry)
        return result

# 存储
    def _store_entries(self, entries: List[Dict[str, Any]]):
        """在本地 sqlite 缓存中写入 (或更新) KEV 条目。"""
        with self._connect() as conn:
            for entry in entries:
                conn.execute(
                    """INSERT OR REPLACE INTO kev_entries
                       (cve_id, vendor_project, product, vulnerability_name,
                        date_added, short_description, required_action, due_date,
                        known_ransomware, notes, raw_json)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        entry["cve_id"],
                        entry.get("vendor_project", ""),
                        entry.get("product", ""),
                        entry.get("vulnerability_name", ""),
                        entry.get("date_added", ""),
                        entry.get("short_description", ""),
                        entry.get("required_action", ""),
                        entry.get("due_date", ""),
                        1 if entry.get("known_ransomware") else 0,
                        entry.get("notes", ""),
                        json.dumps(entry),
                    ),
                )

    def _load_cached_entries(self) -> List[Dict[str, Any]]:
        """从本地 sqlite 缓存加载 KEV 条目。

        从本地缓存加载KEV条目 — 离线模式下的主要数据源
        """
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM kev_entries ORDER BY cve_id").fetchall()
        entries = []
        for row in rows:
            entries.append({
                "cve_id": row["cve_id"],
                "vendor_project": row["vendor_project"] or "",
                "product": row["product"] or "",
                "vulnerability_name": row["vulnerability_name"] or "",
                "date_added": row["date_added"] or "",
                "short_description": row["short_description"] or "",
                "required_action": row["required_action"] or "",
                "due_date": row["due_date"] or "",
                "known_ransomware": bool(row["known_ransomware"]),
                "notes": row["notes"] or "",
            })
        return entries

# 查询
    def is_kev(self, cve_id: str) -> bool:
        """检查 CVE 是否在 KEV 目录中。"""
        cid = cve_id.upper().strip()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM kev_entries WHERE cve_id = ?", (cid,)
            ).fetchone()
        return row is not None

    def get_kev_entry(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """获取 CVE 的完整 KEV 条目，未找到时返回 None。"""
        cid = cve_id.upper().strip()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM kev_entries WHERE cve_id = ?", (cid,)
            ).fetchone()
        if not row:
            return None
        return {
            "cve_id": row["cve_id"],
            "vendor_project": row["vendor_project"] or "",
            "product": row["product"] or "",
            "vulnerability_name": row["vulnerability_name"] or "",
            "date_added": row["date_added"] or "",
            "short_description": row["short_description"] or "",
            "required_action": row["required_action"] or "",
            "due_date": row["due_date"] or "",
            "known_ransomware": bool(row["known_ransomware"]),
            "notes": row["notes"] or "",
        }

    def all_cve_ids(self) -> List[str]:
        """返回 KEV 目录中当前所有 CVE ID。"""
        with self._connect() as conn:
            rows = conn.execute("SELECT cve_id FROM kev_entries ORDER BY cve_id").fetchall()
        return [r["cve_id"] for r in rows]

    def count(self) -> int:
        """返回缓存中 KEV 条目数。"""
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) as cnt FROM kev_entries").fetchone()
        return row["cnt"] if row else 0

# 缓存读写 (供测试与工具使用)
    def _save_to_cache(self, raw_entries: List[Dict], etag: str):
        """将原始 KEV 条目写入本地缓存，并记录 ETag。"""
        normalized = self._normalize_entries(raw_entries)
        self._store_entries(normalized)
        self._set_etag(etag)
        self._set_last_fetch()

    def _load_cached(self) -> List[Dict[str, Any]]:
        """从本地缓存加载原始 KEV 条目；无缓存时返回空列表。"""
        with self._connect() as conn:
            rows = conn.execute("SELECT raw_json FROM kev_entries ORDER BY cve_id").fetchall()
        entries = []
        for row in rows:
            try:
                raw = json.loads(row["raw_json"])
            except (ValueError, TypeError):
                continue
            entries.append({
                "cveID": raw.get("cve_id", ""),
                "vendorProject": raw.get("vendor_project", ""),
                "product": raw.get("product", ""),
                "vulnerabilityName": raw.get("vulnerability_name", ""),
                "dateAdded": raw.get("date_added", ""),
                "shortDescription": raw.get("short_description", ""),
                "requiredAction": raw.get("required_action", ""),
                "dueDate": raw.get("due_date", ""),
                "knownRansomwareCampaignUse": "Known" if raw.get("known_ransomware") else "",
                "notes": raw.get("notes", ""),
            })
        return entries

# 同步到主 KB

    def sync_to_kb(self, kb: Any) -> int:
        """更新主 CVE 知识库中的 cisa_kev 标志。

        直接访问 kb._get_conn() (私有属性) — AUDIT_R4 认为
        替代方案 (在 kb.py 中添加公共连接访问器) 涉及修改另一文件。
        务实选择是使用私有属性。
        这是层次违规，但仅限于此方法。

        返回更新的 KB 条目数。
        """
        entries = self._load_cached_entries()
        if not entries:
            return 0

        # 直接访问 kb._get_conn() — 你知道这是私有属性, 但这是最务实的做法
        try:
            conn = kb._get_conn()
        except AttributeError:
            return 0

        updated = 0
        for entry in entries:
            cid = entry["cve_id"]
            # 检查此 CVE 是否存在于 KB 中
            row = conn.execute(
                "SELECT cve_id FROM cves WHERE cve_id = ?", (cid,)
            ).fetchone()
            if not row:
                continue
            # 更新 KEV 标志和日期
            conn.execute(
                "UPDATE cves SET cisa_kev = 1, cisa_kev_date = ? WHERE cve_id = ?",
                (entry.get("date_added", ""), cid),
            )
            updated += 1

        if updated > 0:
            conn.commit()
        return updated

# 优先级排序
    def kev_priority(self,
                     entries: List[Union[CVEEntry, Dict]],
                     kev_client: Optional["KEVClient"] = None) -> List[Union[CVEEntry, Dict]]:
        """将 KEV 列表中的漏洞排在前面。

        可选 kev_client 参数 — 经典的"为测试修复单例"模式。
        kev_client 为 None 时使用 self (当前实例)。这允许测试
        注入 mock 而不触及全局单例。

        返回新排序列表；不修改输入。
        """
        client = kev_client if kev_client is not None else self

        def _sort_key(entry):
            cve_id = ""
            if hasattr(entry, 'cve_id'):
                cve_id = getattr(entry, 'cve_id', '')
            elif isinstance(entry, dict):
                cve_id = entry.get('cve_id', '')

            is_kev = client.is_kev(cve_id)
            # KEV 优先 (0), 非 KEV 其次 (1)
            return (0 if is_kev else 1, cve_id)

        return sorted(entries, key=_sort_key)

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


# 模块级单例
# 与 get_kb() 和 get_exploitdb() 模式一致
# 全局单例 — 惰性初始化, 线程安全由调用者保证
_kev_instance: Optional[KEVClient] = None


def get_kev(cache_dir: Optional[str] = None) -> KEVClient:
    """获取或创建全局 KEVClient 单例。"""
    global _kev_instance
    if _kev_instance is None:
        _kev_instance = KEVClient(cache_dir)
    return _kev_instance


def is_cisa_kev(cve_id: str) -> bool:
    """便捷函数: 检查 CVE 是否在 KEV 目录中。

    被 cve_exploitdb 和 cve_ssvc 使用，无需了解单例
    或 KEVClient 类即可快速检查。
    """
    return get_kev().is_kev(cve_id)
