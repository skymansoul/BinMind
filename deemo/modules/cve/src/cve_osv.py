# ~ 2026-10-04
# OSV.dev集成——Google开源漏洞数据库。
# OSV汇聚20+生态（PyPI、npm、Maven、Go、crates.io、RubyGems、NuGet等）的安全通告，
# 精度达到包级别。区别于NVD（CPE级匹配，对OSS包精度较低）和GHSA（仅限GitHub）。
#
# API: POST /v1/query，请求体 {package: {ecosystem, name}, version: "1.0.0"}
# 返回影响该package@version的OSV条目列表。
# 批量端点: POST /v1/querybatch，最多1000条查询。
#
# 本地sqlite缓存——与cve_epss + cve_cwe相同的模式。
# 缓存条目以 (ecosystem, package_name, version) → fetched_at 为键。
# OSV数据变更频率低于EPSS，默认TTL为7天。

import json
import os
import sqlite3
import threading
import time
from collections import defaultdict
from typing import Dict, List, Optional, Any, Tuple

from .cve_models import CVEEntry, Severity, cvss_score_to_severity

from ._internal_helpers import _HAS_URLLIB
try:
    import urllib.request
    import urllib.error
    _HAS_URLLIB = True
except ImportError:
    _HAS_URLLIB = False

_OSV_API_BASE = "https://api.osv.dev/v1"
_DEFAULT_CACHE_PATH = os.path.join(
    os.path.expanduser("~"), ".binmind", "osv_cache.db"
)
_DEFAULT_TTL = 7 * 24 * 60 * 60  # 7天


class OSVClient:
    """Google OSV.dev API客户端——带本地sqlite缓存。"""

    def __init__(self, cache_path: Optional[str] = None, cache_ttl: int = _DEFAULT_TTL):
        self._cache_path = cache_path or _DEFAULT_CACHE_PATH
        self._cache_ttl = cache_ttl
        self._lock = threading.Lock()
        self._conn: Optional[sqlite3.Connection] = None
        self._init_cache()

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            if self._cache_path != ":memory:":
                d = os.path.dirname(self._cache_path)
                if d:
                    os.makedirs(d, exist_ok=True)
            self._conn = sqlite3.connect(self._cache_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            if self._cache_path != ":memory:":
                self._conn.execute("PRAGMA journal_mode=WAL")
        return self._conn

    def _init_cache(self):
        conn = self._get_conn()
        with self._lock:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS osv_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ecosystem TEXT NOT NULL,
                    package_name TEXT NOT NULL,
                    version TEXT NOT NULL,
                    response_json TEXT NOT NULL,
                    fetched_at REAL NOT NULL,
                    UNIQUE(ecosystem, package_name, version)
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_osv_pkg
                ON osv_cache(ecosystem, package_name)
            """)
            conn.commit()

# 查询

    def query(
        self, package_name: str, ecosystem: str, version: str = ""
    ) -> List[Dict[str, Any]]:
        """查询OSV中影响package@version的漏洞。
        version为空则返回该包的所有已知漏洞。

        返回OSV漏洞字典列表。
        优先命中缓存，未命中则请求API。"""
        # 规范化
        eco = ecosystem.lower().strip()
        pkg = package_name.lower().strip()
        ver = version.strip()

        # 检查缓存
        cached = self._cache_get(eco, pkg, ver)
        if cached is not None:
            return cached

        if not _HAS_URLLIB:
            return []

        results = self._fetch_from_api(pkg, eco, ver)
        self._cache_set(eco, pkg, ver, results)
        return results

    def query_batch(
        self, queries: List[Dict[str, str]]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """批量查询——多包场景更高效。
        queries: {package_name, ecosystem, version}字典列表。

        返回以 "ecosystem:package@version" 为键的漏洞字典。"""
        results: Dict[str, List[Dict]] = {}
        uncached: List[Dict] = []

        for q in queries:
            eco = q.get("ecosystem", "").lower().strip()
            pkg = q.get("package_name", q.get("name", "")).lower().strip()
            ver = q.get("version", "").strip()
            key = f"{eco}:{pkg}@{ver}"

            cached = self._cache_get(eco, pkg, ver)
            if cached is not None:
                results[key] = cached
            else:
                uncached.append({"package": {"ecosystem": eco, "name": pkg}, "version": ver})

        if uncached and _HAS_URLLIB:
            try:
                api_results = self._fetch_batch(uncached)
                for i, vulns in enumerate(api_results):
                    q = uncached[i]
                    eco = q["package"]["ecosystem"]
                    pkg = q["package"]["name"]
                    ver = q.get("version", "")
                    key = f"{eco}:{pkg}@{ver}"
                    self._cache_set(eco, pkg, ver, vulns)
                    results[key] = vulns
            except Exception as e:
                print(f"[OSV] batch query failed: {e}")

        return results

# API调用

    def _fetch_from_api(self, package: str, ecosystem: str, version: str) -> List[Dict]:
        """单包OSV API查询。"""
        body = json.dumps({
            "package": {"ecosystem": ecosystem, "name": package},
            "version": version,
        }).encode("utf-8")

        req = urllib.request.Request(
            f"{_OSV_API_BASE}/query",
            data=body,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "BinMind-CVE/1.0",
            },
            method="POST",
        )
        time.sleep(0.5)
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        vulns = data.get("vulns", []) if isinstance(data, dict) else []
        return vulns

    def _fetch_batch(self, queries: List[Dict]) -> List[List[Dict]]:
        """批量查询——每次最多1000条。"""
        body = json.dumps({"queries": queries[:1000]}).encode("utf-8")
        req = urllib.request.Request(
            f"{_OSV_API_BASE}/querybatch",
            data=body,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "BinMind-CVE/1.0",
            },
            method="POST",
        )
        time.sleep(0.5)
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        results_raw = data.get("results", []) if isinstance(data, dict) else []
        return [r.get("vulns", []) if isinstance(r, dict) else [] for r in results_raw]

# 缓存操作

    def _cache_get(self, ecosystem: str, package: str, version: str) -> Optional[List[Dict]]:
        conn = self._get_conn()
        with self._lock:
            row = conn.execute(
                "SELECT response_json, fetched_at FROM osv_cache "
                "WHERE ecosystem = ? AND package_name = ? AND version = ?",
                (ecosystem, package, version),
            ).fetchone()
        if row is None:
            return None
        age = time.time() - row["fetched_at"]
        if age > self._cache_ttl:
            return None
        try:
            return json.loads(row["response_json"])
        except json.JSONDecodeError:
            return None

    def _cache_set(self, ecosystem: str, package: str, version: str, data: List[Dict]):
        conn = self._get_conn()
        with self._lock:
            conn.execute(
                "INSERT OR REPLACE INTO osv_cache "
                "(ecosystem, package_name, version, response_json, fetched_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (ecosystem, package, version, json.dumps(data), time.time()),
            )
            conn.commit()

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


# OSV → CVEEntry 转换

def osv_to_cve_entry(osv_vuln: Dict) -> Optional[CVEEntry]:
    """将OSV漏洞字典转换为CVEEntry。
    若OSV条目无可用CVE标识符则返回None。"""
    osv_id = osv_vuln.get("id", "")
    summary = osv_vuln.get("summary", "") or osv_vuln.get("details", "")[:500]
    details = osv_vuln.get("details", "")

    # 查找CVE别名——作为主标识符
    aliases = osv_vuln.get("aliases", [])
    cve_id = ""
    for alias in aliases:
        if alias.upper().startswith("CVE-"):
            cve_id = alias.upper()
            break
    if not cve_id:
        cve_id = osv_id  # 回退到OSV ID（如GHSA-xxxx）

    # 从CVSS提取严重度（若存在）
    severity_str = "UNKNOWN"
    cvss_score = None
    cvss_vector = None
    sev_list = osv_vuln.get("severity", [])
    for s in sev_list:
        if s.get("type") == "CVSS_V3":
            cvss_score = float(s.get("score", 0))
            cvss_vector = s.get("vector", "")
            severity_str = cvss_score_to_severity(cvss_score)
            break
        elif s.get("type") == "CVSS_V2" and cvss_score is None:
            cvss_score = float(s.get("score", 0))
            cvss_vector = s.get("vector", "")

    # 提取受影响的包/产品
    affected = osv_vuln.get("affected", [])
    packages: List[str] = []
    ecosystems: List[str] = []
    ranges: List[Dict] = []
    for a in affected:
        pkg = a.get("package", {})
        name = pkg.get("name", "")
        eco = pkg.get("ecosystem", "")
        if name:
            packages.append(name)
        if eco and eco not in ecosystems:
            ecosystems.append(eco)
        for r in a.get("ranges", []):
            rtype = r.get("type", "SEMVER")
            events = r.get("events", [])
            if events:
                ranges.append({"type": rtype, "events": events})

    # 引用
    refs = [ref.get("url", "") for ref in osv_vuln.get("references", []) if ref.get("url")]

    return CVEEntry(
        cve_id=cve_id,
        description=details if details else summary,
        severity=severity_str,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        products=packages,
        vendors=[],
        affected_ranges=ranges,
        references=refs,
        published_date=osv_vuln.get("published", ""),
        last_modified_date=osv_vuln.get("modified", ""),
        source="osv",
        source_confidence=0.85 if cve_id.startswith("CVE-") else 0.7,
    )


def osv_batch_to_entries(osv_results: Dict[str, List[Dict]]) -> List[CVEEntry]:
    """将批量OSV结果转换为CVEEntry列表，按CVE ID去重。"""
    seen: set = set()
    entries: List[CVEEntry] = []
    for key, vulns in osv_results.items():
        for v in vulns:
            entry = osv_to_cve_entry(v)
            if entry and entry.cve_id not in seen:
                seen.add(entry.cve_id)
                entries.append(entry)
    return entries


# 与知识库交叉引用

def crossref_osv_with_kb(
    osv_client: OSVClient,
    kb,
    packages: List[Dict[str, str]],
) -> Dict[str, Any]:
    """对包列表查询OSV并与知识库交叉引用。
    packages: {name, ecosystem, version}字典列表。
    返回 {new_cves, known_cves, coverage_stats}。"""
    results = osv_client.query_batch([
        {"package_name": p["name"], "ecosystem": p.get("ecosystem", ""), "version": p.get("version", "")}
        for p in packages
    ])
    entries = osv_batch_to_entries(results)

    new_cves: List[Dict] = []
    known_cves: List[Dict] = []

    for entry in entries:
        existing = kb.get(entry.cve_id) if hasattr(kb, 'get') else None
        if existing is not None:
            known_cves.append(entry.to_dict())
        else:
            new_cves.append(entry.to_dict())
            # 可选：插入知识库
            if hasattr(kb, 'insert'):
                try:
                    kb.insert(entry)
                except Exception:
                    pass

    return {
        "new_cves": new_cves,
        "known_cves": known_cves,
        "stats": {
            "packages_queried": len(packages),
            "total_osv_vulns": len(entries),
            "new_to_kb": len(new_cves),
            "already_known": len(known_cves),
        },
    }


# 生态辅助函数
# 将常见生态名称映射到OSV的规范名称

_ECOSYSTEM_ALIASES = {
    "pip": "PyPI", "pypi": "PyPI", "python": "PyPI",
    "npm": "npm", "yarn": "npm", "node": "npm",
    "maven": "Maven", "gradle": "Maven", "java": "Maven",
    "go": "Go", "golang": "Go",
    "cargo": "crates.io", "rust": "crates.io",
    "gem": "RubyGems", "ruby": "RubyGems",
    "nuget": "NuGet", "dotnet": "NuGet",
    "composer": "Packagist", "php": "Packagist",
    "deb": "Debian", "debian": "Debian",
    "alpine": "Alpine", "apk": "Alpine",
    "hex": "Hex", "elixir": "Hex",
    "pub": "Pub", "dart": "Pub",
}


def normalize_ecosystem(raw: str) -> str:
    """将生态名称规范化为OSV规范形式。
    如 'pip' → 'PyPI', 'node' → 'npm'。"""
    return _ECOSYSTEM_ALIASES.get(raw.lower().strip(), raw)
