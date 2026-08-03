# ~ 2026-08-27
# EPSS (Exploit Prediction Scoring System) 集成。
# 使用 FIRST.org 公开 API 获取利用概率分数。
# EPSS 分数 (0.0–1.0) 预测 30 天内被利用的概率。
# 百分位 (0–100) 指示该分数与所有其他 CVE 的比较。
#
# 本地缓存为 sqlite（与 cve_kb 模式一致）— 避免对同一 CVE
# 重复调用 API。缓存 TTL 默认 24 小时，可配置。
#
# urllib 导入使用 try/except — 模块在 API 不可达时可通过缓存数据离线工作。
# 这是有意设计，非回退机制。
#
# 速率限制: EPSS API 无公开速率限制，但保持礼貌 —
# 单线程请求，HTTP 层不批量（每次批量一个请求，非每 CVE 一个）。
#
# 8月27日: 新增 bulk_import() — 从 FIRST.org 下载每日 CSV 转储
# (~240K CVE 条目，15MB 压缩) 并一次性导入本地 sqlite 缓存。
# 批量操作远快于逐 CVE 调用 API。

import csv
import io
import json
import os
import sqlite3
import threading
import time
from typing import Dict, List, Optional, Tuple, Any

from .cve_models import CVEEntry

# 可选 urllib 导入 — 模块可通过缓存离线工作
try:
    import urllib.request
    import urllib.error
    _HAS_URLLIB = True
except ImportError:
    _HAS_URLLIB = False

# FIRST.org EPSS API 端点
_EPSS_API_URL = "https://api.first.org/data/v1/epss"

# 默认缓存文件路径
_DEFAULT_CACHE_PATH = os.path.join(
    os.path.expanduser("~"), ".binmind", "epss_cache.db"
)

# 缓存 TTL (秒, 24 小时)
_DEFAULT_TTL = 24 * 60 * 60


class EPSSClient:
    """FIRST.org EPSS API 客户端，含 sqlite 本地缓存。"""

    def __init__(self, cache_path: Optional[str] = None, cache_ttl: int = _DEFAULT_TTL):
        self._cache_path = cache_path or _DEFAULT_CACHE_PATH
        self._cache_ttl = cache_ttl
        self._lock = threading.Lock()
        self._conn: Optional[sqlite3.Connection] = None
        self._init_cache()

    # ---- 缓存管理（与 cve_kb 模式一致但更简单） ----
    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            if self._cache_path != ":memory:":
                cache_dir = os.path.dirname(self._cache_path)
                if cache_dir:
                    os.makedirs(cache_dir, exist_ok=True)
            self._conn = sqlite3.connect(self._cache_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def _init_cache(self):
        conn = self._get_conn()
        with self._lock:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS epss_cache (
                    cve_id TEXT PRIMARY KEY,
                    score REAL NOT NULL,
                    percentile REAL NOT NULL,
                    fetched_at REAL NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_epss_fetched
                ON epss_cache(fetched_at)
            """)
            conn.commit()

    def _cache_get(self, cve_id: str) -> Optional[Tuple[float, float]]:
        """从缓存返回 (score, percentile)，过期则返回 None。"""
        conn = self._get_conn()
        with self._lock:
            row = conn.execute(
                "SELECT score, percentile, fetched_at FROM epss_cache WHERE cve_id = ?",
                (cve_id,),
            ).fetchone()

        if row is None:
            return None

        age = time.time() - row["fetched_at"]
        if age > self._cache_ttl:
            return None  # 已过期

        return (row["score"], row["percentile"])

    def _cache_set(self, cve_id: str, score: float, percentile: float):
        conn = self._get_conn()
        with self._lock:
            conn.execute(
                "INSERT OR REPLACE INTO epss_cache (cve_id, score, percentile, fetched_at) VALUES (?, ?, ?, ?)",
                (cve_id, score, percentile, time.time()),
            )
            conn.commit()

    # ---- API ----
    def fetch_scores(self, cve_ids: List[str]) -> Dict[str, Dict[str, Any]]:
        """从 FIRST.org API 批量获取 EPSS 分数。
        返回 cve_id -> {epss_score, epss_percentile} dict。
        先查缓存，未缓存则调用 API。"""
        if not cve_ids:
            return {}

        results: Dict[str, Dict[str, Any]] = {}

        # 先查缓存
        uncached: List[str] = []
        for cve_id in cve_ids:
            cached = self._cache_get(cve_id)
            if cached is not None:
                results[cve_id] = {
                    "epss_score": cached[0],
                    "epss_percentile": cached[1],
                }
            else:
                uncached.append(cve_id)

        if not uncached:
            return results

        # 从 API 获取（整批一次请求）
        if _HAS_URLLIB:
            try:
                api_results = self._fetch_from_api(uncached)
                for cve_id, data in api_results.items():
                    # 持久化到缓存
                    self._cache_set(cve_id, data["epss_score"], data["epss_percentile"])
                    results[cve_id] = data
            except Exception as e:
                # API 失败 — 返回已有缓存数据，
                # 未缓存条目返回占位值（调用方可稍后重试）
                print(f"[EPSS] API fetch failed: {e}")
                for cve_id in uncached:
                    if cve_id not in results:
                        results[cve_id] = {
                            "epss_score": None,
                            "epss_percentile": None,
                        }
        else:
            # 无 urllib — 未缓存条目返回 None
            for cve_id in uncached:
                results[cve_id] = {
                    "epss_score": None,
                    "epss_percentile": None,
                }

        return results

    def _fetch_from_api(self, cve_ids: List[str]) -> Dict[str, Dict[str, Any]]:
        """对 FIRST.org EPSS 端点的原始 API 调用。
        使用 CSV 端点: POST 逗号分隔的 CVE ID。
        返回 cve,epss,percentile 列的 CSV。"""
        cve_list = ",".join(cve_ids[:500])  # 合理的批量限制

        # EPSS API 使用 POST 到 /data/v1/epss
        data = urllib.parse.urlencode({"cve": cve_list}).encode("utf-8")
        req = urllib.request.Request(
            _EPSS_API_URL,
            data=data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "BinMind-CVE/1.0",
            },
            method="POST",
        )

        # 速率限制: 请求前简单等待
        time.sleep(0.1)

        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read().decode("utf-8")

        # 解析 CSV 响应
        # 格式: cve,epss,percentile
        results: Dict[str, Dict[str, Any]] = {}
        reader = csv.DictReader(io.StringIO(raw))
        for row in reader:
            cve_id = row.get("cve", "").strip()
            if not cve_id:
                continue
            try:
                score = float(row.get("epss", 0))
                percentile = float(row.get("percentile", 0))
                results[cve_id] = {
                    "epss_score": score,
                    "epss_percentile": percentile,
                }
            except (ValueError, TypeError):
                continue

        # 填充响应中缺失的请求 CVE
        for cve_id in cve_ids:
            if cve_id not in results:
                results[cve_id] = {
                    "epss_score": None,
                    "epss_percentile": None,
                }

        return results

    # ---- 从每日 CSV 转储批量导入 ----
    # first.org 发布 https://epss.first.org/epss_scores-current.csv.gz
    # 包含所有 CVE 的分数。批量扩充远快于 API。
    # 文件约 15MB 压缩，~100MB 解压。

    _BULK_CSV_URL = "https://epss.first.org/epss_scores-current.csv.gz"

    def bulk_import(self, force: bool = False) -> Dict[str, Any]:
        """下载并导入完整 EPSS 每日 CSV 转储。
        流式解压 gzip CSV，逐行解析，upsert 到缓存。
        使用单 sqlite 事务加速 — 240K 行约 5 秒。

        force=True 时即使缓存今日已更新也重新下载。
        返回统计 dict: {downloaded, imported, skipped, elapsed_secs}。

        每日调用一次（如 cron job）以保持分数最新。
        导入后所有 CVE 查询命中本地缓存（无需 API 调用）。"""
        start = time.time()
        stats = {"downloaded": False, "imported": 0, "skipped": 0, "elapsed_secs": 0.0}

        # 检查是否已有新鲜数据
        if not force:
            conn = self._get_conn()
            with self._lock:
                row = conn.execute(
                    "SELECT MAX(fetched_at) as latest FROM epss_cache"
                ).fetchone()
            if row and row["latest"] is not None:
                age = time.time() - row["latest"]
                if age < self._cache_ttl:
                    stats["elapsed_secs"] = round(time.time() - start, 2)
                    stats["skipped"] = -1  # 信号: 缓存仍新鲜
                    return stats

        if not _HAS_URLLIB:
            stats["elapsed_secs"] = round(time.time() - start, 2)
            return stats

        try:
            # 流式下载 + 解压
            req = urllib.request.Request(
                self._BULK_CSV_URL,
                headers={"User-Agent": "BinMind-CVE/1.0"},
            )
            with urllib.request.urlopen(req, timeout=120) as resp:
                raw = resp.read()

            stats["downloaded"] = True

            import gzip
            try:
                decompressed = gzip.decompress(raw)
                content = decompressed.decode("utf-8")
            except Exception:
                # 可能非 gzip（概率低但有可能）
                content = raw.decode("utf-8")

            # 解析 CSV — 格式: cve,epss,percentile
            reader = csv.reader(io.StringIO(content))
            header = next(reader, None)  # 跳过表头

            conn = self._get_conn()
            now = time.time()
            batch: List[Tuple[str, float, float, float]] = []
            batch_size = 5000

            with self._lock:
                for row in reader:
                    if len(row) < 3:
                        continue
                    cve_id = row[0].strip()
                    if not cve_id:
                        continue
                    try:
                        score = float(row[1])
                        pct = float(row[2])
                    except (ValueError, IndexError):
                        continue
                    batch.append((cve_id, score, pct, now))
                    if len(batch) >= batch_size:
                        conn.executemany(
                            "INSERT OR REPLACE INTO epss_cache "
                            "(cve_id, score, percentile, fetched_at) "
                            "VALUES (?, ?, ?, ?)",
                            batch,
                        )
                        stats["imported"] += len(batch)
                        batch.clear()

                # 刷新剩余数据
                if batch:
                    conn.executemany(
                        "INSERT OR REPLACE INTO epss_cache "
                        "(cve_id, score, percentile, fetched_at) "
                        "VALUES (?, ?, ?, ?)",
                        batch,
                    )
                    stats["imported"] += len(batch)

                conn.commit()

        except Exception as e:
            print(f"[EPSS] bulk import failed: {e}")
            stats["error"] = str(e)

        stats["elapsed_secs"] = round(time.time() - start, 2)
        return stats

    # ---- 便捷方法 ----
    def fetch_score(self, cve_id: str) -> Dict[str, Any]:
        """获取单个 CVE 的 EPSS 分数。便捷包装。"""
        return self.fetch_scores([cve_id]).get(cve_id, {
            "epss_score": None,
            "epss_percentile": None,
        })

    def get_score(self, cve_id: str) -> Tuple[Optional[float], Optional[float]]:
        """获取单个 CVE 的 EPSS (score, percentile) 元组。
        不可用时返回 (None, None)。"""
        data = self.fetch_scores([cve_id]).get(cve_id, {})
        return (data.get("epss_score"), data.get("epss_percentile"))

    def enrich_entry(self, entry: CVEEntry) -> CVEEntry:
        """向 CVEEntry 添加 epss_score 和 epss_percentile。
        原地修改并返回条目（流畅式 API）。"""
        data = self.fetch_scores([entry.cve_id]).get(entry.cve_id, {})
        entry.epss_score = data.get("epss_score")
        entry.epss_percentile = data.get("epss_percentile")
        return entry

    def enrich_entries(self, entries: List[CVEEntry]) -> List[CVEEntry]:
        """批量扩充条目列表 — 比逐条调用更高效。"""
        cve_ids = [e.cve_id for e in entries]
        all_data = self.fetch_scores(cve_ids)
        for entry in entries:
            data = all_data.get(entry.cve_id, {})
            entry.epss_score = data.get("epss_score")
            entry.epss_percentile = data.get("epss_percentile")
        return entries

    def close(self):
        """关闭缓存数据库连接。"""
        if self._conn:
            self._conn.close()
            self._conn = None

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass
