# 2026-08-01 ~ 2026-08-27
# EPSS (Exploit Prediction Scoring System) integration.
# Uses FIRST.org's public API to fetch exploit probability scores.
# EPSS scores (0.0–1.0) predict the probability of exploitation within 30 days.
# Percentile (0–100) tells you how the score compares to all other CVEs.
#
# Local cache is sqlite (same pattern as cve_kb) — avoids hitting the API
# for the same CVE twice. Cache TTL is 24 hours by default, configurable.
#
# urllib imports are try/except'd — the module works offline with cached data
# when the API is unreachable. This is intentional, not a fallback.
#
# Rate limiting: EPSS API has no published rate limits but we're polite —
# single-threaded requests with no batching at the HTTP level (one request
# per batch, not one per CVE).
#
# Aug 27: bulk_import() added — downloads the daily CSV dump from FIRST.org
# (~240K CVE entries, 15MB compressed) and imports everything into the local
# sqlite cache in one shot. way faster than per-CVE API calls for bulk ops.

import csv
import io
import json
import os
import sqlite3
import threading
import time
from typing import Dict, List, Optional, Tuple, Any

from .cve_models import CVEEntry

# optional urllib imports — module works offline with cache
try:
    import urllib.request
    import urllib.error
    _HAS_URLLIB = True
except ImportError:
    _HAS_URLLIB = False

# FIRST.org EPSS API endpoint
_EPSS_API_URL = "https://api.first.org/data/v1/epss"

# default cache file path
_DEFAULT_CACHE_PATH = os.path.join(
    os.path.expanduser("~"), ".binmind", "epss_cache.db"
)

# cache TTL in seconds (24 hours)
_DEFAULT_TTL = 24 * 60 * 60


class EPSSClient:
    """Client for FIRST.org EPSS API with sqlite local cache."""

    def __init__(self, cache_path: Optional[str] = None, cache_ttl: int = _DEFAULT_TTL):
        self._cache_path = cache_path or _DEFAULT_CACHE_PATH
        self._cache_ttl = cache_ttl
        self._lock = threading.Lock()
        self._conn: Optional[sqlite3.Connection] = None
        self._init_cache()

    # ---- cache management (same pattern as cve_kb but simpler) ----
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
        """Return (score, percentile) from cache if fresh, None otherwise."""
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
            return None  # expired

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
        """Batch fetch EPSS scores from the FIRST.org API.
        Returns dict of cve_id -> {epss_score, epss_percentile}.
        Hits cache first, then API for uncached CVEs."""
        if not cve_ids:
            return {}

        results: Dict[str, Dict[str, Any]] = {}

        # check cache first
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

        # fetch from API (in one request for the whole batch)
        if _HAS_URLLIB:
            try:
                api_results = self._fetch_from_api(uncached)
                for cve_id, data in api_results.items():
                    # persist to cache
                    self._cache_set(cve_id, data["epss_score"], data["epss_percentile"])
                    results[cve_id] = data
            except Exception as e:
                # API failed — return what we have from cache, with placeholder
                # for uncached entries (caller can retry later)
                print(f"[EPSS] API fetch failed: {e}")
                for cve_id in uncached:
                    if cve_id not in results:
                        results[cve_id] = {
                            "epss_score": None,
                            "epss_percentile": None,
                        }
        else:
            # no urllib — return None for uncached
            for cve_id in uncached:
                results[cve_id] = {
                    "epss_score": None,
                    "epss_percentile": None,
                }

        return results

    def _fetch_from_api(self, cve_ids: List[str]) -> Dict[str, Dict[str, Any]]:
        """Raw API call to FIRST.org EPSS endpoint.
        Uses the CSV endpoint: POST with comma-separated CVE IDs.
        Returns CSV with cve,epss,percentile columns."""
        cve_list = ",".join(cve_ids[:500])  # reasonable batch limit

        # EPSS API uses POST to /data/v1/epss
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

        # rate limiting: simple sleep before request
        time.sleep(0.1)

        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read().decode("utf-8")

        # parse CSV response
        # format: cve,epss,percentile
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

        # fill in any requested CVEs that weren't in the response
        for cve_id in cve_ids:
            if cve_id not in results:
                results[cve_id] = {
                    "epss_score": None,
                    "epss_percentile": None,
                }

        return results

    # ---- bulk import from daily csv dump ----
    # first.org publishes https://epss.first.org/epss_scores-current.csv.gz
    # with scores for ALL CVEs in one file. this is way faster than the API
    # for bulk enrichment. the file is ~15MB compressed, ~100MB uncompressed.

    _BULK_CSV_URL = "https://epss.first.org/epss_scores-current.csv.gz"

    def bulk_import(self, force: bool = False) -> Dict[str, Any]:
        """Download and import the full EPSS daily CSV dump.
        Streams the gzip'd CSV, parses it line by line, upserts into cache.
        Uses a single sqlite transaction for speed — 240K rows in ~5 sec.

        If force=True, re-downloads even if the cache was updated today.
        Returns stats dict: {downloaded, imported, skipped, elapsed_secs}.

        Call this once a day (e.g. from a cron job) to keep scores fresh.
        After import, all CVE lookups hit the local cache (no API calls)."""
        start = time.time()
        stats = {"downloaded": False, "imported": 0, "skipped": 0, "elapsed_secs": 0.0}

        # check if we already have fresh data
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
                    stats["skipped"] = -1  # signal: cache still fresh
                    return stats

        if not _HAS_URLLIB:
            stats["elapsed_secs"] = round(time.time() - start, 2)
            return stats

        try:
            # stream download + decompress
            req = urllib.request.Request(
                self._BULK_CSV_URL,
                headers={"User-Agent": "BinMind-CVE/1.0"},
            )
            with urllib.request.urlopen(req, timeout=120) as resp:
                # handle gzip decompression in streaming fashion
                raw = resp.read()

            stats["downloaded"] = True

            import gzip
            try:
                decompressed = gzip.decompress(raw)
                content = decompressed.decode("utf-8")
            except Exception:
                # might not be gzip'd (unlikely but possible)
                content = raw.decode("utf-8")

            # parse CSV — format: cve,epss,percentile
            reader = csv.reader(io.StringIO(content))
            header = next(reader, None)  # skip header row

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

                # flush remaining
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

    # ---- convenience methods ----
    def fetch_score(self, cve_id: str) -> Dict[str, Any]:
        """Fetch EPSS score for a single CVE. Convenience wrapper."""
        return self.fetch_scores([cve_id]).get(cve_id, {
            "epss_score": None,
            "epss_percentile": None,
        })

    def get_score(self, cve_id: str) -> Tuple[Optional[float], Optional[float]]:
        """Get EPSS (score, percentile) tuple for a single CVE.
        Returns (None, None) if not available."""
        data = self.fetch_scores([cve_id]).get(cve_id, {})
        return (data.get("epss_score"), data.get("epss_percentile"))

    def enrich_entry(self, entry: CVEEntry) -> CVEEntry:
        """Add epss_score and epss_percentile to a CVEEntry.
        Modifies in place AND returns the entry (fluent-ish API)."""
        data = self.fetch_scores([entry.cve_id]).get(entry.cve_id, {})
        entry.epss_score = data.get("epss_score")
        entry.epss_percentile = data.get("epss_percentile")
        return entry

    def enrich_entries(self, entries: List[CVEEntry]) -> List[CVEEntry]:
        """Batch enrich a list of entries — more efficient than per-entry calls."""
        cve_ids = [e.cve_id for e in entries]
        all_data = self.fetch_scores(cve_ids)
        for entry in entries:
            data = all_data.get(entry.cve_id, {})
            entry.epss_score = data.get("epss_score")
            entry.epss_percentile = data.get("epss_percentile")
        return entries

    def close(self):
        """Close the cache database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass
