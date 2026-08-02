# 2026-10-13 ~ 2026-10-16
# NVD incremental sync engine — efficient delta updates using NVD API 2.0's
# lastModStartDate / lastModEndDate parameters. Instead of fetching the full
# dataset every time, we only pull CVEs modified since the last sync.
#
# The NVD API returns at most 2000 results per query (startIndex + resultsPerPage).
# For a date range with >2000 modified CVEs, we split into smaller windows and
# paginate within each. Default window size is 7 days, which fits most weeks
# under 2000 modifications.
#
# Sync state is tracked in a simple JSON file (~/.binmind/nvd_sync_state.json)
# with the last sync timestamp and total CVE count. If no state file exists,
# triggers a full sync (fetch everything, not just modified).

import json
import os
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple, Any

from .cve_models import CVEEntry
from .cve_kb import CVEKnowledgeBase

try:
    import urllib.request
    import urllib.error
    _HAS_URLLIB = True
except ImportError:
    _HAS_URLLIB = False

try:
    from .cve_changelog import CVEChangelog
    _HAS_CHANGELOG = True
except ImportError:
    _HAS_CHANGELOG = False

_NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_SYNC_STATE_PATH = os.path.join(
    os.path.expanduser("~"), ".binmind", "nvd_sync_state.json"
)
_DEFAULT_PAGE_SIZE = 100         # results per page
_MAX_RESULTS_PER_QUERY = 2000    # NVD hard cap
_WINDOW_DAYS = 7                 # split date range into 7-day windows


class NVDSyncEngine:
    """Incremental NVD sync — fetches only modified CVEs since last run."""

    def __init__(self, kb: CVEKnowledgeBase, state_path: Optional[str] = None):
        self._kb = kb
        self._state_path = state_path or _SYNC_STATE_PATH
        self._state = self._load_state()

    # ---- sync ----

    def sync(self, full: bool = False) -> Dict[str, Any]:
        """Run incremental sync. If full=True or no prior sync, do full sync.
        Returns stats dict."""
        if full or self._state.get("last_sync") is None:
            return self._full_sync()

        last_sync = datetime.fromisoformat(self._state["last_sync"])
        now = datetime.now(timezone.utc)
        stats = self._delta_sync(last_sync, now)

        if stats.get("error"):
            return stats

        self._state["last_sync"] = now.isoformat()
        self._state["total_synced"] = self._state.get("total_synced", 0) + stats.get("imported", 0)
        self._save_state()
        return stats

    def _delta_sync(self, from_dt: datetime, to_dt: datetime) -> Dict[str, Any]:
        """Fetch CVEs modified between from_dt and to_dt."""
        stats = {"imported": 0, "updated": 0, "skipped": 0, "errors": 0, "windows": 0}

        if not _HAS_URLLIB:
            stats["error"] = "urllib not available"
            return stats

        current = from_dt
        while current < to_dt:
            window_end = min(current + timedelta(days=_WINDOW_DAYS), to_dt)
            start_idx = 0

            while True:
                page = self._fetch_page(
                    last_mod_start=current.strftime("%Y-%m-%dT%H:%M:%S.000"),
                    last_mod_end=window_end.strftime("%Y-%m-%dT%H:%M:%S.000"),
                    start_index=start_idx,
                )
                if page is None:
                    stats["errors"] += 1
                    break

                vulns = page.get("vulnerabilities", [])
                if not vulns:
                    break

                for vuln in vulns:
                    cve_data = vuln.get("cve", {})
                    cve_id = cve_data.get("id", "")
                    if not cve_id:
                        continue

                    # check if entry exists (for changelog)
                    existing = self._kb.get(cve_id) if hasattr(self._kb, 'get') else None
                    entry = CVEEntry.from_nvd_item({"cve": cve_data})

                    if existing is not None:
                        # record changelog before update
                        if _HAS_CHANGELOG:
                            try:
                                cl = CVEChangelog(self._kb)
                                cl.record_update(existing, entry)
                            except Exception:
                                pass
                        stats["updated"] += 1
                    else:
                        stats["imported"] += 1

                    self._kb.insert(entry)

                results_per_page = page.get("resultsPerPage", _DEFAULT_PAGE_SIZE)
                total_results = page.get("totalResults", 0)
                start_idx += results_per_page

                if start_idx >= total_results:
                    break
                time.sleep(0.6)  # rate limit: ~100 req/min with API key

            stats["windows"] += 1
            current = window_end
            time.sleep(1.0)  # between windows

        return stats

    def _full_sync(self) -> Dict[str, Any]:
        """Full sync — fetch everything. Used on first run or when forced."""
        stats = {"imported": 0, "skipped": 0, "errors": 0, "pages": 0}

        if not _HAS_URLLIB:
            stats["error"] = "urllib not available"
            return stats

        start_idx = 0
        while True:
            page = self._fetch_page(start_index=start_idx)
            if page is None:
                stats["errors"] += 1
                break

            vulns = page.get("vulnerabilities", [])
            if not vulns:
                break

            for vuln in vulns:
                cve_data = vuln.get("cve", {})
                cve_id = cve_data.get("id", "")
                if not cve_id:
                    continue
                try:
                    entry = CVEEntry.from_nvd_item({"cve": cve_data})
                    self._kb.insert(entry)
                    stats["imported"] += 1
                except Exception:
                    stats["skipped"] += 1

            total_results = page.get("totalResults", 0)
            start_idx += page.get("resultsPerPage", _DEFAULT_PAGE_SIZE)
            stats["pages"] += 1

            if start_idx >= total_results:
                break
            time.sleep(0.6)

        self._state["last_sync"] = datetime.now(timezone.utc).isoformat()
        self._save_state()
        return stats

    # ---- api ----

    def _fetch_page(
        self,
        start_index: int = 0,
        results_per_page: int = _DEFAULT_PAGE_SIZE,
        last_mod_start: Optional[str] = None,
        last_mod_end: Optional[str] = None,
    ) -> Optional[Dict]:
        """Fetch one page of NVD API results. Returns parsed JSON or None on error."""
        params = [
            f"startIndex={start_index}",
            f"resultsPerPage={results_per_page}",
        ]
        if last_mod_start:
            params.append(f"lastModStartDate={last_mod_start}")
        if last_mod_end:
            params.append(f"lastModEndDate={last_mod_end}")

        url = f"{_NVD_API_BASE}?{'&'.join(params)}"

        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "BinMind-CVE/1.0"},
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            print(f"[NVD Sync] fetch failed: {e}")
            return None

    # ---- state persistence ----

    def _load_state(self) -> Dict[str, Any]:
        """Load sync state from JSON file."""
        if os.path.exists(self._state_path):
            try:
                with open(self._state_path, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        return {"last_sync": None, "total_synced": 0}

    def _save_state(self):
        """Persist sync state to JSON file."""
        d = os.path.dirname(self._state_path)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(self._state_path, "w") as f:
            json.dump(self._state, f, indent=2)

    @property
    def last_sync_time(self) -> Optional[str]:
        return self._state.get("last_sync")

    @property
    def total_synced(self) -> int:
        return self._state.get("total_synced", 0)


# ---- convenience ----

def quick_sync(kb: CVEKnowledgeBase, full: bool = False) -> Dict[str, Any]:
    """One-shot: create engine and run sync. Returns stats dict."""
    engine = NVDSyncEngine(kb)
    return engine.sync(full=full)
