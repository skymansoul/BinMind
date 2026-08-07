# ~ 2026-10-16
# NVD增量同步引擎——利用NVD API 2.0的lastModStartDate/lastModEndDate做高效增量更新。
# 每次仅拉取自上次同步以来修改的CVE，而非全量重取。
#
# NVD API每查询最多返回2000条（startIndex + resultsPerPage）。
# 对于>2000条修改的日期区间，拆分为更小的时间窗口并在窗口内分页。
# 默认窗口为7天，大部分周区间不会超过2000条修改。
#
# 同步状态通过JSON文件（~/.binmind/nvd_sync_state.json）跟踪，
# 记录上次同步时间戳与总CVE计数。若状态文件不存在，触发全量同步。

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
_DEFAULT_PAGE_SIZE = 100         # 每页结果数
_MAX_RESULTS_PER_QUERY = 2000    # NVD硬上限
_WINDOW_DAYS = 7                 # 日期区间按7天窗口拆分


class NVDSyncEngine:
    """增量NVD同步——仅拉取自上次运行以来修改的CVE。"""

    def __init__(self, kb: CVEKnowledgeBase, state_path: Optional[str] = None):
        self._kb = kb
        self._state_path = state_path or _SYNC_STATE_PATH
        self._state = self._load_state()

# 同步

    def sync(self, full: bool = False) -> Dict[str, Any]:
        """执行增量同步。full=True或无历史同步则执行全量同步。
        返回统计字典。"""
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
        """拉取from_dt到to_dt之间修改的CVE。"""
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

                    # 检查条目是否存在（供变更日志使用）
                    existing = self._kb.get(cve_id) if hasattr(self._kb, 'get') else None
                    entry = CVEEntry.from_nvd_item({"cve": cve_data})

                    if existing is not None:
                        # 更新前记录变更日志
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
                time.sleep(0.6)  # 速率限制：含API密钥时 ~100 req/min

            stats["windows"] += 1
            current = window_end
            time.sleep(1.0)  # 窗口间延迟

        return stats

    def _full_sync(self) -> Dict[str, Any]:
        """全量同步——拉取所有内容。首次运行或强制同步时使用。"""
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

# API

    def _fetch_page(
        self,
        start_index: int = 0,
        results_per_page: int = _DEFAULT_PAGE_SIZE,
        last_mod_start: Optional[str] = None,
        last_mod_end: Optional[str] = None,
    ) -> Optional[Dict]:
        """拉取NVD API的一页结果。返回解析后的JSON或错误时返回None。"""
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

# 状态持久化

    def _load_state(self) -> Dict[str, Any]:
        """从JSON文件加载同步状态。"""
        if os.path.exists(self._state_path):
            try:
                with open(self._state_path, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        return {"last_sync": None, "total_synced": 0}

    def _save_state(self):
        """持久化同步状态到JSON文件。"""
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


# 便捷函数

def quick_sync(kb: CVEKnowledgeBase, full: bool = False) -> Dict[str, Any]:
    """一次性：创建引擎并运行同步。返回统计字典。"""
    engine = NVDSyncEngine(kb)
    return engine.sync(full=full)
