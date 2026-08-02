# 2026-07-27
# Fuzzing campaign management — 多目标、多引擎、长时间运行
# 设计：每个 campaign 有独立的 corpus、统计、时间线。
# merge_campaigns 合并多个 campaign 的 corpus（按覆盖率增量去重）。
import time
import os
import uuid
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from collections import defaultdict


@dataclass
class CampaignStats:
    iterations: int = 0
    crashes: int = 0
    unique_crashes: int = 0
    coverage_pct: float = 0.0
    execs_per_sec: float = 0.0
    uptime_seconds: float = 0.0
    last_new_crash_time: float = 0.0
    corpus_size: int = 0

    def summary(self) -> str:
        return (
            f"iters={self.iterations} crashes={self.crashes}(unique={self.unique_crashes}) "
            f"cov={self.coverage_pct:.1%} speed={self.execs_per_sec:.0f}/s "
            f"uptime={self.uptime_seconds:.0f}s corpus={self.corpus_size}"
        )


@dataclass
class Campaign:
    id: str
    target: str
    engine: str = "afl++"
    start_time: float = 0.0
    end_time: Optional[float] = None
    status: str = "pending"  # pending/running/paused/completed
    stats: CampaignStats = field(default_factory=CampaignStats)
    corpus_dir: str = ""
    findings_dir: str = ""
    config: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_running(self) -> bool:
        return self.status == "running"

    @property
    def elapsed(self) -> float:
        if self.end_time:
            return self.end_time - self.start_time
        if self.status == "running":
            return time.time() - self.start_time
        return 0.0


# ================================================
class CampaignManager:
    """管理多个 fuzzing campaigns。

    典型用法：
        mgr = CampaignManager("output/")
        cid = mgr.start_campaign("my_binary", {"engine": "libfuzzer"})
        while mgr.monitor_campaign(cid).status == "running":
            time.sleep(60)
        stats = mgr.get_campaign(cid).stats
    """

    def __init__(self, output_dir: str = "campaigns"):
        self.output_dir = output_dir
        self._campaigns: Dict[str, Campaign] = {}
        os.makedirs(output_dir, exist_ok=True)

    def start_campaign(self, target: str,
                       config: Dict[str, Any] = None) -> str:
        """启动新 campaign。返回 campaign ID。"""
        _cid = str(uuid.uuid4())[:8]
        _corpus = os.path.join(self.output_dir, _cid, "corpus")
        _findings = os.path.join(self.output_dir, _cid, "findings")
        os.makedirs(_corpus, exist_ok=True)
        os.makedirs(_findings, exist_ok=True)

        _cfg = config or {}
        _campaign = Campaign(
            id=_cid,
            target=target,
            engine=_cfg.get("engine", "afl++"),
            start_time=time.time(),
            status="running",
            corpus_dir=_corpus,
            findings_dir=_findings,
            config=_cfg,
        )
        self._campaigns[_cid] = _campaign
        return _cid

    def stop_campaign(self, campaign_id: str):
        _c = self._campaigns.get(campaign_id)
        if _c and _c.is_running:
            _c.end_time = time.time()
            _c.status = "completed"

    def pause_campaign(self, campaign_id: str):
        _c = self._campaigns.get(campaign_id)
        if _c and _c.is_running:
            _c.status = "paused"
            _c.end_time = time.time()

    def resume_campaign(self, campaign_id: str):
        _c = self._campaigns.get(campaign_id)
        if _c and _c.status == "paused":
            _c.status = "running"
            _c.end_time = None

    def get_campaign(self, campaign_id: str) -> Optional[Campaign]:
        return self._campaigns.get(campaign_id)

    def list_campaigns(self) -> List[Campaign]:
        return list(self._campaigns.values())

    def monitor_campaign(self, campaign_id: str) -> Optional[CampaignStats]:
        """获取 campaign 当前统计。"""
        _c = self._campaigns.get(campaign_id)
        if not _c:
            return None
        # Update live stats
        if _c.status == "running":
            _c.stats.uptime_seconds = time.time() - _c.start_time
        return _c.stats

    def update_stats(self, campaign_id: str, **kwargs):
        """更新 campaign 统计（从 fuzzer 回调）。"""
        _c = self._campaigns.get(campaign_id)
        if not _c:
            return
        for _k, _v in kwargs.items():
            if hasattr(_c.stats, _k):
                setattr(_c.stats, _k, _v)

    # ---- Merge ----
    def merge_campaigns(self, campaign_ids: List[str],
                        output_corpus: str = "") -> int:
        """合并多个 campaign 的 corpus。
        按输入 hash 去重，保留最小尺寸版本。
        """
        _seen: Dict[str, bytes] = {}  # hash -> smallest input
        import hashlib

        for _cid in campaign_ids:
            _c = self._campaigns.get(_cid)
            if not _c:
                continue
            _corpus_dir = _c.corpus_dir
            if not os.path.isdir(_corpus_dir):
                continue
            for _fname in os.listdir(_corpus_dir):
                _fpath = os.path.join(_corpus_dir, _fname)
                if not os.path.isfile(_fpath):
                    continue
                try:
                    with open(_fpath, "rb") as _fh:
                        _data = _fh.read()
                    _h = hashlib.sha256(_data).hexdigest()
                    if _h not in _seen or len(_data) < len(_seen[_h]):
                        _seen[_h] = _data
                except OSError:
                    continue

        _out_dir = output_corpus or os.path.join(self.output_dir, "merged_corpus")
        os.makedirs(_out_dir, exist_ok=True)
        _count = 0
        for _h, _data in _seen.items():
            _out_path = os.path.join(_out_dir, f"id:{_h[:12]}")
            with open(_out_path, "wb") as _fh:
                _fh.write(_data)
            _count += 1
        return _count

    def aggregate_stats(self) -> Dict[str, Any]:
        """聚合所有 campaign 的统计。"""
        _total = CampaignStats()
        for _c in self._campaigns.values():
            _total.iterations += _c.stats.iterations
            _total.crashes += _c.stats.crashes
            _total.unique_crashes += _c.stats.unique_crashes
            _total.corpus_size += _c.stats.corpus_size
        _running = sum(1 for _c in self._campaigns.values() if _c.is_running)
        return {
            "total_campaigns": len(self._campaigns),
            "running": _running,
            "aggregate_stats": _total,
        }
