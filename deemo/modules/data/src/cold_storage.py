"""多级冷存储调度 — 按数据温度自主迁移 + 分层压缩"""
# 参考 "Taming Server Memory TCO with Multiple Software-Defined Compressed Tiers"
# [Kumar et al., arXiv:2404.13886] 的多级压缩内存模型，适配到磁盘存储场景。
# AVS [arXiv:2511.19453] 的两级存储 (SSD hot → HDD archive) 提供分层灵感。
#
# 温度定义:
#   hot   — 最后访问 < 7 天，SSD 存储，不压缩
#   warm  — 7-30 天，SSD 存储，zstd level 1 压缩
#   cold  — 30-180 天，HDD 存储，zstd level 6 压缩
#   frozen — > 180 天，HDD + zstd level 12 压缩，可离线
#
# 迁移调度由 StoragePolicy 定义，TierManager 执行实际数据搬迁。
# 与 LifecycleManager 的区分: LifecycleManager 管控语义阶段迁移
# (raw→analysis→report→archive)，TierManager 管控物理存储位置和压缩等级。
import os
import time
import logging
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 温度等级 + 存储策略
# ---------------------------------------------------------------------------

@dataclass
class TierSpec:
    """单层存储规格: 命名、温度阈值、压缩参数。"""
    name: str                     # hot / warm / cold / frozen
    max_age_days: int             # 此 tier 上限天数，0 表示无上限
    compress_algo: str = "zstd"
    compress_level: int = 0       # 0 = 不压缩
    storage_path: str = ""        # 空 = 使用默认路径
    readonly: bool = False        # frozen tier 通常只读

    @property
    def is_offline(self) -> bool:
        return self.name == "frozen"


DEFAULT_TIERS = [
    TierSpec("hot", 7, "zstd", 0),
    TierSpec("warm", 30, "zstd", 1),
    TierSpec("cold", 180, "zstd", 6),
    TierSpec("frozen", 0, "zstd", 12, readonly=True),
]


@dataclass
class StoragePolicy:
    """完整分层存储策略 —— 组合多条 tier rule。"""
    tiers: List[TierSpec] = field(default_factory=lambda: DEFAULT_TIERS)
    # 基于访问频次的动态回暖阈值
    promotion_threshold: int = 5   # warm→hot 的最小访问次数
    # 定时迁移窗口 (ISO weekday list: ['sat','sun'] = 仅周末)
    migration_windows: List[str] = field(default_factory=list)
    auto_compact: bool = True      # 迁移后自主 VACUUM

    def tier_for_age(self, age_days: float) -> TierSpec:
        """根据数据年龄匹配对应 tier。"""
        for tier in self.tiers:
            if tier.max_age_days == 0:
                return tier
            if age_days <= tier.max_age_days:
                return tier
        return self.tiers[-1]


# ---------------------------------------------------------------------------
# TierManager — 执行实际数据搬迁
# ---------------------------------------------------------------------------

class TierManager:
    """签名数据的物理存储分层管理。

    核心操作:
      classify:  统计所有签名的温度分布（只读评估）。
      demote:    将过期热数据按策略降级到更冷的 tier。
      rebalance: 对指定 tier 执行压缩/解压/搬迁操作。
    """

    def __init__(self, db, policy: StoragePolicy = None):
        self.db = db
        self.policy = policy or StoragePolicy()
        self._migration_log: List[dict] = []

    def classify(self) -> Dict[str, dict]:
        """分类统计: 按 tier 汇总签名数量和估算存储占用。

        遍历 db.list_signatures()，根据 updated_at 计算 age →
        分配至对应 tier。只读操作，无副作用。
        """
        now = time.time()
        bins: Dict[str, dict] = {}
        for t in self.policy.tiers:
            bins[t.name] = {"count": 0, "est_bytes": 0, "oldest_days": 0.0}

        sigs = self.db.list_signatures(limit=100000)  # 扫描上限 10 万条
        for sig in sigs:
            age_days = (now - sig.get("updated_at", 0)) / 86400.0
            tier = self.policy.tier_for_age(age_days)
            bins[tier.name]["count"] += 1
            bins[tier.name]["est_bytes"] += sig.get("file_size", 0)
            if age_days > bins[tier.name]["oldest_days"]:
                bins[tier.name]["oldest_days"] = round(age_days, 1)

        return bins

    def demote(self, dry_run: bool = False) -> Dict[str, int]:
        """将过期数据降级至更冷 tier —— 按 StoragePolicy 温度阈值判定。"""
        from .compression import compress as _cmp
        results = {"hot→warm": 0, "warm→cold": 0, "cold→frozen": 0, "skipped": 0}
        now = time.time()
        self._migration_log = []

        sigs = self.db.list_signatures(limit=100000)
        for sig in sigs:
            age_days = (now - sig.get("updated_at", 0)) / 86400.0
            cur_stage = sig.get("stage", "raw")
            current_tier = self._guess_tier(cur_stage, age_days)

            target = self.policy.tier_for_age(age_days)
            if target.name == current_tier or current_tier == "frozen":
                results["skipped"] += 1
                continue

            transit_key = f"{current_tier}→{target.name}"
            if transit_key in results:
                results[transit_key] += 1
            if not dry_run:
                self._apply_demotion(sig, target)
                self._migration_log.append({
                    "sig_id": sig["id"], "from_tier": current_tier,
                    "to_tier": target.name, "age_days": round(age_days, 1),
                    "ts": now,
                })

        return results

    def _guess_tier(self, stage: str, age_days: float) -> str:
        tier = self.policy.tier_for_age(age_days)
        return tier.name

    def _apply_demotion(self, sig: dict, target: TierSpec):
        """执行单条签名的降级迁移。"""
        conn = self.db.get_connection()
        conn.execute(
            "UPDATE signatures SET stage=(CASE "
            "WHEN stage='raw' THEN 'analysis' "
            "WHEN stage='analysis' THEN 'report' "
            "WHEN stage='report' THEN 'archive' "
            "ELSE stage END), updated_at=? WHERE id=?",
            (time.time(), sig["id"]),
        )
        # 同步标记压缩级别变更
        self.db.update_signature_meta(sig["id"], {
            "storage_tier": target.name,
            "compress_level": target.compress_level,
        })
        conn.commit()

    def rebalance(self, tier_name: str, dry_run: bool = False) -> int:
        """对指定 tier 内未压缩数据执行统一压缩处理。"""
        tier = next((t for t in self.policy.tiers if t.name == tier_name), None)
        if tier is None or tier.compress_level == 0:
            return 0

        from .compression import compress as _cmp
        count = 0
        sigs = self.db.list_signatures(limit=50000)
        for sig in sigs:
            # 检查是否需要 (重新) 压缩
            meta = sig.get("metadata", {})
            if isinstance(meta, str):
                import json
                try:
                    meta = json.loads(meta)
                except Exception:
                    meta = {}
            if meta.get("storage_tier") == tier_name and meta.get("compress_level") == tier.compress_level:
                continue
            if dry_run:
                count += 1
                continue
            self.db.update_signature_meta(sig["id"], {
                "storage_tier": tier_name,
                "compress_level": tier.compress_level,
                "rebalanced_at": time.time(),
            })
            count += 1
        return count

    def migration_report(self) -> List[dict]:
        """返回本轮迁移操作的完整日志。"""
        return list(self._migration_log)

    def cost_estimate(self) -> dict:
        """估算当期存储成本 —— 各 tier 数据量 × 假设 $/GB 单价。

        hot: $0.08/GB-mo, warm: $0.04/GB-mo, cold: $0.01/GB-mo, frozen: $0.002/GB-mo。
        实际部署应替换为对应存储后端的实时定价。
        """
        prices = {"hot": 0.08, "warm": 0.04, "cold": 0.01, "frozen": 0.002}
        dist = self.classify()
        total_cost = 0.0
        total_gb = 0.0
        details = {}
        for name, info in dist.items():
            gb = info["est_bytes"] / (1024**3)
            cost = gb * prices.get(name, 0.01)
            details[name] = {"count": info["count"], "gb": round(gb, 2),
                             "cost_monthly": round(cost, 4)}
            total_cost += cost
            total_gb += gb
        return {"tiers": details, "total_gb": round(total_gb, 2),
                "total_cost_monthly": round(total_cost, 4)}
