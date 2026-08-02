# Lifecycle manager — TTL-based stage transitions + compression aging
# 参考 PostgreSQL WAL 和 Kafka log segment 的生命周期思路
# 不做自动 DELETE（archive stage 由外部 cron 清理）
#
# 压缩老化策略：
#   在 compress_after_days 周期之外，还检查压缩是否实际缩小了数据。
#   若压缩后体积 ≤ 原始体积（某些已压缩数据二次压缩反而膨胀），
#   则跳过并标记为"已尝试压缩"，避免每轮维护都重试无效压缩。
#
# retention_audit: 生成完整保留审计报告 — 各阶段当前状态、
# 预计下一轮会迁移/压缩/清理的数量，不执行任何变更。

import time
from typing import Dict, Any, List, Optional
from .config import LifecycleConfig, LifecycleStageCfg


class LifecycleManager:
    """管理二进制签名的阶段迁移：raw → analysis → report → archive。"""

    def __init__(self, db, config: LifecycleConfig = None):
        self.db = db
        self.cfg = config or LifecycleConfig()
        self._dry_run_log: List[str] = []

    def run_maintenance(self, dry_run: bool = False) -> Dict[str, int]:
        """执行一轮维护：扫描所有非 archive 阶段的签名，按 TTL 推进。"""
        self._dry_run_log = []
        summary = {"transitions": 0, "compressed": 0, "skipped": 0,
                   "orphans_cleaned": 0}

        stage_order = ["raw", "analysis", "report", "archive"]
        stage_cfgs = {s.name: s for s in self.cfg.stages}

        for stage in stage_order[:-1]:
            cfg = stage_cfgs.get(stage)
            if not cfg or cfg.ttl_days <= 0:
                continue
            cutoff = time.time() - cfg.ttl_days * 86400
            sigs = self.db.list_signatures(stage=stage)
            for sig in sigs:
                updated = sig.get("updated_at", 0)
                if updated > cutoff:
                    continue
                next_idx = stage_order.index(stage) + 1
                next_stage = stage_order[next_idx]
                reason = f"TTL expired: {cfg.ttl_days}d in {stage}"
                if dry_run:
                    self._dry_run_log.append(
                        f"  [{stage}→{next_stage}] {sig['file_path'][:60]} ({reason})"
                    )
                    summary["transitions"] += 1
                else:
                    ok = self.db.update_stage(sig["id"], next_stage, reason)
                    if ok:
                        summary["transitions"] += 1

            if cfg.compress_after_days > 0:
                compress_cutoff = time.time() - cfg.compress_after_days * 86400
                for sig in sigs:
                    if sig.get("updated_at", 0) > compress_cutoff:
                        continue
                    if self._compress_if_worthwhile(sig, dry_run):
                        summary["compressed"] += 1
                    else:
                        summary["skipped"] += 1

        orphans = self._clean_orphans(dry_run)
        summary["orphans_cleaned"] = orphans

        return summary

    def retention_audit(self) -> Dict:
        """生成完整的保留策略审计报告 —— 不执行任何变更。

        返回每个阶段当前有多少签名、其中哪些会在下一轮维护中被迁移、
        压缩或清理。用于定期人工审查数据生命周期策略是否合理。
        """
        stage_order = ["raw", "analysis", "report", "archive"]
        stage_cfgs = {s.name: s for s in self.cfg.stages}
        now = time.time()
        report = {}

        for stage in stage_order:
            cfg = stage_cfgs.get(stage)
            total = self.db.count(stage=stage)
            entry = {"total": total, "due_for_transition": 0, "due_for_compress": 0}

            if cfg and total > 0 and stage != "archive":
                ttl_cutoff = now - cfg.ttl_days * 86400 if cfg.ttl_days > 0 else 0
                comp_cutoff = now - cfg.compress_after_days * 86400 if cfg.compress_after_days > 0 else 0

                sigs = self.db.list_signatures(stage=stage)
                for sig in sigs:
                    updated = sig.get("updated_at", 0)
                    if ttl_cutoff and updated <= ttl_cutoff:
                        entry["due_for_transition"] += 1
                    if comp_cutoff and updated <= comp_cutoff:
                        entry["due_for_compress"] += 1

            report[stage] = entry

        # 孤儿记录统计
        conn = self.db.get_connection()
        orphan_count = conn.execute(
            """SELECT COUNT(*) as c FROM lifecycle_log ll
               LEFT JOIN signatures s ON ll.sig_id = s.id WHERE s.id IS NULL"""
        ).fetchone()[0]
        report["orphans"] = orphan_count

        return report

    def _compress_if_worthwhile(self, sig: dict, dry_run: bool) -> bool:
        conn = self.db.get_connection()
        rows = conn.execute(
            "SELECT id, findings, status FROM analysis_results WHERE sig_id=?",
            (sig["id"],),
        ).fetchall()
        any_compressed = False
        for row in rows:
            findings = row["findings"]
            if not findings or len(findings) < 1024:
                continue
            if row["status"] == "compressed":
                continue
            from src.compression import compress as _z
            compressed, codec = _z(findings.encode("utf-8") if isinstance(findings, str) else findings,
                                  min_size=1024)
            if codec == "raw" or len(compressed) >= len(findings if isinstance(findings, bytes) else findings.encode("utf-8")):
                if not dry_run:
                    conn.execute(
                        "UPDATE analysis_results SET status='compress_skipped' WHERE id=?",
                        (row["id"],),
                    )
                continue
            if not dry_run:
                conn.execute(
                    "UPDATE analysis_results SET findings=?, status='compressed' WHERE id=?",
                    (compressed, row["id"]),
                )
            any_compressed = True
        return any_compressed

    def _clean_orphans(self, dry_run: bool) -> int:
        conn = self.db.get_connection()
        count = conn.execute(
            """SELECT COUNT(*) as c FROM lifecycle_log ll
               LEFT JOIN signatures s ON ll.sig_id = s.id
               WHERE s.id IS NULL"""
        ).fetchone()[0]
        if count > 0 and not dry_run:
            conn.execute(
                """DELETE FROM lifecycle_log WHERE sig_id IN
                   (SELECT ll.sig_id FROM lifecycle_log ll
                    LEFT JOIN signatures s ON ll.sig_id = s.id
                    WHERE s.id IS NULL)"""
            )
            conn.commit()
        return count

    def transition(self, sig_id: int, to_stage: str, reason: str = "manual") -> bool:
        return self.db.update_stage(sig_id, to_stage, reason)

    def get_lifecycle_log(self, sig_id: int) -> List[Dict]:
        conn = self.db.get_connection()
        rows = conn.execute(
            "SELECT * FROM lifecycle_log WHERE sig_id=? ORDER BY transition_at",
            (sig_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def dry_run_report(self) -> str:
        return "\n".join(self._dry_run_log) or "(no transitions)"

    def compact_archive(self, max_age_days: int = 365,
                        target_stage: str = "archive", dry_run: bool = False) -> int:
        """归档压缩 —— 将超期 archive stage 签名迁移到冷存储。

        当前实现：标记为 `compact_skipped`（预留后续 S3/tape 接口）。
        返回被处理的签名数量。
        """
        cutoff = time.time() - max_age_days * 86400
        sigs = self.db.list_signatures(stage=target_stage)
        count = 0
        for sig in sigs:
            if sig.get("updated_at", 0) > cutoff:
                continue
            if dry_run:
                count += 1
                continue
            # 标记为已压缩（之后可由外部工具物理迁移）
            self.db.update_signature_meta(sig["id"], {"compact_status": "ready"})
            count += 1
        return count

    def stage_summary(self) -> Dict:
        conn = self.db.get_connection()
        now = time.time()
        rows = conn.execute(
            "SELECT stage, COUNT(*) as cnt, AVG(?) - AVG(updated_at) as avg_age FROM signatures GROUP BY stage",
            (now,)
        ).fetchall()
        return {r["stage"]: {"count": r["cnt"], "avg_age_days": round((r["avg_age"] or 0) / 86400, 1)}
                for r in rows}
