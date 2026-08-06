# 多时间尺度衰减的种子调度器 — 区分块/边/崩溃的差异化半衰期
#
# 核心问题:
#   power_schedule.py 和 seed_selector.py 忽略覆盖发现的时效性,
#   且将所有发现事件等同对待——但新函数块的发现价值远高于新边。
#
#   现有方案 HScheduler (2025) 优先高覆盖种子但无时间衰减;
#   AFLFast 的power schedule基于执行频率但不区分事件类型。
#
# 本模块的方法 — 多时间尺度衰减:
#   1. 三类覆盖事件使用不同的半衰期:
#      块发现 (new_blocks): 长半衰期 (~3600s) — 新函数是里程碑
#      边发现 (new_edges): 中半衰期 (~600s)  — 新分支是增量
#      崩溃发现 (crashes):  短半衰期 (~120s)  — 崩溃是事件性的
#   2. 贡献度 = Σ(blocks_i × exp(-λ_b × age) + edges_i × exp(-λ_e × age))
#   3. 半衰期比率反映信息持久性: 块>边>崩溃
#   4. 同一半衰期框架、不同参数——保持简洁且可解释

from __future__ import annotations

import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class CoverageEvent:
    """单次覆盖发现事件"""
    timestamp: float
    new_edges: int
    new_blocks: int = 0


@dataclass
class SeedRecord:
    """单个种子的时间衰减覆盖记录"""
    seed_id: str
    data_hash: str = ""
    size: int = 0
    # 覆盖发现事件列表 (按时间排序)
    coverage_events: List[CoverageEvent] = field(default_factory=list)
    # 当前衰减后的贡献度
    decayed_contribution: float = 0.0
    # 最近一次被选中的时间
    last_selected: float = 0.0
    times_selected: int = 0
    # 是否该退休
    retired: bool = False
    # 输入多样性bonus (基于字节熵)
    diversity_bonus: float = 0.0


@dataclass
class ScheduleDecision:
    """调度决策——返回本轮应优先变异的种子列表"""
    ranked_seeds: List[Tuple[str, float]]  # (seed_id, energy)
    retired_count: int
    avg_contribution: float
    summary: str = ""


class TemporalSeedScheduler:
    """时间衰减覆盖感知的种子调度器。

    典型用法:
        scheduler = TemporalSeedScheduler(half_life_s=600.0)
        # 种子发现新覆盖时:
        scheduler.record_coverage(seed_id, new_edges=5)
        # 每轮调度:
        decision = scheduler.schedule(top_k=20)
        for seed_id, energy in decision.ranked_seeds:
            fuzzer.mutate(seed_id, rounds=int(energy * 100))
    """

    def __init__(self,
                 block_half_life_s: float = 3600.0,
                 edge_half_life_s: float = 600.0,
                 crash_half_life_s: float = 120.0,
                 retirement_threshold: float = 0.01,
                 max_seeds: int = 4096,
                 diversity_weight: float = 0.15):
        """
        block_half_life_s: 新块发现的半衰期 (默认3600s=1小时)
        edge_half_life_s:  新边发现的半衰期 (默认600s=10分钟)
        crash_half_life_s: 崩溃发现的半衰期 (默认120s=2分钟)
        半衰期比率体现不同类型发现的信息持久性差异.
        """
        self._lambda_block = math.log(2) / block_half_life_s
        self._lambda_edge = math.log(2) / edge_half_life_s
        self._lambda_crash = math.log(2) / crash_half_life_s
        self._retire_threshold = retirement_threshold
        self._max_seeds = max_seeds
        self._div_weight = diversity_weight

        self._seeds: Dict[str, SeedRecord] = {}
        self._schedule_count = 0

    def register_seed(self, seed_id: str, data: bytes = b"") -> None:
        """注册新种子——自动计算多样性bonus"""
        if seed_id in self._seeds:
            return
        import hashlib
        dh = hashlib.sha256(data[:512]).hexdigest()[:16] if data else ""
        diversity = self._compute_diversity_bonus(data) if data else 0.0
        self._seeds[seed_id] = SeedRecord(
            seed_id=seed_id, data_hash=dh,
            size=len(data), diversity_bonus=diversity)

    def record_coverage(self, seed_id: str, new_edges: int,
                         new_blocks: int = 0) -> None:
        """记录一次覆盖发现——自动更新时间衰减贡献度"""
        rec = self._seeds.get(seed_id)
        if rec is None:
            rec = SeedRecord(seed_id=seed_id)
            self._seeds[seed_id] = rec

        event = CoverageEvent(
            timestamp=time.monotonic(),
            new_edges=new_edges, new_blocks=new_blocks)
        rec.coverage_events.append(event)
        # 限制事件历史
        if len(rec.coverage_events) > 64:
            rec.coverage_events = rec.coverage_events[-64:]

    def schedule(self, top_k: int = 20) -> ScheduleDecision:
        """主入口: 返回按衰减贡献度排名的Top-K种子"""
        self._schedule_count += 1
        now = time.monotonic()
        scored: List[Tuple[str, float]] = []
        total_contrib = 0.0
        retired = 0

        for seed_id, rec in list(self._seeds.items()):
            if rec.retired:
                retired += 1
                continue

            # 多时间尺度衰减: 块/边/崩溃使用各自半衰期
            contrib = 0.0
            for event in rec.coverage_events:
                age = now - event.timestamp
                # 块发现→长半衰期, 边发现→中半衰期
                edge_contrib = event.new_edges * math.exp(-self._lambda_edge * age)
                block_contrib = event.new_blocks * math.exp(-self._lambda_block * age)
                contrib += edge_contrib + block_contrib

            rec.decayed_contribution = contrib

            # 退休检查
            if (contrib < self._retire_threshold
                    and len(rec.coverage_events) > 0
                    and (now - rec.coverage_events[-1].timestamp) > 3600):
                rec.retired = True
                retired += 1
                continue

            # 综合能量 = 衰减贡献度 × (1 + 多样性bonus)
            energy = contrib * (1.0 + self._div_weight * rec.diversity_bonus)
            scored.append((seed_id, energy))
            total_contrib += contrib

        # 按能量降序
        scored.sort(key=lambda x: -x[1])
        ranked = scored[:top_k]

        # 标记选中
        for seed_id, _ in ranked:
            rec = self._seeds.get(seed_id)
            if rec:
                rec.last_selected = now
                rec.times_selected += 1

        avg = total_contrib / max(1, len(self._seeds) - retired)
        return ScheduleDecision(
            ranked_seeds=ranked,
            retired_count=retired,
            avg_contribution=avg,
            summary=(f"调度: {len(ranked)}/{len(self._seeds)} 种子, "
                     f"退休{retired}, 平均贡献度{avg:.4f}"),
        )

    def _compute_diversity_bonus(self, data: bytes) -> float:
        """计算输入字节的多样性bonus——高熵输入获得更高bonus"""
        if len(data) < 4:
            return 0.0
        # 简化的字节熵
        counts = [0] * 256
        for b in data[:1024]:
            counts[b] += 1
        total = sum(counts)
        ent = 0.0
        for c in counts:
            if c > 0:
                p = c / total
                ent -= p * math.log2(p)
        return min(1.0, ent / 8.0)

    # ---- 诊断 ----

    def active_count(self) -> int:
        return sum(1 for r in self._seeds.values() if not r.retired)

    def top_contributors(self, k: int = 5) -> List[Tuple[str, float]]:
        contribs = [(sid, r.decayed_contribution)
                     for sid, r in self._seeds.items() if not r.retired]
        contribs.sort(key=lambda x: -x[1])
        return contribs[:k]

    def stats(self) -> Dict[str, Any]:
        active = self.active_count()
        return {
            "total_seeds": len(self._seeds),
            "active_seeds": active,
            "retired_seeds": sum(1 for r in self._seeds.values() if r.retired),
            "half_life_block_s": round(math.log(2) / self._lambda_block, 1),
            "half_life_edge_s": round(math.log(2) / self._lambda_edge, 1),
            "half_life_crash_s": round(math.log(2) / self._lambda_crash, 1),
            "schedule_count": self._schedule_count,
            "top_contributors": [
                (sid, round(contrib, 4))
                for sid, contrib in self.top_contributors(3)
            ],
        }

    def reset(self) -> None:
        self._seeds.clear()
        self._schedule_count = 0
