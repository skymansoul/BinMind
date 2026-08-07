"""熵正则化最优传输种子分发 — Sinkhorn/Wasserstein 种子分布匹配.

修改记录:
2025-08-02 11:23 - Sinkhorn 算法 + 覆盖空间 Wasserstein 距离
2025-08-03 16:08 - Wasserstein 重心: 多实例种子池几何中位数
2025-08-05 13:42 - 稀疏正则化截断低概率传输边

参考: Cuturi Sinkhorn distances, Peyré & Cuturi Computational OT

在 fuzzing 中无先例。将种子分发建模为分布匹配: 最小化覆盖空间
Wasserstein 距离的传输计划。熵正则化防止退化解。"""

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from .sinkhorn_solver import fingerprint, jaccard_dist, sinkhorn_ot


_DEFAULT_EPSILON = 0.1
_MAX_SEEDS_PER_INSTANCE = 100


@dataclass
class SeedRecord:
    seed_id: str
    coverage_fp: FrozenSet[int]
    source_instance: str
    creation_time: float = field(default_factory=time.time)
    ot_weight: float = 1.0


@dataclass
class TransportPlan:
    source_instance: str
    target_instance: str
    transfers: List[Tuple[str, str, float]]
    wasserstein_cost: float
    n_source_seeds: int
    n_target_seeds: int


class OptimalTransportSeedDistributor:
    """基于熵正则化最优传输的种子分发器.

    将种子分发建模为分布匹配: 计算源到目标的最优传输计划,
    按计划传输种子使目标分布向 Wasserstein 重心收敛。
    """

    def __init__(self, epsilon: float = _DEFAULT_EPSILON):
        self.epsilon = epsilon
        self._instances: Dict[str, Dict[str, SeedRecord]] = defaultdict(dict)
        self._global_fingerprints: Dict[str, FrozenSet[int]] = {}
        self._transport_history: List[TransportPlan] = []
        self._dist_cache: Dict[Tuple[str, str], float] = {}

    def register_seeds(self, instance_id: str,
                       seeds: List[Tuple[str, Set[int]]]) -> None:
        inst = self._instances[instance_id]
        for sid, cov in seeds:
            fp = fingerprint(cov)
            self._global_fingerprints[sid] = fp
            inst[sid] = SeedRecord(
                seed_id=sid, coverage_fp=fp, source_instance=instance_id)
        if len(inst) > _MAX_SEEDS_PER_INSTANCE:
            self._prune_instance(instance_id)

    def add_seed(self, instance_id: str, seed_id: str,
                 coverage: Set[int]) -> None:
        fp = fingerprint(coverage)
        self._global_fingerprints[seed_id] = fp
        self._instances[instance_id][seed_id] = SeedRecord(
            seed_id=seed_id, coverage_fp=fp, source_instance=instance_id)

    def compute_transport(self, src_instance: str,
                          tgt_instance: str) -> Optional[TransportPlan]:
        src_seeds = self._instances.get(src_instance, {})
        tgt_seeds = self._instances.get(tgt_instance, {})
        if not src_seeds or not tgt_seeds:
            return None
        src_ids = list(src_seeds.keys())
        tgt_ids = list(tgt_seeds.keys())
        src_fps = [src_seeds[sid].coverage_fp for sid in src_ids]
        tgt_fps = [tgt_seeds[sid].coverage_fp for sid in tgt_ids]
        transfers, w_cost = sinkhorn_ot(src_fps, tgt_fps, self.epsilon)
        named_transfers = [(src_ids[i], tgt_ids[j], w)
                          for i, j, w in transfers
                          if i < len(src_ids) and j < len(tgt_ids)]
        plan = TransportPlan(
            source_instance=src_instance, target_instance=tgt_instance,
            transfers=named_transfers, wasserstein_cost=w_cost,
            n_source_seeds=len(src_ids), n_target_seeds=len(tgt_ids))
        self._transport_history.append(plan)
        if len(self._transport_history) > 50:
            self._transport_history = self._transport_history[-30:]
        return plan

    def select_seeds_to_transfer(self, plan: TransportPlan,
                                  max_seeds: int = 10) -> List[Tuple[str, float]]:
        sorted_t = sorted(plan.transfers, key=lambda x: x[2], reverse=True)
        selected = []; sent_src = set()
        for src_id, _tgt_id, weight in sorted_t:
            if src_id in sent_src: continue
            if len(selected) >= max_seeds: break
            selected.append((src_id, weight))
            sent_src.add(src_id)
        return selected

    def compute_wasserstein_barycenter(self,
                                        instance_ids: List[str]) -> Dict[str, float]:
        if len(instance_ids) < 2:
            return {}
        all_fps = {iid: [sr.coverage_fp
                        for sr in self._instances.get(iid, {}).values()]
                  for iid in instance_ids}
        best_iid = instance_ids[0]; best_dist = float('inf')
        for iid in instance_ids:
            total_w = 0.0
            fps_a = all_fps.get(iid, [])
            for other in instance_ids:
                if other == iid: continue
                fps_b = all_fps.get(other, [])
                if not fps_a or not fps_b: continue
                avg_d = sum(jaccard_dist(fa, fb)
                           for fa in fps_a[:20] for fb in fps_b[:20])
                total_w += avg_d / max(1, min(20, len(fps_a)) * min(20, len(fps_b)))
            if total_w < best_dist:
                best_dist = total_w; best_iid = iid
        result = {}
        for sid in self._instances.get(best_iid, {}):
            result[sid] = 1.0 / max(1, len(self._instances[best_iid]))
        return result

    def transport_diversity_score(self, src_instance: str,
                                   tgt_instance: str,
                                   candidate_seeds: List[str]
                                   ) -> List[Tuple[str, float]]:
        tgt = self._instances.get(tgt_instance, {})
        if not tgt:
            return [(sid, 1.0) for sid in candidate_seeds]
        tgt_fps = [sr.coverage_fp for sr in tgt.values()]
        scores = []
        for sid in candidate_seeds:
            src_seed = self._instances.get(src_instance, {}).get(sid)
            if src_seed is None:
                scores.append((sid, 0.0)); continue
            max_sim = max(
                (1.0 - jaccard_dist(src_seed.coverage_fp, tf)
                 for tf in tgt_fps[:30]), default=0.0)
            scores.append((sid, 1.0 - max_sim))
        scores.sort(key=lambda x: x[1], reverse=True)
        return scores

    def _prune_instance(self, instance_id: str) -> None:
        inst = self._instances[instance_id]
        if len(inst) <= _MAX_SEEDS_PER_INSTANCE:
            return
        ranked = sorted(inst.items(),
                       key=lambda x: (len(x[1].coverage_fp), x[1].creation_time),
                       reverse=True)
        keep = {sid for sid, _ in ranked[:_MAX_SEEDS_PER_INSTANCE]}
        self._instances[instance_id] = {s: r for s, r in inst.items() if s in keep}

    def stats(self) -> dict:
        n = len(self._transport_history)
        tc = sum(p.wasserstein_cost for p in self._transport_history[-10:])
        return {
            "instances": len(self._instances),
            "total_seeds_registered": len(self._global_fingerprints),
            "transport_plans_computed": n,
            "avg_wasserstein_cost": round(tc / max(1, min(10, n)), 4),
            "epsilon": self.epsilon,
            "distance_cache_size": len(self._dist_cache),
        }

    def clear(self) -> None:
        self._instances.clear(); self._global_fingerprints.clear()
        self._transport_history.clear(); self._dist_cache.clear()
