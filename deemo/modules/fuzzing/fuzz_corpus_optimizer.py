# 2026-08-02

"""语料库多样性与优化 -- RandSet/KRAKEN-FUZZ 风格的运行时语料修剪。

参考:
  RandSet     (arXiv:2602.22729, 2025) -- 随机化集合覆盖的语料规约, 高频调度友好
  KRAKEN-FUZZ (SBFT 2025 @ ICSE 2025)    -- 动态飞行中语料最小化
  MCM         (IST 2025)                  -- 历史模糊测试结果驱动的多语料最小化
  ISC4DGF     (JCST 2025)                 -- LLM驱动定向模糊测试初始语料生成

提供:
  - 基于覆盖集合覆盖的语料贪心规约 (afl-cmin 算法)
  - RandSet 风格的随机化规约 (引入随机性避免确定性覆盖盲区)
  - 语料多样性度量: Jaccard/熵/指纹唯一率
  - KRAKEN-FUZZ 风格的飞行中修剪 (低贡献种子淘汰)
  - MCM 风格的历史数据融合
"""

import hashlib
import json
import logging
import math
import os
import random
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


@dataclass
class SeedScore:
    """种子的多维度评分。"""
    seed_id: str
    edge_coverage: Set[int] = field(default_factory=set)
    coverage_count: int = 0
    exec_time_ms: float = 0.0
    file_size: int = 0
    generation: int = 0
    crash_triggered: bool = False
    novelty_score: float = 0.0       # 覆盖新颖性
    efficiency_score: float = 0.0    # 执行效率
    composite_score: float = 0.0     # 综合评分


class DiversityMetric(str, Enum):
    JACCARD = "jaccard"
    ENTROPY = "entropy"
    FINGERPRINT = "fingerprint"
    COVERAGE_UNION = "coverage_union"


class CorpusOptimizer:
    """语料库质量优化器。

    核心操作:
      1. 贪心覆盖规约 (afl-cmin): 选择最小种子子集维持全部覆盖
      2. 随机化规约 (RandSet): 加入随机性, 每次选择不同的最小覆盖集
      3. 飞行中修剪 (KRAKEN-FUZZ): 周期性淘汰低贡献种子
      4. 多样性度量: 评估语料库的健康状况
    """

    def __init__(self, max_corpus_size: int = 5000):
        self.max_corpus = max_corpus_size
        self._seed_scores: Dict[str, SeedScore] = {}
        self._prune_history: List[Dict] = []
        # MCM 风格的历史覆盖频率
        self._historical_edge_freq: Dict[int, int] = defaultdict(int)
        self._campaign_count: int = 0

    # ===== 注册种子评分 =====

    def register_seed(self, seed_id: str, coverage: Set[int],
                      exec_time_ms: float = 0.0, file_size: int = 0,
                      generation: int = 0, crash: bool = False) -> None:
        ss = SeedScore(
            seed_id=seed_id,
            edge_coverage=coverage,
            coverage_count=len(coverage),
            exec_time_ms=exec_time_ms,
            file_size=file_size,
            generation=generation,
            crash_triggered=crash,
        )
        ss.novelty_score = self._compute_novelty(coverage)
        ss.efficiency_score = (
            len(coverage) / max(1.0, exec_time_ms / 10.0)
            if exec_time_ms > 0 else 0.0
        )
        ss.composite_score = 0.4 * ss.novelty_score + 0.4 * ss.efficiency_score + 0.2 * (1.0 if crash else 0.0)
        self._seed_scores[seed_id] = ss

        # 更新历史频率 (MCM)
        for edge in coverage:
            self._historical_edge_freq[edge] += 1

    def _compute_novelty(self, coverage: Set[int]) -> float:
        """基于历史频率的新颖性评分。

        MCM: edge_freq 越低 → 该覆盖越稀有 → 新颖性越高。
        """
        if not coverage:
            return 0.0
        rarity_sum = 0.0
        for edge in coverage:
            freq = self._historical_edge_freq.get(edge, 0)
            rarity_sum += 1.0 / (1.0 + freq)
        return rarity_sum / len(coverage)

    # ===== 贪心覆盖规约 (afl-cmin 算法) =====

    def greedy_minimize(self, seed_ids: List[str]) -> List[str]:
        """选择最小种子子集, 使并集覆盖等价于全集。

        标准贪心集合覆盖: 每次选覆盖最多未覆盖边的种子。
        时间复杂度 O(k·n) 其中 k=选出的种子数, n=总种子数。
        """
        if not seed_ids:
            return []

        # 只处理已知评分的种子
        known = [sid for sid in seed_ids if sid in self._seed_scores]
        if not known:
            return seed_ids

        all_edges: Set[int] = set()
        for sid in known:
            all_edges.update(self._seed_scores[sid].edge_coverage)

        if not all_edges:
            return known[:1]

        selected: List[str] = []
        remaining = set(all_edges)
        available = set(known)

        while remaining and available:
            best_sid = max(
                available,
                key=lambda sid: len(
                    self._seed_scores[sid].edge_coverage & remaining
                )
            )
            selected.append(best_sid)
            remaining -= self._seed_scores[best_sid].edge_coverage
            available.remove(best_sid)

        return selected

    # ===== 随机化规约 (RandSet 2025) =====

    def randomized_minimize(self, seed_ids: List[str],
                            target_ratio: float = 0.15) -> List[str]:
        """RandSet 风格: 每次规约输出不同的最小覆盖集。

        先执行贪心规约选出候选集, 然后随机丢弃一部分并重新填补,
        产生一个不同但覆盖仍完整的子集。
        """
        base = self.greedy_minimize(seed_ids)
        if len(base) <= 2:
            return base

        # 随机丢弃 30% 的已选种子
        drop_count = max(1, int(len(base) * 0.3))
        kept = random.sample(base, len(base) - drop_count)

        # 重新收集未覆盖的边
        covered: Set[int] = set()
        for sid in kept:
            covered.update(self._seed_scores.get(sid, SeedScore(seed_id=sid)).edge_coverage)

        all_edges: Set[int] = set()
        for sid in seed_ids:
            if sid in self._seed_scores:
                all_edges.update(self._seed_scores[sid].edge_coverage)

        remaining = all_edges - covered
        candidates = [sid for sid in seed_ids if sid not in kept and sid in self._seed_scores]
        random.shuffle(candidates)

        for sid in candidates:
            if not remaining:
                break
            contrib = self._seed_scores[sid].edge_coverage & remaining
            if contrib:
                kept.append(sid)
                remaining -= contrib

        return kept

    # ===== KRAKEN-FUZZ 飞行中修剪 =====

    def inflight_prune(self, threshold_ratio: float = 0.1) -> int:
        """淘汰综合评分最低的种子。

        KRAKEN-FUZZ (SBFT 2025) 的核心思想: 在模糊测试进行中,
        周期性移除那些对覆盖率贡献低的种子, 释放内存和调度开销。

        threshold_ratio: 淘汰评分低于此比例(相对于最高分)的种子。
        """
        if not self._seed_scores:
            return 0

        max_score = max(s.composite_score for s in self._seed_scores.values())
        if max_score <= 0:
            return 0

        threshold = max_score * threshold_ratio
        to_remove = [
            sid for sid, ss in self._seed_scores.items()
            if ss.composite_score < threshold and not ss.crash_triggered
        ]

        for sid in to_remove:
            del self._seed_scores[sid]

        if to_remove:
            self._prune_history.append({
                'ts': time.time(),
                'removed': len(to_remove),
                'retained': len(self._seed_scores),
            })

        return len(to_remove)

    # ===== 多样性度量 =====

    def diversity_score(self, seed_ids: List[str],
                        metric: DiversityMetric = DiversityMetric.JACCARD) -> float:
        if len(seed_ids) <= 1:
            return 1.0

        if metric == DiversityMetric.FINGERPRINT:
            fp_set = set()
            for sid in seed_ids:
                if sid in self._seed_scores:
                    cov = sorted(self._seed_scores[sid].edge_coverage)
                    cov_str = str(cov)[:64]
                    fp = hashlib.sha256(cov_str.encode()).hexdigest()[:8]
                    fp_set.add(fp)
            return len(fp_set) / max(1, len(seed_ids))

        if metric == DiversityMetric.JACCARD:
            total_dist = 0.0
            pairs = 0
            ids_with_cov = [sid for sid in seed_ids if sid in self._seed_scores]
            for i in range(min(len(ids_with_cov), 30)):
                for j in range(i + 1, min(len(ids_with_cov), 30)):
                    a = self._seed_scores[ids_with_cov[i]].edge_coverage
                    b = self._seed_scores[ids_with_cov[j]].edge_coverage
                    if not a and not b:
                        continue
                    union = len(a | b)
                    inter = len(a & b)
                    jaccard = inter / union if union > 0 else 1.0
                    total_dist += (1.0 - jaccard)
                    pairs += 1
            return total_dist / max(1, pairs)

        if metric == DiversityMetric.COVERAGE_UNION:
            all_edges: Set[int] = set()
            total_edges = 0
            for sid in seed_ids:
                if sid in self._seed_scores:
                    cov = self._seed_scores[sid].edge_coverage
                    all_edges.update(cov)
                    total_edges += len(cov)
            return len(all_edges) / max(1, total_edges)

        if metric == DiversityMetric.ENTROPY:
            edge_counter = Counter()
            for sid in seed_ids:
                if sid in self._seed_scores:
                    for e in self._seed_scores[sid].edge_coverage:
                        edge_counter[e] += 1
            total = sum(edge_counter.values())
            if total == 0:
                return 0.0
            ent = 0.0
            for cnt in edge_counter.values():
                p = cnt / total
                ent -= p * math.log2(p)
            max_ent = math.log2(len(edge_counter)) if edge_counter else 1.0
            return ent / max_ent if max_ent > 0 else 0.0

        return 0.0

    # ===== 综合优化报告 =====

    def optimize_report(self, seed_ids: List[str]) -> Dict:
        """对语料库执行一轮完整优化并生成报告。"""
        start_count = len(seed_ids)
        div_before = self.diversity_score(seed_ids, DiversityMetric.JACCARD)

        # RandSet 规约
        optimized = self.randomized_minimize(seed_ids)
        div_after = self.diversity_score(optimized, DiversityMetric.JACCARD)

        # 飞行中修剪
        pruned = self.inflight_prune(threshold_ratio=0.05)

        return {
            "original_count": start_count,
            "optimized_count": len(optimized),
            "reduction_ratio": len(optimized) / max(1, start_count),
            "diversity_before": round(div_before, 4),
            "diversity_after": round(div_after, 4),
            "inflight_pruned": pruned,
            "prune_history_count": len(self._prune_history),
        }

    def export_state(self, path: str) -> None:
        """持久化优化器状态 (MCM 历史频率等)。"""
        state = {
            "historical_freq": dict(self._historical_edge_freq),
            "seed_count": len(self._seed_scores),
            "prune_history": self._prune_history,
            "campaign_count": self._campaign_count,
        }
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(state, f, indent=2)

    def import_state(self, path: str) -> None:
        """加载之前的优化器状态。"""
        if not os.path.isfile(path):
            return
        with open(path, 'r', encoding='utf-8') as f:
            state = json.load(f)
        self._historical_edge_freq = defaultdict(int, state.get("historical_freq", {}))
        self._prune_history = state.get("prune_history", [])
        self._campaign_count = state.get("campaign_count", 0)


def optimize_corpus(seed_ids: List[str],
                    coverage_getter: Callable[[str], Set[int]],
                    target_ratio: float = 0.15) -> Tuple[List[str], Dict]:
    """模块级便捷入口: 规约并报告。"""
    opt = CorpusOptimizer()
    for sid in seed_ids:
        cov = coverage_getter(sid)
        opt.register_seed(sid, cov)
    result_ids = opt.randomized_minimize(seed_ids, target_ratio)
    report = opt.optimize_report(seed_ids)
    return result_ids, report
