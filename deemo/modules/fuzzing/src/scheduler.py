"""AFLfast调度器 + 语料库持久化管理 -- 种子选择/队列裁剪/文件IO."""

import json
import math
import os
import random
import time
from collections import defaultdict
from pathlib import Path

from .core import Seed

# ---- 支持动态策略切换 ----
_VALID_STRATEGIES = frozenset({"aflfast", "roundrobin", "random", "weighted", "bandit"})

# ===== 主要调度器 =====
class Scheduler:
    """AFLfast马尔可夫链调度 -- 根据种子性能和覆盖反馈动态调整概率。

    核心思想：维护一个状态转移链，跟踪每个种子选中后是否产生新发现，
    更新该种子所在"状态"的转移概率，类似多臂老虎机。
    """

    def __init__(self, strategy: str = "aflfast"):
        if strategy not in _VALID_STRATEGIES:
            raise ValueError(f"Unknown strategy: {strategy}, valid: {_VALID_STRATEGIES}")
        self.strategy = strategy
        self._seed_queue: list[Seed] = []
        self._seed_scores: dict[str, float] = {}
        self._selection_counts: dict[str, int] = defaultdict(int)

        # ---- 马尔可夫链状态 ----
        self._markov_chain: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
        self._current_state: str = "init"
        self._state_history: list[tuple[str, bool]] = []  # (state, is_new_find)
        self._round_robin_idx: int = 0
        self._total_picks: int = 0
        # ISRG + Pareto: 按需懒加载, 避免默认引入开销
        self._srg = None          # SeedRelationGraph | None
        self._pareto = None       # ParetoArchive | None
        self._path_cluster = None       # PathCluster | None
        self._mutation_ensemble = None  # MutationEnsemble | None
        self._coverage_splicer = None   # CoverageAwareSplicer | None
        self._cost_forecaster = None    # ExecutionCostForecaster | None

    # //// 种子评分 -- AFLfast风格 ////
    def seed_score(self, seed: Seed) -> float:
        """基于执行速度 + 覆盖量 + 代数计算加权分数"""
        _time_ms = seed.metadata.get("exec_time_ms", 10.0)
        _exec_factor = 1.0 / max(1.0, _time_ms / 10.0)

        _edge_count = seed.metadata.get("edge_count", len(seed.coverage))
        _cov_factor = math.log2(1 + _edge_count)

        _gen = seed.generation
        _gen_factor = 1.0 / (1.0 + _gen)

        # 最近发现的新覆盖加权
        _is_recent = seed.metadata.get("is_recent_find", False)
        _recent_bonus = 1.5 if _is_recent else 1.0

        return _exec_factor * _cov_factor * _gen_factor * _recent_bonus

    # //// 选择下一个种子 -- 根据策略分发 ////
    def pick_seed(self) -> Seed | None:
        if not self._seed_queue:
            return None

        # 更新所有种子评分
        for _s in self._seed_queue:
            self._seed_scores[_s.id] = self.seed_score(_s)

        self._total_picks += 1

        if self.strategy == "aflfast":
            _chosen = self._pick_aflfast()
        elif self.strategy == "roundrobin":
            _chosen = self._pick_roundrobin()
        elif self.strategy == "random":
            _chosen = random.choice(self._seed_queue)
        elif self.strategy == "weighted":
            _chosen = self._pick_weighted()
        elif self.strategy == "bandit":
            _chosen = self._pick_bandit()
        else:
            _chosen = self._seed_queue[0]

        if _chosen is not None:
            self._selection_counts[_chosen.id] += 1
            _chosen.mutation_count += 1
        return _chosen

    # ---- bandit: 委托给 MAB 调度器 (LinUCB / UCB / Exp3 / Thompson) ----
    def _pick_bandit(self) -> Seed:
        # 懒加载, 避免循环导入和依赖侵入
        try:
            from fuzzing.fuzz_bandit_scheduler import BanditScheduler
        except ImportError:
            return self._seed_queue[0]
        if not hasattr(self, '_bandit_impl'):
            self._bandit_impl = BanditScheduler("linucb", alpha=0.8)
        bctx = None  # LinUCB 会自动从 seed.metadata 生成特征
        picked = self._bandit_impl.select_seed(self._seed_queue, contexts=None)
        if picked is None:
            return self._seed_queue[0]
        idx, _score = picked
        # 对选中的种子注入reward偏差: 新种子(unpicked)默认被识别为高潜力
        chosen = self._seed_queue[idx]
        sid = getattr(chosen, 'id', str(idx))
        is_new = chosen.metadata.get("is_recent_find", False)
        self._bandit_impl.notify_reward(sid, None, is_new_find=is_new)
        return chosen

    # ---- AFLfast加权随机 ----
    def _pick_aflfast(self) -> Seed:
        _scores = [self._seed_scores.get(_s.id, 1.0) for _s in self._seed_queue]
        _idx = self._roulette_wheel(_scores)
        return self._seed_queue[_idx]

    # ---- 轮询 ----
    def _pick_roundrobin(self) -> Seed:
        self._round_robin_idx = self._round_robin_idx % len(self._seed_queue)
        _seed = self._seed_queue[self._round_robin_idx]
        self._round_robin_idx += 1
        return _seed

    # ---- 加权 ----
    def _pick_weighted(self) -> Seed:
        _scores = [self._seed_scores.get(_s.id, 1.0) for _s in self._seed_queue]
        _idx = self._roulette_wheel(_scores)
        return self._seed_queue[_idx]

    # //// 轮盘赌选择 ////
    def _roulette_wheel(self, weights: list[float]) -> int:
        _total = sum(weights)
        if _total <= 0:
            return random.randrange(len(weights))
        _r = random.random() * _total
        _cum = 0.0
        for _i, _w in enumerate(weights):
            _cum += _w
            if _cum >= _r:
                return _i
        return len(weights) - 1

    # //// 队列管理 ////
    def add_seed(self, seed: Seed) -> None:
        self._seed_queue.append(seed)
        self._seed_scores[seed.id] = self.seed_score(seed)

    def remove_seed(self, seed_id: str) -> bool:
        for _i, _s in enumerate(self._seed_queue):
            if _s.id == seed_id:
                self._seed_queue.pop(_i)
                self._seed_scores.pop(seed_id, None)
                self._selection_counts.pop(seed_id, None)
                return True
        return False

    # //// 队列裁剪 -- 贪心最小化 + ISRG/Pareto保护 ////
    def cull_queue(self) -> int:
        """去除冗余种子，只保留那些贡献了独特覆盖的种子。

        排序依据：执行时间升序（快的优先）、覆盖边数降序（多的优先）。
        贪心算法：对于每个种子，检查其覆盖是否被已保留的种子集合完全覆盖。

        ISRG/Pareto 保护: 若启用了关系图或归档, 桥接种子和 Pareto 最优种子
        在裁剪中优先保留, 即使它们的覆盖被其他种子包含。
        """
        if len(self._seed_queue) <= 1:
            return 0

        # 获取保护列表
        _protected: set[str] = set()
        _protected.update(self.get_bridge_seeds())
        _protected.update(self.get_pareto_retained_ids())

        # 排序：快的在前，覆盖多的在前
        self._seed_queue.sort(
            key=lambda s: (
                s.metadata.get("exec_time_ms", 999999.0),
                -len(s.coverage),
            )
        )

        _kept: list[Seed] = []
        _covered_union: set = set()
        _removed = 0

        for _s in self._seed_queue:
            _new_coverage = _s.coverage - _covered_union
            # 受保护种子: 即使无新覆盖也保留, 但通过其独有覆盖增益决定是否更新并集
            if _new_coverage or _s.id in _protected:
                _covered_union.update(_s.coverage)
                _kept.append(_s)
            else:
                _removed += 1

        self._seed_queue = _kept
        # 清理被移除种子的评分
        _kept_ids = {_s.id for _s in _kept}
        self._seed_scores = {_k: _v for _k, _v in self._seed_scores.items() if _k in _kept_ids}
        return _removed

    # //// 获取队列统计 ////
    def get_queue_stats(self) -> dict:
        _edge_counts = [len(_s.coverage) for _s in self._seed_queue] if self._seed_queue else [0]
        _total_edges_across_all = sum(_edge_counts)
        _stats = {
            "queue_length": len(self._seed_queue),
            "strategy": self.strategy,
            "total_picks": self._total_picks,
            "avg_edges_per_seed": _total_edges_across_all / max(1, len(self._seed_queue)),
            "max_edges_any_seed": max(_edge_counts),
            "min_edges_any_seed": min(_edge_counts),
            "unique_seeds_picked": len(self._selection_counts),
        }
        if self._srg is not None:
            _stats["isrg"] = self._srg.stats()
        if self._pareto is not None:
            _stats["pareto"] = self._pareto.stats()
        if self._path_cluster is not None:
            _stats["path_cluster"] = self._path_cluster.stats()
        if self._mutation_ensemble is not None:
            _stats["mutation_ensemble"] = self._mutation_ensemble.stats()
        if self._coverage_splicer is not None:
            _stats["coverage_splicer"] = self._coverage_splicer.stats()
        if self._cost_forecaster is not None:
            _stats["cost_forecaster"] = self._cost_forecaster.stats()
        return _stats

    # //// 更新马尔可夫状态 -- 根据fuzzing结果反馈 ////
    def _update_markov_state(self, seed: Seed, is_new_find: bool) -> None:
        """基于最近种子的表现调整状态转移概率"""
        _prev = self._current_state

        # 状态编码：该种子被归类为哪种"类型"
        _exec_time = seed.metadata.get("exec_time_ms", 10.0)
        _edges = len(seed.coverage)

        if _edges < 10:
            _state_suffix = "low_cov"
        elif _edges < 50:
            _state_suffix = "mid_cov"
        else:
            _state_suffix = "high_cov"

        _time_category = "fast" if _exec_time < 5.0 else "mid" if _exec_time < 50.0 else "slow"
        _new_state = f"{_time_category}_{_state_suffix}"

        self._current_state = _new_state
        self._state_history.append((_prev, is_new_find))

        # 更新转移计数
        _count_key = "hit" if is_new_find else "miss"
        self._markov_chain[_prev][_count_key] += 1.0

        # 归一化当前状态的转移概率
        _hits = self._markov_chain[_new_state].get("hit", 0.0)
        _misses = self._markov_chain[_new_state].get("miss", 0.0)
        _denom = _hits + _misses
        if _denom > 0:
            self._markov_chain[_new_state]["prob_new_find"] = _hits / _denom

    # //// 通知调度器执行结果（供外部调用）////
    def notify_result(self, seed: Seed, is_new_find: bool) -> None:
        self._update_markov_state(seed, is_new_find)
        if is_new_find:
            seed.metadata["is_recent_find"] = True
            seed.energy = min(seed.energy * 1.2, 10.0)
        else:
            seed.metadata["is_recent_find"] = False
            seed.energy = max(seed.energy * 0.95, 0.1)

    # //// ISRG (种子间覆盖关系图) 集成 ////
    def enable_graph_awareness(self) -> None:
        """启用种子关系图感知 -- 懒加载 ISRG, 开始追踪种子间覆盖关系。"""
        if self._srg is None:
            from fuzzing.src.seed_relation_graph import SeedRelationGraph
            self._srg = SeedRelationGraph()

    def update_relation_graph(self, seed: Seed, coverage: set) -> None:
        """将种子及其覆盖信息录入 ISRG。

        在每次执行后调用, 维护种子间覆盖关系的实时图。
        若未启用图感知, 则无操作。
        """
        if self._srg is None:
            return
        self._srg.upsert_seed(seed.id, coverage)
        # 此段后续可微调: 当前每 50 次更新才重建中心性以平衡精度和计算开销
        if self._total_picks % 50 == 0:
            self._srg.compute_flow_centrality()

    def seed_diversity_bonus(self, seed_id: str) -> float:
        """从 ISRG 获取种子的多样性奖励因子 [0, 1]。

        返回 1.0 表示高度多样性 (应加分), 0.0 表示冗余 (应减分)。
        用于在 AFLfast 评分中乘入多样性维度, 使调度偏好独特种子。
        若未启用图感知, 返回中性值 0.5。
        """
        if self._srg is None:
            return 0.5
        return self._srg.diversity_score(seed_id)

    def get_bridge_seeds(self) -> list[str]:
        """返回 ISRG 识别出的桥接种子 ID 列表 -- 裁剪时需额外保留。"""
        if self._srg is None:
            return []
        return self._srg.find_bridge_seeds()

    # //// Pareto 归档集成 ////
    def enable_pareto_archive(self, n_objectives: int = 4,
                              max_archive_size: int = 200) -> None:
        """启用多目标 Pareto 归档 -- 跨代保留非支配种子。"""
        if self._pareto is None:
            from fuzzing.src.pareto_archive import ParetoArchive
            self._pareto = ParetoArchive(
                n_objectives=n_objectives,
                max_archive_size=max_archive_size,
            )

    def submit_to_pareto(self, seed: Seed, exec_time_ms: float = 10.0,
                         rarity_score: float = 0.5) -> bool:
        """将种子提交到 Pareto 归档评估。

        返回 True 若该种子被接受进入 Pareto 前沿。
        若未启用归档, 返回 False。
        """
        if self._pareto is None:
            return False
        from fuzzing.src.pareto_archive import ParetoArchive
        objs = ParetoArchive.objectives_from_seed(
            seed, edge_coverage=seed.coverage,
            exec_time_ms=exec_time_ms, rarity_score=rarity_score,
        )
        return self._pareto.submit(seed.id, objs, metadata=seed.metadata)

    def get_pareto_retained_ids(self) -> frozenset[str]:
        """返回 Pareto 归档中必须保留的种子ID。"""
        if self._pareto is None:
            return frozenset()
        return self._pareto.get_retained_ids()

    # //// 增强的种子评分: 融合 ISRG 多样性 ////
    def seed_score_enhanced(self, seed: Seed) -> float:
        """基于原始 AFLfast 评分 + ISRG 多样性奖励的增强评分。

        score = base_score * (0.7 + 0.3 * diversity_bonus)
        多样性奖励最高可提升 30%, 最低降低 30%。
        未启用 ISRG 时退化为原始评分。
        """
        base = self.seed_score(seed)
        div = self.seed_diversity_bonus(seed.id)
        return base * (0.7 + 0.3 * div)

    # //// PathCluster (MinHash LSH 路径聚类) 集成 ////
    def enable_path_clustering(self) -> None:
        """启用执行路径聚类 — 基于 MinHash LSH 的路径相似性快速检索。"""
        if self._path_cluster is None:
            from fuzzing.src.path_trace_cluster import PathCluster
            self._path_cluster = PathCluster()

    def insert_execution_trace(self, seed_id: str, trace: list[int]) -> None:
        """将种子执行 trace 插入路径聚类器。trace 为边 ID 有序列表。"""
        if self._path_cluster is None:
            return
        self._path_cluster.insert(seed_id, trace)

    def path_diversity_score(self, seed_id: str) -> float:
        """从路径聚类器获取路径结构多样性 (0~1)。

        与 ISRG 多样性互补: ISRG 看覆盖集合 → 静态; 此处看路径顺序 → 动态。
        两者取 max 作为综合多样性度量。
        """
        if self._path_cluster is None:
            return 0.5
        return self._path_cluster.path_diversity_score(seed_id)

    # //// MutationEnsemble (突变策略集成) 集成 ////
    def enable_mutation_ensemble(self, learning_rate: float = 0.1) -> None:
        """启用突变策略在线集成 — EG 自适应加权融合 8 种突变算子。"""
        if self._mutation_ensemble is None:
            from fuzzing.src.mutation_ensemble import MutationEnsemble
            self._mutation_ensemble = MutationEnsemble(learning_rate=learning_rate)

    def sample_mutation_strategy(self) -> str | None:
        """从集成中采样一个突变策略名称。未启用时返回 None (使用默认策略)。"""
        if self._mutation_ensemble is None:
            return None
        return self._mutation_ensemble.sample()

    def update_mutation_feedback(self, strategy_name: str, reward: float,
                                 precursor: str | None = None) -> None:
        """向突变集成反馈一次变异的结果奖励。奖励 ∈ [0, 2]。"""
        if self._mutation_ensemble is None:
            return
        self._mutation_ensemble.update(strategy_name, reward, precursor=precursor)

    # //// CoverageAwareSplicer (覆盖感知拼接) 集成 ////
    def enable_coverage_splicer(self) -> None:
        """启用覆盖感知拼接 — 在覆盖转移边界处执行 splice, 替代随机中点。"""
        if self._coverage_splicer is None:
            from fuzzing.src.coverage_splicer import CoverageAwareSplicer
            self._coverage_splicer = CoverageAwareSplicer()

    def register_splice_feedback(self, seed_id: str, offset: int,
                                 cov_before: set, cov_after: set) -> None:
        """向覆盖感知拼接器注册变异反馈, 用于学习覆盖转移边界。"""
        if self._coverage_splicer is None:
            return
        self._coverage_splicer.register_mutation(
            seed_id, offset, cov_before, cov_after
        )

    def splice_at_boundary(self, data_a: bytes, seed_a: str,
                           data_b: bytes, seed_b: str,
                           cov_a: set | None = None,
                           cov_b: set | None = None) -> tuple:
        """在覆盖转移边界处拼接两个种子。回退到中点随机拼接。"""
        if self._coverage_splicer is None:
            # 回退: 中点拼接
            mid = len(data_a) // 2 if data_a else 0
            return (data_a[:mid] + data_b[mid:], mid, 0.0)
        return self._coverage_splicer.splice(
            data_a, seed_a, data_b, seed_b, cov_a, cov_b
        )

    # //// ExecutionCostForecaster (执行开销预测) 集成 ////
    def enable_cost_forecaster(self) -> None:
        """启用执行开销预测 — 在线分位数回归预估 P50/P95 执行时间。"""
        if self._cost_forecaster is None:
            from fuzzing.src.exec_cost_forecaster import ExecutionCostForecaster
            self._cost_forecaster = ExecutionCostForecaster()

    def observe_execution_time(self, seed_id: str, actual_ms: float,
                               seed=None) -> object:
        """记录一次实际执行时间, 返回 CostEstimate。"""
        if self._cost_forecaster is None:
            return None
        return self._cost_forecaster.observe(seed_id, actual_ms, seed)

    def predict_execution_time(self, seed_id: str) -> tuple[float, float]:
        """查询种子的 P50 和 P95 执行时间预估 (ms)。未启用时返回默认值。"""
        if self._cost_forecaster is None:
            return (5.0, 50.0)
        return self._cost_forecaster.predict(seed_id)

    def throughput_aware_seed_score(self, seed: Seed) -> float:
        """融合执行开销的吞吐量感知种子评分。

        enhanced_score * throughput_score → 偏好快速+高潜力的种子。
        在探索阶段使用此评分可最大化 有效执行次数/秒。
        """
        quality = self.seed_score_enhanced(seed)
        if self._cost_forecaster is None:
            return quality
        tp = self._cost_forecaster.throughput_score(seed.id)
        return quality * (0.5 + 0.5 * tp)

    # //// 综合多样性评分: ISRG + PathCluster ////
    def comprehensive_diversity(self, seed_id: str) -> float:
        """融合 ISRG 覆盖多样性和 PathCluster 路径多样性的综合度量。

        max(isrg_div, path_div): 偏向乐观估计 — 只要在某一个维度上独特就保留。
        """
        cov_div = self.seed_diversity_bonus(seed_id)
        path_div = self.path_diversity_score(seed_id)
        return max(cov_div, path_div)

    def queue_size(self) -> int:
        return len(self._seed_queue)

    def is_empty(self) -> bool:
        return len(self._seed_queue) == 0


# ===== 语料库管理器 =====
class CorpusManager:
    """种子文件持久化 -- save/load/prune"""

    def __init__(self, corpus_dir: str):
        self.corpus_dir = Path(corpus_dir)
        self.corpus_dir.mkdir(parents=True, exist_ok=True)
        self._meta_path = self.corpus_dir / ".queue_meta.json"
        self._seed_dir = self.corpus_dir / "seeds"
        self._seed_dir.mkdir(parents=True, exist_ok=True)

    # ---- 文件路径生成 ----
    def _corpus_path(self, seed_id: str) -> str:
        """每个种子按id前两位分子目录，避免单目录文件过多"""
        _prefix = seed_id[:2]
        _subdir = self._seed_dir / _prefix
        _subdir.mkdir(parents=True, exist_ok=True)
        return str(_subdir / f"{seed_id}.bin")

    # ---- 保存单个种子 ----
    def save_seed(self, seed: Seed) -> str:
        _path = self._corpus_path(seed.id)
        _payload = self._serialize_seed(seed)
        with open(_path, "wb") as _f:
            _f.write(_payload)
        return _path

    # //// 序列化种子为二进制格式 ////
    def _serialize_seed(self, seed: Seed) -> bytes:
        """Format: [id_len:2B][id:UTF8][data_len:4B][data][metadata_json_len:4B][metadata_json]"""
        _id_bytes = seed.id.encode("utf-8")
        _parts: list[bytes] = []

        # ID长度 + ID
        _parts.append(len(_id_bytes).to_bytes(2, "little"))
        _parts.append(_id_bytes)

        # 数据长度 + 数据
        _parts.append(len(seed.data).to_bytes(4, "little"))
        _parts.append(seed.data)

        # 元信息
        _meta = {
            "fitness": seed.fitness,
            "energy": seed.energy,
            "coverage": sorted(seed.coverage),
            "created_at": seed.created_at,
            "parent_id": seed.parent_id,
            "generation": seed.generation,
            "mutation_count": seed.mutation_count,
            **seed.metadata,
        }
        _meta_json = json.dumps(_meta, ensure_ascii=False).encode("utf-8")
        _parts.append(len(_meta_json).to_bytes(4, "little"))
        _parts.append(_meta_json)

        return b"".join(_parts)

    # ---- 加载单个种子 ----
    def load_seed(self, seed_id: str) -> Seed | None:
        _path = self._corpus_path(seed_id)
        if not os.path.isfile(_path):
            return None
        try:
            with open(_path, "rb") as _f:
                _raw = _f.read()
            return self._deserialize_seed(seed_id, _raw)
        except (OSError, ValueError):
            return None

    # //// 反序列化 ////
    def _deserialize_seed(self, seed_id: str, raw: bytes) -> Seed:
        _off = 0

        # 读取ID（跳过，已从文件名知道）
        _id_len = int.from_bytes(raw[_off:_off + 2], "little")
        _off += 2 + _id_len

        # 读取数据
        _data_len = int.from_bytes(raw[_off:_off + 4], "little")
        _off += 4
        _data = raw[_off:_off + _data_len]
        _off += _data_len

        # 读取元信息JSON
        _meta_len = int.from_bytes(raw[_off:_off + 4], "little")
        _off += 4
        _meta_json = raw[_off:_off + _meta_len].decode("utf-8")
        _meta = json.loads(_meta_json)

        return Seed(
            id=seed_id,
            data=_data,
            fitness=_meta.get("fitness", 0.0),
            energy=_meta.get("energy", 1.0),
            coverage=set(_meta.get("coverage", [])),
            created_at=_meta.get("created_at", 0.0),
            parent_id=_meta.get("parent_id"),
            generation=_meta.get("generation", 0),
            metadata={_k: _v for _k, _v in _meta.items()
                      if _k not in {"fitness", "energy", "coverage",
                                     "created_at", "parent_id", "generation"}},
            mutation_count=_meta.get("mutation_count", 0),
        )

    # ---- 加载全部种子 ----
    def load_all(self) -> list[Seed]:
        _seeds: list[Seed] = []
        _idx = -1
        for _subdir in sorted(self._seed_dir.iterdir()):
            if not _subdir.is_dir():
                continue
            for _fpath in sorted(_subdir.glob("*.bin")):
                _seed_id = _fpath.stem
                try:
                    with open(_fpath, "rb") as _f:
                        _raw = _f.read()
                    _seeds.append(self._deserialize_seed(_seed_id, _raw))
                except (OSError, ValueError, json.JSONDecodeError):
                    continue  # 损坏的种子文件跳过
        return _seeds

    # ---- 保存/加载队列元数据 ----
    def save_queue(self, queue: list[Seed]) -> None:
        _ids = [_s.id for _s in queue]
        _payload = json.dumps({"seed_ids": _ids, "timestamp": time.time()}, indent=2)
        self._meta_path.write_text(_payload, encoding="utf-8")

    def load_queue(self) -> list[Seed]:
        if not self._meta_path.is_file():
            return []
        _meta = json.loads(self._meta_path.read_text(encoding="utf-8"))
        _ids = _meta.get("seed_ids", [])
        _seeds: list[Seed] = []
        for _sid in _ids:
            _s = self.load_seed(_sid)
            if _s is not None:
                _seeds.append(_s)
        return _seeds

    # ---- 修剪：保留分数最高的N个种子 ----
    def prune(self, max_seeds: int) -> int:
        """移除分数最低的种子，将队列大小控制在max_seeds以内"""
        if max_seeds <= 0:
            return 0

        _all = self.load_all()
        if len(_all) <= max_seeds:
            return 0

        # 按覆盖量+代数排序
        _all.sort(
            key=lambda s: (
                -len(s.coverage),   # 覆盖越多越好
                s.generation,       # 代数越低越基础
            )
        )

        _keep = _all[:max_seeds]
        _discard = len(_all) - max_seeds

        # 删除多余的种子文件
        _keep_ids = {_s.id for _s in _keep}
        for _s in _all[max_seeds:]:
            _path = self._corpus_path(_s.id)
            if os.path.isfile(_path):
                os.unlink(_path)

        return _discard

    def count_seeds_on_disk(self) -> int:
        """统计磁盘上实际存在的种子文件数量"""
        _cnt = 0
        for _subdir in self._seed_dir.iterdir():
            if _subdir.is_dir():
                _cnt += len(list(_subdir.glob("*.bin")))
        return _cnt


# ===== 独立的便捷函数 =====

def pick_seed(scheduler: Scheduler) -> Seed | None:
    """从调度器中选取下一个种子"""
    return scheduler.pick_seed()


def cull_queue(scheduler: Scheduler) -> int:
    """对调度器队列执行贪心裁剪，返回被移除的种子数"""
    return scheduler.cull_queue()
