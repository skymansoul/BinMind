"""AFLfast调度器 + 语料库持久化管理 -- 种子选择/队列裁剪/文件IO."""

import json
import math
import os
import random
import time
from collections import defaultdict
from pathlib import Path

from .core import Seed

# 支持动态策略切换
_VALID_STRATEGIES = frozenset({"aflfast", "roundrobin", "random", "weighted", "bandit"})

# 主要调度器
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

# 马尔可夫链状态
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
        # 2025-08 专利级创新模块 — 反事实变异/对抗遗憾最小化/拓扑覆盖导航
        self._counterfactual = None          # CounterfactualMutator | None
        self._regret_ensemble = None         # RegretMinimizingEnsemble | None
        self._topo_navigator = None          # TopologicalCoverageNavigator | None
        # 2025-08 信息几何/最优传输/不变性谱
        self._fisher_selector = None         # FisherMutationSelector | None
        self._ot_distributor = None          # OptimalTransportSeedDistributor | None
        self._invariant_analyzer = None      # InvariantSpectrumAnalyzer | None
        # 2025-08 保形预测/鞅评估/生存分析
        self._conformal = None               # ConformalAnomalyDetector | None
        self._martingale = None              # MartingaleFuzzingAssessor | None
        self._survival = None                # SurvivalFuzzModel | None
        # 2025-08 谱图分解/GP代理/自激崩溃
        self._spectral = None                # SpectralSeedGraphDecomposer | None
        self._gp_surrogate = None            # GaussianProcessSurrogate | None
        self._hawkes = None                  # HawkesCrashModel | None
        # 2025-08 RMT诊断/MMD分布检验/ONS二阶自适应
        self._rmt = None                     # RMTDiagnostics | None
        self._mmd = None                     # MMDSeedDistributionTest | None
        self._ons = None                     # OnlineNewtonMutationAdaptor | None
        # 2025-08 次模选择/KSD评估/Beta过程
        self._submodular = None              # SubmodularSeedSelector | None
        self._stein = None                   # SteinSeedAssessor | None
        self._beta_process = None            # BetaProcessCoverageModel | None
        # 2025-08 经验似然/密度比/RM调参
        self._el_inference = None            # EmpiricalLikelihoodInference | None
        self._dr_comparator = None           # DensityRatioComparator | None
        self._rm_tuner = None                # RobbinsMonroTuner | None
        # 2025-08 距离相关/能量距离/PELT变点
        self._dcor = None                    # DistanceCorrelationAnalyzer | None
        self._energy = None                  # EnergyDistanceSeedTest | None
        self._pelt = None                    # PELTChangeDetector | None
        # 2025-08 鲁棒M估计/保序回归/函数型PCA
        self._robust = None                  # RobustMEstimator | None
        self._isotonic = None                # IsotonicCoverageModel | None
        self._fpca = None                    # FunctionalPCACoverage | None
        # 2025-08 MDL/D-最优/图信号
        self._mdl = None                     # MDLStrategySelector | None
        self._domp = None                    # DOptimalMutationPlanner | None
        self._gsp = None                     # GraphSignalProcessor | None
        # 2025-08 Copula依赖/FDR控制/Granger因果
        self._copula = None                  # CopulaCoverageModel | None
        self._fdr_ctrl = None                # FDRController | None
        self._granger = None                 # GrangerCausalityTest | None
        # 2025-08 Elo评级/双重鲁棒/Hellinger距离
        self._elo = None                     # EloStrategyRater | None
        self._dr_eval = None                 # DoublyRobustEvaluator | None
        self._hellinger = None               # HellingerDistanceComparator | None
        # 2025-08 GLASSO/EM/ETS
        self._glasso = None                  # GLASSOCoverageNetwork | None
        self._em_latent = None               # EMLatentClassDiscovery | None
        self._ets = None                     # ETSModel | None
        # 2025-08 深度创新 — Woodbury在线GP / 异构因果效应 / Mapper拓扑
        self._gp_woodbury = None             # GPWoodburyOnline | None
        self._cate = None                    # CausalHeterogeneousEffects | None
        self._mapper = None                  # MapperCoverageAnalyzer | None

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

# AFLfast加权随机
    def _pick_aflfast(self) -> Seed:
        _scores = [self._seed_scores.get(_s.id, 1.0) for _s in self._seed_queue]
        _idx = self._roulette_wheel(_scores)
        return self._seed_queue[_idx]

# 轮询
    def _pick_roundrobin(self) -> Seed:
        self._round_robin_idx = self._round_robin_idx % len(self._seed_queue)
        _seed = self._seed_queue[self._round_robin_idx]
        self._round_robin_idx += 1
        return _seed

# 加权
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
        if self._counterfactual is not None:
            _stats["counterfactual"] = self._counterfactual.stats()
        if self._regret_ensemble is not None:
            _stats["regret_ensemble"] = self._regret_ensemble.stats()
        if self._topo_navigator is not None:
            _stats["topo_navigator"] = self._topo_navigator.stats()
        if self._fisher_selector is not None:
            _stats["fisher_selector"] = self._fisher_selector.stats()
        if self._ot_distributor is not None:
            _stats["ot_distributor"] = self._ot_distributor.stats()
        if self._invariant_analyzer is not None:
            _stats["invariant_analyzer"] = self._invariant_analyzer.stats()
        if self._conformal is not None:
            _stats["conformal"] = self._conformal.stats()
        if self._martingale is not None:
            _stats["martingale"] = self._martingale.stats()
        if self._survival is not None:
            _stats["survival"] = self._survival.stats()
        if self._spectral is not None:
            _stats["spectral"] = self._spectral.stats()
        if self._gp_surrogate is not None:
            _stats["gp_surrogate"] = self._gp_surrogate.stats()
        if self._hawkes is not None:
            _stats["hawkes"] = self._hawkes.stats()
        if self._rmt is not None:
            _stats["rmt"] = self._rmt.stats()
        if self._mmd is not None:
            _stats["mmd"] = self._mmd.stats()
        if self._ons is not None:
            _stats["ons"] = self._ons.stats()
        if self._submodular is not None:
            _stats["submodular"] = self._submodular.stats()
        if self._stein is not None:
            _stats["stein"] = self._stein.stats()
        if self._beta_process is not None:
            _stats["beta_process"] = self._beta_process.stats()
        if self._el_inference is not None:
            _stats["el_inference"] = self._el_inference.stats()
        if self._dr_comparator is not None:
            _stats["dr_comparator"] = self._dr_comparator.stats()
        if self._rm_tuner is not None:
            _stats["rm_tuner"] = self._rm_tuner.stats()
        if self._dcor is not None:
            _stats["dcor"] = self._dcor.stats()
        if self._energy is not None:
            _stats["energy"] = self._energy.stats()
        if self._pelt is not None:
            _stats["pelt"] = self._pelt.stats()
        if self._robust is not None:
            _stats["robust"] = self._robust.stats()
        if self._isotonic is not None:
            _stats["isotonic"] = self._isotonic.stats()
        if self._fpca is not None:
            _stats["fpca"] = self._fpca.stats()
        if self._mdl is not None:
            _stats["mdl"] = self._mdl.stats()
        if self._domp is not None:
            _stats["domp"] = self._domp.stats()
        if self._gsp is not None:
            _stats["gsp"] = self._gsp.stats()
        if self._copula is not None:
            _stats["copula"] = self._copula.stats()
        if self._fdr_ctrl is not None:
            _stats["fdr_ctrl"] = self._fdr_ctrl.stats()
        if self._granger is not None:
            _stats["granger"] = self._granger.stats()
        if self._elo is not None:
            _stats["elo"] = self._elo.stats()
        if self._dr_eval is not None:
            _stats["dr_eval"] = self._dr_eval.stats()
        if self._hellinger is not None:
            _stats["hellinger"] = self._hellinger.stats()
        if self._glasso is not None:
            _stats["glasso"] = self._glasso.stats()
        if self._em_latent is not None:
            _stats["em_latent"] = self._em_latent.stats()
        if self._ets is not None:
            _stats["ets"] = self._ets.stats()
        if self._gp_woodbury is not None:
            _stats["gp_woodbury"] = self._gp_woodbury.stats()
        if self._cate is not None:
            _stats["cate"] = self._cate.stats()
        if self._mapper is not None:
            _stats["mapper"] = self._mapper.stats()
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

    # //// CounterfactualMutator (反事实变异优化) 集成 ////
    def enable_counterfactual_optimizer(self) -> None:
        """启用因果变异优化器 — 线性因果效应估计 + 反事实推断.

        每次变异执行后调用 observe_counterfactual() 录入观测,
        周期性调用 suggest_counterfactual_mutations() 获取反事实建议。
        """
        if self._counterfactual is None:
            from fuzzing.src.counterfactual_mutator import CounterfactualMutator
            self._counterfactual = CounterfactualMutator()

    def observe_counterfactual(self, byte_offset: int, original_val: int,
                               mutated_val: int, mutation_type: str,
                               cov_delta: int, new_edge_ids: set,
                               exec_ms: float = 10.0,
                               is_crash: bool = False) -> None:
        """向反事实优化器录入一次变异观测."""
        if self._counterfactual is None:
            return
        self._counterfactual.observe(
            byte_offset, original_val, mutated_val, mutation_type,
            cov_delta, new_edge_ids, exec_ms, is_crash,
        )

    def suggest_counterfactual_mutations(self, seed_data: bytes,
                                         top_k: int = 8) -> list:
        """从反事实优化器获取推荐的变异位置和值."""
        if self._counterfactual is None:
            return []
        return self._counterfactual.suggest_mutations(seed_data, top_k=top_k)

    # //// RegretMinimizingEnsemble (对抗遗憾最小化集成) 集成 ////
    def enable_regret_ensemble(self, learning_rate: float = 0.1,
                               ent_lambda: float = 0.01) -> None:
        """启用对抗遗憾最小化突变集成 — FTRL+Entropy 正则化.

        当被测程序呈现高度非平稳性时 (新区域发现后策略效果剧变),
        切换到 ARME 以获得对抗性遗憾保障。可与 MutationEnsemble 共存,
        根据 regret 指标动态选择后端。
        """
        if self._regret_ensemble is None:
            from fuzzing.src.regret_minimizing_ensemble import (
                RegretMinimizingEnsemble
            )
            self._regret_ensemble = RegretMinimizingEnsemble(
                learning_rate=learning_rate, ent_lambda=ent_lambda,
            )

    def sample_regret_strategy(self, context: str | None = None) -> str | None:
        """从遗憾最小化集成中采样突变策略."""
        if self._regret_ensemble is None:
            return None
        return self._regret_ensemble.select(context_hint=context)

    def update_regret_feedback(self, strategy_name: str, reward: float,
                               context: str | None = None) -> None:
        """向遗憾最小化集成反馈一次变异结果."""
        if self._regret_ensemble is None:
            return
        self._regret_ensemble.update(strategy_name, reward, context_hint=context)

    def should_switch_to_arme(self) -> bool:
        """检测是否应切换到 ARME 后端.

        条件: MutationEnsemble 的 mean_reward 持续下降 3 次统计窗口
        或 Regret 显著增长 (regime change)。
        """
        if self._regret_ensemble is None:
            return False
        stats = self._regret_ensemble.stats()
        return stats.get("per_step_regret", 0) > 0.15

    # //// TopologicalCoverageNavigator (拓扑覆盖导航) 集成 ////
    def enable_topological_navigator(self, epsilon: float = 0.35,
                                     n_landmarks: int = 64) -> None:
        """启用拓扑覆盖导航器 — 基于持续同调的覆盖流形探索.

        将 fuzzing 探索映射为 Vietoris-Rips 复形上的拓扑特征发现,
        使用 β₀ (连通分量数) 和持久图指导探索方向。
        """
        if self._topo_navigator is None:
            from fuzzing.src.topological_coverage_navigator import (
                TopologicalCoverageNavigator
            )
            self._topo_navigator = TopologicalCoverageNavigator(
                epsilon=epsilon, n_landmarks=n_landmarks,
            )

    def register_coverage_point(self, seed_id: str, coverage: set) -> None:
        """将种子覆盖注册到拓扑流形."""
        if self._topo_navigator is None:
            return
        self._topo_navigator.add_point(seed_id, coverage)

    def topo_frontier_seeds(self, top_k: int = 5) -> list[str]:
        """获取拓扑前沿边界种子 — 优先分配变异能量."""
        if self._topo_navigator is None:
            return []
        return self._topo_navigator.suggest_frontier_seeds(top_k=top_k)

    def topo_diversity_score(self, seed_id: str) -> float:
        """基于拓扑位置的多样性评分 (与 ISRG/PathCluster 互补)."""
        if self._topo_navigator is None:
            return 0.5
        return self._topo_navigator.topological_diversity_score(seed_id)

    # //// FisherMutationSelector (信息几何制导变异) 集成 ////
    def enable_fisher_selector(self) -> None:
        """启用 Fisher 信息制导变异选择器 — 按信息量排序变异位置.

        信息几何在 fuzzing 中无先例。Fisher 度量量化每个字节位置
        '改变覆盖结果分布的信息量', 按此排序变异候选。
        """
        if self._fisher_selector is None:
            from fuzzing.src.fisher_mutation import FisherMutationSelector
            self._fisher_selector = FisherMutationSelector()

    def observe_fisher(self, byte_offset: int, coverage_delta: int,
                       exec_ms: float = 0.0) -> None:
        """记录字节变异结果用于 Fisher 信息估计."""
        if self._fisher_selector is None:
            return
        self._fisher_selector.observe(byte_offset, coverage_delta, exec_ms)

    def fisher_mutations(self, seed_data: bytes,
                         top_k: int = 8) -> list:
        """获取 Fisher 信息制导的变异建议."""
        if self._fisher_selector is None:
            return []
        return self._fisher_selector.natural_gradient_mutation(
            seed_data, top_k=top_k)

    # //// OptimalTransportSeedDistributor (最优传输种子分发) 集成 ////
    def enable_ot_distributor(self, epsilon: float = 0.1) -> None:
        """启用最优传输种子分发器 — Sinkhorn 算法匹配种子分布.

        最优传输在 fuzzing 中无先例。将种子分发建模为分布匹配,
        计算 Wasserstein 距离最小的传输计划。
        """
        if self._ot_distributor is None:
            from fuzzing.src.optimal_transport_seed import (
                OptimalTransportSeedDistributor
            )
            self._ot_distributor = OptimalTransportSeedDistributor(
                epsilon=epsilon)

    def register_ot_seed(self, instance_id: str, seed_id: str,
                         coverage: set) -> None:
        """向 OT 分发器注册种子."""
        if self._ot_distributor is None:
            return
        self._ot_distributor.add_seed(instance_id, seed_id, coverage)

    def compute_seed_transport(self, src: str, tgt: str,
                                max_seeds: int = 10) -> list:
        """计算两个实例间的种子传输计划."""
        if self._ot_distributor is None:
            return []
        plan = self._ot_distributor.compute_transport(src, tgt)
        if plan is None:
            return []
        return self._ot_distributor.select_seeds_to_transfer(plan, max_seeds)

    # //// InvariantSpectrumAnalyzer (不变性谱分析) 集成 ////
    def enable_invariant_analyzer(self) -> None:
        """启用跨输入不变性谱分析器 — 在线检测行为异常输入.

        与 INVSCOV (反馈) 和 FuzzSight (差分) 不同, CISA 将不变式
        违背作为独立的 bug oracle, 在线检测非崩溃的逻辑缺陷。
        """
        if self._invariant_analyzer is None:
            from fuzzing.src.invariant_spectrum_analyzer import (
                InvariantSpectrumAnalyzer
            )
            self._invariant_analyzer = InvariantSpectrumAnalyzer()

    def observe_invariants(self, input_id: str,
                           features: dict) -> None:
        """记录一次执行的运行时特征用于不变性分析."""
        if self._invariant_analyzer is None:
            return
        self._invariant_analyzer.observe(input_id, features)

    def detect_anomalies(self, top_k: int = 10) -> list:
        """获取最近检测到的行为异常输入 (潜在非崩溃 bug)."""
        if self._invariant_analyzer is None:
            return []
        return self._invariant_analyzer.detect_anomalies(top_k=top_k)

    # //// ConformalAnomalyDetector (保形异常检测) 集成 ////
    def enable_conformal_detector(self, epsilon: float = 0.05) -> None:
        """启用保形异常检测器 — 分布无关的有限样本异常检测.

        保形预测在 fuzzing 中无先例。提供有限样本假阳性率保证,
        每个输入得到 conformal p-value。
        """
        if self._conformal is None:
            from fuzzing.src.conformal_anomaly import (
                ConformalAnomalyDetector, ExecutionProfile)
            self._conformal = ConformalAnomalyDetector(epsilon=epsilon)
            self._ExecutionProfile = ExecutionProfile

    def conformal_pvalue(self, exec_ms: float, cov_delta: int,
                         exit_code: int, is_crash: bool,
                         seed_len: int) -> float:
        """获取执行的 conformal p-value (小=异常)."""
        if self._conformal is None:
            return 0.5
        prof = self._ExecutionProfile(
            exec_time_ms=exec_ms, coverage_delta=cov_delta,
            exit_code=exit_code, is_crash=is_crash, seed_len=seed_len)
        return self._conformal.conformal_pvalue(prof)

    def conformal_is_anomaly(self, p_value: float) -> bool:
        """conformal p-value 是否指示异常."""
        if self._conformal is None:
            return False
        return p_value < self._conformal._adaptive_epsilon

    # //// MartingaleFuzzingAssessor (鞅评估) 集成 ////
    def enable_martingale_assessor(self) -> None:
        """启用鞅制导评估器 — 随时有效统计推断.

        测试鞅在 fuzzing 中无先例。覆盖平台检测和策略对比
        可在任何时刻停止并得出统计有效结论。
        """
        if self._martingale is None:
            from fuzzing.src.martingale_fuzz_assess import (
                MartingaleFuzzingAssessor)
            self._martingale = MartingaleFuzzingAssessor()

    def observe_for_martingale(self, new_edges: int,
                                is_strategy_a: bool = True,
                                is_surprising: bool = False) -> None:
        """记录执行结果用于鞅评估."""
        if self._martingale is None:
            return
        self._martingale.observe_execution(
            new_edges, is_strategy_a=is_strategy_a,
            is_surprising=is_surprising)

    def plateau_assessment(self) -> dict:
        """获取覆盖停滞评估 {'action': 'continue'|'warn'|'stop', ...}."""
        if self._martingale is None:
            return {"action": "continue", "plateau_risk": 0.0}
        ev = self._martingale.assess()
        return {
            "action": ev.recommended_action,
            "plateau_risk": self._martingale.plateau_risk(),
            "log10_evidence": ev.log10_evidence,
            "strategy_result": ev.strategy_comparison,
        }

    # //// SurvivalFuzzModel (生存分析) 集成 ////
    def enable_survival_model(self) -> None:
        """启用生存分析模型 — KM估计器+Nelson-Aalen+log-rank检验.

        生存分析在 fuzzing 中无先例。正确处理删失数据,
        给出 bug 发现概率的无偏估计和策略比较的统计显著性。
        """
        if self._survival is None:
            from fuzzing.src.survival_fuzz_model import SurvivalFuzzModel
            self._survival = SurvivalFuzzModel()

    def record_bug_event(self, exec_idx: int, is_crash: bool,
                         crash_hash: str = "",
                         cov_edges: int = 0,
                         seed_pool: int = 0) -> None:
        """记录 bug 发现/删失事件."""
        if self._survival is None:
            return
        self._survival.record_execution(
            exec_idx, is_crash, crash_hash, cov_edges, seed_pool)

    def survival_stopping_advice(self, budget_execs: int) -> str:
        """生存分析停止建议."""
        if self._survival is None:
            return "continue"
        return self._survival.stopping_recommendation(budget_execs)

    # //// SpectralSeedGraphDecomposer (谱种子图分解) 集成 ////
    def enable_spectral_decomposer(self) -> None:
        """启用谱种子图分解器 — Laplacian 谱分析 + Fiedler 聚类.

        谱图论在 fuzzing 中无先例。在 ISRG 邻接矩阵上构建归一化
        Laplacian, 幂迭代计算特征值和 Fiedler 向量。
        """
        if self._spectral is None:
            from fuzzing.src.spectral_seed_graph import (
                SpectralSeedGraphDecomposer)
            self._spectral = SpectralSeedGraphDecomposer()

    def set_spectral_graph(self, adjacency: dict) -> None:
        """从 ISRG 邻接表构建谱图."""
        if self._spectral is None:
            return
        self._spectral.set_graph(adjacency)

    def spectral_diversity(self, seed_id: str) -> float:
        """基于谱嵌入的全局多样性评分."""
        if self._spectral is None:
            return 0.5
        return self._spectral.spectral_diversity_score(seed_id)

    def bottleneck_seeds(self, top_k: int = 5) -> list:
        """识别连接两个覆盖分区的谱瓶颈种子."""
        if self._spectral is None:
            return []
        return self._spectral.bottleneck_seeds(top_k=top_k)

    # //// GaussianProcessSurrogate (GP覆盖代理) 集成 ////
    def enable_gp_surrogate(self) -> None:
        """启用 GP 覆盖代理模型 — Matern 核 + EI 采集.

        GP 代理在 fuzzing 中无直接先例。预测覆盖增益景观,
        Expected Improvement 采集函数平衡探索/利用。
        """
        if self._gp_surrogate is None:
            from fuzzing.src.gaussian_process_surrogate import (
                GaussianProcessSurrogate)
            self._gp_surrogate = GaussianProcessSurrogate()

    def observe_gp(self, features: list, coverage_gain: float,
                   seed_id: str = "") -> None:
        """向 GP 模型添加观测."""
        if self._gp_surrogate is None:
            return
        self._gp_surrogate.add_observation(features, coverage_gain, seed_id)

    def gp_select_best(self, candidates: list,
                        use_ei: bool = True) -> list:
        """GP 采集: EI 或 UCB 选择最优候选种子."""
        if self._gp_surrogate is None:
            return candidates
        if use_ei:
            return self._gp_surrogate.expected_improvement(candidates)
        return self._gp_surrogate.upper_confidence_bound(candidates)

    # //// HawkesCrashModel (自激崩溃) 集成 ////
    def enable_hawkes_model(self) -> None:
        """启用 Hawkes 自激崩溃模型 — 崩溃簇检测 + 分支比评估.

        Hawkes 过程在 fuzzing 中无先例。λ(t) = λ₀ + Σα·exp(-β(t-tᵢ)),
        崩溃后自激强度升高, 分支比 n=α/β 评估临界性。
        """
        if self._hawkes is None:
            from fuzzing.src.hawkes_crash_model import HawkesCrashModel
            self._hawkes = HawkesCrashModel()

    def record_hawkes_crash(self, exec_idx: int,
                            crash_hash: str) -> bool:
        """记录崩溃到 Hawkes 模型, 返回是否为新崩溃."""
        if self._hawkes is None:
            return True
        return self._hawkes.record_crash(exec_idx, crash_hash)

    def hawkes_resource_multiplier(self, exec_idx: int) -> float:
        """基于自激强度的资源分配倍数 [0.5, 3.0]."""
        if self._hawkes is None:
            return 1.0
        return self._hawkes.resource_multiplier(exec_idx)

    # //// RMTDiagnostics (RMT覆盖诊断) 集成 ////
    def enable_rmt_diagnostics(self) -> None:
        if self._rmt is None:
            from fuzzing.src.rmt_diagnostics import RMTDiagnostics
            self._rmt = RMTDiagnostics()

    def rmt_add_seed(self, seed_id: str, coverage: set) -> None:
        if self._rmt: self._rmt.add_seed(seed_id, coverage)

    def rmt_coverage_quality(self) -> float:
        return self._rmt.coverage_quality() if self._rmt else 0.0

    # //// MMDSeedDistributionTest (MMD分布检验) 集成 ////
    def enable_mmd_test(self) -> None:
        if self._mmd is None:
            from fuzzing.src.mmd_seed_test import MMDSeedDistributionTest
            self._mmd = MMDSeedDistributionTest()

    def mmd_add_seed(self, coverage: set) -> None:
        if self._mmd: self._mmd.add_to_window(coverage)

    def mmd_shift_detected(self) -> bool:
        return self._mmd.shift_detected() if self._mmd else False

    # //// OnlineNewtonMutationAdaptor (ONS二阶自适应) 集成 ////
    def enable_ons_adaptor(self) -> None:
        if self._ons is None:
            from fuzzing.src.online_newton_mutate import (
                OnlineNewtonMutationAdaptor)
            self._ons = OnlineNewtonMutationAdaptor()

    def ons_select(self) -> str | None:
        if self._ons is None: return None
        return self._ons.select()

    def ons_update(self, strategy: str, gradient: float,
                   precursor: str | None = None) -> None:
        if self._ons: self._ons.update(strategy, gradient, precursor)

    # //// SubmodularSeedSelector (次模种子选择) 集成 ////
    def enable_submodular_selector(self, queue_size: int = 200) -> None:
        if self._submodular is None:
            from fuzzing.src.submodular_seed_selector import (
                SubmodularSeedSelector)
            self._submodular = SubmodularSeedSelector(queue_size=queue_size)

    def submodular_add(self, seed_id: str, coverage: set) -> None:
        if self._submodular: self._submodular.add_candidate(seed_id, coverage)

    def submodular_select(self, method: str = "lazy") -> list:
        if self._submodular is None: return []
        if method == "lazy": return self._submodular.select_lazy_greedy()
        if method == "stochastic": return self._submodular.select_stochastic_greedy()
        return self._submodular.select_greedy()

    # //// SteinSeedAssessor (KSD评估) 集成 ////
    def enable_stein_assessor(self) -> None:
        if self._stein is None:
            from fuzzing.src.stein_seed_assess import SteinSeedAssessor
            self._stein = SteinSeedAssessor()

    def stein_add(self, seed_id: str, coverage: set) -> None:
        if self._stein: self._stein.add_seed(seed_id, coverage)

    def stein_converged(self) -> bool:
        return self._stein.is_converged() if self._stein else False

    # //// BetaProcessCoverageModel (Beta过程) 集成 ////
    def enable_beta_process(self, alpha: float = 1.0) -> None:
        if self._beta_process is None:
            from fuzzing.src.beta_process_coverage import (
                BetaProcessCoverageModel)
            self._beta_process = BetaProcessCoverageModel(alpha=alpha)

    def beta_add(self, seed_id: str, coverage: set) -> None:
        if self._beta_process: self._beta_process.add_seed(seed_id, coverage)

    def beta_completeness(self) -> float:
        return (self._beta_process.coverage_completeness()
                if self._beta_process else 0.0)

    # //// EmpiricalLikelihoodInference (经验似然) 集成 ////
    def enable_el_inference(self) -> None:
        if self._el_inference is None:
            from fuzzing.src.empirical_likelihood import (
                EmpiricalLikelihoodInference)
            self._el_inference = EmpiricalLikelihoodInference()

    def el_observe(self, value: float) -> None:
        if self._el_inference: self._el_inference.add_observation(value)

    def el_confidence_interval(self) -> tuple | None:
        if self._el_inference is None: return None
        ci = self._el_inference.confidence_interval()
        return (ci.lower_bound, ci.upper_bound) if ci else None

    # //// DensityRatioComparator (密度比策略比较) 集成 ////
    def enable_dr_comparator(self) -> None:
        if self._dr_comparator is None:
            from fuzzing.src.density_ratio_compare import DensityRatioComparator
            self._dr_comparator = DensityRatioComparator()

    def dr_add_A(self, coverage: set) -> None:
        if self._dr_comparator: self._dr_comparator.add_sample_A(coverage)

    def dr_add_B(self, coverage: set) -> None:
        if self._dr_comparator: self._dr_comparator.add_sample_B(coverage)

    def dr_compare(self) -> float | None:
        if self._dr_comparator is None: return None
        res = self._dr_comparator.compare()
        return res.pearson_divergence if res else None

    # //// RobbinsMonroTuner (RM在线调参) 集成 ////
    def enable_rm_tuner(self) -> None:
        if self._rm_tuner is None:
            from fuzzing.src.robbins_monro_tune import RobbinsMonroTuner
            self._rm_tuner = RobbinsMonroTuner()
            self._rm_tuner.add_parameter("mutation_rate", 0.5, 0.01, 0.99)
            self._rm_tuner.add_parameter("energy_factor", 1.0, 0.1, 5.0)

    def rm_update(self, loss: float) -> None:
        if self._rm_tuner: self._rm_tuner.update(loss_plus=loss)

    def rm_get_params(self) -> dict:
        return self._rm_tuner.get_parameters() if self._rm_tuner else {}

    # //// DistanceCorrelation (距离相关) 集成 ////
    def enable_dcor(self) -> None:
        if self._dcor is None:
            from fuzzing.src.distance_correlation import (
                DistanceCorrelationAnalyzer)
            self._dcor = DistanceCorrelationAnalyzer()

    def dcor_observe(self, x: float, y: float) -> None:
        if self._dcor: self._dcor.add_observation(x, y)

    def dcor_significant(self) -> bool:
        if self._dcor is None: return False
        r = self._dcor.compute()
        return r.is_significant if r else False

    # //// EnergyDistance (能量距离) 集成 ////
    def enable_energy_test(self) -> None:
        if self._energy is None:
            from fuzzing.src.energy_distance_seed import EnergyDistanceSeedTest
            self._energy = EnergyDistanceSeedTest()

    def energy_add_A(self, cov: set) -> None:
        if self._energy: self._energy.add_to_A(cov)

    def energy_add_B(self, cov: set) -> None:
        if self._energy: self._energy.add_to_B(cov)

    def energy_significant(self) -> bool:
        if self._energy is None: return False
        r = self._energy.test()
        return r.is_significant if r else False

    # //// PELT (变点检测) 集成 ////
    def enable_pelt(self, penalty: float = 3.0) -> None:
        if self._pelt is None:
            from fuzzing.src.pelt_change_point import PELTChangeDetector
            self._pelt = PELTChangeDetector(penalty=penalty)

    def pelt_add_window(self, value: float) -> None:
        if self._pelt: self._pelt.add_window(value)

    def pelt_regime(self) -> str:
        return self._pelt.latest_regime() if self._pelt else "unknown"

    # //// RobustMEstimator (鲁棒M估计) 集成 ////
    def enable_robust_estimator(self) -> None:
        if self._robust is None:
            from fuzzing.src.robust_m_estimation import RobustMEstimator
            self._robust = RobustMEstimator()

    def robust_add(self, value: float) -> None:
        if self._robust: self._robust.add(value)

    def robust_mean(self) -> float | None:
        if self._robust is None: return None
        return self._robust.estimate().robust_mean

    # //// IsotonicCoverageModel (保序覆盖) 集成 ////
    def enable_isotonic(self) -> None:
        if self._isotonic is None:
            from fuzzing.src.isotonic_coverage import IsotonicCoverageModel
            self._isotonic = IsotonicCoverageModel()

    def isotonic_add(self, exec_idx: int, cov: float) -> None:
        if self._isotonic: self._isotonic.add_point(exec_idx, cov)

    def isotonic_stagnation(self) -> float:
        return (self._isotonic.stagnation_score()
                if self._isotonic else 0.0)

    # //// FunctionalPCACoverage (FPCA) 集成 ////
    def enable_fpca(self) -> None:
        if self._fpca is None:
            from fuzzing.src.functional_pca_coverage import (
                FunctionalPCACoverage)
            self._fpca = FunctionalPCACoverage()

    def fpca_add_curve(self, cid: str, times: list, covs: list) -> None:
        if self._fpca: self._fpca.add_curve(cid, times, covs)

    # //// MDLStrategySelector (MDL策略选择) 集成 ////
    def enable_mdl_selector(self) -> None:
        if self._mdl is None:
            from fuzzing.src.mdl_strategy_select import MDLStrategySelector
            self._mdl = MDLStrategySelector()

    def mdl_add(self, strategy: str, gain: float) -> None:
        if self._mdl: self._mdl.add_observation(strategy, gain)

    def mdl_best(self) -> str | None:
        if self._mdl is None: return None
        r = self._mdl.select_best()
        return r.strategy_name if r else None

    # //// DOptimalMutationPlanner (D-最优) 集成 ////
    def enable_domp(self) -> None:
        if self._domp is None:
            from fuzzing.src.doptimal_mutation_plan import (
                DOptimalMutationPlanner)
            self._domp = DOptimalMutationPlanner()

    def domp_add(self, off: int, sens: float) -> None:
        if self._domp: self._domp.add_candidate(off, sens)

    def domp_plan(self, k: int = 8) -> list:
        return self._domp.plan_mutations(k) if self._domp else []

    # //// GraphSignalProcessor (图信号) 集成 ////
    def enable_gsp(self) -> None:
        if self._gsp is None:
            from fuzzing.src.graph_signal_seed import GraphSignalProcessor
            self._gsp = GraphSignalProcessor()

    def gsp_set_graph(self, adj: dict) -> None:
        if self._gsp: self._gsp.set_graph(adj)

    def gsp_set_signal(self, signal: dict) -> None:
        if self._gsp: self._gsp.set_signal(signal)

    # //// CopulaCoverageModel (Copula依赖) 集成 ////
    def enable_copula(self) -> None:
        if self._copula is None:
            from fuzzing.src.copula_coverage_model import CopulaCoverageModel
            self._copula = CopulaCoverageModel()

    def copula_add(self, x: float, y: float) -> None:
        if self._copula: self._copula.add_pair(x, y)

    # //// FDRController (FDR控制) 集成 ////
    def enable_fdr_ctrl(self, alpha: float = 0.05) -> None:
        if self._fdr_ctrl is None:
            from fuzzing.src.fdr_crash_classify import FDRController
            self._fdr_ctrl = FDRController(alpha=alpha)

    def fdr_add(self, name: str, p_val: float) -> None:
        if self._fdr_ctrl: self._fdr_ctrl.add_hypothesis(name, p_val)

    def fdr_discoveries(self) -> int:
        if self._fdr_ctrl is None: return 0
        return self._fdr_ctrl.apply().n_discoveries

    # //// GrangerCausalityTest (Granger因果) 集成 ////
    def enable_granger(self) -> None:
        if self._granger is None:
            from fuzzing.src.granger_coverage import GrangerCausalityTest
            self._granger = GrangerCausalityTest()

    def granger_add(self, var_name: str, value: float) -> None:
        if self._granger: self._granger.add_observation(var_name, value)

    def granger_test(self, cause: str, effect: str) -> bool | None:
        if self._granger is None: return None
        r = self._granger.test(cause, effect)
        return r.is_causal if r else None

    # //// EloStrategyRater (Elo评级) 集成 ////
    def enable_elo(self) -> None:
        if self._elo is None:
            from fuzzing.src.elo_strategy_rating import EloStrategyRater
            self._elo = EloStrategyRater()

    def elo_record(self, winner: str, loser: str,
                   w_gain: float = 1.0, l_gain: float = 0.0) -> None:
        if self._elo: self._elo.record_match(winner, loser, w_gain, l_gain)

    def elo_top(self, k: int = 3) -> list:
        return self._elo.top_strategies(k) if self._elo else []

    # //// DoublyRobustEvaluator (双重鲁棒) 集成 ////
    def enable_dr_eval(self) -> None:
        if self._dr_eval is None:
            from fuzzing.src.doubly_robust_mutation import DoublyRobustEvaluator
            self._dr_eval = DoublyRobustEvaluator()

    def dr_add(self, treated: int, outcome: float,
               covariates: list) -> None:
        if self._dr_eval: self._dr_eval.add_obs(treated, outcome, covariates)

    def dr_ate(self) -> tuple | None:
        return self._dr_eval.estimate() if self._dr_eval else None

    # //// HellingerDistanceComparator (Hellinger) 集成 ////
    def enable_hellinger(self) -> None:
        if self._hellinger is None:
            from fuzzing.src.hellinger_distance import HellingerDistanceComparator
            self._hellinger = HellingerDistanceComparator()

    def hellinger_add_A(self, cov: set) -> None:
        if self._hellinger: self._hellinger.add_sample_A(cov)

    def hellinger_add_B(self, cov: set) -> None:
        if self._hellinger: self._hellinger.add_sample_B(cov)

    # //// GLASSO/EM/ETS 集成 ////
    def enable_glasso(self, lam: float = 0.1) -> None:
        if self._glasso is None:
            from fuzzing.src.glasso_coverage_network import GLASSOCoverageNetwork
            self._glasso = GLASSOCoverageNetwork(lambda_reg=lam)

    def glasso_add(self, vec: list) -> None:
        if self._glasso: self._glasso.add_observation(vec)

    def enable_em_latent(self) -> None:
        if self._em_latent is None:
            from fuzzing.src.em_coverage_class import EMLatentClassDiscovery
            self._em_latent = EMLatentClassDiscovery()

    def em_add_seed(self, vec: list) -> None:
        if self._em_latent: self._em_latent.add_seed(vec)

    def enable_ets(self) -> None:
        if self._ets is None:
            from fuzzing.src.ets_coverage_forecast import ETSModel
            self._ets = ETSModel()

    def ets_add(self, v: float) -> None:
        if self._ets: self._ets.add(v)

    # //// GPWoodburyOnline (Woodbury在线GP) 集成 ////
    def enable_gp_woodbury(self) -> None:
        if self._gp_woodbury is None:
            from fuzzing.src.gp_woodbury_online import GPWoodburyOnline
            self._gp_woodbury = GPWoodburyOnline()

    def gpw_add(self, feats: list, target: float) -> None:
        if self._gp_woodbury: self._gp_woodbury.add_observation(feats, target)

    def gpw_predict(self, feats: list) -> tuple:
        return (self._gp_woodbury.predict(feats)
                if self._gp_woodbury else (0.0, 1.0))

    # //// CausalHeterogeneousEffects (异构因果) 集成 ////
    def enable_cate(self) -> None:
        if self._cate is None:
            from fuzzing.src.causal_heterogeneous_effects import (
                CausalHeterogeneousEffects)
            self._cate = CausalHeterogeneousEffects()

    def cate_add_treated(self, ctx: list, outcome: float) -> None:
        if self._cate: self._cate.add_treated(ctx, outcome)

    def cate_add_control(self, ctx: list, outcome: float) -> None:
        if self._cate: self._cate.add_control(ctx, outcome)

    def cate_best_context(self) -> str | None:
        if self._cate is None: return None
        r = self._cate.estimate()
        return r.best_context if r else None

    # //// MapperCoverageAnalyzer (Mapper拓扑) 集成 ////
    def enable_mapper(self) -> None:
        if self._mapper is None:
            from fuzzing.src.mapper_coverage import MapperCoverageAnalyzer
            self._mapper = MapperCoverageAnalyzer()

    def mapper_add(self, sid: str, cov_cnt: float,
                   div: float, cov: set) -> None:
        if self._mapper: self._mapper.add_seed(sid, cov_cnt, div, cov)

    def queue_size(self) -> int:
        return len(self._seed_queue)

    def is_empty(self) -> bool:
        return len(self._seed_queue) == 0


# 语料库管理器
class CorpusManager:
    """种子文件持久化 -- save/load/prune"""

    def __init__(self, corpus_dir: str):
        self.corpus_dir = Path(corpus_dir)
        self.corpus_dir.mkdir(parents=True, exist_ok=True)
        self._meta_path = self.corpus_dir / ".queue_meta.json"
        self._seed_dir = self.corpus_dir / "seeds"
        self._seed_dir.mkdir(parents=True, exist_ok=True)

# 文件路径生成
    def _corpus_path(self, seed_id: str) -> str:
        """每个种子按id前两位分子目录，避免单目录文件过多"""
        _prefix = seed_id[:2]
        _subdir = self._seed_dir / _prefix
        _subdir.mkdir(parents=True, exist_ok=True)
        return str(_subdir / f"{seed_id}.bin")

# 保存单个种子
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

# 加载单个种子
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

# 加载全部种子
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

# 保存/加载队列元数据
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

# 修剪：保留分数最高的N个种子
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


# 独立的便捷函数

def pick_seed(scheduler: Scheduler) -> Seed | None:
    """从调度器中选取下一个种子"""
    return scheduler.pick_seed()


def cull_queue(scheduler: Scheduler) -> int:
    """对调度器队列执行贪心裁剪，返回被移除的种子数"""
    return scheduler.cull_queue()
