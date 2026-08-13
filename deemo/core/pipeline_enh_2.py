"""
(k) 求解器周期性重建调度器
"""

import logging

logger = logging.getLogger(__name__)


def apply_enhancements_2(result, binary_path, binfo, kwargs, binary_hash=None):
    """应用第 2 批可选增强层。"""
    # (k) 求解器周期性重建调度器
    # 解决 IncrementalSolverCache 的 Z3 状态累积问题。
    # 成本预估 + 内存压力感知 + warm_start 传递。
    try:
        from analysis.symbolic.src.solver_rebuild_scheduler import (
            SolverRebuildScheduler,
        )
        _rebuild_scheduler = SolverRebuildScheduler(
            hard_rebuild_pushes=500,
            hard_rebuild_solves=200,
            warm_start_transfer=True,
        )
        result['_solver_rebuild_scheduler'] = _rebuild_scheduler
        logger.debug("求解器重建调度器已激活（成本预估 + 内存感知）")
    except ImportError:
        logger.debug('optional plugin not available')

    # (l) 谱保持边丢弃
    # 在 gravity_edge_dropout 基础上增加桥边检测和
    # 谱连通性监控，防止边丢弃破坏 CFG 的全局连通结构。
    try:
        from ai_ml.src.data.spectral_edge_dropout import (
            DegreeAwareSpectralDropout,
        )
        _spectral_dropout = DegreeAwareSpectralDropout(
            base_dropout=0.2,
            low_degree_threshold=1,
        )
        result['_spectral_edge_dropout'] = _spectral_dropout
        logger.debug("谱保持边丢弃已激活（桥边保护 + 自适应温度）")
    except ImportError:
        logger.debug('optional plugin not available')
    # (m) 状态备忘录 (StateMemento)
    # Memento 模式的符号状态增量快照与压缩。
# KLEE 2024 ICSE Workshop; Gamma et al. 1995
    try:
        from analysis.symbolic.src.state_memento import StateMemento
        _memento = StateMemento(
            memory_budget_mb=kwargs.get("memento_budget_mb", 256.0),
            max_mementos_per_path=kwargs.get("memento_max_per_path", 10),
        )
        result["_state_memento"] = _memento
        logger.debug("state memento activated (budget: %.0f MB)",
                    kwargs.get("memento_budget_mb", 256.0))
    except ImportError:
        logger.debug('optional plugin not available')

    # (n) 冷点引导探索器 (ColdSpotGuidedExplorer)
    # PathHeatmap cold spot -> constraint edit distance -> redirection
# Sun et al. ICSE 2024 — 路径覆盖热力图与约束编辑距离
    try:
        from analysis.symbolic.src.coldspot_guided_explorer import (
            ColdSpotGuidedExplorer,
        )
        _coldspot_explorer = ColdSpotGuidedExplorer(
            max_edit_distance=kwargs.get("coldspot_max_edit_dist", 15.0),
            min_reachability=kwargs.get("coldspot_min_reach", 0.1),
        )
        result["_coldspot_explorer"] = _coldspot_explorer
        logger.debug("coldspot guided explorer activated")
    except ImportError:
        logger.debug('optional plugin not available')

    # (o) 时态路径缓存 (TemporalPathCache)
    # Integrated into enhanced pipeline
    try:
        from analysis.symbolic.src.temporal_path_cache import TemporalPathCache
        _temporal_cache = TemporalPathCache(
            halflife_seconds=kwargs.get("temporal_halflife", 120.0),
            max_per_bucket=kwargs.get("temporal_max_per_bucket", 50),
        )
        result["_temporal_cache"] = _temporal_cache
        logger.debug("temporal path cache activated (halflife: %.0fs)",
                    kwargs.get("temporal_halflife", 120.0))
    except ImportError:
        logger.debug('optional plugin not available')

    # (p) 度保持边丢弃 (DegreePreservingDropout)
    # degree-aware protection over DropEdge O(|V|)
# DropEdge
    try:
        from ai_ml.src.augment.degree_preserving_dropout import (
            DegreePreservingDropout,
        )
        _deg_dropout = DegreePreservingDropout(
            drop_prob=kwargs.get("degree_dropout_p", 0.15),
            beta=kwargs.get("degree_dropout_beta", 2.0),
        )
        result["_degree_preserving_dropout"] = _deg_dropout
        logger.debug("degree-preserving dropout activated (p=%.2f beta=%.1f)",
                    kwargs.get("degree_dropout_p", 0.15),
                    kwargs.get("degree_dropout_beta", 2.0))
    except ImportError:
        logger.debug('optional plugin not available')

    # (l) 混淆类型预分类器与跨函数证据传播
    # 在反混淆pass之前判定混淆类型；证据传播器沿
    # 调用图追踪常量来源。参考: Chisel + Tkachenko et al..
    try:
        from deobfuscation.src.obfuscation_classifier import (
            ObfuscationClassifier, VoteTally,
        )
        _obf_classifier = ObfuscationClassifier()
        result['_obfuscation_classifier'] = _obf_classifier
        logger.debug("混淆类型预分类器已就绪（多特征融合投票）")
    except ImportError:
        logger.debug('optional plugin not available')

    try:
        from deobfuscation.src.evidence_propagation import (
            EvidencePropagator, EvidenceRecord,
        )
        _evidence_prop = EvidencePropagator()
        result['_evidence_propagator'] = _evidence_prop
        logger.debug("跨函数证据传播器已就绪（信任衰减+循环截断）")
    except ImportError:
        logger.debug('optional plugin not available')

    # (m) 时态新颖度模糊调度器
    # Ebbinghaus遗忘曲线式种子新颖度衰减，双队列调度。
    # 与Scheduler(AFLfast马尔可夫链)互补。参考: Graphuzz +
    # SEAFuzz — 本模块在关系图基础上新增时间衰减维度。
    try:
        from fuzzing.src.decaying_novelty_scheduler import (
            DecayingNoveltyScheduler, NoveltyRecord,
        )
        _novelty_scheduler = DecayingNoveltyScheduler(
            halflife_sec=kwargs.get('novelty_halflife', 1800.0),
            min_novelty=kwargs.get('novelty_min', 0.10),
            resurrection_cooldown=kwargs.get('novelty_resurrection_cooldown', 600.0),
        )
        result['_decaying_novelty_scheduler'] = _novelty_scheduler
        logger.debug("时态新颖度调度器已就绪 (halflife=%.0fs)", _novelty_scheduler.halflife)
    except ImportError:
        logger.debug('optional plugin not available')

    # (n) 约束依赖图拓扑排序求解
    # 约束间变量依赖建模为有向图，拓扑分层递进求解。
    # SCC condensation 处理循环依赖，partial SAT propagation 缩小搜索空间。
    try:
        from analysis.symbolic.src.constraint_dependency_graph import (
            ConstraintDependencyGraph,
        )
        _cdg = ConstraintDependencyGraph(min_constraints_for_sort=10)
        result['_constraint_dependency_graph'] = _cdg
        logger.debug("约束依赖图排序已激活（拓扑分层 + SCC condensation）")
    except ImportError:
        logger.debug('optional plugin not available')

    # (o) 二进制语义差异分析
    # 双二进制语义级 diff，用于补丁分析和 1-day exploit 目标筛选。
    # 仅当调用方提供了 baseline_binary 参数时激活（可选路径，不强制）。
    baseline_path = kwargs.get('baseline_binary')
    if baseline_path:
        try:
            from analysis.static.binary_diff.src.func_differ import diff_pipeline
            from analysis.static.binary_diff.src.patch_classifier import classify_patch
            from analysis.static.binary_diff.src.exploit_ranker import rank_patches

            result['_diff_baseline_path'] = baseline_path
            result['_diff_pipeline'] = diff_pipeline
            result['_classify_patch'] = classify_patch
            result['_rank_patches'] = rank_patches
            logger.debug("二进制差异分析已就绪，基线: %s", baseline_path)
        except ImportError:
            logger.debug('optional plugin not available')


