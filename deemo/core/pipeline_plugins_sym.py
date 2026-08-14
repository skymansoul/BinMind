"""
符号执行/求解器/GNN/反编译器 增强层注册器。
"""

from typing import Any, Dict


def _register_sym_layers(
    result: Dict[str, Any],
    binary_path: str,
    binfo: Dict[str, Any],
    binary_hash: str,
    sym_result: Any,
    kwargs: Dict[str, Any],
    logger: Any,
) -> None:
    """注册符号执行/求解器/GNN/反编译器增强层 (layers a-o, v, ae, az)。"""

    # (a) 路径多样性管理
    if sym_result:
        try:
            # path_diversity_core 已重写, SimHashCalibrator/ConvergenceAnalyzer 不存在, 该增强当前跳过
            from modules.analysis.symbolic.src.path_diversity_core import (
                PathDiversityTracker, DiversityAwarePathSelector,
                DiversityStrategy, SimHashCalibrator, ConvergenceAnalyzer,
            )
            _diversity_tracker = PathDiversityTracker(
                similarity_threshold=0.8,
                max_paths=kwargs.get('diversity_max_paths', 1000),
            )
            result['_diversity_tracker'] = _diversity_tracker
            logger.debug("路径多样性管理器已激活")
        except ImportError:
            logger.debug('optional plugin not available')

    # (b) 求解器优化管线
    try:
        from modules.analysis.symbolic.src.symexec_opt_passes import (
            ConstraintComplexityEstimator, IncrementalSolverCache,
            SolverBudgetManager, OptimizationPipeline,
        )
        from modules.analysis.symbolic.src.adaptive_complexity_calibrator import (
            AdaptiveComplexityCalibrator,
        )
        from modules.analysis.symbolic.src.entropy_guided_budget import (
            EntropyBudgetAllocator,
        )
        _estimator = ConstraintComplexityEstimator()
        _calibrator = AdaptiveComplexityCalibrator()
        _budget_mgr = SolverBudgetManager()
        _entropy_allocator = EntropyBudgetAllocator()

        def _on_recalibration(state):
            _estimator.learning_rate = _calibrator.recommended_learning_rate(0.01)
            if _calibrator.should_reset_weights():
                _estimator.weights = dict(_estimator._DEFAULT_WEIGHTS)
                logger.warning("求解时间预估器精度严重退化——已重置为初始权重")

        _calibrator.on_recalibration(_on_recalibration)
        result['_complexity_estimator'] = _estimator
        result['_complexity_calibrator'] = _calibrator
        result['_solver_budget_mgr'] = _budget_mgr
        result['_entropy_allocator'] = _entropy_allocator
        logger.debug("求解器优化管线已激活")
    except ImportError:
        logger.debug('optional plugin not available')

    # (c) 反编译器集成
    try:
        from modules.analysis.decompiler.src.decompiler_confidence_ensemble import (
            DecompilerConfidenceEnsemble,
        )
        result['_decompiler_ensemble'] = DecompilerConfidenceEnsemble()
        logger.debug("多反编译器置信度集成已激活")
    except ImportError:
        logger.debug('optional plugin not available')

    # (d) GNN 预处理增强
    try:
        from modules.ai_ml.src.data.cfg_coarsening import coarsen_cfg
        result['_cfg_coarsening_fn'] = coarsen_cfg
        logger.debug("CFG 粗化已就绪")
    except ImportError:
        logger.debug('optional plugin not available')
    try:
        from modules.ai_ml.src.data.cross_arch_normalizer import normalize_mnemonic
        result['_cross_arch_normalizer'] = normalize_mnemonic
        result['_arch'] = binfo.get('arch', 'unknown')
        logger.debug("跨架构归一化已就绪，目标架构: %s", binfo.get('arch', 'unknown'))
    except ImportError:
        logger.debug('optional plugin not available')

    # (e) 前向支配前沿探索器
    try:
        from modules.analysis.symbolic.src.forward_frontier_explorer import (
            ForwardFrontierExplorer,
        )
        _frontier_explorer = ForwardFrontierExplorer()
        result['_frontier_explorer'] = _frontier_explorer
        try:
            decomp_info = result.get('decomp_analysis', [])
            if decomp_info and hasattr(decomp_info[0], 'get'):
                _cfg_edges, _block_sizes = {}, {}
                for func_info in decomp_info:
                    for block in func_info.get('cfg_blocks', []):
                        addr = block.get('address', 0)
                        succs = block.get('successors', [])
                        if addr and succs:
                            _cfg_edges[addr] = [s.get('address', 0) for s in succs if s]
                        if addr and 'instruction_count' in block:
                            _block_sizes[addr] = block['instruction_count']
                if _cfg_edges:
                    _frontier_explorer.load_cfg(idom={}, cfg_edges=_cfg_edges, block_sizes=_block_sizes)
                    logger.debug("前向支配前沿探索器已激活 (%d 个 CFG 块)", len(_cfg_edges))
        except Exception as _cfg_err:
            logger.debug("CFG 加载跳过（探索器已就绪但未加载图）: %s", _cfg_err)
        logger.debug("前向支配前沿探索器已激活")
    except ImportError:
        logger.debug('optional plugin not available')

    # (f) 三模态融合引擎
    try:
        from modules.multimodal.src.tri_modal_fusion import (
            TriModalFusionEngine, ModalityConflictArbiter,
        )
        _fusion_engine = TriModalFusionEngine(
            dim=kwargs.get('fusion_dim', 128),
            entropy_alpha=kwargs.get('fusion_alpha', 2.0),
        )
        _fusion_engine.begin_analysis(binary_hash)
        result['_tri_modal_engine'] = _fusion_engine
        result['_modal_features'] = {}
        logger.debug("三模态融合引擎已激活（熵加权注意力 + 冲突仲裁 + 溯源链）")
    except ImportError:
        logger.debug('optional plugin not available')

    # (h) 非线性约束求解时间预测器
    try:
        from modules.analysis.symbolic.src.constraint_predictor_nonlinear import (
            NonlinearConstraintPredictor,
        )
        result['_nonlinear_predictor'] = NonlinearConstraintPredictor(learning_rate=0.005)
        logger.debug("非线性约束求解时间预测器已激活（多项式展开 + phase detection）")
    except ImportError:
        logger.debug('optional plugin not available')

    # (i) 滞环防抖自适应阈值控制器
    try:
        from modules.analysis.symbolic.src.adaptive_threshold_controller import (
            OscillationDampedController,
        )
        result['_threshold_controller'] = OscillationDampedController(
            initial_threshold=kwargs.get('diversity_threshold', 0.80),
        )
        logger.debug("防抖阈值控制器已激活（滞环 + 积分项 + 收敛检测）")
    except ImportError:
        logger.debug('optional plugin not available')

    # (j) 跨层优化反馈环
    try:
        from modules.analysis.symbolic.src.cross_layer_feedback import CrossLayerFeedbackLoop
        result['_cross_layer_feedback'] = CrossLayerFeedbackLoop(
            base_budget_per_path=kwargs.get('base_solver_budget', 5.0),
        )
        logger.debug("跨层反馈环已激活（Path↔Solver 双向）")
    except ImportError:
        logger.debug('optional plugin not available')

    # (k) 求解器周期性重建调度器
    try:
        from modules.analysis.symbolic.src.solver_rebuild_scheduler import SolverRebuildScheduler
        result['_solver_rebuild_scheduler'] = SolverRebuildScheduler(
            hard_rebuild_pushes=500, hard_rebuild_solves=200, warm_start_transfer=True,
        )
        logger.debug("求解器重建调度器已激活（成本预估 + 内存感知）")
    except ImportError:
        logger.debug('optional plugin not available')

    # (l) 谱保持边丢弃
    try:
        from modules.ai_ml.src.data.spectral_edge_dropout import DegreeAwareSpectralDropout
        result['_spectral_edge_dropout'] = DegreeAwareSpectralDropout(
            base_dropout=0.2, low_degree_threshold=1,
        )
        logger.debug("谱保持边丢弃已激活（桥边保护 + 自适应温度）")
    except ImportError:
        logger.debug('optional plugin not available')

    # (m) 状态备忘录 (StateMemento)
    try:
        from modules.analysis.symbolic.src.state_memento import StateMemento
        result["_state_memento"] = StateMemento(
            memory_budget_mb=kwargs.get("memento_budget_mb", 256.0),
            max_mementos_per_path=kwargs.get("memento_max_per_path", 10),
        )
        logger.debug("state memento activated (budget: %.0f MB)",
                    kwargs.get("memento_budget_mb", 256.0))
    except ImportError:
        logger.debug('optional plugin not available')

    # (n) 冷点引导探索器
    try:
        from modules.analysis.symbolic.src.coldspot_guided_explorer import ColdSpotGuidedExplorer
        result["_coldspot_explorer"] = ColdSpotGuidedExplorer(
            max_edit_distance=kwargs.get("coldspot_max_edit_dist", 15.0),
            min_reachability=kwargs.get("coldspot_min_reach", 0.1),
        )
        logger.debug("coldspot guided explorer activated")
    except ImportError:
        logger.debug('optional plugin not available')

    # (o) 时态路径缓存
    try:
        from modules.analysis.symbolic.src.temporal_path_cache import TemporalPathCache
        result["_temporal_cache"] = TemporalPathCache(
            halflife_seconds=kwargs.get("temporal_halflife", 120.0),
            max_per_bucket=kwargs.get("temporal_max_per_bucket", 50),
        )
        logger.debug("temporal path cache activated (halflife: %.0fs)",
                    kwargs.get("temporal_halflife", 120.0))
    except ImportError:
        logger.debug('optional plugin not available')

    # (v) 污点约束符号探索器
    try:
        from modules.analysis.symbolic.src.taint_constrained_explorer import (
            TaintConstrainedExplorer,
        )
        result['_taint_constrained_explorer'] = TaintConstrainedExplorer(
            taint_decay_factor=kwargs.get('taint_decay', 0.85),
            direct_taint_weight=kwargs.get('taint_direct_weight', 1.0),
            indirect_taint_weight=kwargs.get('taint_indirect_weight', 0.6),
        )
        logger.debug('TaintConstrainedExplorer activated (decay=%.2f)',
                    kwargs.get('taint_decay', 0.85))
    except ImportError:
        logger.debug('optional plugin not available')

    # (ae) LLM-SMT 混合约束求解器
    try:
        from modules.analysis.symbolic.src.llm_smt_hybrid_solver import (
            LLMSMTHybridSolver, ConstraintTemplateCache,
        )
        _template_cache = ConstraintTemplateCache(max_size=128)
        result['_llm_smt_solver'] = LLMSMTHybridSolver(
            llm_callable=kwargs.get('llm_callable'),
            z3_factory=kwargs.get('z3_solver_factory'),
        )
        result['_constraint_template_cache'] = _template_cache
        logger.debug("LLM-SMT 混合求解器已激活")
    except ImportError:
        logger.debug('optional plugin not available')

    # (az) 分治符号执行切片器
    try:
        from modules.analysis.symbolic.src.divide_conquer_slicer import (
            DivideConquerSymExec, build_dataflow_graph, backward_slice,
        )
        result['_divide_conquer_symexec'] = DivideConquerSymExec()
        result['_dataflow_graph_builder'] = build_dataflow_graph
        result['_backward_slice_fn'] = backward_slice
        logger.debug("分治符号执行切片器已激活 (backward slicing)")
    except ImportError:
        logger.debug('optional plugin not available')

    # (p) 度保持边丢弃
    try:
        from modules.ai_ml.src.augment.degree_preserving_dropout import DegreePreservingDropout
        result["_degree_preserving_dropout"] = DegreePreservingDropout(
            drop_prob=kwargs.get("degree_dropout_p", 0.15),
            beta=kwargs.get("degree_dropout_beta", 2.0),
        )
        logger.debug("degree-preserving dropout activated (p=%.2f beta=%.1f)",
                    kwargs.get("degree_dropout_p", 0.15),
                    kwargs.get("degree_dropout_beta", 2.0))
    except ImportError:
        logger.debug('optional plugin not available')

    # (n) 约束依赖图拓扑排序求解
    try:
        from modules.analysis.symbolic.src.constraint_dependency_graph import (
            ConstraintDependencyGraph,
        )
        result['_constraint_dependency_graph'] = ConstraintDependencyGraph(
            min_constraints_for_sort=10)
        logger.debug("约束依赖图排序已激活（拓扑分层 + SCC condensation）")
    except ImportError:
        logger.debug('optional plugin not available')
