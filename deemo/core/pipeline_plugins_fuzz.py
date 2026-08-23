"""
模糊测试/插桩/种子调度 增强层注册器。
"""

from typing import Any, Dict


def _register_fuzz_layers(
    result: Dict[str, Any],
    binary_path: str,
    binfo: Dict[str, Any],
    binary_hash: str,
    kwargs: Dict[str, Any],
    logger: Any,
) -> None:
    """注册模糊测试/插桩/种子调度增强层。"""

    # 时态新颖度模糊调度器
    # Ebbinghaus遗忘曲线式种子新颖度衰减，双队列调度。
    try:
        from modules.fuzzing.src.decaying_novelty_scheduler import (
            DecayingNoveltyScheduler, NoveltyRecord,
        )
        result['_decaying_novelty_scheduler'] = DecayingNoveltyScheduler(
            halflife_sec=kwargs.get('novelty_halflife', 1800.0),
            min_novelty=kwargs.get('novelty_min', 0.10),
            resurrection_cooldown=kwargs.get('novelty_resurrection_cooldown', 600.0),
        )
        logger.debug("时态新颖度调度器已就绪")
    except ImportError:
        logger.debug('optional plugin not available')

    # 语义执行新颖度检测器 (SEND)
    try:
        from modules.fuzzing.src.semantic_novelty_detector import (
            SemanticNoveltyDetector, ExecutionSummary,
            NoveltyGuidedEnergyPolicy,
        )
        _send_detector = SemanticNoveltyDetector(
            dim=kwargs.get('send_dim', 128),
            window_size=kwargs.get('send_window', 200),
        )
        result['_semantic_novelty_detector'] = _send_detector
        result['_novelty_energy_policy'] = NoveltyGuidedEnergyPolicy(_send_detector)
        logger.debug("语义执行新颖度检测器已激活 (dim=%d)", _send_detector._dim)
    except ImportError:
        logger.debug('optional plugin not available')

    # Thompson 采样多模糊器编排器
    try:
        from modules.fuzzing.src.thompson_orchestrator import (
            ThompsonOrchestrator, make_crash_signature,
        )
        result['_thompson_orchestrator'] = ThompsonOrchestrator(
            default_interval=kwargs.get('thompson_interval', 300.0),
            min_allocation_ratio=kwargs.get('thompson_min_alloc', 0.05),
        )
        result['_crash_signature_fn'] = make_crash_signature
        logger.debug("Thompson 采样编排器已激活")
    except ImportError:
        logger.debug('optional plugin not available')

    # 约束感知 def-use 链引导变异
    try:
        from modules.fuzzing.src.defuse_mutation_guide import (
            ConstraintGuidedMutator, ConditionBranchCollector,
            defuse_guided_mutation_pipeline, BranchCoverageFingerprint,
        )
        result['_defuse_mutator'] = ConstraintGuidedMutator()
        result['_defuse_collector'] = ConditionBranchCollector()
        result['_defuse_pipeline_fn'] = defuse_guided_mutation_pipeline
        result['_branch_fingerprint'] = BranchCoverageFingerprint()
        logger.debug("def-use 链引导变异已就绪")
    except ImportError:
        logger.debug('optional plugin not available')

    # 反事实变异优化器
    try:
        from modules.fuzzing.src.counterfactual_mutator import CounterfactualMutator
        result['_counterfactual_mutator'] = CounterfactualMutator(
            max_history=kwargs.get('cf_max_history', 500),
        )
        logger.debug("反事实变异优化器已激活 (SCM rung-3)")
    except ImportError:
        logger.debug('optional plugin not available')

    # 对抗遗憾最小化变异集成
    try:
        from modules.fuzzing.src.regret_minimizing_ensemble import RegretMinimizingEnsemble
        result['_regret_ensemble'] = RegretMinimizingEnsemble(
            learning_rate=kwargs.get('regret_lr', 0.1),
            ent_lambda=kwargs.get('regret_ent_lambda', 0.01),
        )
        logger.debug("遗憾最小化变异集成已激活 (FTRL+Entropy)")
    except ImportError:
        logger.debug('optional plugin not available')

    # 拓扑覆盖导航器
    try:
        from modules.fuzzing.src.topological_coverage_navigator import (
            TopologicalCoverageNavigator, CoveragePoint, TopologicalFeature,
        )
        result['_topological_navigator'] = TopologicalCoverageNavigator(
            epsilon=kwargs.get('topo_epsilon', 0.35),
            n_landmarks=kwargs.get('topo_landmarks', 64),
        )
        logger.debug("拓扑覆盖导航器已激活 (持久同调)")
    except ImportError:
        logger.debug('optional plugin not available')

    # 风险调整模糊测试能量调度
    try:
        from modules.fuzzing.src.risk_adjusted_schedule import (
            RiskAdjustedScheduler, SeedPerformanceHistory,
        )
        result['_risk_adjusted_scheduler'] = RiskAdjustedScheduler(
            base_energy=kwargs.get('risk_base_energy', 100.0),
            risk_preference=kwargs.get('risk_preference', 0.6),
        )
        logger.debug("风险调整能量调度已激活 (Sharpe/Calmar/Martin)")
    except ImportError:
        logger.debug('optional plugin not available')

    # 路径转换图种子探索器
    try:
        from modules.fuzzing.src.path_transition_explorer import (
            PathTransitionGraph, hash_coverage_state,
            context_aware_schedule,
        )
        result['_path_transition_graph'] = PathTransitionGraph()
        result['_coverage_state_hash_fn'] = hash_coverage_state
        result['_context_aware_schedule_fn'] = context_aware_schedule
        logger.debug("路径转换图探索器已激活 (Markov state transition)")
    except ImportError:
        logger.debug('optional plugin not available')

    # Intel PT 覆盖位图重建器
    try:
        from modules.analysis.dynamic.engine.intel_pt_coverage import (
            PTCoverageReconstructor, find_psb_boundaries,
            parse_pt_packets, bb_sequence_to_edge_bitmap,
        )
        result['_pt_coverage_reconstructor'] = PTCoverageReconstructor(
            binary_base=kwargs.get('binary_base_addr', 0),
        )
        result['_pt_psb_finder'] = find_psb_boundaries
        result['_pt_packet_parser'] = parse_pt_packets
        logger.debug("Intel PT 覆盖重建器已激活 (hardware trace→edge bitmap)")
    except ImportError:
        logger.debug('optional plugin not available')

    # EVT 差分模糊测试风险估计器
    try:
        from modules.fuzzing.src.evt_risk_estimator import (
            EVTRiskEstimator, fit_gpd, score_diff_severity,
        )
        result['_evt_risk_estimator'] = EVTRiskEstimator(
            threshold_percentile=kwargs.get('evt_threshold_pct', 80.0),
        )
        result['_diff_severity_scorer'] = score_diff_severity
        logger.debug("EVT 风险估计器已激活 (GPD tail + early stopping)")
    except ImportError:
        logger.debug('optional plugin not available')

    # 二进制语义差分 Oracle
    try:
        from modules.analysis.dynamic.engine.semantic_diff_oracle import (
            SemanticDiffOracle, ExecutionSnapshot, DiffType,
            capture_execution,
        )
        result['_semantic_diff_oracle'] = SemanticDiffOracle(
            output_threshold=kwargs.get('diff_output_threshold', 0.99),
            coverage_threshold=kwargs.get('diff_coverage_threshold', 0.99),
        )
        result['_execution_capture_fn'] = capture_execution
        logger.debug("语义差分 Oracle 已激活 (4-dim: output×coverage×perf×syscall)")
    except ImportError:
        logger.debug('optional plugin not available')

    # 崩溃变体生成器
    try:
        from modules.analysis.dynamic.engine.crash_variant_generator import (
            CrashVariantGenerator, triangulate_root_cause,
            CrashVariant, TriangulationResult,
        )
        result['_crash_variant_generator'] = CrashVariantGenerator()
        result['_crash_triangulate_fn'] = triangulate_root_cause
        logger.debug("崩溃变体生成器已激活 (controlled mutation + triangulation)")
    except ImportError:
        logger.debug('optional plugin not available')

    # 嵌入式 DBI 追踪适配器
    try:
        from modules.analysis.dynamic.engine.embedded_dbi_tracer import (
            EmbeddedDBIRewriter, TraceBuffer, TraceDecoder,
            ISAFamily,
        )
        result['_embedded_dbi_rewriter'] = EmbeddedDBIRewriter(
            isa=ISAFamily(kwargs.get('embedded_isa', 'armv7m')),
            trace_buf_size=kwargs.get('trace_buf_size', 4096),
        )
        result['_trace_decoder'] = TraceDecoder()
        logger.debug("嵌入式 DBI 追踪器已激活 (ISA=%s)",
                    kwargs.get('embedded_isa', 'armv7m'))
    except ImportError:
        logger.debug('optional plugin not available')

    # 执行上下文崩溃去重引擎
    try:
        from modules.analysis.dynamic.engine.crash_context_dedup import (
            CrashContextDeduplicator, CrashRecord,
            make_crash_signature, bb_sequence_embedding,
        )
        result['_crash_context_dedup'] = CrashContextDeduplicator(
            context_threshold=kwargs.get('crash_dedup_threshold', 0.85),
        )
        result['_crash_signature_fn'] = make_crash_signature
        result['_bb_embed_fn'] = bb_sequence_embedding
        logger.debug("上下文感知崩溃去重已激活 (threshold=%.2f)",
                    kwargs.get('crash_dedup_threshold', 0.85))
    except ImportError:
        logger.debug('optional plugin not available')

    # 见证支持的崩溃根因定位器
    try:
        from modules.analysis.dynamic.engine.witness_root_cause import (
            backward_crash_slice, rank_blame_candidates,
            WitnessPath, BlameCandidate,
        )
        result['_witness_root_cause_fn'] = backward_crash_slice
        result['_blame_ranking_fn'] = rank_blame_candidates
        logger.debug("见证根因定位器已激活 (witness-backed blame ranking)")
    except ImportError:
        logger.debug('optional plugin not available')

    # 协议边界检测 + 状态机推断
    try:
        from modules.analysis.static.tools.entropy_jump_detector import (
            EntropyJumpDetector, IncrementalEntropyWindow,
        )
        result['_entropy_jump_detector'] = EntropyJumpDetector()
        logger.debug('熵跳变检测器已就绪（增量 O(1) 窗口）')
    except ImportError:
        logger.debug('optional plugin not available')
    try:
        from modules.analysis.static.tools.protocol_state_inferrer import (
            ProtocolStateInferrer,
        )
        result['_protocol_state_inferrer'] = ProtocolStateInferrer()
        logger.debug('协议状态机推断器已就绪（SimHash 消息聚类）')
    except ImportError:
        logger.debug('optional plugin not available')
