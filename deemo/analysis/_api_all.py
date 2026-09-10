"""
仅定义 __all__, 不执行实际导入 (导入在 __init__.py 和 _api_deep.py 中完成)。
"""

__all__ = [
    # 轻量值范围引擎 (C源码级, 无需IR提升)
    'Range', 'INF', 'ValueRangeEngine',
    'eval_expr_impl', '_eval_sizeof', '_apply_op',
    # Strided Interval 域
    'StridedInterval', 'si_singleton', 'si_interval', 'si_range',
    'si_unbounded', 'si_from_mul',
    'BranchConstraint', 'PathConstraints', 'PathConstraintCollector',
    'ChunkClass', 'ChunkLayout', 'HeapRegion', 'HeapLayoutOracle',
    'ProofResult', 'HeapBoundsProver', 'prove_store_safety',
    'FilterStage', 'FilterReport', 'UnifiedFPFilter',
    'detect_heap_overflow', 'propagate_sizes',
    'extract_allocation_sites', 'extract_write_sites', 'analyze_heap_risk',
    'filter_false_positives', 'extract_constants', 'simplify', 'parse_constraints',
    'GuardInferenceEngine', 'GuardVerdict', 'GuardCondition',
    'analyze_heap_bounds', 'extract_alloc_sites', 'extract_heap_writes',
    'check_bounds', 'Interval', 'AllocSite', 'HeapWrite', 'BoundsViolation',
    'TaintSource', 'TaintSink', 'TaintPath', 'is_source', 'is_sink',
    'track_taint_intraprocedural', 'filter_by_taint',
    # 新增: 路径敏感区间分析 & 多因子评分
    'Interval', 'IntervalKind', 'widen_sequence', 'interval_from_constrained_source',
    'PathSensitiveHeapAnalyzer', 'HeapPathVerdict', 'AbstractState',
    'BasicBlock', 'path_sensitive_analyze',
    'PointerAlias', 'ResolvedStore', 'PointerAliasTracker', 'track_pointer_aliases',
    'ConfidenceFactors', 'HeapConfidenceScorer', 'classify_heap_overflows',
    'run_heap_analysis_pipeline', 'PipelineStats',
    # 新增模块
    'run_enhanced_filter',
    'VRInterval', 'VarRange', 'ValueRangePropagator', 'extract_size_constraints_from_ir',
    'GuardCondition', 'find_guard_for_variable', 'is_store_safeguarded', 'extract_all_guards',
    'ChunkLayout', 'estimate_chunk_layout', 'is_within_slack', 'would_overflow', 'compute_effective_boundary',
    'MemAccess', 'MemRegion', 'is_likely_heap_write', 'classify_memory_access', 'extract_heap_accesses',
    'AllocRecord', 'VarsEquivClass', 'FlowSensitiveTracker',
    # 四层 Tier 管线 + 多漏洞深度验证
    # Tier 0
    'AllocKind', 'AllocatorModel', 'ptmalloc2_usable_size',
    'jemalloc_usable_size', 'tcmalloc_usable_size',
    # Tier 1
    'AffineInterval', 'PathCondition', 'LinearInequality',
    'affine_const', 'affine_var', 'affine_unbounded',
    'CfgParser', 'CfgBasicBlock', 'ControlFlowGraph',
    'HeapExprParser', 'quick_parse_size',
    'PathSensitiveVRF', 'VrfAllocRecord', 'VrfVerdict',
    # IR匹配器 (Tier 1辅助)
    'match_assign', 'match_if', 'match_alloc', 'match_write', 'match_condition',
    # Tier 2 (SymExpr/sym_const/指令匹配器在 symbolic_arith_matcher)
    'SymExpr', 'sym_const',
    'try_arith_insn', 'try_load_store_insn',
    'try_conditional_insn', 'refine_range_by_constraints',
    'SelectiveSymExec', 'SymVerdict',
    # Tier 3
    'InfeasiblePathPruner', 'PruneResult', 'GuardPatternDetector',
    # UAF TARPS
    'UafTarpsVerifier', 'TarpsVerdict', 'TarpsResult', 'batch_verify_uaf',
    # 格式化字符串
    'FormatStringVerifier', 'FmtStringVerdict',
    # 整数溢出
    'IntOverflowVerifier', 'IntOverflowVerdict', 'ValueRange',
    # 统一管线
    'UnifiedPipeline', 'PipelineReport', 'TierResult',
    'TierStage', 'VulnType',
    'run_heap_overflow_pipeline', 'run_uaf_pipeline',
    'run_format_string_pipeline', 'run_int_overflow_pipeline',
    # 深度分析模块
    'HeapCFGBuilder', 'build_heap_cfg',
    'phase_allocator_semantics', 'phase_path_constraints',
    'phase_heap_layout', 'phase_z3_prove', 'phase_strided_interval',
    'CallingConvention', 'StackOffsetEstimate', 'FmtCallSite',
    'FormatStackOffsetAnalyzer', 'infer_fmt_offset',
    'IntWidth', 'Signedness', 'IntConstraintRange',
    'IntOpSite', 'IntRangeConstraintChecker', 'check_int_overflow_enhanced',
    'TemporalVerdict', 'TemporalResult', 'UafTemporalVerifier',
    'verify_uaf_temporal', 'verify_uaf_batch',
    'UAFDominatorVerifier', 'DominatorVerdict', 'DominatorResult',
    'dominator_batch_verify',
    'compute_exploitability', 'compute_impact',
    'compute_cia_impact', 'generate_assessment',
    'UafBasicBlock', 'UafCFGBuilder',
    'extract_alloc_write_pairs', 'apply_interproc_summaries',
    'compute_final_verdict',
    # UAF四阶段FP削减级联 (TARP-E)
    'UafVerdict', 'EscapeLevel', 'UafCandidate', 'CascadeReport',
    'extract_uaf_candidates', 'run_uaf_cascade',
    'phase0_pattern_safety', 'phase1_alias_lifetime',
    'phase2_path_dominance', 'phase3_escape_analysis',
    # 新增: UAF跨过程摘要 + 格式字符串DFA解析器
    'Lifetime', 'HeapPtrSummary', 'FuncSummary',
    'InterProcLifetimeAnalyzer',
    'FmtDanger', 'FmtSpec', 'ParsedFmtString',
    'FmtStringParser', 'classify_fmt_danger',
    # 贝叶斯置信度融合
    'BayesianFusionEngine', 'fuse_scores', 'risk_classify',
    'probability_to_log_odds', 'log_odds_to_probability',
    # GAPSBV (证明义务+约束收集+积分器)
    'HeapProofEngine', 'ProofVerdict', 'ProofObligation',
    'SizeConstraint', 'prove_heap_safety',
    'SizeConstraintCollector', 'SizeVarSummary', 'SizeVarConstraint',
    'apply_size_constraints_to_findings',
    'FPReductionIntegrator', 'AblationReport', 'StageStats',
    # fp_filter_stages 独立阶段函数
    'stage1_allocator_semantics', 'stage2_guard_aware',
    'stage3_size_constraints', 'stage4_proof_obligations',
    'stage5_slack_space', 'stage6_value_range', 'stage7_non_heap',
    # GAPSBV端到端检测管道
    'GapsbvVerdict', 'DimensionResult', 'GapsbvReport',
    'detect_heap_overflow_gapsbv', 'detect_heap_gapsbv_quick',
    '_resolve_macros',
    # I-GUARD C源码整数溢出
    'IntOverflowFinding',
    'detect_int_overflow_c_source', 'detect_int_overflow_quick',
    # 循环归纳变量追踪
    'InductionKind', 'InductionVar', 'LoopInfo', 'LoopOverflowRisk',
    'LoopInductionTracker', 'integrate_loop_analysis_with_iguard',
    # GAPSBV dimensions
    'dim1_affine_relations', 'dim2_guard_analysis',
    'dim3_strided_interval', 'dim4_allocator_semantics',
    'dim5_completeness_check',
    '_extract_size_interval', '_estimate_sizeof',
    # MIVR 路径敏感约束传播 (GAPSBV维度6)
    'VarConstraint', 'GuardSite', 'ConstraintEdge', 'MIVRConstraintGraph',
    'PropagatedState', 'WriteSafetyVerdict', 'MIVRPathPropagator',
    'PairProof', 'MIVRPairProver',
    'dim6_mivr_constraint_proof', 'detect_heap_overflow_mivr',
    'run_gapsbv_with_mivr',
    # 分配-写入关系提取器
    'AllocSite', 'WriteSite', 'AllocWritePair',
    'AllocWriteExtractor', 'extract_alloc_write_pairs',
    # FSTP 格式说明符语义感知污点传播
    'SemClass', 'FstpVerdict', 'FmtSemanticTaintPropagator',
    # HOIG 对象身份追踪 UAF检测
    'ObjState', 'ObjectID', 'ObjStateAtPoint',
    'IdentityEdge', 'FuncObjSummary', 'UafHoigVerdict',
    'HoigBuilder', 'HoigPropagator', 'HoigCrossFuncVerifier',
    'HoigVerifier', 'HoigReallocTracker',
    # PTASM UAF检测
    'PTASMEngine', 'PTASMStats', 'ptasm_analyze',
    'ptasm_verify_candidates', 'ptasm_detect_uaf', 'ptasm_pipeline_detect',
    'PTASM_PROTECTED', 'PTASM_CONFIRMED', 'PTASM_UNCERTAIN',
    'PtrState', 'PtrTransition', 'PtrInfo', 'PTASMResult',
    'parse_line_operations',
    'normalize_single_line_ifs', 'find_branch_bodies', 'join_ptr_states',
    # 桥接模块
    'refine_fmt_findings', 'refine_int_overflow_findings',
    'filter_by_value_range',
]
