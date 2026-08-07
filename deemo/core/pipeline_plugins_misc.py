"""
安全特性/固件/编译器/分布式/其他 增强层注册器。
"""

from typing import Any, Dict


def _register_misc_layers(
    result: Dict[str, Any],
    binary_path: str,
    binfo: Dict[str, Any],
    kwargs: Dict[str, Any],
    logger: Any,
) -> None:
    """注册安全特性/固件/分布式/其他增强层."""

    # MMIO 外设模型推断
    try:
        from platform.firmware.src.mmio_inference import (
            MMIORegister, MMIORegisterClassifier, Peripheral,
            detect_lms_patterns, infer_peripherals, link_isr_to_mmio,
        )
        result['_mmio_classifier'] = MMIORegisterClassifier()
        result['_mmio_lms_detect_fn'] = detect_lms_patterns
        result['_mmio_peripheral_infer_fn'] = infer_peripherals
        result['_mmio_isr_link_fn'] = link_isr_to_mmio
        logger.debug("MMIO 外设推断已激活 (T0-T4 + LMS + ISR association)")
    except ImportError:
        logger.debug('optional plugin not available')

    # 隐私保护漏洞情报共享
    try:
        from cve.src.private_vuln_sharing import (
            VulnerabilityPrivatizer, FederatedAggregator,
            simhash_64, VulnerabilityRecord,
        )
        result['_vuln_privatizer'] = VulnerabilityPrivatizer(
            epsilon=kwargs.get('dp_epsilon', 1.0),
        )
        result['_vuln_aggregator'] = FederatedAggregator()
        result['_simhash_fn'] = simhash_64
        logger.debug("隐私保护漏洞共享已激活 (Local DP ε=%.1f)",
                    kwargs.get('dp_epsilon', 1.0))
    except ImportError:
        logger.debug('optional plugin not available')

    # 流分叉分析重入检测器
    try:
        from crypto.src.evm.flow_divergence_detector import (
            StorageFlowTracer, FlowDivergenceDetector,
            replay_evm_trace,
        )
        result['_evm_flow_tracer'] = StorageFlowTracer()
        result['_flow_divergence_detector'] = FlowDivergenceDetector()
        result['_evm_trace_replay_fn'] = replay_evm_trace
        logger.debug("流分叉重入检测器已激活")
    except ImportError:
        logger.debug('optional plugin not available')

    # IOCTL 调度面静态映射器
    try:
        from platform.kernel.ioctl_surface_mapper import (
            IOCTLSurfaceMapper, IOCTLDispatchTable,
            decode_windows_ioctl, decode_linux_ioctl,
        )
        result['_ioctl_surface_mapper'] = IOCTLSurfaceMapper(
            os_type=kwargs.get('ioctl_os', 'windows'),
        )
        result['_ioctl_decode_windows'] = decode_windows_ioctl
        result['_ioctl_decode_linux'] = decode_linux_ioctl
        logger.debug("IOCTL 调度面映射器已激活")
    except ImportError:
        logger.debug('optional plugin not available')

    # API 时序图恶意软件行为嵌入
    try:
        from platform.malware.temporal_api_graph import (
            build_markov_graph, decompose_sequence,
            embed_api_sequence, APIGraphIndex, MarkovAPIGraph,
        )
        result['_api_graph_index'] = APIGraphIndex(
            dim=kwargs.get('api_graph_dim', 32),
        )
        result['_api_markov_build_fn'] = build_markov_graph
        result['_api_embed_fn'] = embed_api_sequence
        result['_api_decompose_fn'] = decompose_sequence
        logger.debug("API 时序图嵌入已激活")
    except ImportError:
        logger.debug('optional plugin not available')

    # 二进制级锁图 must-race 检测器
    try:
        from analysis.static.concurrency_analysis.src.binary_lock_race import (
            LockGraphRaceDetector, identify_lock_functions,
            RaceSeverity,
        )
        result['_binary_lock_race_detector'] = LockGraphRaceDetector()
        result['_binary_lock_identify_fn'] = identify_lock_functions
        logger.debug("二进制级锁图 race 检测器已激活 (must-race 分类)")
    except ImportError:
        logger.debug('optional plugin not available')

    # 加密 Merkle SBOM 构建器
    try:
        from data.src.merkle_sbom import (
            MerkleSBOM, SBOMEntry, MerkleProof, selective_disclosure,
        )
        result['_merkle_sbom'] = MerkleSBOM()
        result['_merkle_selective_disclosure_fn'] = selective_disclosure
        logger.debug("加密 Merkle SBOM 已激活")
    except ImportError:
        logger.debug('optional plugin not available')

    # SimHash LSH 函数搜索索引
    try:
        from data.src.lsh_function_index import (
            LSHFunctionIndex, build_function_embedding,
        )
        result['_lsh_function_index'] = LSHFunctionIndex(
            n_tables=kwargs.get('lsh_tables', 8),
            k_bits=kwargs.get('lsh_k_bits', 16),
            dim=kwargs.get('lsh_dim', 64),
        )
        result['_lsh_embed_build_fn'] = build_function_embedding
        logger.debug("SimHash LSH 函数索引已激活 (%d 表 × %d bit)",
                    kwargs.get('lsh_tables', 8), kwargs.get('lsh_k_bits', 16))
    except ImportError:
        logger.debug('optional plugin not available')

    # 二进制级推测执行小工具检测器
    try:
        from analysis.static.const_time.src.speculation_gadget_detector import (
            SpeculationTaintTracker, GadgetValidator,
            SpecGadget, GadgetType, Certainty,
        )
        result['_speculation_taint_tracker'] = SpeculationTaintTracker()
        result['_speculation_gadget_validator'] = GadgetValidator()
        logger.debug("推测执行小工具检测器已激活 (Spectre v1/v2/v4)")
    except ImportError:
        logger.debug('optional plugin not available')

    # 反编译 I/O 等价性验证器
    try:
        from analysis.decompiler.decomp_equivalence_verifier import (
            DecompEquivalenceVerifier, EquivalenceLevel,
            check_recompilability, generate_test_inputs,
        )
        result['_decomp_equivalence_verifier'] = DecompEquivalenceVerifier()
        result['_decomp_test_inputs_fn'] = generate_test_inputs
        logger.debug("反编译等价性验证器已激活 (I/O behavior)")
    except ImportError:
        logger.debug('optional plugin not available')

    # 反分析技术加权检测器
    try:
        from analysis.deobfuscation.anti_analysis_detector import (
            AntiAnalysisDetector, AntiAnalysisReport,
        )
        result['_anti_analysis_detector'] = AntiAnalysisDetector()
        logger.debug("反分析技术检测器已激活 (22 indicators × weighted risk)")
    except ImportError:
        logger.debug('optional plugin not available')

    # 稳定锚点补丁定位器
    try:
        from analysis.static.binary_diff.src.patch_anchor_localizer import (
            extract_anchors, match_anchors, locate_patch_regions,
            StableAnchor, PatchCandidate,
        )
        result['_patch_anchor_extract_fn'] = extract_anchors
        result['_patch_anchor_match_fn'] = match_anchors
        result['_patch_anchor_locate_fn'] = locate_patch_regions
        logger.debug("稳定锚点补丁定位器已激活 (cross-compiler anchor matching)")
    except ImportError:
        logger.debug('optional plugin not available')

    # 行为级可利用性评分器
    try:
        from core.behavioral_exploitability import (
            BehavioralExploitabilityScorer, RegisterState,
            ExploitabilityLevel,
        )
        result['_behavioral_exploitability_scorer'] = BehavioralExploitabilityScorer()
        logger.debug("行为级可利用性评分器已激活 (5-dim behavioral scoring)")
    except ImportError:
        logger.debug('optional plugin not available')

    # 访问模式结构体布局恢复
    try:
        from analysis.static.binary_analysis.struct_layout_recovery import (
            StructLayoutRecoverer, collect_struct_accesses,
            infer_field_boundaries,
        )
        result['_struct_layout_recoverer'] = StructLayoutRecoverer()
        result['_struct_access_collector'] = collect_struct_accesses
        result['_struct_boundary_inferrer'] = infer_field_boundaries
        logger.debug("结构体布局恢复器已激活 (access pattern → C struct)")
    except ImportError:
        logger.debug('optional plugin not available')

    # 自适应漏洞利用策略选择器
    try:
        from exploit.src.strategy.adaptive_exploit_selector import (
            AdaptiveExploitSelector, BinaryFingerprint, StrategyKind,
            assess_strategy,
        )
        result['_adaptive_exploit_selector'] = AdaptiveExploitSelector()
        result['_strategy_assess_fn'] = assess_strategy
        logger.debug("自适应利用策略选择器已激活 (8 strategies × precondition check)")
    except ImportError:
        logger.debug('optional plugin not available')

    # 法定人数共识引擎
    try:
        from distributed.src.quorum_consensus import (
            QuorumConsensusEngine, NodeWeightTracker,
            weighted_quorum_vote,
        )
        result['_quorum_consensus_engine'] = QuorumConsensusEngine()
        result['_quorum_vote_fn'] = weighted_quorum_vote
        logger.debug("法定人数共识引擎已激活 (BFT weighted quorum ≥2/3)")
    except ImportError:
        logger.debug('optional plugin not available')

    # Trampoline 二进制函数钩子重写器
    try:
        from analysis.dynamic.engine.trampoline_hook import (
            TrampolineHookRewriter, generate_x86_64_trampoline,
            generate_arm64_trampoline, Arch,
        )
        result['_trampoline_hook_rewriter'] = TrampolineHookRewriter(
            arena_base=kwargs.get('trampoline_arena', 0x70000000),
        )
        result['_trampoline_x86_gen'] = generate_x86_64_trampoline
        result['_trampoline_arm64_gen'] = generate_arm64_trampoline
        logger.debug("Trampoline 钩子重写器已激活 (x86-64 + ARM64)")
    except ImportError:
        logger.debug('optional plugin not available')

    # 编译器/工具链元数据指纹识别
    try:
        from analysis.static.tools.compiler_fingerprinter import (
            CompilerFingerprinter, CompilerFingerprint,
            detect_from_strings, detect_from_code_idioms,
            detect_from_epilogue_patterns,
        )
        result['_compiler_fingerprinter'] = CompilerFingerprinter()
        result['_compiler_string_detect'] = detect_from_strings
        result['_compiler_idiom_detect'] = detect_from_code_idioms
        logger.debug("编译器指纹识别器已激活 (strings+idioms+epilogue→Bayesian fusion)")
    except ImportError:
        logger.debug('optional plugin not available')

    # 空间覆盖热力图生成器
    try:
        from output.src.coverage_heatmap import (
            CoverageHeatmapGenerator, aggregate_heatmap,
            suggest_coldspot_targets,
        )
        result['_coverage_heatmap_generator'] = CoverageHeatmapGenerator(
            bucket_size=kwargs.get('heatmap_bucket_size', 256),
        )
        result['_coldspot_suggester'] = suggest_coldspot_targets
        logger.debug("覆盖热力图生成器已激活 (spatial coverage→hot/cold boundary)")
    except ImportError:
        logger.debug('optional plugin not available')

    # IR 提升质量评估器
    try:
        from analysis.static.binary_analysis.ir_lifting_quality import (
            IRLiftingQualityEvaluator, IRQualityReport,
        )
        result['_ir_lifting_quality_evaluator'] = IRLiftingQualityEvaluator()
        logger.debug("IR 提升质量评估器已激活 (virtual stack + memory fidelity)")
    except ImportError:
        logger.debug('optional plugin not available')

    # 前向边 CFI 插桩器
    try:
        from analysis.static.binary_analysis.forward_edge_cfi import (
            ForwardEdgeCFI, locate_indirect_calls,
            infer_function_signatures,
        )
        result['_forward_edge_cfi'] = ForwardEdgeCFI(arch=kwargs.get('cfi_arch', 'x86_64'))
        result['_cfi_call_locator'] = locate_indirect_calls
        logger.debug("前向边 CFI 已激活 (software forward-edge protection)")
    except ImportError:
        logger.debug('optional plugin not available')

    # DFG 子图同构函数匹配
    try:
        from analysis.static.binary_diff.src.dfg_isomorphism_match import (
            build_dfg_from_instructions, compute_dfg_similarity,
            DFGGraph, DFGNode,
        )
        result['_dfg_builder_fn'] = build_dfg_from_instructions
        result['_dfg_similarity_fn'] = compute_dfg_similarity
        logger.debug("DFG 子图同构匹配已激活 (def-use isomorphism)")
    except ImportError:
        logger.debug('optional plugin not available')
