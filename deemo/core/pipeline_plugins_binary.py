"""
二进制分析/漏洞利用/安全特性 增强层注册器。
"""

from typing import Any, Dict


def _register_binary_layers(
    result: Dict[str, Any],
    binary_path: str,
    binfo: Dict[str, Any],
    binary_hash: str,
    kwargs: Dict[str, Any],
    logger: Any,
) -> None:
    """注册 exploit/二进制分析/安全特性增强层 (g, p-r, s-x, af-bq 中剩余块)。"""

    # (g) exploit 原语组合文法
    try:
        from modules.exploit.src.core.primitive_composer import (
            PrimitiveComposer, AtomicPrimitive, PrimitiveType,
        )
        from modules.exploit.src.core.constraint_propagator import (
            ConstraintPropagator, MachineState,
        )
        result['_primitive_composer'] = PrimitiveComposer(
            arch=binfo.get('arch', 'x86_64'),
            max_chain_depth=kwargs.get('composer_max_depth', 10),
        )
        result['_constraint_propagator'] = ConstraintPropagator(
            arch=binfo.get('arch', 'x86_64'),
        )
        logger.debug("exploit 原语组合文法已就绪（类型导向组合 + 约束传播验证）")
    except ImportError:
        logger.debug('optional plugin not available')

    # (p) 静态并发缺陷检测
    try:
        _imports_for_concurrency = kwargs.get('concurrency_imports', [])
        if not _imports_for_concurrency:
            _imports_for_concurrency = binfo.get('imports', [])
        if _imports_for_concurrency:
            from modules.analysis.static.concurrency_analysis.src.sync_primitive import (
                extract_sync_primitives,
            )
            if extract_sync_primitives(_imports_for_concurrency):
                from modules.analysis.static.concurrency_analysis.src.concurrency_pipeline import (
                    analyze_binary_concurrency,
                )
                result['_concurrency_analyzer'] = analyze_binary_concurrency
                result['_concurrency_imports'] = _imports_for_concurrency
                logger.debug("并发缺陷检测已就绪")
    except ImportError:
        logger.debug('optional plugin not available')

    # 混淆类型预分类器与跨函数证据传播
    try:
        from modules.analysis.deobfuscation.src.obfuscation_classifier import (
            ObfuscationClassifier, VoteTally,
        )
        result['_obfuscation_classifier'] = ObfuscationClassifier()
        logger.debug("混淆类型预分类器已就绪（多特征融合投票）")
    except ImportError:
        logger.debug('optional plugin not available')
    try:
        from modules.analysis.deobfuscation.src.evidence_propagation import (
            EvidencePropagator, EvidenceRecord,
        )
        result['_evidence_propagator'] = EvidencePropagator()
        logger.debug("跨函数证据传播器已就绪（信任衰减+循环截断）")
    except ImportError:
        logger.debug('optional plugin not available')

    # (o) 二进制语义差异分析
    baseline_path = kwargs.get('baseline_binary')
    if baseline_path:
        try:
            from modules.analysis.static.binary_diff.src.func_differ import diff_pipeline
            from modules.analysis.static.binary_diff.src.patch_classifier import classify_patch
            from modules.analysis.static.binary_diff.src.exploit_ranker import rank_patches
            result['_diff_baseline_path'] = baseline_path
            result['_diff_pipeline'] = diff_pipeline
            result['_classify_patch'] = classify_patch
            result['_rank_patches'] = rank_patches
            logger.debug("二进制差异分析已就绪，基线: %s", baseline_path)
        except ImportError:
            logger.debug('optional plugin not available')

    # (q) 跨合约污点流分析器
    try:
        from modules.platform.smart_contract.src.cross_contract_taint import (
            CrossContractTaintAnalyzer, CrossContractCallGraph,
            ContractCallEdge, CrossContractTaintPath,
        )
        result['_cross_contract_taint_analyzer'] = CrossContractTaintAnalyzer()
        logger.debug("跨合约污点流分析器已就绪（proxy解析+置信度衰减）")
    except ImportError:
        logger.debug('optional plugin not available')

    # (r) 崩溃原语多维指纹识别
    try:
        from core.crash_primitive_fingerprint import (
            fingerprint_crash, CrashFingerprint, PrimitiveType,
            RegisterControl, RegisterAnalysis, HeapOperationSequence,
        )
        result['_crash_fingerprinter'] = fingerprint_crash
        logger.debug("崩溃原语指纹识别已就绪（三维评分+寄存器可控性分类）")
    except ImportError:
        logger.debug('optional plugin not available')

    # 子寄存器污点追踪 (SubRegTaintState)
    try:
        from modules.core.compat.subreg_taint import (
            SubRegTaintState, propagate_subreg,
        )
        result['_subreg_taint_state'] = SubRegTaintState(
            merge_mode=kwargs.get('subreg_merge_mode', 'union'),
        )
        result['_subreg_propagate'] = propagate_subreg
        logger.debug('SubRegTaintState activated (merge_mode=%s)',
                    kwargs.get('subreg_merge_mode', 'union'))
    except ImportError:
        logger.debug('optional plugin not available')

    # 漂移校准器 (DriftCalibrator)
    try:
        from modules.core.compat.drift_calibrator import (
            DriftCalibrator, WeightImportanceTracker,
        )
        result['_drift_calibrator'] = DriftCalibrator()
        result['_weight_tracker'] = WeightImportanceTracker()
        logger.debug('DriftCalibrator activated (CUSUM + auto omega)')
    except ImportError:
        logger.debug('optional plugin not available')

    # CFG 熵指纹
    try:
        from modules.core.compat.cfg_entropy_fingerprint import (
            cfg_entropy_fingerprint, fingerprint_similarity,
        )
        result['_cfg_entropy_fn'] = cfg_entropy_fingerprint
        result['_fingerprint_similarity_fn'] = fingerprint_similarity
        logger.debug('CFG entropy fingerprint ready')
    except ImportError:
        logger.debug('optional plugin not available')

    # 编译器产物归一化器
    try:
        from modules.core.compat.compiler_artifact_normalizer import normalize_cfg
        result['_compiler_normalizer'] = normalize_cfg
        logger.debug('compiler artifact normalizer activated')
    except ImportError:
        logger.debug('optional plugin not available')

    # 跨层污点路由器
    try:
        from modules.core.compat.cross_layer_taint_router import (
            CrossLayerTaintRouter,
        )
        result['_cross_layer_taint_router'] = CrossLayerTaintRouter()
        logger.debug('CrossLayerTaintRouter activated')
    except ImportError:
        logger.debug('optional plugin not available')

    # ptmalloc2 堆状态机
    try:
        from modules.exploit.ptmalloc2_state_machine import Ptmalloc2StateMachine
        result['_ptmalloc2_state_machine'] = Ptmalloc2StateMachine(
            start_address=kwargs.get('heap_start_addr', 0x100000),
        )
        logger.debug('Ptmalloc2StateMachine activated')
    except ImportError:
        logger.debug('optional plugin not available')

    # EVM 重入检测器
    try:
        from modules.crypto.src.evm.reentrancy_detector import (
            EVMReentrancyDetector, EVMDisassembler,
        )
        result['_evm_reentrancy_detector'] = EVMReentrancyDetector()
        logger.debug('EVM 重入检测器已就绪（CALL/SSTORE 时序分析）')
    except ImportError:
        logger.debug('optional plugin not available')

    # 堆原语链搜索
    try:
        from modules.exploit.src.heap.primitive_chain.primitive_classifier import (
            classify_heap_ops,
        )
        from modules.exploit.src.heap.primitive_chain.chain_search import (
            search_primitive_chain, rank_chains,
        )
        from modules.exploit.src.heap.primitive_chain.allocator_constraints import (
            PTMalloc2Constraints,
        )
        result['_heap_primitive_classifier'] = classify_heap_ops
        result['_heap_chain_search'] = search_primitive_chain
        result['_heap_chain_ranker'] = rank_chains
        result['_heap_allocator_constraints'] = PTMalloc2Constraints()
        logger.debug("堆原语链搜索已就绪")
    except ImportError:
        logger.debug('optional plugin not available')

    # 二进制级常量时间验证
    try:
        from modules.analysis.static.const_time.src.const_time_pipeline import (
            verify_constant_time, ViolationSeverity,
        )
        result['_const_time_verifier'] = verify_constant_time
        result['_const_time_severity'] = ViolationSeverity
        logger.debug("常量时间验证器已就绪（二进制层）")
    except ImportError:
        logger.debug('optional plugin not available')

    # 堆分配器副作用补偿引擎
    try:
        from modules.exploit.src.heap.side_effect_compensator import (
            SideEffectPredictor, CompensationSynthesizer,
            predict_and_compensate,
        )
        result['_heap_side_effect_predictor'] = SideEffectPredictor()
        result['_heap_compensator'] = CompensationSynthesizer(
            max_ops=kwargs.get('compensator_max_ops', 5),
        )
        result['_heap_compensate_fn'] = predict_and_compensate
        logger.debug("堆副作用补偿引擎已激活")
    except ImportError:
        logger.debug('optional plugin not available')

    # 可解释二进制特征提取器
    try:
        from modules.analysis.static.binary_analysis.interpretable_features import (
            InterpretableFeatureExtractor, InvertedFeatureIndex,
            FunctionFeatures,
        )
        result['_interpretable_feature_extractor'] = InterpretableFeatureExtractor()
        result['_interpretable_feature_index'] = InvertedFeatureIndex()
        logger.debug("可解释特征提取器已激活")
    except ImportError:
        logger.debug('optional plugin not available')

    # E-Graph 等式饱和 MBA 简化器
    try:
        from modules.analysis.deobfuscation.egraph_mba_simplifier import EGraphMBASimplifier
        result['_egraph_mba_simplifier'] = EGraphMBASimplifier(
            max_iterations=kwargs.get('egraph_max_iter', 10),
            max_nodes=kwargs.get('egraph_max_nodes', 5000),
        )
        logger.debug("E-Graph MBA 简化器已激活 (等式饱和)")
    except ImportError:
        logger.debug('optional plugin not available')

    # 主动协议状态机推断器
    try:
        from modules.network.active_state_inferrer import (
            ActiveStateInferrer, generate_counterexample_candidates,
        )
        result['_active_state_inferrer'] = ActiveStateInferrer(
            membership_query=kwargs.get('protocol_mq_fn', lambda x: [0]),
            equivalence_check=kwargs.get('protocol_eq_fn'),
        )
        result['_counterexample_generator'] = generate_counterexample_candidates
        logger.debug("主动协议状态机推断器已激活 (L* adaptation)")
    except ImportError:
        logger.debug('optional plugin not available')

    # 表达式基元对齐微补丁生成器
    try:
        from modules.patching.expression_primitive_aligner import (
            PrimitiveDecomposer, BehavioralSignatureMatcher,
            MicroPatchGenerator, RelationalEquivalenceVerifier,
        )
        result['_primitive_decomposer'] = PrimitiveDecomposer()
        result['_behavioral_sig_matcher'] = BehavioralSignatureMatcher()
        result['_micropatch_generator'] = MicroPatchGenerator(
            patch_section_base=kwargs.get('patch_section_base', 0),
        )
        result['_relational_verifier'] = RelationalEquivalenceVerifier()
        logger.debug("表达式基元对齐器已激活 (源码→二进制微补丁)")
    except ImportError:
        logger.debug('optional plugin not available')

    # 引力模型对比学习二进制嵌入
    try:
        from modules.ai_ml.src.training.gravity_contrastive import (
            MomentumContrastEmbedder, build_gravity_model,
            GravityCFGNode, pretrain_step,
        )
        result['_moco_embedder'] = MomentumContrastEmbedder(
            embed_dim=kwargs.get('moco_dim', 64),
            queue_size=kwargs.get('moco_queue', 128),
            momentum=kwargs.get('moco_momentum', 0.999),
        )
        result['_gravity_build_fn'] = build_gravity_model
        result['_gravity_pretrain_fn'] = pretrain_step
        logger.debug("引力模型对比嵌入已激活 (MoCo + Gravity augment)")
    except ImportError:
        logger.debug('optional plugin not available')
