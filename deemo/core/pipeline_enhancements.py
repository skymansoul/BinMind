"""可选增强层 — 在标准管线上叠加的独立增强策略。
每个策略以 (result, binary_path, binfo, kwargs, binary_hash) 为输入, 在 result 上注入扩展对象;
所有模块为可选依赖, ImportError 时静默降级。ENHANCEMENT_STRATEGIES 维护策略映射。"""

import logging

logger = logging.getLogger(__name__)


def apply_diversity_and_solver_optimizations(result, binary_path, binfo, kwargs, binary_hash=None):
    """路径多样性管理、求解器优化、多反编译器集成与 GNN 预处理。"""
    import hashlib
    sym_result = result.get('symbolic_execution')

    def _hash_file(path):
        h = hashlib.sha256()
        try:
            with open(path, 'rb') as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            return h.hexdigest()
        except OSError:
            return ''

    # (a) 路径多样性管理
    if sym_result:
        try:
            # path_diversity_core 已重写, SimHashCalibrator/ConvergenceAnalyzer 不存在, 该增强当前跳过
            from modules.analysis.symbolic.src.path_diversity_core import (
                PathDiversityTracker, DiversityAwarePathSelector,
                DiversityStrategy, SimHashCalibrator, ConvergenceAnalyzer,
            )
            # 惰性初始化——仅在符号执行被激活时构造
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

        # 注册重校准回调——当预测精度退化时自动提升学习率
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
        _ensemble = DecompilerConfidenceEnsemble()
        result['_decompiler_ensemble'] = _ensemble
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
    # 在路径多样性管理之上叠加 CFG 支配前沿引导。
    # 与 (a) path_diversity_core 互补: 多样性保证广度，前沿引导保证方向。
    try:
        from modules.analysis.symbolic.src.forward_frontier_explorer import (
            ForwardFrontierExplorer,
        )
        _frontier_explorer = ForwardFrontierExplorer()
        result['_frontier_explorer'] = _frontier_explorer
        # 若 CFG 数据可用，自动加载到探索器中
        try:
            decomp_info = result.get('decomp_analysis', [])
            if decomp_info and hasattr(decomp_info[0], 'get'):
                # 尝试从反编译结果中提取 CFG 边和块信息
                _cfg_edges = {}
                _block_sizes = {}
                for func_info in decomp_info:
                    blocks = func_info.get('cfg_blocks', [])
                    for block in blocks:
                        addr = block.get('address', 0)
                        succs = block.get('successors', [])
                        if addr and succs:
                            _cfg_edges[addr] = [s.get('address', 0) for s in succs if s]
                        if addr and 'instruction_count' in block:
                            _block_sizes[addr] = block['instruction_count']
                if _cfg_edges:
                    # idom 可从 angr CFG 获取——此处留空让调用方按需填充
                    _frontier_explorer.load_cfg(
                        idom={},  # 调用方需从 angr CFG 填充
                        cfg_edges=_cfg_edges,
                        block_sizes=_block_sizes,
                    )
                    logger.debug("前向支配前沿探索器已激活 (%d 个 CFG 块)", len(_cfg_edges))
        except Exception as _cfg_err:
            logger.debug("CFG 加载跳过（探索器已就绪但未加载图）: %s", _cfg_err)
        logger.debug("前向支配前沿探索器已激活")
    except ImportError:
        logger.debug('optional plugin not available')

    # (f) 三模态融合引擎
    # 将静态分析、动态执行、符号约束视为三个独立"模态"，
    # 使用熵加权注意力自动融合为统一的漏洞判定。
    # 常规流程中三模态数据需要上游填充到 result['_modal_features']；
    # 此处仅初始化引擎并注入 result，供下游按需调用 fuse_step()。
    try:
        from modules.multimodal.src.tri_modal_fusion import (
            TriModalFusionEngine, ModalityConflictArbiter,
        )
        from modules.multimodal.src.fusion_provenance import (
            FusionProvenanceTracker, ProvenanceEdge,
        )

        _fusion_engine = TriModalFusionEngine(
            dim=kwargs.get('fusion_dim', 128),
            entropy_alpha=kwargs.get('fusion_alpha', 2.0),
        )
        _fusion_engine.begin_analysis(binary_hash or _hash_file(binary_path))

        result['_tri_modal_engine'] = _fusion_engine
        result['_modal_features'] = {}  # 上游按需填充 static/dynamic/symbolic
        logger.debug("三模态融合引擎已激活（熵加权注意力 + 冲突仲裁 + 溯源链）")
    except ImportError:
        logger.debug('optional plugin not available')

    # (g) exploit 原语组合文法
    # 将分散的 exploit primitive 按类型文法归约为完整攻击链。
    # 使用约束传播验证（格代数替代 SMT 求解），降低组合路径的验证开销。
    try:
        from modules.exploit.src.core.primitive_composer import (
            PrimitiveComposer, AtomicPrimitive, PrimitiveType,
        )
        from modules.exploit.src.core.constraint_propagator import (
            ConstraintPropagator, MachineState,
        )

        _composer = PrimitiveComposer(
            arch=binfo.get('arch', 'x86_64'),
            max_chain_depth=kwargs.get('composer_max_depth', 10),
        )
        result['_primitive_composer'] = _composer
        result['_constraint_propagator'] = ConstraintPropagator(
            arch=binfo.get('arch', 'x86_64'),
        )
        logger.debug("exploit 原语组合文法已就绪（类型导向组合 + 约束传播验证）")
    except ImportError:
        logger.debug('optional plugin not available')

    # (h) 非线性约束求解时间预测器
    # 多项式特征展开 + log目标变换 + phase detection。
    # 与 (b) 中的 _estimator 互补：estimator 做快速线性预测，
    # nonlinear_predictor 处理高约束数区域（线性模型系统性低估的场景）。
    try:
        from modules.analysis.symbolic.src.constraint_predictor_nonlinear import (
            NonlinearConstraintPredictor,
        )
        _nonlinear_predictor = NonlinearConstraintPredictor(learning_rate=0.005)
        result['_nonlinear_predictor'] = _nonlinear_predictor
        logger.debug("非线性约束求解时间预测器已激活（多项式展开 + phase detection）")
    except ImportError:
        logger.debug('optional plugin not available')

    # (i) 滞环防抖自适应阈值控制器
    # 替代 path_diversity_core 中原始的比例控制器，
    # 通过 hysteresis band + integral accumulator 消除阈值振荡。
    try:
        from modules.analysis.symbolic.src.adaptive_threshold_controller import (
            OscillationDampedController,
        )
        _threshold_controller = OscillationDampedController(
            initial_threshold=kwargs.get('diversity_threshold', 0.80),
        )
        result['_threshold_controller'] = _threshold_controller
        logger.debug("防抖阈值控制器已激活（滞环 + 积分项 + 收敛检测）")
    except ImportError:
        logger.debug('optional plugin not available')

    # (j) 跨层优化反馈环
    # 建立路径多样性 ↔ 求解器预算的双向信息通道。
    # 高新颖度路径获更多求解预算，求解结果反向更新路径新颖度评分。
    try:
        from modules.analysis.symbolic.src.cross_layer_feedback import (
            CrossLayerFeedbackLoop,
        )
        _cross_layer = CrossLayerFeedbackLoop(
            base_budget_per_path=kwargs.get('base_solver_budget', 5.0),
        )
        result['_cross_layer_feedback'] = _cross_layer
        logger.debug("跨层反馈环已激活（Path↔Solver 双向）")
    except ImportError:
        logger.debug('optional plugin not available')

def apply_solver_rebuild_scheduler(result, binary_path, binfo, kwargs, binary_hash=None):
    """求解器周期性重建调度。"""
    # (k) 求解器周期性重建调度器
    # 解决 IncrementalSolverCache 的 Z3 状态累积问题。
    # 成本预估 + 内存压力感知 + warm_start 传递。
    try:
        from modules.analysis.symbolic.src.solver_rebuild_scheduler import (
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
        from modules.ai_ml.src.data.spectral_edge_dropout import (
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
    try:
        from modules.analysis.symbolic.src.state_memento import StateMemento
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
    # 热力图冷点 → 约束编辑距离 → 路径重定向
    try:
        from modules.analysis.symbolic.src.coldspot_guided_explorer import (
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
    # 时态路径缓存并入增强管线
    try:
        from modules.analysis.symbolic.src.temporal_path_cache import TemporalPathCache
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
    # 度感知保护, 优于DropEdge O(|V|)
    try:
        from modules.ai_ml.src.augment.degree_preserving_dropout import (
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
    # 调用图追踪常量来源。
    try:
        from modules.analysis.deobfuscation.src.obfuscation_classifier import (
            ObfuscationClassifier, VoteTally,
        )
        _obf_classifier = ObfuscationClassifier()
        result['_obfuscation_classifier'] = _obf_classifier
        logger.debug("混淆类型预分类器已就绪（多特征融合投票）")
    except ImportError:
        logger.debug('optional plugin not available')

    try:
        from modules.analysis.deobfuscation.src.evidence_propagation import (
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
        from modules.fuzzing.src.decaying_novelty_scheduler import (
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
        from modules.analysis.symbolic.src.constraint_dependency_graph import (
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

def apply_static_concurrency_checks(result, binary_path, binfo, kwargs, binary_hash=None):
    """静态并发缺陷检查 (锁图死锁 + happens-before 竞争)。"""
    # (p) 静态并发缺陷检测
    # 锁图死锁检测 + happens-before 数据竞争分析，无运行时开销。
    # 需要导入表包含同步原语时才激活（纯单线程程序不触发）。
    try:
        _imports_for_concurrency = kwargs.get('concurrency_imports', [])
        if not _imports_for_concurrency:
            _imports_for_concurrency = binfo.get('imports', [])
        if _imports_for_concurrency:
            from modules.analysis.static.concurrency_analysis.src.sync_primitive import (
                extract_sync_primitives,
            )
            _primitives = extract_sync_primitives(_imports_for_concurrency)
            if _primitives:
                from modules.analysis.static.concurrency_analysis.src.concurrency_pipeline import (
                    analyze_binary_concurrency,
                )
                result['_concurrency_analyzer'] = analyze_binary_concurrency
                result['_concurrency_imports'] = _imports_for_concurrency
                logger.debug("并发缺陷检测已就绪，识别到 %d 个同步原语", len(_primitives))
    except ImportError:
        logger.debug('optional plugin not available')

    # (q) 跨合约污点流分析器
    # 在合约边界间追踪污染数据，检测单合约分析遗漏的
    # 跨合约重入和状态不一致。支持proxy/delegatecall动态dispatch解析。
    # SmartReco — 跨DApp边界识别; CrossMiner — 跨合约依赖图建模。
    try:
        from modules.platform.smart_contract.src.cross_contract_taint import (
            CrossContractTaintAnalyzer, CrossContractCallGraph,
            ContractCallEdge, CrossContractTaintPath,
        )
        _cross_taint = CrossContractTaintAnalyzer()
        result['_cross_contract_taint_analyzer'] = _cross_taint
        logger.debug("跨合约污点流分析器已就绪（proxy解析+置信度衰减）")
    except ImportError:
        logger.debug('optional plugin not available')

    # (r) 崩溃原语多维指纹识别
    # 多维寄存器可控性分析+堆操作序列提取+策略推荐，
    # 替代简单的二值exploitable判定。参考: Lancet,
    # HEXP, AutoPwn.
    try:
        from core.crash_primitive_fingerprint import (
            fingerprint_crash, CrashFingerprint, PrimitiveType,
            RegisterControl, RegisterAnalysis, HeapOperationSequence,
        )
        result['_crash_fingerprinter'] = fingerprint_crash
        logger.debug("崩溃原语指纹识别已就绪（三维评分+寄存器可控性分类）")
    except ImportError:
        logger.debug('optional plugin not available')


    # (q) 子寄存器污点追踪 (SubRegTaintState)
    try:
        from modules.core.compat.subreg_taint import (
            SubRegTaintState, propagate_subreg,
        )
        _subreg_state = SubRegTaintState(
            merge_mode=kwargs.get('subreg_merge_mode', 'union'),
        )
        result['_subreg_taint_state'] = _subreg_state
        result['_subreg_propagate'] = propagate_subreg
        logger.debug('SubRegTaintState activated (merge_mode=%s)',
                    kwargs.get('subreg_merge_mode', 'union'))
    except ImportError:
        logger.debug('optional plugin not available')

    # (r) 漂移校准器 (DriftCalibrator)
    try:
        from modules.core.compat.drift_calibrator import (
            DriftCalibrator, WeightImportanceTracker,
        )
        _drift_cal = DriftCalibrator()
        _weight_tracker = WeightImportanceTracker()
        result['_drift_calibrator'] = _drift_cal
        result['_weight_tracker'] = _weight_tracker
        logger.debug('DriftCalibrator activated (CUSUM + auto omega)')
    except ImportError:
        logger.debug('optional plugin not available')

    # (s) CFG 熵指纹 (cfg_entropy_fingerprint)
    # 参考: Spielman — 谱图理论与拉普拉斯特征值分解
    try:
        from modules.core.compat.cfg_entropy_fingerprint import (
            cfg_entropy_fingerprint, fingerprint_similarity,
        )
        result['_cfg_entropy_fn'] = cfg_entropy_fingerprint
        result['_fingerprint_similarity_fn'] = fingerprint_similarity
        logger.debug('CFG entropy fingerprint ready')
    except ImportError:
        logger.debug('optional plugin not available')

    # (t) 编译器产物归一化器 (CompilerArtifactNormalizer)
    try:
        from modules.core.compat.compiler_artifact_normalizer import (
            CompilerArtifactNormalizer,
        )
        _compiler_norm = CompilerArtifactNormalizer()
        result['_compiler_normalizer'] = _compiler_norm
        logger.debug('CompilerArtifactNormalizer activated')
    except ImportError:
        logger.debug('optional plugin not available')

    # (u) 跨层污点路由器 (CrossLayerTaintRouter)
    try:
        from modules.core.compat.cross_layer_taint_router import (
            CrossLayerTaintRouter,
        )
        _taint_router = CrossLayerTaintRouter()
        result['_cross_layer_taint_router'] = _taint_router
        logger.debug('CrossLayerTaintRouter activated')
    except ImportError:
        logger.debug('optional plugin not available')

    # (v) 污点约束符号探索器 (TaintConstrainedExplorer)
    # 字节级污点 → 符号路径优先级桥接。
    try:
        from modules.analysis.symbolic.src.taint_constrained_explorer import (
            TaintConstrainedExplorer,
        )
        _taint_explorer = TaintConstrainedExplorer(
            taint_decay_factor=kwargs.get('taint_decay', 0.85),
            direct_taint_weight=kwargs.get('taint_direct_weight', 1.0),
            indirect_taint_weight=kwargs.get('taint_indirect_weight', 0.6),
        )
        result['_taint_constrained_explorer'] = _taint_explorer
        logger.debug('TaintConstrainedExplorer activated (decay=%.2f)',
                    kwargs.get('taint_decay', 0.85))
    except ImportError:
        logger.debug('optional plugin not available')

    # (w) ptmalloc2 堆状态机 (Ptmalloc2StateMachine)
    # DFA确定性堆布局预测。
    try:
        from modules.exploit.ptmalloc2_state_machine import (
            Ptmalloc2StateMachine,
        )
        _heap_sm = Ptmalloc2StateMachine(
            start_address=kwargs.get('heap_start_addr', 0x100000),
        )
        result['_ptmalloc2_state_machine'] = _heap_sm
        logger.debug('Ptmalloc2StateMachine activated')
    except ImportError:
        logger.debug('optional plugin not available')

def apply_evm_reentrancy_check(result, binary_path, binfo, kwargs, binary_hash=None):
    """EVM 重入检测。"""
    # (x) EVM 重入检测器
    # 字节码层面分析 CALL/SSTORE 时序关系，
    # 检测 classic/cross-function/read-only 三类重入模式。
    # Consensys SWC-107
    try:
        from modules.crypto.src.evm.reentrancy_detector import (
            EVMReentrancyDetector, EVMDisassembler,
        )
        _evm_detector = EVMReentrancyDetector()
        result['_evm_reentrancy_detector'] = _evm_detector
        logger.debug('EVM 重入检测器已就绪（CALL/SSTORE 时序分析）')
    except ImportError:
        logger.debug('optional plugin not available')

    # (y) 协议边界检测 + 状态机推断
    # 三级回退消息边界检测（魔数→长度字段→熵跳变）
    # 配合协议状态机推断，从二进制网络流自动逆向协议格式。
    try:
        from modules.analysis.static.tools.entropy_jump_detector import (
            EntropyJumpDetector, IncrementalEntropyWindow,
        )
        _entropy_detector = EntropyJumpDetector()
        result['_entropy_jump_detector'] = _entropy_detector
        logger.debug('熵跳变检测器已就绪（增量 O(1) 窗口）')
    except ImportError:
        logger.debug('optional plugin not available')

    try:
        from modules.analysis.static.tools.protocol_state_inferrer import (
            ProtocolStateMachineInferrer,
        )
        _proto_inferrer = ProtocolStateMachineInferrer()
        result['_protocol_state_inferrer'] = _proto_inferrer
        logger.debug('协议状态机推断器已就绪（SimHash 消息聚类）')
    except ImportError:
        logger.debug('optional plugin not available')

    # (w) 堆原语链搜索
    # A* 搜索从漏洞点到可利用状态的最短堆原语链。
    # 与(r)堆布局求解器互补: 求解器面向已知目标布局, 本模块搜索候选布局。
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

    # (x) 二进制级常量时间验证
    # 无源码条件下检测秘密依赖的分支/访存/循环违规。
    # 对固件、闭源密码库等无 LLVM IR 的场景提供常量时间合规检查。
    try:
        from modules.analysis.static.const_time.src.const_time_pipeline import (
            verify_constant_time, ViolationSeverity,
        )
        result['_const_time_verifier'] = verify_constant_time
        result['_const_time_severity'] = ViolationSeverity
        logger.debug("常量时间验证器已就绪（二进制层）")
    except ImportError:
        logger.debug('optional plugin not available')

    # (y) 语义执行新颖度检测器 (SEND)
    # 运行时行为嵌入 + 特征哈希 + 滑动窗口余弦相似度。
    # 与 (m) decaying_novelty_scheduler 互补：后者做时间维度的 Ebbinghaus
    # 遗忘曲线，本模块做语义维度的行为新颖度检测。
    # 参考LLM引导语义模糊测试思路,
    # 但将 LLM 嵌入替换为确定性 feature hashing，消除外部模型依赖
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

    # (z) Thompson 采样多模糊器编排器
    # Bayesian bandit 在线学习 → 异构模糊器实例的动态 CPU 分配。
    # 与现有的 load_balancer.py / work_stealing_coordinator.py 互补：
    # 后者解决"均匀分配任务到同构 worker"，
    # 本模块解决"异质模糊器的非均匀资源分配"——不同模糊器对同一目标
    # 的产出率差异可能达 10x，均匀分配会浪费算力。
    # BandFuzz 多臂老虎机协作fuzzing思路,
    # 本项目将其推广到异构模糊器编排场景
    try:
        from modules.fuzzing.src.thompson_orchestrator import (
            ThompsonOrchestrator, make_crash_signature,
        )
        _orchestrator = ThompsonOrchestrator(
            default_interval=kwargs.get('thompson_interval', 300.0),
            min_allocation_ratio=kwargs.get('thompson_min_alloc', 0.05),
        )
        result['_thompson_orchestrator'] = _orchestrator
        result['_crash_signature_fn'] = make_crash_signature
        logger.debug("Thompson 采样编排器已激活")
    except ImportError:
        logger.debug('optional plugin not available')

    # (aa) 约束感知 def-use 链引导变异
    # 二进制级 def-use 重建 + Jaccard 聚类 + 约束引导的字节翻转。
    # 与 (g) primitive_composer 互补：primitive_composer 做 exploit 阶段
    # 的原语组合，本模块做 fuzzing 阶段的输入字节级定向变异。
    # 参考FuzzRDUCC def-use链覆盖思路,
    # 本项目在"重建"基础上增加约束引导赋值阶段
    try:
        from modules.fuzzing.src.defuse_mutation_guide import (
            ConstraintGuidedMutator, ConditionBranchCollector,
            defuse_guided_mutation_pipeline, BranchCoverageFingerprint,
        )
        _defuse_mutator = ConstraintGuidedMutator()
        _defuse_collector = ConditionBranchCollector()
        _branch_fingerprint = BranchCoverageFingerprint()
        result['_defuse_mutator'] = _defuse_mutator
        result['_defuse_collector'] = _defuse_collector
        result['_defuse_pipeline_fn'] = defuse_guided_mutation_pipeline
        result['_branch_fingerprint'] = _branch_fingerprint
        logger.debug("def-use 链引导变异已就绪")
    except ImportError:
        logger.debug('optional plugin not available')

    # (ab) 反事实变异优化器
    # Pearl SCM rung-3: 已知变异X→效果Y, 反事实推断"若做X'会如何"。
    # 将变异选择从随机探索升级为因果推断——现有变异器全在 rung-1/2。
    # Pearl "Causality" §7; DeCaF
    try:
        from modules.fuzzing.src.counterfactual_mutator import CounterfactualMutator
        _cf_mutator = CounterfactualMutator(
            max_history=kwargs.get('cf_max_history', 500),
        )
        result['_counterfactual_mutator'] = _cf_mutator
        logger.debug("反事实变异优化器已激活 (SCM rung-3)")
    except ImportError:
        logger.debug('optional plugin not available')

    # (ac) 对抗遗憾最小化变异集成
    # 8 种突变策略 → FTRL+Entropy 在线加权 → 对抗性非平稳环境的最优混合。
    # surprise bonus 检测逆预期高收益事件, regret monitor 检测策略退化。
    # 参考: Shalev-Shwartz (2012); Hazan (2016); Cesa-Bianchi & Lugosi (2006)
    try:
        from modules.fuzzing.src.regret_minimizing_ensemble import RegretMinimizingEnsemble
        _regret_ensemble = RegretMinimizingEnsemble(
            learning_rate=kwargs.get('regret_lr', 0.1),
            ent_lambda=kwargs.get('regret_ent_lambda', 0.01),
        )
        result['_regret_ensemble'] = _regret_ensemble
        logger.debug("遗憾最小化变异集成已激活 (FTRL+Entropy)")
    except ImportError:
        logger.debug('optional plugin not available')

    # (ad) 拓扑覆盖导航器
    # 持久同调 (Vietoris-Rips + single-linkage) 检测覆盖流形的拓扑空洞。
    # β₀ 连通分量追踪 + 前沿边界检测 → 识别未探索的程序行为区域。
    # 与 ISRG/PathCluster 互补: 前者看局部关系, TCN 看全局拓扑结构。
    # Edelsbrunner & Harer; Carlsson "Topology and Data"
    try:
        from modules.fuzzing.src.topological_coverage_navigator import (
            TopologicalCoverageNavigator, CoveragePoint, TopologicalFeature,
        )
        _topo_nav = TopologicalCoverageNavigator(
            epsilon=kwargs.get('topo_epsilon', 0.35),
            n_landmarks=kwargs.get('topo_landmarks', 64),
        )
        result['_topological_navigator'] = _topo_nav
        logger.debug("拓扑覆盖导航器已激活 (持久同调)")
    except ImportError:
        logger.debug('optional plugin not available')

def apply_llm_smt_hybrid_solver(result, binary_path, binfo, kwargs, binary_hash=None):
    """LLM-SMT 混合约束求解。"""
    # (ae) LLM-SMT 混合约束求解器
    # 约束分解 → LLM 草图生成 → SMT 验证 → 模板缓存。
    # 与 (b) symexec_opt_passes 的求解器优化互补: 后者优化 Z3 调用策略,
    # 本模块在 Z3 之前插入 LLM 草图层——利用语义理解跳过位级搜索。
    # LLM 不可用时自动降级为纯 Z3 求解。
    # 参考: LLM 路径约束求解思路
    try:
        from modules.analysis.symbolic.src.llm_smt_hybrid_solver import (
            LLMSMTHybridSolver, ConstraintTemplateCache,
        )
        _template_cache = ConstraintTemplateCache(max_size=128)
        _llm_smt_solver = LLMSMTHybridSolver(
            llm_callable=kwargs.get('llm_callable'),
            z3_factory=kwargs.get('z3_solver_factory'),
        )
        result['_llm_smt_solver'] = _llm_smt_solver
        result['_constraint_template_cache'] = _template_cache
        logger.debug("LLM-SMT 混合求解器已激活")
    except ImportError:
        logger.debug('optional plugin not available')

    # (af) 堆分配器副作用补偿引擎
    # 代数建模 ptmalloc2 副作用 (分裂/合并/bin迁移) →
    # 贪心合成最小补偿操作序列。
    # 与 (w) Ptmalloc2StateMachine 互补: 后者执行操作,
    # 本模块在执行前预测副作用并计算补偿。
    # 参考: Bagua ILP副作用消除; MAZE Dig&Fill 丢番图求解
    try:
        from modules.exploit.src.heap.side_effect_compensator import (
            SideEffectPredictor, CompensationSynthesizer,
            predict_and_compensate,
        )
        _heap_predictor = SideEffectPredictor()
        _heap_compensator = CompensationSynthesizer(
            max_ops=kwargs.get('compensator_max_ops', 5),
        )
        result['_heap_side_effect_predictor'] = _heap_predictor
        result['_heap_compensator'] = _heap_compensator
        result['_heap_compensate_fn'] = predict_and_compensate
        logger.debug("堆副作用补偿引擎已激活")
    except ImportError:
        logger.debug('optional plugin not available')

    # (ag) 可解释二进制特征提取器
    # 确定性模式匹配 + 轻量抽象解释 → 人类可读的函数特征。
    # 与现有 GNN embedding 互补: GNN 做语义近似搜索,
    # 本模块做精确特征标注 + 倒排索引快速精确检索。
    # 不依赖外部模型 API, 保持跨架构泛化能力
    try:
        from modules.analysis.static.binary_analysis.interpretable_features import (
            InterpretableFeatureExtractor, InvertedFeatureIndex,
            FunctionFeatures,
        )
        _ife_extractor = InterpretableFeatureExtractor()
        _ife_index = InvertedFeatureIndex()
        result['_interpretable_feature_extractor'] = _ife_extractor
        result['_interpretable_feature_index'] = _ife_index
        logger.debug("可解释特征提取器已激活")
    except ImportError:
        logger.debug('optional plugin not available')

    # (ah) E-Graph 等式饱和 MBA 简化器
    # 用 e-graph + 等式饱和替代传统固定规则代数重写。
    # 在指数级等价形式空间中通过 cost-guided extraction 找最简形式。
    # 与现有 mba_deobfuscator/semilinear_mba 互补: 后者做确定性规则链,
    # 本模块做非确定性搜索——发现固定规则无法触达的等价简化。
    # 参考: ProMBA; SaMBA; egg
    try:
        from modules.analysis.deobfuscation.egraph_mba_simplifier import (
            EGraphMBASimplifier,
        )
        _egraph_simplifier = EGraphMBASimplifier(
            max_iterations=kwargs.get('egraph_max_iter', 10),
            max_nodes=kwargs.get('egraph_max_nodes', 5000),
        )
        result['_egraph_mba_simplifier'] = _egraph_simplifier
        logger.debug("E-Graph MBA 简化器已激活 (等式饱和)")
    except ImportError:
        logger.debug('optional plugin not available')

    # (ai) 主动协议状态机推断器
    # L* 算法适配 Mealy 机 + 消息子类型发现 + 确定性 counterexample 生成。
    # 与现有 protocol_state_inferrer 互补: 后者被动观测 trace,
    # 本模块主动探测——发送 membership query 补全 trace 未覆盖的转换。
    # 参考: Act_Infer; Angluin L*; ICEPRE
    try:
        from modules.network.active_state_inferrer import (
            ActiveStateInferrer, generate_counterexample_candidates,
        )
        _active_inferrer = ActiveStateInferrer(
            membership_query=kwargs.get('protocol_mq_fn', lambda x: [0]),
            equivalence_check=kwargs.get('protocol_eq_fn'),
        )
        result['_active_state_inferrer'] = _active_inferrer
        result['_counterexample_generator'] = generate_counterexample_candidates
        logger.debug("主动协议状态机推断器已激活 (L* adaptation)")
    except ImportError:
        logger.debug('optional plugin not available')

    # (aj) 表达式基元对齐微补丁生成器
    # 源码 AST diff → 基元分解 → 行为签名匹配 → 二进制 trampoline 补丁。
    # 与现有 auto_patcher/patch_suggestion 互补: 后者生成源码补丁,
    # 本模块在无源码场景下将补丁映射到二进制层。
    try:
        from modules.patching.expression_primitive_aligner import (
            PrimitiveDecomposer, BehavioralSignatureMatcher,
            MicroPatchGenerator, RelationalEquivalenceVerifier,
        )
        _prim_decomposer = PrimitiveDecomposer()
        _sig_matcher = BehavioralSignatureMatcher()
        _micropatch_gen = MicroPatchGenerator(
            patch_section_base=kwargs.get('patch_section_base', 0),
        )
        _rel_verifier = RelationalEquivalenceVerifier()
        result['_primitive_decomposer'] = _prim_decomposer
        result['_behavioral_sig_matcher'] = _sig_matcher
        result['_micropatch_generator'] = _micropatch_gen
        result['_relational_verifier'] = _rel_verifier
        logger.debug("表达式基元对齐器已激活 (源码→二进制微补丁)")
    except ImportError:
        logger.debug('optional plugin not available')

    # (ak) 引力模型对比学习二进制嵌入
    # MoCo + 引力感知 CFG 增广 → 自监督预训练, 无需标注数据。
    # 两个增广视图通过引力模型(质量×质量/距离²)控制边丢弃,
    # InfoNCE 对比损失训练嵌入空间。与 (d) GNN 分类器互补:
    # 先自监督预训练 → 再微调下游任务 (CWE/CVE 分类)。
    # 参考: BEGA; MoCo; GraphCL
    try:
        from modules.ai_ml.src.training.gravity_contrastive import (
            MomentumContrastEmbedder, build_gravity_model,
            GravityCFGNode, pretrain_step,
        )
        _moco_embedder = MomentumContrastEmbedder(
            embed_dim=kwargs.get('moco_dim', 64),
            queue_size=kwargs.get('moco_queue', 128),
            momentum=kwargs.get('moco_momentum', 0.999),
        )
        result['_moco_embedder'] = _moco_embedder
        result['_gravity_build_fn'] = build_gravity_model
        result['_gravity_pretrain_fn'] = pretrain_step
        logger.debug("引力模型对比嵌入已激活 (MoCo + Gravity augment)")
    except ImportError:
        logger.debug('optional plugin not available')

    # (al) MMIO 外设模型推断
    # 从裸机固件自动推断 MMIO 寄存器类型 (T0-T4) + 外设边界 +
    # 中断向量表→ISR→MMIO 追溯。与现有 firmware_analyzer 互补:
    # 后者做通用固件解包/格式识别, 本模块做 MMIO 语义推断。
    # 参考: XtractIO; ES-Fuzz; μEmu
    try:
        from modules.platform.firmware.src.mmio_inference import (
            MMIORegister, MMIORegisterClassifier, Peripheral,
            detect_lms_patterns, infer_peripherals, link_isr_to_mmio,
        )
        _mmio_classifier = MMIORegisterClassifier()
        result['_mmio_classifier'] = _mmio_classifier
        result['_mmio_lms_detect_fn'] = detect_lms_patterns
        result['_mmio_peripheral_infer_fn'] = infer_peripherals
        result['_mmio_isr_link_fn'] = link_isr_to_mmio
        logger.debug("MMIO 外设推断已激活 (T0-T4 + LMS + ISR association)")
    except ImportError:
        logger.debug('optional plugin not available')

    # (am) 隐私保护漏洞情报共享
    # 本地差分隐私 (Local DP) + SimHash 相似性保持 + 联邦聚合。
    # 组织间共享漏洞数据无需可信中心——在本地加噪后共享,
    # 聚合时噪声相互抵消恢复人口统计。与现有 CVE/cve_kb 互补:
    # 后者做单方 CVE 管理, 本模块做多方隐私保护情报共享。
    # 参考: Dwork & Roth ε-DP; RAPPOR; DDP-SA
    try:
        from modules.cve.src.private_vuln_sharing import (
            VulnerabilityPrivatizer, FederatedAggregator,
            simhash_64, VulnerabilityRecord,
        )
        _vuln_privatizer = VulnerabilityPrivatizer(
            epsilon=kwargs.get('dp_epsilon', 1.0),
        )
        _vuln_aggregator = FederatedAggregator()
        result['_vuln_privatizer'] = _vuln_privatizer
        result['_vuln_aggregator'] = _vuln_aggregator
        result['_simhash_fn'] = simhash_64
        logger.debug("隐私保护漏洞共享已激活 (Local DP ε=%.1f)",
                    kwargs.get('dp_epsilon', 1.0))
    except ImportError:
        logger.debug('optional plugin not available')

    # (an) 流分叉分析重入检测器
    # 存储变量流追踪 + CALL前后分叉检测 → exploitable reentrancy判定。
    # 与现有 (x) EVMReentrancyDetector 互补: 后者做快速 CALL/SSTORE
    # 模式匹配 (高召回), 本模块做流分叉精确判定 (高精度)。
    # 参考: DivertScan; Oyente
    try:
        from modules.crypto.src.evm.flow_divergence_detector import (
            StorageFlowTracer, FlowDivergenceDetector,
            replay_evm_trace,
        )
        _flow_tracer = StorageFlowTracer()
        _flow_div_detector = FlowDivergenceDetector()
        result['_evm_flow_tracer'] = _flow_tracer
        result['_flow_divergence_detector'] = _flow_div_detector
        result['_evm_trace_replay_fn'] = replay_evm_trace
        logger.debug("流分叉重入检测器已激活")
    except ImportError:
        logger.debug('optional plugin not available')

def apply_ioctl_surface_mapping(result, binary_path, binfo, kwargs, binary_hash=None):
    """IOCTL 调度面静态映射。"""
    # (ao) IOCTL 调度面静态映射器
    # 零符号执行的二进制驱动 IOCTL 攻击面完整枚举。
    # CTL_CODE/_IOC 解码 + switch-case 分发表恢复 + buffered-input
    # 污点 sink 标记 + METHOD_NEITHER 风险分类。
    # 参考: Windows IOCTL Census; Linux IOCTL Census
    try:
        from modules.platform.kernel.ioctl_surface_mapper import (
            IOCTLSurfaceMapper, IOCTLDispatchTable,
            decode_windows_ioctl, decode_linux_ioctl,
        )
        _ioctl_mapper = IOCTLSurfaceMapper(
            os_type=kwargs.get('ioctl_os', 'windows'),
        )
        result['_ioctl_surface_mapper'] = _ioctl_mapper
        result['_ioctl_decode_windows'] = decode_windows_ioctl
        result['_ioctl_decode_linux'] = decode_linux_ioctl
        logger.debug("IOCTL 调度面映射器已激活")
    except ImportError:
        logger.debug('optional plugin not available')

    # (ap) API 时序图恶意软件行为嵌入
    # Markov 转移矩阵 + 时序窗口分解 + 单层 GCN 聚合 →
    # 固定维度行为嵌入用于恶意软件家族分类/相似搜索。
    # 与现有 malware_family_classifier 互补: 后者做静态特征分类,
    # 本模块做动态 API 调用序列的时序图嵌入。
    # 参考: GraphShield; AEGCN; MAMBA+
    try:
        from modules.platform.malware.temporal_api_graph import (
            build_markov_graph, decompose_sequence,
            embed_api_sequence, APIGraphIndex, MarkovAPIGraph,
        )
        _api_graph_index = APIGraphIndex(
            dim=kwargs.get('api_graph_dim', 32),
        )
        result['_api_graph_index'] = _api_graph_index
        result['_api_markov_build_fn'] = build_markov_graph
        result['_api_embed_fn'] = embed_api_sequence
        result['_api_decompose_fn'] = decompose_sequence
        logger.debug("API 时序图嵌入已激活")
    except ImportError:
        logger.debug('optional plugin not available')

    # (aq) 二进制级锁图 must-race 检测器
    # stripped binary 中原子指令模式识别锁函数 + lockset 分析 +
    # must-race vs may-race 分类。与现有 (p) 源码级并发检测互补:
    # 后者需要符号/debug 信息, 本模块在裸二进制 IR 层工作。
    # 参考: RacerF; RAProducer; Eraser
    try:
        from modules.analysis.static.concurrency_analysis.src.binary_lock_race import (
            LockGraphRaceDetector, identify_lock_functions,
            RaceSeverity,
        )
        _binary_race_detector = LockGraphRaceDetector()
        result['_binary_lock_race_detector'] = _binary_race_detector
        result['_binary_lock_identify_fn'] = identify_lock_functions
        logger.debug("二进制级锁图 race 检测器已激活 (must-race 分类)")
    except ImportError:
        logger.debug('optional plugin not available')

    # (ar) 加密 Merkle SBOM 构建器
    # 内容寻址防篡改 SBOM + Merkle inclusion proof 选择性披露。
    # 与现有 cve_sbom/cbom_generator 互补: 后者生成明文 SBOM,
    # 本模块提供加密完整性锚定 + 仅披露指定条目的证明。
    # 参考: Bomfather; VeriSBOM; Certificate Transparency (RFC 6962)
    try:
        from modules.data.src.merkle_sbom import (
            MerkleSBOM, SBOMEntry, MerkleProof, selective_disclosure,
        )
        _merkle_sbom = MerkleSBOM()
        result['_merkle_sbom'] = _merkle_sbom
        result['_merkle_selective_disclosure_fn'] = selective_disclosure
        logger.debug("加密 Merkle SBOM 已激活")
    except ImportError:
        logger.debug('optional plugin not available')

    # (as) SimHash LSH 函数搜索索引
    # 多表 SimHash LSH → O(L·K) 亚线性函数相似搜索。
    # 与现有 semantic_search/vector_search 互补: 后者遍历全量嵌入,
    # 本模块的多表 LSH 将查询降至常量复杂度, 与 N 无关。
    # 参考: Charikar — 动态查询修改
    try:
        from modules.data.src.lsh_function_index import (
            LSHFunctionIndex, build_function_embedding,
        )
        _lsh_index = LSHFunctionIndex(
            n_tables=kwargs.get('lsh_tables', 8),
            k_bits=kwargs.get('lsh_k_bits', 16),
            dim=kwargs.get('lsh_dim', 64),
        )
        result['_lsh_function_index'] = _lsh_index
        result['_lsh_embed_build_fn'] = build_function_embedding
        logger.debug("SimHash LSH 函数索引已激活 (%d 表 × %d bit)",
                    kwargs.get('lsh_tables', 8), kwargs.get('lsh_k_bits', 16))
    except ImportError:
        logger.debug('optional plugin not available')

    # (at) 二进制级推测执行小工具检测器
    # 多污点追踪 + 控制流标记 → Spectre v1/v2/v4 gadget 检测。
    # 分类 confirmed(必然可利用)/potential(条件触发)/false_alarm(过近似)。
    # 与现有 (x) const_time_verifier 互补: 后者检测泄露,
    # 本模块检测推测执行打破常量时间假设的场景。
    # 参考: SCOUT-CT; ExfilState; Spectre
    try:
        from modules.analysis.static.const_time.src.speculation_gadget_detector import (
            SpeculationTaintTracker, GadgetValidator,
            SpecGadget, GadgetType, Certainty,
        )
        _spec_tracker = SpeculationTaintTracker()
        _gadget_validator = GadgetValidator()
        result['_speculation_taint_tracker'] = _spec_tracker
        result['_speculation_gadget_validator'] = _gadget_validator
        logger.debug("推测执行小工具检测器已激活 (Spectre v1/v2/v4)")
    except ImportError:
        logger.debug('optional plugin not available')

    # (au) 嵌入式 DBI 追踪适配器
    # 离线 IR 重写 + 8 字节压缩追踪桩 + RISC-V/ARMv6M ISA 适配。
    # 与现有 instrumentation/dynamic_analysis 互补: 后者面向 x86/Linux,
    # 本模块针对 64KB SRAM 的 Cortex-M/RISC-V MCU。
    # 参考: R-Visor; Intel PT+DBI hybrid
    try:
        from modules.analysis.dynamic.engine.embedded_dbi_tracer import (
            EmbeddedDBIRewriter, TraceBuffer, TraceDecoder,
            ISAFamily,
        )
        _embedded_rewriter = EmbeddedDBIRewriter(
            isa=ISAFamily(kwargs.get('embedded_isa', 'armv7m')),
            trace_buf_size=kwargs.get('trace_buf_size', 4096),
        )
        result['_embedded_dbi_rewriter'] = _embedded_rewriter
        result['_trace_decoder'] = TraceDecoder()
        logger.debug("嵌入式 DBI 追踪器已激活 (ISA=%s)",
                    kwargs.get('embedded_isa', 'armv7m'))
    except ImportError:
        logger.debug('optional plugin not available')

    # (av) 执行上下文崩溃去重引擎
    # 三级去重: 精确签名 → 上下文嵌入余弦相似度 → LCA 根因验证。
    # 与现有 crash_lsh_dedup 互补: 后者做 LSH 粗筛,
    # 本模块增加执行轨迹嵌入维度——同一 bug 的不同路径正确合并。
    try:
        from modules.analysis.dynamic.engine.crash_context_dedup import (
            CrashContextDeduplicator, CrashRecord,
            make_crash_signature, bb_sequence_embedding,
        )
        _crash_dedup = CrashContextDeduplicator(
            context_threshold=kwargs.get('crash_dedup_threshold', 0.85),
        )
        result['_crash_context_dedup'] = _crash_dedup
        result['_crash_signature_fn'] = make_crash_signature
        result['_bb_embed_fn'] = bb_sequence_embedding
        logger.debug("上下文感知崩溃去重已激活 (threshold=%.2f)",
                    kwargs.get('crash_dedup_threshold', 0.85))
    except ImportError:
        logger.debug('optional plugin not available')

    # (aw) 反编译 I/O 等价性验证器
    # 三层递进验证: 重编译检查 → I/O concolic 测试 → 覆盖率匹配。
    # 替代 BLEU/edit distance 等与语义无关的语法指标。
    # 与现有 decompiler_confidence_ensemble 互补: 后者评估反编译器置信度,
    # 本模块验证反编译输出的实际语义正确性。
    # 参考: codealign; D-SCORE; DEBENCH
    try:
        from modules.analysis.decompiler.decomp_equivalence_verifier import (
            DecompEquivalenceVerifier, EquivalenceLevel,
            check_recompilability, generate_test_inputs,
        )
        _decomp_verifier = DecompEquivalenceVerifier()
        result['_decomp_equivalence_verifier'] = _decomp_verifier
        result['_decomp_test_inputs_fn'] = generate_test_inputs
        logger.debug("反编译等价性验证器已激活 (I/O behavior)")
    except ImportError:
        logger.debug('optional plugin not available')

    # (ax) 反分析技术加权检测器
    # 22 项指标库 × 加权可靠性评分 × 多样性奖励 → [0,100] 风险分。
    # 与现有 anti_analysis/anti_vm_bypass 互补: 后者做单一技术检测,
    # 本模块做系统化枚举 + 综合风险判定。
    # 参考: LibIHT; Sabri
    try:
        from modules.analysis.deobfuscation.anti_analysis_detector import (
            AntiAnalysisDetector, AntiAnalysisReport,
        )
        _anti_analysis_detector = AntiAnalysisDetector()
        result['_anti_analysis_detector'] = _anti_analysis_detector
        logger.debug("反分析技术检测器已激活 (22 indicators × weighted risk)")
    except ImportError:
        logger.debug('optional plugin not available')

def apply_patch_anchor_localization(result, binary_path, binfo, kwargs, binary_hash=None):
    """稳定锚点补丁定位。"""
    # (ay) 稳定锚点补丁定位器
    # cmp_imm/call_target/struct 三类语义常量锚点 → 贪心匹配 → 未匹配区域=补丁。
    # 与现有 binary_diff/block_matcher 互补: 后者做指令级相似度,
    # 本模块在跨编译器/优化级别场景下用语义常量锚点定位补丁。
    # 参考: PLocator; 1dFuzz
    try:
        from modules.analysis.static.binary_diff.src.patch_anchor_localizer import (
            extract_anchors, match_anchors, locate_patch_regions,
            StableAnchor, PatchCandidate,
        )
        result['_patch_anchor_extract_fn'] = extract_anchors
        result['_patch_anchor_match_fn'] = match_anchors
        result['_patch_anchor_locate_fn'] = locate_patch_regions
        logger.debug("稳定锚点补丁定位器已激活 (cross-compiler anchor matching)")
    except ImportError:
        logger.debug('optional plugin not available')

    # (az) 分治符号执行切片器
    # 后向数据流切片→独立切片符号执行→副作用摘要组合。
    # 从漏洞 sink 回溯, 自动裁剪 90%+ 无关代码, 每切片独立探索避免路径爆炸。
    # 参考: BinSleuth; Divide,Conquer&Verify
    try:
        from modules.analysis.symbolic.src.divide_conquer_slicer import (
            DivideConquerSymExec, build_dataflow_graph, backward_slice,
        )
        _dc_symexec = DivideConquerSymExec()
        result['_divide_conquer_symexec'] = _dc_symexec
        result['_dataflow_graph_builder'] = build_dataflow_graph
        result['_backward_slice_fn'] = backward_slice
        logger.debug("分治符号执行切片器已激活 (backward slicing)")
    except ImportError:
        logger.debug('optional plugin not available')

    # (ba) 风险调整模糊测试能量调度
    # Sharpe/Calmar/Martin 量化金融指标→风险调整种子能量分配。
    # 惩罚高波动性种子, 奖励稳定产出种——反直觉于传统平均收益调度。
    # Kummita & Bodden; Truzz; Sharpe
    try:
        from modules.fuzzing.src.risk_adjusted_schedule import (
            RiskAdjustedScheduler, SeedPerformanceHistory,
        )
        _risk_scheduler = RiskAdjustedScheduler(
            base_energy=kwargs.get('risk_base_energy', 100.0),
            risk_preference=kwargs.get('risk_preference', 0.6),
        )
        result['_risk_adjusted_scheduler'] = _risk_scheduler
        logger.debug("风险调整能量调度已激活 (Sharpe/Calmar/Martin)")
    except ImportError:
        logger.debug('optional plugin not available')

    # (bb) 路径转换图种子探索器
    # 覆盖状态哈希→Markov 转换模型→上下文感知种子选择 + 字节级验证检查保护。
    # 建模同一种子在不同程序状态下的有效性差异——突破 stationary 假设。
    # 参考: Truzz; PathFuzzing; SEAFuzz
    try:
        from modules.fuzzing.src.path_transition_explorer import (
            PathTransitionGraph, hash_coverage_state,
            context_aware_schedule,
        )
        _path_transition_graph = PathTransitionGraph()
        result['_path_transition_graph'] = _path_transition_graph
        result['_coverage_state_hash_fn'] = hash_coverage_state
        result['_context_aware_schedule_fn'] = context_aware_schedule
        logger.debug("路径转换图探索器已激活 (Markov state transition)")
    except ImportError:
        logger.debug('optional plugin not available')

    # (bc) Intel PT 覆盖位图重建器
    # 硬件 PT trace (TNT/TIP 包)→并行 PSB 分段解码→边覆盖位图→fuzzer 反馈。
    # 零运行时开销, 不可被反插桩检测——替代软件插桩 (Pin/DynamoRIO)。
    # LibIHT; HardTaint; PT+DBI hybrid
    try:
        from modules.analysis.dynamic.engine.intel_pt_coverage import (
            PTCoverageReconstructor, find_psb_boundaries,
            parse_pt_packets, bb_sequence_to_edge_bitmap,
        )
        _pt_recon = PTCoverageReconstructor(
            binary_base=kwargs.get('binary_base_addr', 0),
        )
        result['_pt_coverage_reconstructor'] = _pt_recon
        result['_pt_psb_finder'] = find_psb_boundaries
        result['_pt_packet_parser'] = parse_pt_packets
        logger.debug("Intel PT 覆盖重建器已激活 (hardware trace→edge bitmap)")
    except ImportError:
        logger.debug('optional plugin not available')

    # (bd) EVT 差分模糊测试风险估计器
    # GPD (广义 Pareto) 尾部拟合→残余差异数估计→早期停止策略。
    # 回答"还有多少 bug 没找到"——差分 fuzzing 的统计收敛判定。
    # ASE 2025 "Risk Estimation in Differential Fuzzing via EVT";
    # Coles (2001); Pickands (1975)
    try:
        from modules.fuzzing.src.evt_risk_estimator import (
            EVTRiskEstimator, fit_gpd, score_diff_severity,
        )
        _evt_estimator = EVTRiskEstimator(
            threshold_percentile=kwargs.get('evt_threshold_pct', 80.0),
        )
        result['_evt_risk_estimator'] = _evt_estimator
        result['_diff_severity_scorer'] = score_diff_severity
        logger.debug("EVT 风险估计器已激活 (GPD tail + early stopping)")
    except ImportError:
        logger.debug('optional plugin not available')

    # (be) 二进制语义差分 Oracle
    # 四维差分判定 (输出/覆盖/性能/系统调用)→差异分类+严重度评估。
    # 无需源码——纯黑盒 I/O+覆盖比较, 闭源二进制版本间的回归检测。
    # 参考: DDYF; DIFFSPEC; HyDiff
    try:
        from modules.analysis.dynamic.engine.semantic_diff_oracle import (
            SemanticDiffOracle, ExecutionSnapshot, DiffType,
            capture_execution,
        )
        _diff_oracle = SemanticDiffOracle(
            output_threshold=kwargs.get('diff_output_threshold', 0.99),
            coverage_threshold=kwargs.get('diff_coverage_threshold', 0.99),
        )
        result['_semantic_diff_oracle'] = _diff_oracle
        result['_execution_capture_fn'] = capture_execution
        logger.debug("语义差分 Oracle 已激活 (4-dim: output×coverage×perf×syscall)")
    except ImportError:
        logger.debug('optional plugin not available')

    # (bf) 行为级可利用性评分器
    # 五维运行时评分 (寄存器可控性+内存布局+保护状态+崩溃类型+输入可控性)
    # → 0-100 连续评分替代 CVSS 静态三档分类。
    # 与现有 crash_analysis/exploit_gen 互补: 后者做可利用性判定,
    # 本模块做连续量化评分 + 保护缺失枚举。
    # MS Exploitability Index; !exploitable; Lancet
    try:
        from core.behavioral_exploitability import (
            BehavioralExploitabilityScorer, RegisterState,
            ExploitabilityLevel,
        )
        _beh_scorer = BehavioralExploitabilityScorer()
        result['_behavioral_exploitability_scorer'] = _beh_scorer
        logger.debug("行为级可利用性评分器已激活 (5-dim behavioral scoring)")
    except ImportError:
        logger.debug('optional plugin not available')

    # (bg) 见证支持的崩溃根因定位器
    # 后向数据流切片→见证路径→evidence-weighted 最小 blame 集 ranking。
    # 从崩溃 symptom 追溯到 root cause——O(30) 步 use-def 回溯。
    # 与现有 crash_analysis 互补: 后者报告崩溃点, 本模块报告根因函数。
    # 参考: Veritas; Kumushi; AutoCrashFL
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

    # (bh) 崩溃变体生成器
    # 受控变异 (长度字段+padding)+覆盖引导变异→多个相关崩溃→LCA三角化根因。
    # 与现有 crash_analysis 互补: 后者分析单个崩溃, 本模块从单个 PoC 生成变体族。
    # Kumushi crash exploration; AFL++ crash exploration mode
    try:
        from modules.analysis.dynamic.engine.crash_variant_generator import (
            CrashVariantGenerator, triangulate_root_cause,
            CrashVariant, TriangulationResult,
        )
        _variant_gen = CrashVariantGenerator()
        result['_crash_variant_generator'] = _variant_gen
        result['_crash_triangulate_fn'] = triangulate_root_cause
        logger.debug("崩溃变体生成器已激活 (controlled mutation + triangulation)")
    except ImportError:
        logger.debug('optional plugin not available')

def apply_struct_layout_recovery(result, binary_path, binfo, kwargs, binary_hash=None):
    """访问模式结构体布局恢复。"""
    # (bi) 访问模式结构体布局恢复
    # n-gram 内存访问模式→字段边界推断→C struct 生成, 无需 ML 训练。
    # 与现有 type_inferrer/precise_vtable_recovery 互补: 后者做虚表/类型推断,
    # 本模块做完整 struct 布局恢复 (字段偏移+类型+对齐)。
    # 参考: XTRIDE; ReSym; TYGR
    try:
        from modules.analysis.static.binary_analysis.struct_layout_recovery import (
            StructLayoutRecoverer, collect_struct_accesses,
            infer_field_boundaries,
        )
        _struct_recoverer = StructLayoutRecoverer()
        result['_struct_layout_recoverer'] = _struct_recoverer
        result['_struct_access_collector'] = collect_struct_accesses
        result['_struct_boundary_inferrer'] = infer_field_boundaries
        logger.debug("结构体布局恢复器已激活 (access pattern → C struct)")
    except ImportError:
        logger.debug('optional plugin not available')

    # (bj) 自适应漏洞利用策略选择器
    # 二进制指纹(保护/原语/gadgets)→8条策略前提条件评估→composite排序。
    # 自动适配目标特性, 替代硬编码策略或人工选择。
    # ARCANIST; PBAEG
    try:
        from modules.exploit.src.strategy.adaptive_exploit_selector import (
            AdaptiveExploitSelector, BinaryFingerprint, StrategyKind,
            assess_strategy,
        )
        _exploit_selector = AdaptiveExploitSelector()
        result['_adaptive_exploit_selector'] = _exploit_selector
        result['_strategy_assess_fn'] = assess_strategy
        logger.debug("自适应利用策略选择器已激活 (8 strategies × precondition check)")
    except ImportError:
        logger.debug('optional plugin not available')

    # (bk) 法定人数共识引擎
    # BFT 风格加权法定人数 (≥2/3)→分布式分析节点结果聚合+冲突分解。
    # 容忍 f 个 Byzantine 节点 (N≥3f+1)——解决不同分析工具结果冲突。
    # PBFT; ensemble weighted voting
    try:
        from modules.distributed.src.quorum_consensus import (
            QuorumConsensusEngine, NodeWeightTracker,
            weighted_quorum_vote,
        )
        _quorum_engine = QuorumConsensusEngine()
        result['_quorum_consensus_engine'] = _quorum_engine
        result['_quorum_vote_fn'] = weighted_quorum_vote
        logger.debug("法定人数共识引擎已激活 (BFT weighted quorum ≥2/3)")
    except ImportError:
        logger.debug('optional plugin not available')

    # (bl) Trampoline 二进制函数钩子重写器
    # 函数入口 jmp→trampoline(保存上下文→调用钩子→恢复→重放原指令→跳回)。
    # x86-64 + ARM64 双架构支持, 原子 8-byte jmp 写入避免多线程竞争。
    # ASC-Hook; DIBE; zpoline
    try:
        from modules.analysis.dynamic.engine.trampoline_hook import (
            TrampolineHookRewriter, generate_x86_64_trampoline,
            generate_arm64_trampoline, Arch,
        )
        _hook_rewriter = TrampolineHookRewriter(
            arena_base=kwargs.get('trampoline_arena', 0x70000000),
        )
        result['_trampoline_hook_rewriter'] = _hook_rewriter
        result['_trampoline_x86_gen'] = generate_x86_64_trampoline
        result['_trampoline_arm64_gen'] = generate_arm64_trampoline
        logger.debug("Trampoline 钩子重写器已激活 (x86-64 + ARM64)")
    except ImportError:
        logger.debug('optional plugin not available')

    # (bm) 编译器/工具链元数据指纹识别
    # 字符串+代码惯用法+尾声模式→贝叶斯融合→编译器+版本+O级别+语言方言。
    # 与现有 compiler_fingerprint 互补: 后者做粗粒度识别, 本模块做版本/O级细粒度。
    try:
        from modules.analysis.static.tools.compiler_fingerprinter import (
            CompilerFingerprinter, CompilerFingerprint,
            detect_from_strings, detect_from_code_idioms,
            detect_from_epilogue_patterns,
        )
        _compiler_fp = CompilerFingerprinter()
        result['_compiler_fingerprinter'] = _compiler_fp
        result['_compiler_string_detect'] = detect_from_strings
        result['_compiler_idiom_detect'] = detect_from_code_idioms
        logger.debug("编译器指纹识别器已激活 (strings+idioms+epilogue→Bayesian fusion)")
    except ImportError:
        logger.debug('optional plugin not available')

    # (bn) 空间覆盖热力图生成器
    # 边覆盖位图→地址空间 256B bucket 密度聚合→冷热点分类→冷热边界检测。
    # 与现有 coverage/edge_coverage 互补: 后者报告覆盖统计, 本模块做空间可视化。
    # AFL++ collision-free coverage; DrCov (DynamoRIO)
    try:
        from modules.output.src.coverage_heatmap import (
            CoverageHeatmapGenerator, aggregate_heatmap,
            suggest_coldspot_targets,
        )
        _heatmap_gen = CoverageHeatmapGenerator(
            bucket_size=kwargs.get('heatmap_bucket_size', 256),
        )
        result['_coverage_heatmap_generator'] = _heatmap_gen
        result['_coldspot_suggester'] = suggest_coldspot_targets
        logger.debug("覆盖热力图生成器已激活 (spatial coverage→hot/cold boundary)")
    except ImportError:
        logger.debug('optional plugin not available')

    # (bo) IR 提升质量评估器
    # 虚拟栈检测 + 内存模型保真度 + 分析适用性 → 0-100 质量评分。
    # 无源码 ground truth 的自动化 IR 质量度量。
    # An & Lee; RetDec/McSema IR formats
    try:
        from modules.analysis.static.binary_analysis.ir_lifting_quality import (
            IRLiftingQualityEvaluator, IRQualityReport,
        )
        _ir_quality_evaluator = IRLiftingQualityEvaluator()
        result['_ir_lifting_quality_evaluator'] = _ir_quality_evaluator
        logger.debug("IR 提升质量评估器已激活 (virtual stack + memory fidelity)")
    except ImportError:
        logger.debug('optional plugin not available')

    # (bp) 前向边 CFI 插桩器
    # 间接调用定位 + 函数类型恢复 + landing pad 插入。
    # COTS 剥离二进制的纯软件前向边控制流完整性保护。
    # 参考: MOBIUS; Branch Landing
    try:
        from modules.analysis.static.binary_analysis.forward_edge_cfi import (
            ForwardEdgeCFI, locate_indirect_calls,
            infer_function_signatures,
        )
        _cfi = ForwardEdgeCFI(arch=kwargs.get('cfi_arch', 'x86_64'))
        result['_forward_edge_cfi'] = _cfi
        result['_cfi_call_locator'] = locate_indirect_calls
        logger.debug("前向边 CFI 已激活 (software forward-edge protection)")
    except ImportError:
        logger.debug('optional plugin not available')

    # (bq) DFG 子图同构函数匹配
    # 数据流图构建 → 2-hop 邻域哈希 → 贪心拓扑扩展 → 跨架构相似度。
    # 基于 def-use 依赖的语义匹配——比 CFG 跨编译器/优化级别更稳定。
    # CSB; VxWolf/BinDiff
    try:
        from modules.analysis.static.binary_diff.src.dfg_isomorphism_match import (
            build_dfg_from_instructions, compute_dfg_similarity,
            DFGGraph, DFGNode,
        )
        result['_dfg_builder_fn'] = build_dfg_from_instructions
        result['_dfg_similarity_fn'] = compute_dfg_similarity
        logger.debug("DFG 子图同构匹配已激活 (def-use isomorphism)")
    except ImportError:
        logger.debug('optional plugin not available')


ENHANCEMENT_STRATEGIES = {
    'diversity_solver_optimization': apply_diversity_and_solver_optimizations,
    'solver_rebuild': apply_solver_rebuild_scheduler,
    'static_concurrency': apply_static_concurrency_checks,
    'evm_reentrancy': apply_evm_reentrancy_check,
    'llm_smt_hybrid': apply_llm_smt_hybrid_solver,
    'ioctl_surface': apply_ioctl_surface_mapping,
    'patch_anchor': apply_patch_anchor_localization,
    'struct_layout': apply_struct_layout_recovery,
}


def run_enhancement_strategies(result, binary_path, binfo, kwargs,
                               binary_hash=None, strategies=None):
    """按序应用指定或全部增强策略, 单策略失败不影响其余策略。"""
    if strategies is None:
        strategies = list(ENHANCEMENT_STRATEGIES.values())
    for apply in strategies:
        try:
            apply(result, binary_path, binfo, kwargs, binary_hash)
        except ImportError:
            logger.debug('optional enhancement module not available')
