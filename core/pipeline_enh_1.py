"""第1批可选增强: (a) 路径多样性管理。"""

import logging

logger = logging.getLogger(__name__)


def apply_enhancements_1(result, binary_path, binfo, kwargs, binary_hash=None):
    """应用第 1 批可选增强层。"""
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
            from modules.analysis.symbolic.src.path_diversity_core import (
                PathDiversityTracker, DiversityAwarePathSelector,
                DiversityStrategy,
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


