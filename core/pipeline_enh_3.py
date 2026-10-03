"""第3批可选增强: (p) 静态并发缺陷检测。"""

import logging

logger = logging.getLogger(__name__)


def apply_enhancements_3(result, binary_path, binfo, kwargs, binary_hash=None):
    """应用第 3 批可选增强层。"""
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
    # 参考: Intel SDM Vol.1; Brumley et al. BAP (CMU)
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
    # 参考: Gama et al. ACM CSUR; Page Biometrika
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
    # 参考: Caballero et al. USENIX Security 2009
    try:
        from modules.core.compat.compiler_artifact_normalizer import normalize_cfg
        result['_compiler_normalizer'] = normalize_cfg
        logger.debug('compiler artifact normalizer activated')
    except ImportError:
        logger.debug('optional plugin not available')

    # (u) 跨层污点路由器 (CrossLayerTaintRouter)
    # 参考: Caballero et al. USENIX Security 2009
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
    # DFA确定性堆布局预测。参考: glibc malloc/malloc.c; He et al. IEEE S&P 2023
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


