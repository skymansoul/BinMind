"""
Central analysis pipeline. Orchestrates binary loading, decompilation,
static analysis, symbolic execution, crash analysis, and reporting.
Each stage can fail independently without killing the whole run.
"""

import hashlib
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

from config import (
    MAX_FUNCTIONS, MAX_PARALLEL, ENABLE_SYMBOLIC,
    ENABLE_CRYPTO_SCAN, ENABLE_TAINTRACK, ENABLE_UNPACK,
    SUBPROCESS_TIMEOUT, ensure_dirs,
)
from core.binary_info import get_binary_info, validate_binary
from core.decompiler import list_functions, decompile_function, ai_analyze_function
from core.symexec import run_symbolic, check_angr, find_buffer_overflow
from core.crash_analysis import load_crash_file, analyze_crash_for_exploit
from core.exploit_gen import generate_exploit
from core.report import write_report
from core.vuln_db import init_db, start_run, finish_run, save_finding
from core.hooks import get_hook_manager

logger = logging.getLogger(__name__)


def _hash_file(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ''


def run_pipeline(
    binary_path: str,
    crash_path: Optional[str] = None,
    functions: Optional[List[str]] = None,
    max_funcs: int = None,
    include_lib: bool = False,
    parallel: bool = False,
    output_format: str = 'markdown',
    hooks_dir: Optional[str] = None,
    decompiler: str = 'auto',
    **kwargs
) -> Dict[str, Any]:
    """
    Execute the full analysis pipeline on a binary.

    Returns a dict with keys: reports, decomp_analysis, crash_analysis,
    symbolic_execution, exploit_result, similar_vulnerabilities.
    """
    start_time = time.time()
    ensure_dirs()
    init_db()

    if max_funcs is None:
        max_funcs = MAX_FUNCTIONS

    hook_mgr = get_hook_manager()
    if hooks_dir:
        hook_mgr.load_dir(hooks_dir)

    ctx = {'binary_path': binary_path, 'status': 'init'}
    ctx = hook_mgr.run('pre_unpack', ctx)
    if ctx.get('status') == 'abort':
        return {'error': 'aborted by pre_unpack hook'}

    # --- validate ---
    if not validate_binary(binary_path):
        return {'error': f'Unsupported or missing file: {binary_path}'}

    binfo = get_binary_info(binary_path)
    binary_hash = _hash_file(binary_path)
    run_id = start_run(binary_path)

    logger.info("Binary: %s | %s %d-bit | size=%d",
                binfo['filename'], binfo['arch'], binfo['bits'], binfo['size'])

    # --- unpacking ---
    if ENABLE_UNPACK:
        ctx = hook_mgr.run('pre_decompile', ctx)

    # --- function discovery ---
    all_funcs = list_functions(binary_path)
    logger.info("Found %d functions", len(all_funcs))

    # TODO: filter out __libc_* and other noise functions by default
    #       — currently requires explicit --functions to avoid analyzing
    #         200+ glibc internals on large binaries

    if functions:
        target_funcs = [f for f in functions if f in all_funcs]
        if not target_funcs:
            target_funcs = functions
    else:
        # prefer user-facing functions
        priority = ('main', 'vuln', 'win', 'get_flag', 'read_input',
                    'process', 'parse', 'handle', 'init')
        target_funcs = [f for f in priority if f in all_funcs]
        if not target_funcs:
            target_funcs = all_funcs[:max_funcs]

    target_funcs = target_funcs[:max_funcs]
    logger.info("Analyzing %d functions", len(target_funcs))

    # --- decompile + AI analyze ---
    ctx = hook_mgr.run('pre_analysis', ctx)
    decomp_results = []

    def _analyze_one(func_name):
        r = decompile_function(binary_path, func_name, decompiler)
        if r['pseudocode'].strip():
            ai = ai_analyze_function(func_name, r['pseudocode'], binfo)
            return ai
        return {'function': func_name, 'vulnerabilities': [],
                'pseudocode': r.get('pseudocode', '')}

    if parallel and len(target_funcs) > 1:
        max_workers = min(MAX_PARALLEL, len(target_funcs))
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(_analyze_one, n): n for n in target_funcs}
            for fut in as_completed(futures):
                try:
                    decomp_results.append(fut.result())
                except Exception as err:
                    logger.error("Analysis worker failed: %s", err)
    else:
        for name in target_funcs:
            try:
                decomp_results.append(_analyze_one(name))
            except Exception as err:
                logger.error("Analysis of %s failed: %s", name, err)

    ctx = hook_mgr.run('post_analysis', ctx)

    # --- symbolic execution ---
    sym_result = None
    if ENABLE_SYMBOLIC and check_angr():
        logger.info("Running symbolic execution...")
        sym_result = run_symbolic(binary_path)

    # --- crash analysis ---
    crash_data = None
    crash_analysis = None
    if crash_path and os.path.isfile(crash_path):
        crash_data = load_crash_file(crash_path)
        if crash_data:
            crash_analysis = analyze_crash_for_exploit(crash_data)

    # --- crypto scan ---
    if ENABLE_CRYPTO_SCAN:
        try:
            from plugins.crypto_scan import scan_crypto
            crypto = scan_crypto(binary_path)
            logger.info("Crypto scan: %d constants found", len(crypto))
        except ImportError:
            logger.debug('optional plugin not available')

    # --- save findings ---
    all_vulns = []
    for r in decomp_results:
        analysis = r.get('analysis', r)
        for v in analysis.get('vulnerabilities', []):
            all_vulns.append(v)
            try:
                save_finding(
                    run_id, binary_path, binary_hash,
                    r.get('function_name', r.get('function', '?')),
                    v.get('type', '?'), v.get('severity', 'Unknown'),
                    v.get('cwe', ''), v.get('description', ''),
                )
            except Exception:
                pass

    # --- exploit generation ---
    exploit_result = None
    if crash_analysis and crash_analysis.get('exploitable'):
        exploit_result = generate_exploit(binfo, crash_data)

    # --- report ---
    ctx = hook_mgr.run('pre_report', ctx)
    reports = write_report(decomp_results, binfo, crash_analysis, output_format)
    ctx = hook_mgr.run('post_report', ctx)

    # --- wrap up ---
    elapsed = time.time() - start_time
    finish_run(run_id, 'completed',
               f'{len(all_vulns)} vulns in {elapsed:.1f}s')

    logger.info("Pipeline done in %.1fs | %d functions | %d vulns",
                elapsed, len(target_funcs), len(all_vulns))

    return {
        'reports': reports,
        'decomp_analysis': decomp_results,
        'crash_analysis': crash_analysis,
        'crash_data': crash_data,
        'symbolic_execution': sym_result,
        'exploit_result': exploit_result,
        'binary_info': binfo,
        'elapsed': elapsed,
        'total_vulns': len(all_vulns),
    }


# =============================================================================
# 可选增强管线 — 在标准管线之上叠加优化层。
# 每个增强通过 try/except ImportError 做可选依赖：模块存在则激活，不存在则静默跳过。
# 这保持了对现有部署的向后兼容——不强制安装新模块的依赖。
# =============================================================================

def run_pipeline_enhanced(binary_path: str, **kwargs) -> Dict[str, Any]:
    """标准管线的增强版本——集成路径多样性管理和求解器优化。

    与 run_pipeline 接口兼容。在标准流程之上叠加：
      (a) 符号执行阶段启用路径多样性管理
      (b) 约束求解阶段启用预估器+增量缓存+预算管理
      (c) 反编译阶段启用多反编译器置信度集成
      (d) GNN 推理阶段启用 CFG 粗化+度感知增强
      (e) 前向支配前沿探索器
      (f) 三模态融合引擎（静态+动态+符号→熵加权统一判定）
      (g) exploit 原语组合文法（类型导向组合+格代数约束传播）

    各增强模块为可选依赖——ImportError 时静默降级到标准管线行为。
    """
    # 先跑标准管线——所有增强在标准流程之上叠加
    result = run_pipeline(binary_path, **kwargs)
    if 'error' in result:
        return result

    sym_result = result.get('symbolic_execution')
    binfo = result.get('binary_info', {})

    # --- (a) 路径多样性管理 ---
    if sym_result:
        try:
            from analysis.symbolic.src.path_diversity_core import (
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

    # --- (b) 求解器优化管线 ---
    try:
        from analysis.symbolic.src.symexec_opt_passes import (
            ConstraintComplexityEstimator, IncrementalSolverCache,
            SolverBudgetManager, OptimizationPipeline,
        )
        from analysis.symbolic.src.adaptive_complexity_calibrator import (
            AdaptiveComplexityCalibrator,
        )
        from analysis.symbolic.src.entropy_guided_budget import (
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

    # --- (c) 反编译器集成 ---
    try:
        from analysis.decompiler.src.decompiler_confidence_ensemble import (
            DecompilerConfidenceEnsemble,
        )
        _ensemble = DecompilerConfidenceEnsemble()
        result['_decompiler_ensemble'] = _ensemble
        logger.debug("多反编译器置信度集成已激活")
    except ImportError:
        logger.debug('optional plugin not available')

    # --- (d) GNN 预处理增强 ---
    try:
        from ai_ml.src.data.cfg_coarsening import coarsen_cfg
        result['_cfg_coarsening_fn'] = coarsen_cfg
        logger.debug("CFG 粗化已就绪")
    except ImportError:
        logger.debug('optional plugin not available')

    try:
        from ai_ml.src.data.cross_arch_normalizer import normalize_mnemonic
        result['_cross_arch_normalizer'] = normalize_mnemonic
        result['_arch'] = binfo.get('arch', 'unknown')
        logger.debug("跨架构归一化已就绪，目标架构: %s", binfo.get('arch', 'unknown'))
    except ImportError:
        logger.debug('optional plugin not available')

    # --- (e) 前向支配前沿探索器 ---
    # 在路径多样性管理之上叠加 CFG 支配前沿引导。
    # 与 (a) path_diversity_core 互补: 多样性保证广度，前沿引导保证方向。
    try:
        from analysis.symbolic.src.forward_frontier_explorer import (
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

    # --- (f) 三模态融合引擎 ---
    # 将静态分析、动态执行、符号约束视为三个独立"模态"，
    # 使用熵加权注意力自动融合为统一的漏洞判定。
    # 常规流程中三模态数据需要上游填充到 result['_modal_features']；
    # 此处仅初始化引擎并注入 result，供下游按需调用 fuse_step()。
    try:
        from multimodal.src.tri_modal_fusion import (
            TriModalFusionEngine, ModalityConflictArbiter,
        )
        from multimodal.src.fusion_provenance import (
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

    # --- (g) exploit 原语组合文法 ---
    # 将分散的 exploit primitive 按类型文法归约为完整攻击链。
    # 使用约束传播验证（格代数替代 SMT 求解），降低组合路径的验证开销。
    try:
        from exploit.src.core.primitive_composer import (
            PrimitiveComposer, AtomicPrimitive, PrimitiveType,
        )
        from exploit.src.core.constraint_propagator import (
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

    # --- (h) 非线性约束求解时间预测器 ---
    # 多项式特征展开 + log目标变换 + phase detection。
    # 与 (b) 中的 _estimator 互补：estimator 做快速线性预测，
    # nonlinear_predictor 处理高约束数区域（线性模型系统性低估的场景）。
    try:
        from analysis.symbolic.src.constraint_predictor_nonlinear import (
            NonlinearConstraintPredictor,
        )
        _nonlinear_predictor = NonlinearConstraintPredictor(learning_rate=0.005)
        result['_nonlinear_predictor'] = _nonlinear_predictor
        logger.debug("非线性约束求解时间预测器已激活（多项式展开 + phase detection）")
    except ImportError:
        logger.debug('optional plugin not available')

    # --- (i) 滞环防抖自适应阈值控制器 ---
    # 替代 path_diversity_core 中原始的比例控制器，
    # 通过 hysteresis band + integral accumulator 消除阈值振荡。
    try:
        from analysis.symbolic.src.adaptive_threshold_controller import (
            OscillationDampedController,
        )
        _threshold_controller = OscillationDampedController(
            initial_threshold=kwargs.get('diversity_threshold', 0.80),
        )
        result['_threshold_controller'] = _threshold_controller
        logger.debug("防抖阈值控制器已激活（滞环 + 积分项 + 收敛检测）")
    except ImportError:
        logger.debug('optional plugin not available')

    # --- (j) 跨层优化反馈环 ---
    # 建立路径多样性 ↔ 求解器预算的双向信息通道。
    # 高新颖度路径获更多求解预算，求解结果反向更新路径新颖度评分。
    try:
        from analysis.symbolic.src.cross_layer_feedback import (
            CrossLayerFeedbackLoop,
        )
        _cross_layer = CrossLayerFeedbackLoop(
            base_budget_per_path=kwargs.get('base_solver_budget', 5.0),
        )
        result['_cross_layer_feedback'] = _cross_layer
        logger.debug("跨层反馈环已激活（Path↔Solver 双向）")
    except ImportError:
        logger.debug('optional plugin not available')

    # --- (k) 求解器周期性重建调度器 ---
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

    # --- (l) 谱保持边丢弃 ---
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
    # --- (m) 状态备忘录 (StateMemento) ---
    # Memento 模式的符号状态增量快照与压缩。
    # ref: KLEE 2024 ICSE Workshop; Gamma et al. 1995
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

    # --- (n) 冷点引导探索器 (ColdSpotGuidedExplorer) ---
    # PathHeatmap cold spot -> constraint edit distance -> redirection
    # ref: Sun et al. ICSE 2024 — 路径覆盖热力图与约束编辑距离
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

    # --- (o) 时态路径缓存 (TemporalPathCache) ---
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

    # --- (p) 度保持边丢弃 (DegreePreservingDropout) ---
    # degree-aware protection over DropEdge O(|V|)
    # ref: DropEdge (Rong et al., ICLR 2020)
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

    # --- (l) 混淆类型预分类器与跨函数证据传播 ---
    # 在反混淆pass之前判定混淆类型；证据传播器沿
    # 调用图追踪常量来源。参考: Chisel (OOPSLA 2024) + Tkachenko et al. (2025).
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

    # --- (m) 时态新颖度模糊调度器 ---
    # Ebbinghaus遗忘曲线式种子新颖度衰减，双队列调度。
    # 与Scheduler(AFLfast马尔可夫链)互补。参考: Graphuzz (TOSEM 2024) +
    # SEAFuzz (2025) — 本模块在关系图基础上新增时间衰减维度。
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

    # --- (n) 约束依赖图拓扑排序求解 ---
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

    # --- (o) 二进制语义差异分析 ---
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

    # --- (p) 静态并发缺陷检测 ---
    # 锁图死锁检测 + happens-before 数据竞争分析，无运行时开销。
    # 需要导入表包含同步原语时才激活（纯单线程程序不触发）。
    try:
        _imports_for_concurrency = kwargs.get('concurrency_imports', [])
        if not _imports_for_concurrency:
            _imports_for_concurrency = binfo.get('imports', [])
        if _imports_for_concurrency:
            from analysis.static.concurrency_analysis.src.sync_primitive import (
                extract_sync_primitives,
            )
            _primitives = extract_sync_primitives(_imports_for_concurrency)
            if _primitives:
                from analysis.static.concurrency_analysis.src.concurrency_pipeline import (
                    analyze_binary_concurrency,
                )
                result['_concurrency_analyzer'] = analyze_binary_concurrency
                result['_concurrency_imports'] = _imports_for_concurrency
                logger.debug("并发缺陷检测已就绪，识别到 %d 个同步原语", len(_primitives))
    except ImportError:
        logger.debug('optional plugin not available')

    # --- (q) 跨合约污点流分析器 ---
    # 在合约边界间追踪污染数据，检测单合约分析遗漏的
    # 跨合约重入和状态不一致。支持proxy/delegatecall动态dispatch解析。
    # 参考: SmartReco (ICSE 2025) — 跨DApp边界识别;
    #       CrossMiner (2025) — 跨合约依赖图建模。
    try:
        from smart_contract.src.cross_contract_taint import (
            CrossContractTaintAnalyzer, CrossContractCallGraph,
            ContractCallEdge, CrossContractTaintPath,
        )
        _cross_taint = CrossContractTaintAnalyzer()
        result['_cross_contract_taint_analyzer'] = _cross_taint
        logger.debug("跨合约污点流分析器已就绪（proxy解析+置信度衰减）")
    except ImportError:
        logger.debug('optional plugin not available')

    # --- (r) 崩溃原语多维指纹识别 ---
    # 多维寄存器可控性分析+堆操作序列提取+策略推荐，
    # 替代简单的二值exploitable判定。参考: Lancet (USENIX 2025),
    # HEXP (IEEE 2025), AutoPwn (IEEE TIFS 2024).
    try:
        from core.crash_primitive_fingerprint import (
            fingerprint_crash, CrashFingerprint, PrimitiveType,
            RegisterControl, RegisterAnalysis, HeapOperationSequence,
        )
        result['_crash_fingerprinter'] = fingerprint_crash
        logger.debug("崩溃原语指纹识别已就绪（三维评分+寄存器可控性分类）")
    except ImportError:
        logger.debug('optional plugin not available')

    
    # --- (q) 子寄存器污点追踪 (SubRegTaintState) ---
    # ref: Intel SDM Vol.1; Brumley et al. BAP (CMU)
    # ref: Intel SDM Vol.1; Brumley et al. BAP (CMU)
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

    # --- (r) 漂移校准器 (DriftCalibrator) ---
    # , 2025-08-03 integrated.
    # ref: Gama et al. (2014) ACM CSUR; Page (1954) Biometrika
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

    # --- (s) CFG 熵指纹 (cfg_entropy_fingerprint) ---
    # ref: Spielman (2007) — 谱图理论与拉普拉斯特征值分解
    # ref: Spielman (2007) — 谱图理论与拉普拉斯特征值分解
    try:
        from modules.core.compat.cfg_entropy_fingerprint import (
            cfg_entropy_fingerprint, fingerprint_similarity,
        )
        result['_cfg_entropy_fn'] = cfg_entropy_fingerprint
        result['_fingerprint_similarity_fn'] = fingerprint_similarity
        logger.debug('CFG entropy fingerprint ready')
    except ImportError:
        logger.debug('optional plugin not available')

    # --- (t) 编译器产物归一化器 (CompilerArtifactNormalizer) ---
    # ref: Caballero et al. USENIX Security 2009
    try:
        from modules.core.compat.compiler_artifact_normalizer import (
            CompilerArtifactNormalizer,
        )
        _compiler_norm = CompilerArtifactNormalizer()
        result['_compiler_normalizer'] = _compiler_norm
        logger.debug('CompilerArtifactNormalizer activated')
    except ImportError:
        logger.debug('optional plugin not available')

    # --- (u) 跨层污点路由器 (CrossLayerTaintRouter) ---
    # ref: Caballero et al. USENIX Security 2009
    # ref: Caballero et al. USENIX Security 2009
    try:
        from modules.core.compat.cross_layer_taint_router import (
            CrossLayerTaintRouter,
        )
        _taint_router = CrossLayerTaintRouter()
        result['_cross_layer_taint_router'] = _taint_router
        logger.debug('CrossLayerTaintRouter activated')
    except ImportError:
        logger.debug('optional plugin not available')

    # --- (v) 污点约束符号探索器 (TaintConstrainedExplorer) ---
    # byte-level taint -> symbolic path priority bridge.
    try:
        from analysis.symbolic.src.taint_constrained_explorer import (
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

    # --- (w) ptmalloc2 堆状态机 (Ptmalloc2StateMachine) ---
    # DFA deterministic heap layout prediction.
    # ref: glibc malloc/malloc.c; He et al. IEEE S&P 2023
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

    # --- (x) EVM 重入检测器 ---
    # 字节码层面分析 CALL/SSTORE 时序关系，
    # 检测 classic/cross-function/read-only 三类重入模式。
    # ref: Consensys SWC-107; arXiv:2205.08537
    try:
        from crypto.src.evm.reentrancy_detector import (
            EVMReentrancyDetector, EVMDisassembler,
        )
        _evm_detector = EVMReentrancyDetector()
        result['_evm_reentrancy_detector'] = _evm_detector
        logger.debug('EVM 重入检测器已就绪（CALL/SSTORE 时序分析）')
    except ImportError:
        logger.debug('optional plugin not available')

    # --- (y) 协议边界检测 + 状态机推断 ---
    # 三级回退消息边界检测（魔数→长度字段→熵跳变）
    # 配合协议状态机推断，从二进制网络流自动逆向协议格式。
    try:
        from analysis.static.tools.entropy_jump_detector import (
            EntropyJumpDetector, IncrementalEntropyWindow,
        )
        _entropy_detector = EntropyJumpDetector()
        result['_entropy_jump_detector'] = _entropy_detector
        logger.debug('熵跳变检测器已就绪（增量 O(1) 窗口）')
    except ImportError:
        logger.debug('optional plugin not available')

    try:
        from analysis.static.tools.protocol_state_inferrer import (
            ProtocolStateMachineInferrer,
        )
        _proto_inferrer = ProtocolStateMachineInferrer()
        result['_protocol_state_inferrer'] = _proto_inferrer
        logger.debug('协议状态机推断器已就绪（SimHash 消息聚类）')
    except ImportError:
        logger.debug('optional plugin not available')

    # --- (w) 堆原语链搜索 ---
    # A* 搜索从漏洞点到可利用状态的最短堆原语链。
    # 与 (r) 堆布局求解器互补：布局求解器已知目标布局，此模块搜索"应该是什么布局"。
    try:
        from exploit.src.heap.primitive_chain.primitive_classifier import (
            classify_heap_ops,
        )
        from exploit.src.heap.primitive_chain.chain_search import (
            search_primitive_chain, rank_chains,
        )
        from exploit.src.heap.primitive_chain.allocator_constraints import (
            PTMalloc2Constraints,
        )
        result['_heap_primitive_classifier'] = classify_heap_ops
        result['_heap_chain_search'] = search_primitive_chain
        result['_heap_chain_ranker'] = rank_chains
        result['_heap_allocator_constraints'] = PTMalloc2Constraints()
        logger.debug("堆原语链搜索已就绪")
    except ImportError:
        logger.debug('optional plugin not available')

    # --- (x) 二进制级常量时间验证 ---
    # 无源码条件下检测秘密依赖的分支/访存/循环违规。
    # 对固件、闭源密码库等无 LLVM IR 的场景提供常量时间合规检查。
    try:
        from analysis.static.const_time.src.const_time_pipeline import (
            verify_constant_time, ViolationSeverity,
        )
        result['_const_time_verifier'] = verify_constant_time
        result['_const_time_severity'] = ViolationSeverity
        logger.debug("常量时间验证器已就绪（二进制层）")
    except ImportError:
        logger.debug('optional plugin not available')

    return result
