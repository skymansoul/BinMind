"""第4批可选增强: (x) EVM 重入检测器。"""

import logging

logger = logging.getLogger(__name__)


def apply_enhancements_4(result, binary_path, binfo, kwargs, binary_hash=None):
    """应用第 4 批可选增强层。"""
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
            ProtocolStateInferrer,
        )
        _proto_inferrer = ProtocolStateInferrer()
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
    # 参考LLM引导语义模糊测试思路, 但将LLM嵌入替换为确定性feature hashing，
    # 消除外部模型依赖
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
    # BandFuzz 多臂老虎机协作fuzzing思路, 本项目将其推广到异构模糊器编排场景
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
    # 参考FuzzRDUCC def-use链覆盖思路, 本项目在"重建"基础上增加约束引导赋值阶段
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
    # 参考: Pearl (2009) "Causality" §7; DeCaF
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
    # FIX: 2026-08-15 原引用行缺 # 前缀, 挂载后执行期 NameError, 转为注释
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
    # Edelsbrunner & Harer (2010); Carlsson (2009) "Topology and Data"
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


