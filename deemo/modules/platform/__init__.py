# platform/ 平台专项：固件、内核、硬件、移动端、恶意软件、智能合约
# 建立时间: 2025-07-20 11:08
# 修改记录:
# 2025-07-22 15:37 - 增加跨平台传播图和关联引擎的懒加载入口
# 2025-07-26 09:43 - 增加版本格和来源追踪模块
# 2025-08-01 17:14 - 导出符号整合，保持与 modules/__init__.py _FlatFinder 兼容
# 2025-08-02 14:28 - 增加风险评分器、平台协调器、差分-格桥接器入口
# 2025-08-03 16:05 - 增加跨层污点桥接器、统一CLI入口
#
# 懒加载入口 — 与 firmware/kernel/hardware 子包采用相同的 __getattr__ 模式。
# 模块首次访问时才 import，避免冷启动加载所有平台分析器。
# 注意：此文件不承担子包内部的懒加载，子包 __init__.py 各自管理符号表。

__all__ = [
    # 跨平台关联
    'PropagationGraph', 'PlatformLayer', 'VulnNode', 'PropagationEdge',
    'CrossPlatformCorrelator',
    # 版本演化
    'VersionLattice', 'VersionNode', 'VulnIntroductionWitness',
    # 来源追踪
    'ProvenanceGraph', 'ProvenanceNode', 'DependencyEdge',
    'ProvenanceLatticeIntegrator',
    # 风险评分与协调
    'RiskScorer', 'PlatformOrchestrator', 'OrchestratorReport',
    # 差分-格桥接
    'DiffLatticeBridge', 'ClassifiedDiff', 'DiffClassification',
    # 跨层污点追踪
    'TaintBridge', 'TaintHop', 'TaintPath', 'TaintHopDirection',
    'MMIOToRegisterMapper', 'TaintHopInferrer',
]


def __getattr__(name):
    _LAZY = {
        'PropagationGraph': ('.propagation_graph', 'PropagationGraph'),
        'PlatformLayer': ('.propagation_graph', 'PlatformLayer'),
        'VulnNode': ('.propagation_graph', 'VulnNode'),
        'PropagationEdge': ('.propagation_graph', 'PropagationEdge'),
        'CrossPlatformCorrelator': ('.cross_platform_correlator', 'CrossPlatformCorrelator'),
        'VersionLattice': ('.version_lattice', 'VersionLattice'),
        'VersionNode': ('.version_lattice', 'VersionNode'),
        'VulnIntroductionWitness': ('.version_lattice', 'VulnIntroductionWitness'),
        'ProvenanceGraph': ('.binary_provenance', 'ProvenanceGraph'),
        'ProvenanceNode': ('.binary_provenance', 'ProvenanceNode'),
        'DependencyEdge': ('.binary_provenance', 'DependencyEdge'),
        'ProvenanceLatticeIntegrator': ('.binary_provenance', 'ProvenanceLatticeIntegrator'),
        'RiskScorer': ('.risk_scorer', 'RiskScorer'),
        'PlatformOrchestrator': ('.platform_orchestrator', 'PlatformOrchestrator'),
        'OrchestratorReport': ('.platform_orchestrator', 'OrchestratorReport'),
        'DiffLatticeBridge': ('.diff_lattice_bridge', 'DiffLatticeBridge'),
        'ClassifiedDiff': ('.diff_lattice_bridge', 'ClassifiedDiff'),
        'DiffClassification': ('.diff_lattice_bridge', 'DiffClassification'),
        'TaintBridge': ('.taint_bridge', 'TaintBridge'),
        'TaintHop': ('.taint_bridge', 'TaintHop'),
        'TaintPath': ('.taint_bridge', 'TaintPath'),
        'TaintHopDirection': ('.taint_bridge', 'TaintHopDirection'),
        'MMIOToRegisterMapper': ('.taint_bridge', 'MMIOToRegisterMapper'),
        'TaintHopInferrer': ('.taint_hop_inferrer', 'TaintHopInferrer'),
    }
    if name in _LAZY:
        import importlib
        mod_path, attr = _LAZY[name]
        mod = importlib.import_module(mod_path, __package__)
        obj = getattr(mod, attr)
        # 缓存到模块全局，第二次访问走标准属性查找
        globals()[name] = obj
        return obj
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
