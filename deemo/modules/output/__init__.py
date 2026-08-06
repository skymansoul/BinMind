"""output/ — 报告构造与 Web API 交付层

子模块:
  report          — 报告构造器 (Markdown/JSON/HTML/PDF/SARIF)
  evidence_chain  — RAVEN/Veritas 证据链追踪 + Merkle 完整性绑定
  web_api         — FastAPI REST 服务端点
  src/
    report_core           — CVSS 评分/可视化/Ghidra 脚本构造
    report_formats        — JSON/HTML/PDF/SARIF 多格式序列化
    cvss_temporal         — CVSS 3.1 时间度量推断计算
    cvss_environmental    — CVSS 3.1 环境度量 (checksec → Modified Base)
    checksec_to_cvss      — checksec 加固状态 → CVSS 环境度量映射规则
    evidence_merkle       — Merkle 树证据完整性密码学层
    report_differ         — 增量分析发现差异比对引擎
    report_cache          — 内容寻址报告缓存 (输入哈希→输出路径)
    sarif_output          — SARIF v2.1.0 输出 (GitHub Code Scanning 集成)
    sarif_codeflows       — 证据链 → SARIF threadFlow 步骤映射
    cfg_entropy_fingerprint — CFG 结构熵指纹 + 圈复杂度漏洞预筛
    subreg_taint          — x86/x64 子寄存器级污点状态机
    drift_calibrator      — AI 置信度 Platt 标度 + 滑动窗口漂移检测
    evidence_fusion       — Dempster-Shafer 多源证据融合 (静态/fuzz/LLM/符号执行)
    evidence_mass_functions — D-S 源特化 mass 函数 (4个分析源各自的BPA映射)
    vuln_contagion        — 跨二进制漏洞传染风险图 (导入面重叠+加固差分)
    contagion_metrics     — 传染图度量函数 (导入重叠/符号亲密度/加固比)
    temporal_cvss_drift   — CVSS 时间评分漂移追踪 (衰减/增强双机制)
    drift_models          — 漂移追踪的数据模型 (快照/事件/状态枚举)
    patch_impact          — 补丁语义影响力验证 (CFG 可达性保持分析)
    patch_helpers         — 补丁分析辅助 (基本块签名/可达性估算)
    hardening_advisor     — Pareto 最优加固 ROI 顾问 (安全增益×重建成本)
    vuln_pattern_descriptor — 跨架构漏洞模式描述符 (伪C层特征, 规避ISA偏移)
    risk_surface          — 三层风险面映射器 (攻击面→漏洞→可利用性)
    fp_calibrator         — 贝叶斯序贯误报率校准 (证据源似然比驱动)
    remediation_scorer    — 二进制特化修复难度评分 (CFG+调用面+加固)
    vuln_lifespan         — 漏洞寿命估计 (Cox比例风险生存分析)
    opt_sensitivity       — 编译器优化敏感性评分 (死存储/内联/循环展开)
    primitive_quality     — 利用原语质量评分 (可控性×范围×可靠性×副作用)
    ipc_attack_surface    — 进程间IPC攻击面传播 (D-Bus/socket/shm/signal)
    sandbox_escape        — 沙箱逃逸难度评分 (seccomp×cap×namespace)
    delta_risk            — 增量更新风险评估 (新导入/新代码/加固退化)
    analysis_reliability  — 分析可靠度评分 (混淆/加壳/损坏置信度折扣)
    aslr_entropy          — ASLR 熵质量评估 (CCS 2024 基线校准)
    binary_bitrot         — 二进制比特腐烂评分 (编译年龄×依赖陈旧度)
    rop_gadget_quality    — ROP 小工具质量评分 (寄存器效应×语义分类)
    func_security_debt    — 函数级安全债务评分 (复杂度×复发×关键度)
    vuln_density_scaling  — 漏洞密度幂律标度 (期望值+离群检测)
    heap_exploitability   — 堆分配器特化可利用性 (ptmalloc/jemalloc/tcmalloc)
    stack_pivot           — 栈迁移难度评估 (小工具×寄存器约束×CFI惩罚)
    info_leak_quantify    — 信息泄露比特量化 (CCS 2024 关联熵+暴力破解)
    dead_code_audit       — 死代码攻击面审计 (未使用导入×段膨胀×符号膨胀)
    signal_attack_surface — 信号处理器攻击面映射 (sigaction×异步不安全)
    format_string_scorer  — 格式串漏洞精度评分 (偏移×%n×输出可见性)
    race_window           — 竞态窗口宽度估计 (指令间距→时间窗口)
    integer_overflow_triage — 整数溢出下游影响分类 (5级利用链)
    off_by_one_scorer     — Off-by-One 精度评分 (边界类型×相邻敏感度)
    uninitialized_memory_scorer — 未初始化内存影响评分 (残存类型×下游使用)
    null_deref_scorer     — 空指针解引用利用性 (用户/内核×读写×SMAP/SMEP)
    double_free_scorer    — Double-Free 利用性 (tcache key×fastbin检测)
    type_confusion_scorer — C++ 类型混淆利用性 (类层次×虚方法×vtable)
    buffer_underflow_scorer — 缓冲区下溢利用性 (位置×元数据×freelist)
    urgency_scorer        — 操作紧迫度评分 (利用×补丁×暴露面→时间-行动)
    response_timeline     — 事件响应时间线生成 (5阶段遏制→复盘)
    score_cross_validate  — 评分交叉验证 (模块间矛盾检测+元质量)
    unified_dashboard     — 统一风险仪表盘 (六维雷达+加权指数+趋势)
"""
from modules.output.report import ReportGenerator
from modules.output.evidence_chain_report import EvidenceChainReporter, EvidenceNode, ReportSection, ReportAudience
from modules.output.web_api import start_server

# 惰性导入: 减少启动时依赖解析开销
def get_evidence_merkle():
    from modules.output.src.evidence_merkle import build_merkle_tree, verify_inclusion_proof
    return build_merkle_tree, verify_inclusion_proof

def get_report_differ():
    from modules.output.src.report_differ import diff_findings, generate_diff_report
    return diff_findings, generate_diff_report

def get_sarif_generator():
    from modules.output.src.sarif_output import generate_sarif, write_sarif_file
    return generate_sarif, write_sarif_file

def get_cvss_environmental():
    from modules.output.src.cvss_environmental import compute_environmental_score
    return compute_environmental_score

def get_cfg_triage():
    from modules.output.src.cfg_entropy_fingerprint import compute_cfg_fingerprint, triage_functions, quick_filter
    return compute_cfg_fingerprint, triage_functions, quick_filter

def get_subreg_tracker():
    from modules.output.src.subreg_taint import SubRegTaintTracker, TaintState
    return SubRegTaintTracker, TaintState

def get_drift_calibrator():
    from modules.output.src.drift_calibrator import ConfidenceCalibrator
    return ConfidenceCalibrator

def get_evidence_fusion():
    from modules.output.src.evidence_fusion import (
        fuse_evidence, conflict_matrix, EvidenceSource
    )
    from modules.output.src.evidence_mass_functions import (
        mass_from_static, mass_from_fuzz, mass_from_llm, mass_from_symbex
    )
    return (fuse_evidence, mass_from_static, mass_from_fuzz,
            mass_from_llm, mass_from_symbex, conflict_matrix, EvidenceSource)

def get_drift_models():
    from modules.output.src.drift_models import (
        ChecksecSnapshot, TemporalEvent, DriftState, DriftDirection,
        EVENT_DEFAULT_MAGNITUDE
    )
    return ChecksecSnapshot, TemporalEvent, DriftState, DriftDirection, EVENT_DEFAULT_MAGNITUDE

def get_vuln_contagion():
    from modules.output.src.vuln_contagion import (
        assess_contagion, build_contagion_graph, contagion_summary,
        ContagionEdge
    )
    from modules.output.src.contagion_metrics import (
        compute_import_overlap, compute_symbol_proximity,
        compute_hardening_ratio, DEFAULT_WEIGHTS
    )
    return (assess_contagion, build_contagion_graph, contagion_summary,
            ContagionEdge, compute_import_overlap, compute_symbol_proximity,
            compute_hardening_ratio, DEFAULT_WEIGHTS)

def get_temporal_drift():
    from modules.output.src.temporal_cvss_drift import (
        TemporalDriftTracker, DriftState, DriftDirection
    )
    return TemporalDriftTracker, DriftState, DriftDirection

def get_patch_impact():
    from modules.output.src.patch_impact import (
        assess_patch, batch_assess, fix_summary, FixAssessment
    )
    from modules.output.src.patch_helpers import (
        bb_signature, BlockMatch, _estimate_reachable, _entry_candidates
    )
    return (assess_patch, batch_assess, fix_summary, FixAssessment,
            bb_signature, BlockMatch, _estimate_reachable, _entry_candidates)

def get_hardening_advisor():
    from modules.output.src.hardening_advisor import (
        compute_hardening_gains, pareto_frontier, recommend, HardeningOption
    )
    return compute_hardening_gains, pareto_frontier, recommend, HardeningOption

def get_vuln_pattern_descriptor():
    from modules.output.src.vuln_pattern_descriptor import (
        extract_pattern, pattern_cosine_similarity, cross_arch_match, VulnPattern
    )
    return extract_pattern, pattern_cosine_similarity, cross_arch_match, VulnPattern

def get_risk_surface():
    from modules.output.src.risk_surface import (
        compute_risk_surface, risk_summary, FunctionRisk
    )
    return compute_risk_surface, risk_summary, FunctionRisk

def get_fp_calibrator():
    from modules.output.src.fp_calibrator import (
        SequentialFpCalibrator, calibrate_from_fusion, CalibrationStep
    )
    return SequentialFpCalibrator, calibrate_from_fusion, CalibrationStep

def get_remediation_scorer():
    from modules.output.src.remediation_scorer import (
        score_remediation, batch_score, prioritize, RemediationScore
    )
    return score_remediation, batch_score, prioritize, RemediationScore

def get_vuln_lifespan():
    from modules.output.src.vuln_lifespan import (
        estimate_lifespan, batch_estimate, lifespan_summary, LifespanEstimate
    )
    return estimate_lifespan, batch_estimate, lifespan_summary, LifespanEstimate

def get_opt_sensitivity():
    from modules.output.src.opt_sensitivity import (
        score_optimization_sensitivity, batch_sensitivity,
        sensitivity_summary, OptSensitivity
    )
    return (score_optimization_sensitivity, batch_sensitivity,
            sensitivity_summary, OptSensitivity)

def get_primitive_quality():
    from modules.output.src.primitive_quality import (
        score_primitive, chain_potential, batch_score_primitives,
        PrimitiveQuality, PrimitiveType
    )
    return (score_primitive, chain_potential, batch_score_primitives,
            PrimitiveQuality, PrimitiveType)

def get_ipc_attack_surface():
    from modules.output.src.ipc_attack_surface import (
        map_ipc_surface, ipc_risk_summary, IpcEdge, IpcMechanism
    )
    return map_ipc_surface, ipc_risk_summary, IpcEdge, IpcMechanism

def get_sandbox_escape():
    from modules.output.src.sandbox_escape import (
        score_sandbox_escape, escape_summary, SandboxEscapeScore
    )
    return score_sandbox_escape, escape_summary, SandboxEscapeScore

def get_delta_risk():
    from modules.output.src.delta_risk import (
        assess_delta_risk, delta_risk_summary, DeltaRisk
    )
    return assess_delta_risk, delta_risk_summary, DeltaRisk

def get_analysis_reliability():
    from modules.output.src.analysis_reliability import (
        assess_reliability, ReliabilityScore
    )
    return assess_reliability, ReliabilityScore

def get_aslr_entropy():
    from modules.output.src.aslr_entropy import (
        assess_aslr_entropy, aslr_summary, AslrEntropyScore
    )
    return assess_aslr_entropy, aslr_summary, AslrEntropyScore

def get_binary_bitrot():
    from modules.output.src.binary_bitrot import (
        assess_bitrot, bitrot_summary, BitrotScore
    )
    return assess_bitrot, bitrot_summary, BitrotScore

def get_rop_gadget_quality():
    from modules.output.src.rop_gadget_quality import (
        score_gadget, score_gadgets, gadget_class_summary, GadgetQuality, GadgetClass
    )
    return score_gadget, score_gadgets, gadget_class_summary, GadgetQuality, GadgetClass

def get_func_security_debt():
    from modules.output.src.func_security_debt import (
        score_security_debt, debt_summary, SecurityDebt
    )
    return score_security_debt, debt_summary, SecurityDebt

def get_vuln_density_scaling():
    from modules.output.src.vuln_density_scaling import (
        assess_density, batch_density, density_summary, DensityScore
    )
    return assess_density, batch_density, density_summary, DensityScore

def get_heap_exploitability():
    from modules.output.src.heap_exploitability import (
        score_heap_exploitability, HeapExploitScore
    )
    return score_heap_exploitability, HeapExploitScore

def get_stack_pivot():
    from modules.output.src.stack_pivot import (
        assess_stack_pivot, pivot_summary, PivotDifficulty, PivotGadgetType
    )
    return assess_stack_pivot, pivot_summary, PivotDifficulty, PivotGadgetType

def get_info_leak_quantify():
    from modules.output.src.info_leak_quantify import (
        quantify_leak, leak_summary, LeakQuantification, LeakType
    )
    return quantify_leak, leak_summary, LeakQuantification, LeakType

def get_dead_code_audit():
    from modules.output.src.dead_code_audit import (
        audit_dead_code, bloat_summary, BloatAudit
    )
    return audit_dead_code, bloat_summary, BloatAudit

def get_signal_attack_surface():
    from modules.output.src.signal_attack_surface import (
        score_signal_risk, signal_surface_summary, SignalRisk,
        _detect_signal_usage
    )
    return score_signal_risk, signal_surface_summary, SignalRisk, _detect_signal_usage

def get_format_string_scorer():
    from modules.output.src.format_string_scorer import (
        score_format_string, FormatStringScore, FormatStringContext
    )
    return score_format_string, FormatStringScore, FormatStringContext

def get_race_window():
    from modules.output.src.race_window import (
        estimate_race_window, race_summary, RaceWindow, RaceType
    )
    return estimate_race_window, race_summary, RaceWindow, RaceType

def get_integer_overflow_triage():
    from modules.output.src.integer_overflow_triage import (
        triage_overflow, OverflowTriage, OverflowLevel
    )
    return triage_overflow, OverflowTriage, OverflowLevel

def get_off_by_one_scorer():
    from modules.output.src.off_by_one_scorer import (
        score_off_by_one, OffByOneScore, BoundaryType, AdjacentType
    )
    return score_off_by_one, OffByOneScore, BoundaryType, AdjacentType

def get_uninitialized_memory_scorer():
    from modules.output.src.uninitialized_memory_scorer import (
        score_uninitialized_memory, UninitMemoryScore,
        MemoryRegion, ResidualType, DownstreamUse
    )
    return (score_uninitialized_memory, UninitMemoryScore,
            MemoryRegion, ResidualType, DownstreamUse)

def get_null_deref_scorer():
    from modules.output.src.null_deref_scorer import (
        score_null_deref, NullDerefScore, DerefMode
    )
    return score_null_deref, NullDerefScore, DerefMode

def get_double_free_scorer():
    from modules.output.src.double_free_scorer import (
        score_double_free, DoubleFreeScore, ChunkSizeClass
    )
    return score_double_free, DoubleFreeScore, ChunkSizeClass

def get_type_confusion_scorer():
    from modules.output.src.type_confusion_scorer import (
        score_type_confusion, TypeConfusionScore, ConfusionKind, InheritanceType
    )
    return score_type_confusion, TypeConfusionScore, ConfusionKind, InheritanceType

def get_buffer_underflow_scorer():
    from modules.output.src.buffer_underflow_scorer import (
        score_buffer_underflow, UnderflowScore, UnderflowLocation
    )
    return score_buffer_underflow, UnderflowScore, UnderflowLocation

def get_urgency_scorer():
    from modules.output.src.urgency_scorer import (
        score_urgency, UrgencyScore, UrgencyLevel
    )
    return score_urgency, UrgencyScore, UrgencyLevel

def get_response_timeline():
    from modules.output.src.response_timeline import (
        generate_timeline, ResponseTimeline, TimelinePhase, PhaseType
    )
    return generate_timeline, ResponseTimeline, TimelinePhase, PhaseType

def get_score_cross_validate():
    from modules.output.src.score_cross_validate import (
        cross_validate, CrossValidation, Contradiction, ContradictionType
    )
    return cross_validate, CrossValidation, Contradiction, ContradictionType

def get_unified_dashboard():
    from modules.output.src.unified_dashboard import (
        generate_dashboard, RiskDashboard
    )
    return generate_dashboard, RiskDashboard


# 差分报告 / 多受众摘要 / 置信度校准 (2026 Q3 专利补齐)
def get_differential_report_generator():
    from modules.output.differential_report import DifferentialReportGenerator, Finding
    return DifferentialReportGenerator, Finding

def get_executive_summary_synthesizer():
    from modules.output.executive_summary import ExecutiveSummarySynthesizer, AnalysisResult
    return ExecutiveSummarySynthesizer, AnalysisResult

def get_confidence_calibrator():
    from modules.output.confidence_calibration import ConfidenceCalibrator, EvidenceChain
    return ConfidenceCalibrator, EvidenceChain
