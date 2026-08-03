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
