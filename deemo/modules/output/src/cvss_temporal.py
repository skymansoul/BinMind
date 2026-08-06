"""
CVSS 3.1 时间度量推断与计算。

依据:
  CVSS v3.1 Specification (FIRST.org) Temporal Metric Group。
  参考 CVSS-BT/CVSS-TE (github.com/t0sche/cvss-bt) 决策树组合方法，
  本项目针对二进制漏洞分析场景做裁剪:
    - 不依赖外部 CISA KEV / EPSS (离线可用)
    - 利用崩溃可利用性反向推断 Exploit Code Maturity
    - 利用分析置信度推断 Report Confidence

  EP3975080A1 时间序列方法: 按事件顺序映射 E/RL/RC 状态迁移，
  取其启发式规则，简化为静态快照。

修改记录:
  2025-07-17 16:41 - RL 推断加入 Ghidra 标注脚本存在性检查
"""

import logging
from typing import Dict, Optional, Tuple

_log = logging.getLogger(__name__)

# CVSS 3.1 时间度量枚举
# E: Exploit Code Maturity — X/H/F/P/U
# RL: Remediation Level — X/U/W/T/O
# RC: Report Confidence — X/C/R/U

# 各度量对应的基础分乘数因子 (CVSS 3.1 规范表)
_E_FACTORS = {'X': 1.00, 'U': 0.91, 'P': 0.94, 'F': 0.97, 'H': 1.00}
_RL_FACTORS = {'X': 1.00, 'U': 1.00, 'W': 0.97, 'T': 0.96, 'O': 0.95}
_RC_FACTORS = {'X': 1.00, 'U': 0.92, 'R': 0.96, 'C': 1.00}


def infer_exploit_maturity(
    crash_analysis: Optional[Dict],
    exploit_result: Optional[Dict],
    symbolic_result: Optional[Dict]
) -> str:
    """
    从分析上下文反向推断 Exploit Code Maturity。

    决策序 (优先级降序):
      H (High)              — 利用脚本验证通过且已获得 shell/code execution
      F (Functional)        — 脚本已产出但未验证，或崩溃输入可控
      P (Proof-of-Concept)  — 符号执行找到触发路径但无完整利用
      U (Unproven)          — 仅静态分析报出，无动态验证

    边界: 全部输入为 None 时返回 'U'。
    """
    if exploit_result and exploit_result.get('success'):
        # 验证通过 → 至少 Functional
        # 进一步确认是否有代码执行证据
        validation = exploit_result.get('validation', {})
        if validation.get('shell_obtained') or validation.get('code_execution'):
            return 'H'
        return 'F'

    if exploit_result and exploit_result.get('script_path'):
        # 已产出脚本但未经实际验证
        return 'F'

    if crash_analysis:
        combined = crash_analysis.get('combined', {})
        exploitability = combined.get('exploitability', '').lower()
        if 'high' in exploitability or 'probable' in exploitability:
            return 'F'
        if 'medium' in exploitability or 'possible' in exploitability:
            return 'P'

    if symbolic_result and symbolic_result.get('success'):
        crash_path = symbolic_result.get('crash_path', {})
        if crash_path.get('found') or crash_path.get('concrete_input'):
            return 'P'

    return 'U'


def infer_remediation_level(
    vuln_info: Optional[Dict],
    has_ghidra_script: bool = False,
    has_patch_info: bool = False
) -> str:
    """
    推断 Remediation Level。

    O (Official Fix)   — 已知补丁信息存在
    T (Temporary Fix)  — 已产出 Ghidra 标注脚本 (可视为临时缓解)
    W (Workaround)     — 报告中包含缓解建议
    U (Unavailable)    — 无修复信息

    Ghidra 脚本判为 Temporary Fix 而非 Official —
    标注不等同修补，但提供可操作审查入口。
    """
    if has_patch_info:
        return 'O'
    if has_ghidra_script:
        return 'T'
    if vuln_info and vuln_info.get('description'):
        desc_lower = vuln_info['description'].lower()
        if any(kw in desc_lower for kw in ('mitigation', 'workaround', 'disable', 'sanitize')):
            return 'W'
    return 'U'


def infer_report_confidence(
    ai_confidence: float = 0.0,
    evidence_chain_nodes: int = 0,
    has_crash_corroboration: bool = False
) -> str:
    """
    推断 Report Confidence — 多源印证计数。

    C (Confirmed)     — 多源印证 (分析 + 证据链 ≥ 2 + 崩溃确认)
    R (Reasonable)    — 双源印证
    U (Unknown)       — 单源或无证据链

    RC 直接决定时间评分权重: 确认报告全权重，未确认乘以 0.92。
    """
    sources = 1  # AI 分析始终算一源
    if evidence_chain_nodes >= 2:
        sources += 1
    if has_crash_corroboration:
        sources += 1
    if ai_confidence >= 0.85:
        sources += 1

    if sources >= 3:
        return 'C'
    if sources >= 2:
        return 'R'
    return 'U'


def compute_temporal_score(
    base_score: float,
    e: str = 'X',
    rl: str = 'X',
    rc: str = 'X'
) -> float:
    """
    CVSS 3.1 时间评分: Temporal = round_up(Base × E_factor × RL_factor × RC_factor)。
    """
    factor = _E_FACTORS.get(e, 1.0) * _RL_FACTORS.get(rl, 1.0) * _RC_FACTORS.get(rc, 1.0)
    # 复用 round_up: 向上取整至小数点后 1 位
    from math import ceil
    raw = base_score * factor
    return ceil(raw * 10) / 10.0


def build_temporal_vector(e: str, rl: str, rc: str) -> str:
    """拼接 CVSS 时间向量后缀，格式 '/E:F/RL:U/RC:R'。"""
    return f"/E:{e}/RL:{rl}/RC:{rc}"


def compute_full_temporal(
    base_score: float,
    crash_analysis: Optional[Dict] = None,
    exploit_result: Optional[Dict] = None,
    symbolic_result: Optional[Dict] = None,
    vuln_info: Optional[Dict] = None,
    has_ghidra_script: bool = False,
    ai_confidence: float = 0.0,
    evidence_chain_nodes: int = 0
) -> Dict:
    """
    一站式入口: 从分析上下文推断 E/RL/RC 三维时间度量并计算评分。

    返回 {base_score, temporal_score, e, rl, rc, vector_suffix}。
    全部度量为 X 时 temporal_score == base_score。
    """
    e = infer_exploit_maturity(crash_analysis, exploit_result, symbolic_result)
    rl = infer_remediation_level(vuln_info, has_ghidra_script)
    has_crash = bool(crash_analysis and crash_analysis.get('combined'))
    rc = infer_report_confidence(ai_confidence, evidence_chain_nodes, has_crash)

    temporal = compute_temporal_score(base_score, e, rl, rc)
    vector_suffix = build_temporal_vector(e, rl, rc)

    return {
        'base_score': base_score,
        'temporal_score': temporal,
        'exploit_maturity': e,
        'remediation_level': rl,
        'report_confidence': rc,
        'vector_suffix': vector_suffix,
    }
