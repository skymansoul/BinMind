"""
操作紧迫度评分 — 利用公开性×补丁可用性×组织暴露面的时间-行动映射。

问题定义:
  CVSS temporal (E/RL/RC) 度量漏洞状态的三个方面，但不输出
  "你应该在 N 小时内行动"。安全团队需要操作级紧迫度:
    - 利用已公开 + 无补丁 + 互联网暴露 → 立即行动 (0-4h)
    - 利用理论 + 补丁可用 + 内网 → 常规排期 (7-30d)

  本模块将技术评分转化为操作级时间-行动指令。

  四维紧迫度:
    1. 利用成熟度 (从 temporal_cvss_drift 获取)
    2. 补丁状态 (从 vuln_lifespan 获取)
    3. 暴露面 (从 risk_surface 获取)
    4. 组织影响 (资产重要性 + 合规压力)

  CISA KEV: Known Exploited Vulnerabilities → 紧迫度基线
  CVSS 4.0: 新增 "Urgency" 字段 (Supplemental Metric Group)
  ITIL Incident Response: P1-P4 优先级框架

修改记录:
  2026-08-01 11:52 - 初始版本，四维紧迫度→时间-行动映射
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

class UrgencyLevel(Enum):
    IMMEDIATE = "immediate"      # 0-4 小时
    CRITICAL = "critical"        # 4-24 小时
    HIGH = "high"                # 1-7 天
    MEDIUM = "medium"            # 7-30 天
    LOW = "low"                  # 30+ 天
    NONE = "none"                # 无紧迫度

@dataclass
class UrgencyScore:
    """操作紧迫度评分。"""
    urgency_level: UrgencyLevel
    time_to_act_hours: float     # 建议行动时间 (小时)
    exploit_public_factor: float # 利用公开贡献
    patch_status_factor: float   # 补丁状态贡献
    exposure_factor: float       # 暴露面贡献
    compliance_factor: float     # 合规压力贡献
    sla_recommendation: str = ''

def _exploit_urgency(
    exploit_public: bool = False,
    kev_listed: bool = False,
    exploit_weaponized: bool = False,
    poc_published: bool = False,
) -> float:
    """利用公开性→紧迫度分。"""
    if exploit_weaponized or kev_listed:
        return 9.5  # CISA KEV → 最高紧迫度
    if exploit_public:
        return 7.5
    if poc_published:
        return 5.5
    return 2.0  # 理论利用 → 低紧迫

def _patch_urgency(
    patch_available: bool = False,
    patch_days_old: float = 999,
    workaround_available: bool = False,
) -> float:
    """补丁状态→紧迫度。无补丁+利用公开=最紧迫。"""
    if not patch_available and not workaround_available:
        return 8.0
    if not patch_available and workaround_available:
        return 5.0  # 有缓解 → 略降
    if patch_days_old < 7:
        return 1.0  # 新鲜补丁 → 团队应该已经在行动
    if patch_days_old < 30:
        return 3.0
    return 5.0  # 旧补丁未应用 → 债务累积

def _exposure_urgency(
    internet_facing: bool = False,
    internal_critical: bool = False,
    multi_tenant: bool = False,
    authenticated_only: bool = True,
) -> float:
    """暴露面→紧迫度。"""
    if internet_facing and not authenticated_only:
        return 9.0  # 互联网+无需认证 → 极紧迫
    if internet_facing:
        return 7.0
    if multi_tenant:
        return 6.0  # 多租户 → 数据隔离风险
    if internal_critical:
        return 4.0
    return 2.0

def _compliance_urgency(
    is_pii: bool = False,
    is_phi: bool = False,    # HIPAA
    is_pci: bool = False,    # PCI-DSS
    is_sox: bool = False,    # SOX 财务
    is_gdpr: bool = False,
) -> float:
    """合规压力→紧迫度。受监管数据泄露→处罚风险。"""
    if is_phi or is_pci:
        return 8.0  # HIPAA/PCI — 最高合规风险
    if is_gdpr and is_pii:
        return 7.0  # GDPR + PII → 72h 通报要求
    if is_pii:
        return 5.0
    if is_sox:
        return 4.0
    return 0.0

def _hours_from_score(raw: float) -> float:
    """紧迫度分→建议行动时间 (小时)。"""
    if raw >= 8.0:
        return 4.0     # 立即
    if raw >= 6.0:
        return 24.0    # 1 天
    if raw >= 4.5:
        return 72.0    # 3 天
    if raw >= 3.0:
        return 168.0   # 7 天
    if raw >= 1.5:
        return 720.0   # 30 天
    return 2160.0      # 90 天

def _level_from_hours(hours: float) -> UrgencyLevel:
    if hours <= 4:
        return UrgencyLevel.IMMEDIATE
    if hours <= 24:
        return UrgencyLevel.CRITICAL
    if hours <= 168:
        return UrgencyLevel.HIGH
    if hours <= 720:
        return UrgencyLevel.MEDIUM
    return UrgencyLevel.LOW

def score_urgency(
    exploit_public: bool = False,
    kev_listed: bool = False,
    exploit_weaponized: bool = False,
    poc_published: bool = False,
    patch_available: bool = False,
    patch_days_old: float = 999,
    workaround_available: bool = False,
    internet_facing: bool = False,
    internal_critical: bool = False,
    multi_tenant: bool = False,
    authenticated_only: bool = True,
    is_pii: bool = False,
    is_phi: bool = False,
    is_pci: bool = False,
    is_sox: bool = False,
    is_gdpr: bool = False,
) -> UrgencyScore:
    """
    计算操作紧迫度 — 输出建议的响应时间窗。

    权重: 利用公开 40%, 补丁状态 25%, 暴露面 25%, 合规 10%。
    """
    eu = _exploit_urgency(exploit_public, kev_listed, exploit_weaponized, poc_published)
    pu = _patch_urgency(patch_available, patch_days_old, workaround_available)
    xu = _exposure_urgency(internet_facing, internal_critical, multi_tenant, authenticated_only)
    cu = _compliance_urgency(is_pii, is_phi, is_pci, is_sox, is_gdpr)

    raw = 0.40 * eu + 0.25 * pu + 0.25 * xu + 0.10 * cu
    hours = _hours_from_score(raw)
    level = _level_from_hours(hours)

    if level == UrgencyLevel.IMMEDIATE:
        sla = '立即响应 (0-4h): 启动安全事件响应流程。通知 CISO 和安全团队'
    elif level == UrgencyLevel.CRITICAL:
        sla = '紧急响应 (4-24h): 评估影响范围, 准备补丁或缓解措施'
    elif level == UrgencyLevel.HIGH:
        sla = '高优先级 (1-7d): 排入当前 sprint, 评估修复方案'
    elif level == UrgencyLevel.MEDIUM:
        sla = '中优先级 (7-30d): 排入下个 release cycle'
    else:
        sla = '低优先级: 常规漏洞管理流程'

    return UrgencyScore(
        urgency_level=level,
        time_to_act_hours=hours,
        exploit_public_factor=round(eu, 1),
        patch_status_factor=round(pu, 1),
        exposure_factor=round(xu, 1),
        compliance_factor=round(cu, 1),
        sla_recommendation=sla,
    )
