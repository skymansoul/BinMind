"""
事件响应时间线生成 — 基于漏洞画像的阶段式行动规划。

问题定义:
  现有的漏洞报告输出 "CVSS 7.5" 和 "建议修复" — 但安全团队需要
  具体的、分阶段的行动计划。本模块是第一个从二进制分析结果自动
  生成事件响应时间线的工具。

  五阶段响应模型:
    T+0    (遏制): 立即止损措施
    T+4h   (分析): 根因确认和影响评估
    T+24h  (修复): 补丁开发和测试
    T+72h  (部署): 灰度发布和验证
    T+7d   (收尾): 事后复盘和流程改进

  每阶段的行动根据漏洞特征动态生成，而非静态模板。

  NIST SP 800-61r2: Computer Security Incident Handling Guide
  SANS Incident Response Process: Preparation→Identification→Containment→...
  ITIL Incident Management: 事件优先级→响应SLA映射

修改记录:
  2025-03-28 12:33 - 初始版本，五阶段动态响应时间线
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

class PhaseType(Enum):
    CONTAIN = "contain"        # 遏制
    ANALYZE = "analyze"        # 分析
    REMEDIATE = "remediate"    # 修复
    DEPLOY = "deploy"          # 部署
    REVIEW = "review"          # 复盘

@dataclass
class TimelinePhase:
    """响应时间线的单个阶段。"""
    phase: PhaseType
    time_offset_hours: float      # 距 T+0 的小时数
    title: str
    actions: List[str] = field(default_factory=list)
    owner: str = ''
    success_criteria: str = ''

@dataclass
class ResponseTimeline:
    """完整事件响应时间线。"""
    vulnerability_name: str
    urgency_level: str
    phases: List[TimelinePhase] = field(default_factory=list)
    total_containment_cost_est: str = ''

def _contain_actions(
    is_heap: bool = False,
    is_stack: bool = False,
    is_network: bool = False,
    is_local: bool = False,
) -> List[str]:
    actions = []
    if is_network:
        actions.append('部署 WAF 规则阻止可疑输入模式')
        actions.append('限制源 IP 访问 (netfilter/iptables 临时规则)')
        actions.append('启用 rate limiting 减缓潜在扫描')
    if is_local:
        actions.append('限制二进制执行权限 (chmod 750)')
        actions.append('临时移除 SUID/SGID 位')
    if is_heap:
        actions.append('启用 glibc malloc 调试 (MALLOC_CHECK_=3)')
    if is_stack:
        actions.append('启用 ASLR 强化 (echo 2 > /proc/sys/kernel/randomize_va_space)')
    if not actions:
        actions.append('评估是否需要立即下线服务')
    return actions

def _analyze_actions(
    has_poc: bool = False,
    root_cause_known: bool = False,
    affected_versions: Optional[List[str]] = None,
) -> List[str]:
    actions = ['确认漏洞触发条件并复现']
    if not root_cause_known:
        actions.append('执行根因分析 (使用 Ghidra/IDA 定位漏洞函数)')
    if has_poc:
        actions.append('在隔离环境中验证 PoC 的有效性')
        actions.append('使用 PoC 测试缓解措施的有效性')
    if affected_versions:
        actions.append(f'评估影响范围: {", ".join(affected_versions[:3])}')
    actions.append('更新 CMDB 中受影响资产的状态')
    return actions

def _remediate_actions(
    is_open_source: bool = False,
    hardening_applicable: bool = False,
    complexity: str = 'medium',
) -> List[str]:
    actions = []
    if hardening_applicable:
        actions.append('评估编译器加固选项 (PIE/Full RELRO/FORTIFY)')
    if complexity == 'low':
        actions.append('开发补丁 — 预期 <4h 编码 + 2h 测试')
    elif complexity == 'high':
        actions.append('补丁开发 — 需要架构级变更，分配 3-5 天')
    else:
        actions.append('补丁开发 — 预期 1-2 天编码和测试')
    if is_open_source:
        actions.append('准备 upstream 补丁提交 (遵循项目贡献指南)')
    actions.append('在 staging 环境中验证修复不引入回归')
    return actions

def _deploy_actions(
    is_shared_library: bool = False,
    requires_reboot: bool = False,
    rollback_plan: bool = True,
) -> List[str]:
    actions = ['灰度发布: 先部署至 5% 实例观察 2h']
    if is_shared_library:
        actions.append('注意: 共享库更新→所有依赖此库的二进制需重启')
    if requires_reboot:
        actions.append('协调维护窗口进行重启')
    if rollback_plan:
        actions.append('准备回滚方案: 保留旧版本二进制, 验证回滚流程')
    actions.append('监控错误率/崩溃率/性能指标 24h')
    return actions

def _review_actions(
    was_exploited: bool = False,
    regulatory_reportable: bool = False,
) -> List[str]:
    actions = ['撰写事后复盘报告 (post-mortem)']
    if was_exploited:
        actions.append('执行影响评估: 数据泄露范围/资产受损程度')
    if regulatory_reportable:
        actions.append('准备监管通报 (GDPR 72h / HIPAA 60d / PCI-DSS)')
    actions.append('更新安全测试用例以覆盖此类漏洞')
    actions.append('评估是否需要在 CI/CD 中加入自动化检测')
    return actions

def generate_timeline(
    vulnerability_name: str = '',
    urgency_hours: float = 24.0,
    is_heap: bool = False, is_stack: bool = False,
    is_network: bool = False, is_local: bool = True,
    has_poc: bool = False, root_cause_known: bool = False,
    affected_versions: Optional[List[str]] = None,
    is_open_source: bool = False,
    hardening_applicable: bool = True,
    remediation_complexity: str = 'medium',
    is_shared_library: bool = False,
    requires_reboot: bool = False,
    was_exploited: bool = False,
    regulatory_reportable: bool = False,
) -> ResponseTimeline:
    """
    生成五阶段事件响应时间线。

    urgency_hours: 来自 urgency_scorer 的 time_to_act_hours。
    remediation_complexity: low/medium/high — 来自 remediation_scorer。
    """
    urgency_label = ('immediate' if urgency_hours <= 4 else
                     'critical' if urgency_hours <= 24 else
                     'high' if urgency_hours <= 168 else
                     'medium' if urgency_hours <= 720 else 'low')

    phases = [
        TimelinePhase(
            phase=PhaseType.CONTAIN, time_offset_hours=0,
            title='T+0 — 遏制',
            actions=_contain_actions(is_heap, is_stack, is_network, is_local),
            owner='安全运维 (SecOps)',
            success_criteria='攻击面已临时关闭; 无新增利用尝试成功',
        ),
        TimelinePhase(
            phase=PhaseType.ANALYZE, time_offset_hours=4,
            title='T+4h — 分析',
            actions=_analyze_actions(has_poc, root_cause_known, affected_versions),
            owner='安全分析 (SecAnalysis)',
            success_criteria='根因已确认; 影响范围已量化',
        ),
        TimelinePhase(
            phase=PhaseType.REMEDIATE, time_offset_hours=24,
            title='T+24h — 修复',
            actions=_remediate_actions(is_open_source, hardening_applicable, remediation_complexity),
            owner='开发团队 + 安全工程师',
            success_criteria='补丁在 staging 通过所有测试; 无回归',
        ),
        TimelinePhase(
            phase=PhaseType.DEPLOY, time_offset_hours=72,
            title='T+72h — 部署',
            actions=_deploy_actions(is_shared_library, requires_reboot, True),
            owner='SRE / DevOps',
            success_criteria='100% 实例已更新; 监控 24h 无异常',
        ),
        TimelinePhase(
            phase=PhaseType.REVIEW, time_offset_hours=168,
            title='T+7d — 复盘',
            actions=_review_actions(was_exploited, regulatory_reportable),
            owner='安全团队 + 工程 VP',
            success_criteria='事后报告已签发; 改进措施已纳入 backlog',
        ),
    ]

    # 紧迫度调整: 高紧迫度→压缩后期阶段
    if urgency_hours <= 4:
        phases[2].time_offset_hours = 12   # 修复压缩到 12h
        phases[3].time_offset_hours = 36   # 部署压缩到 36h
        phases[4].time_offset_hours = 96   # 复盘压缩到 4d

    cost_est = ('<1 人天' if remediation_complexity == 'low' else
                '2-5 人天' if remediation_complexity == 'medium' else '10+ 人天')

    return ResponseTimeline(
        vulnerability_name=vulnerability_name or 'unnamed',
        urgency_level=urgency_label,
        phases=phases,
        total_containment_cost_est=cost_est,
    )
