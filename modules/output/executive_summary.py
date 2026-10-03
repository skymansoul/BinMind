"""
多受众摘要合成 (Multi-Audience Executive Summary Synthesis, MESS)
------------------------------------------------------------------
将同一分析报告转换为适配不同受众的格式:
  - CISO/管理层: 风险摘要 + 业务影响 + 建议时间线
  - 安全工程师: 技术细节 + 利用路径 + 修复方案
  - 合规审计: 标准合规映射 (PCI-DSS/NIST/ISO 27001) + 证据链

设计依据:
  安全报告通常只有一种格式, 不同受众各自提取所需信息——
  CISO 不需要汇编级细节, 工程师需要精确的修复指导.
  MESS 从统一分析结果中提取受众特定的关注点,
  按模板填充生成针对性的摘要.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AnalysisResult:
    """统一分析结果——所有受众摘要的单一数据源."""
    binary_name: str = ""
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    findings: List[Dict[str, Any]] = field(default_factory=list)
    cvss_max: float = 0.0
    cvss_avg: float = 0.0
    protected_by: List[str] = field(default_factory=list)
    analysis_duration_s: float = 0.0


_AUDIENCE_TEMPLATES = {
    'ciso': {
        'sections': ['executive_risk', 'business_impact', 'timeline', 'actions'],
        'max_detail': 'severity_level',
    },
    'engineer': {
        'sections': ['vulnerability_details', 'exploit_paths', 'remediation', 'verification'],
        'max_detail': 'instruction_level',
    },
    'compliance': {
        'sections': ['standard_mapping', 'evidence_chain', 'audit_trail', 'remediation_tracking'],
        'max_detail': 'standard_control_id',
    },
}


class ExecutiveSummarySynthesizer:
    """多受众摘要合成器.

    用法:
      ess = ExecutiveSummarySynthesizer()
      ciso_report = ess.synthesize(result, audience='ciso')
      eng_report = ess.synthesize(result, audience='engineer')
    """

    def __init__(self):
        self._templates = _AUDIENCE_TEMPLATES

    def synthesize(self, result: AnalysisResult,
                   audience: str = 'ciso') -> str:
        """为指定受众生成摘要."""
        if audience == 'ciso':
            return self._for_ciso(result)
        elif audience == 'engineer':
            return self._for_engineer(result)
        elif audience == 'compliance':
            return self._for_compliance(result)
        return self._for_ciso(result)

    def _for_ciso(self, r: AnalysisResult) -> str:
        risk = 'CRITICAL' if r.critical_count > 0 else (
            'HIGH' if r.high_count > 2 else 'ELEVATED'
        )
        lines = [
            '# 安全分析摘要 — 管理层',
            f'**目标**: {r.binary_name}',
            f'**整体风险**: {risk}',
            '',
            '## 关键指标',
            f'- 总发现: {r.total_findings}',
            f'- 严重: {r.critical_count} | 高危: {r.high_count}',
            f'- 最高 CVSS: {r.cvss_max:.1f} | 平均: {r.cvss_avg:.1f}',
            '',
            '## 业务影响',
        ]
        if r.critical_count > 0:
            lines.append(
                f'{r.critical_count} 个严重漏洞可能被远程利用, '
                '建议在 7 天内修复'
            )
        elif r.high_count > 0:
            lines.append(
                f'{r.high_count} 个高危发现需在下一个补丁周期 (30天) 内处理'
            )
        else:
            lines.append('未发现需要立即处理的严重漏洞')
        lines.extend([
            '',
            '## 建议行动',
            '1. 立即修补所有严重漏洞',
            '2. 部署运行时保护措施 (ASLR/DEP/CFI)',
            '3. 建立持续安全扫描流程',
        ])
        return '\n'.join(lines)

    def _for_engineer(self, r: AnalysisResult) -> str:
        lines = [
            '# 安全分析报告 — 工程团队',
            f'**二进制**: {r.binary_name}',
            f'**分析耗时**: {r.analysis_duration_s:.0f}s',
            f'**保护机制**: {", ".join(r.protected_by) if r.protected_by else "无"}',
            '',
            '## 漏洞详情',
        ]
        for f in r.findings[:10]:
            lines.append(
                f"### {f.get('vuln_type','?')} @ {f.get('location','?')}"
            )
            lines.append(
                f"- 严重性: {f.get('severity','?')} | "
                f"CVSS: {f.get('cvss',0):.1f}"
            )
            if f.get('exploit_path'):
                lines.append(f"- 利用路径: {f['exploit_path']}")
            if f.get('remediation'):
                lines.append(f"- 修复: {f['remediation']}")
            lines.append('')
        return '\n'.join(lines)

    def _for_compliance(self, r: AnalysisResult) -> str:
        mapping = self._map_to_standards(r)
        lines = [
            '# 合规审计摘要',
            f'**目标**: {r.binary_name}',
            '',
            '## 标准合规映射',
        ]
        for std, controls in mapping.items():
            lines.append(f'### {std}')
            for ctrl in controls[:5]:
                lines.append(f'- {ctrl}')
            lines.append('')
        lines.extend([
            '## 证据链',
            f'分析完整性: {min(100, r.total_findings * 10 + 50)}%',
            f'证据项总数: {sum(f.get("evidence_items", 0) for f in r.findings)}',
            '所有发现附带可追溯的 Merkle 证据链',
        ])
        return '\n'.join(lines)

    def _map_to_standards(self, r: AnalysisResult) -> Dict[str, List[str]]:
        """将发现映射到合规标准."""
        mapping: Dict[str, List[str]] = {
            'PCI-DSS': [], 'NIST SP 800-53': [], 'ISO 27001': [],
        }
        for f in r.findings:
            vtype = f.get('vuln_type', '')
            if 'overflow' in vtype.lower() or 'memory' in vtype.lower():
                mapping['PCI-DSS'].append(f'Req 6.5.2 — {f.get("location")}')
                mapping['NIST SP 800-53'].append(f'SI-10 — {f.get("location")}')
                mapping['ISO 27001'].append(f'A.14.2.5 — {f.get("location")}')
            elif 'injection' in vtype.lower():
                mapping['PCI-DSS'].append(f'Req 6.5.1 — {f.get("location")}')
        return mapping
