"""
差分报告生成 (Differential Report Generation, DRG)
---------------------------------------------------
比较两次分析运行的输出, 自动生成变更摘要报告.

设计依据:
  二进制分析经常重复运行 (CI/CD 集成、定期安全扫描).
  每次运行产出完整报告——安全分析师需手动对比找差异.
  DRG 自动识别新增/消除/变更的发现, 生成 diff 风格报告.

算法:
  1. 按 (文件, 函数, 漏洞类型) 三元组对齐两次运行的发现
  2. 分类: NEW (仅新运行有), RESOLVED (仅旧运行有), CHANGED (两运行都有但不同)
  3. 对 CHANGED 进一步分析: 严重性变化/置信度变化/证据链变化
  4. 生成三栏对比表格 + 趋势总结
"""
import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class Finding:
    """单次分析发现."""
    finding_id: str
    file_path: str = ""
    function_name: str = ""
    vuln_type: str = ""
    severity: str = "MEDIUM"        # CRITICAL/HIGH/MEDIUM/LOW
    confidence: float = 0.5
    description: str = ""
    evidence_items: int = 0
    run_timestamp: float = 0.0

    def key(self) -> str:
        """对齐键——用于跨运行匹配."""
        return hashlib.sha256(
            f'{self.file_path}|{self.function_name}|{self.vuln_type}'.encode()
        ).hexdigest()[:16]


@dataclass
class DiffEntry:
    """差分条目."""
    change_type: str  # 'NEW' | 'RESOLVED' | 'CHANGED' | 'UNCHANGED'
    finding_key: str
    old_finding: Optional[Finding] = None
    new_finding: Optional[Finding] = None
    changes: List[str] = field(default_factory=list)


class DifferentialReportGenerator:
    """差分报告生成器.

    用法:
      drg = DifferentialReportGenerator()
      diff = drg.compare(previous_run_findings, current_run_findings)
      report = drg.render(diff, format='markdown')
    """

    def compare(self, old_findings: List[Finding],
                new_findings: List[Finding]) -> List[DiffEntry]:
        """比较两次运行的发现."""
        old_map = {f.key(): f for f in old_findings}
        new_map = {f.key(): f for f in new_findings}
        all_keys = set(old_map) | set(new_map)
        entries = []

        for key in sorted(all_keys):
            old_f = old_map.get(key)
            new_f = new_map.get(key)
            if old_f is None and new_f is not None:
                entries.append(DiffEntry('NEW', key, new_finding=new_f))
            elif old_f is not None and new_f is None:
                entries.append(DiffEntry('RESOLVED', key, old_finding=old_f))
            elif old_f is not None and new_f is not None:
                changes = self._detect_changes(old_f, new_f)
                if changes:
                    entries.append(DiffEntry('CHANGED', key, old_f, new_f, changes))
                else:
                    entries.append(DiffEntry('UNCHANGED', key, old_f, new_f))
        return entries

    def _detect_changes(self, old_f: Finding, new_f: Finding) -> List[str]:
        changes = []
        if old_f.severity != new_f.severity:
            changes.append(f'severity: {old_f.severity} → {new_f.severity}')
        if abs(old_f.confidence - new_f.confidence) > 0.05:
            changes.append(f'confidence: {old_f.confidence:.2f} → {new_f.confidence:.2f}')
        if old_f.evidence_items != new_f.evidence_items:
            changes.append(f'evidence: {old_f.evidence_items} → {new_f.evidence_items}')
        return changes

    def render(self, entries: List[DiffEntry],
               format: str = 'markdown') -> str:
        """渲染差分报告."""
        if format == 'markdown':
            return self._render_markdown(entries)
        return self._render_text(entries)

    def _render_markdown(self, entries: List[DiffEntry]) -> str:
        summary = self._summarize(entries)
        lines = [
            '# 分析差异报告',
            f'新增: {summary["new"]} | 消除: {summary["resolved"]} | '
            f'变更: {summary["changed"]} | 不变: {summary["unchanged"]}',
            '',
        ]
        for entry in entries:
            if entry.change_type == 'UNCHANGED':
                continue
            icon = {'NEW': '➕', 'RESOLVED': '✅', 'CHANGED': '🔄'}[entry.change_type]
            f = entry.new_finding or entry.old_finding
            lines.append(f'{icon} **{entry.change_type}**: {f.file_path}::{f.function_name}')
            lines.append(f'  类型: {f.vuln_type} | 严重性: {f.severity}')
            if entry.changes:
                lines.append(f'  变更: {", ".join(entry.changes)}')
            lines.append('')
        return '\n'.join(lines)

    def _render_text(self, entries: List[DiffEntry]) -> str:
        lines = ['=== ANALYSIS DIFF REPORT ===']
        for entry in entries:
            if entry.change_type == 'UNCHANGED':
                continue
            f = entry.new_finding or entry.old_finding
            lines.append(
                f'[{entry.change_type}] {f.file_path}::{f.function_name} '
                f'({f.vuln_type}, {f.severity})'
            )
        return '\n'.join(lines)

    def _summarize(self, entries: List[DiffEntry]) -> Dict[str, int]:
        counts = {'new': 0, 'resolved': 0, 'changed': 0, 'unchanged': 0}
        for e in entries:
            counts[e.change_type.lower()] += 1
        return counts

    def trend_analysis(self, entries: List[DiffEntry]) -> Dict[str, Any]:
        """趋势分析——整体安全态势变化."""
        new_crit = sum(1 for e in entries if e.change_type == 'NEW'
                       and e.new_finding and e.new_finding.severity == 'CRITICAL')
        resolved_crit = sum(1 for e in entries if e.change_type == 'RESOLVED'
                            and e.old_finding and e.old_finding.severity == 'CRITICAL')
        worsened = sum(1 for e in entries if e.change_type == 'CHANGED'
                       and e.old_finding and e.new_finding
                       and _severity_rank(e.new_finding.severity) > _severity_rank(e.old_finding.severity))
        improved = sum(1 for e in entries if e.change_type == 'CHANGED'
                       and e.old_finding and e.new_finding
                       and _severity_rank(e.new_finding.severity) < _severity_rank(e.old_finding.severity))

        return {
            'new_critical': new_crit,
            'resolved_critical': resolved_crit,
            'net_critical_change': new_crit - resolved_crit,
            'worsened': worsened,
            'improved': improved,
            'trend': 'improving' if resolved_crit > new_crit else (
                'degrading' if new_crit > resolved_crit else 'stable'
            ),
        }


def _severity_rank(sev: str) -> int:
    return {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}.get(sev, 0)
