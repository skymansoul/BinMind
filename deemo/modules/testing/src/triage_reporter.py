# 2026-08-02
# 自动化崩溃 Triage 报告生成器
# 将结构化的崩溃信息（CrashInfo / SanitizerFinding / ExecutionResult）
# 转化为人类可读的安全审计报告（Markdown / JSON / HTML）。
# 报告按照 ClusterFuzz 的四阶段分类（minimize→symbolize→dedup→root cause）
# 排列，补以可利用性评估与缓解建议。
#
# 参考文献:
#   ClusterFuzz (Google, 2019-) — crash triage pipeline design
#   crashwalk (zyantific, 2017-) — automated crash bucketing & reporting
#   GDB Exploitable (2013-) — signal-based exploitability classification
import os
import time
import json
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from datetime import datetime


@dataclass
class TriageEntry:
    """单条 triage 记录：一次崩溃的完整分析上下文。"""
    crash_id: str
    signal_num: int
    signal_name: str
    crash_type: str                    # HEAP_BUFFER_OVERFLOW, USE_AFTER_FREE, ...
    exploitability_score: float       # [0, 1]
    exploitability_verdict: str       # high / medium / low
    minimized_size: int = 0
    original_size: int = 0
    dedup_group: str = ""
    dedup_group_size: int = 0
    stack_frames: List[str] = field(default_factory=list)
    sanitizer_output: str = ""
    root_cause_hint: str = ""
    mitigation_gap: List[str] = field(default_factory=list)
    cve_candidates: List[str] = field(default_factory=list)
    discovery_time: float = 0.0
    binary_path: str = ""
    input_hash: str = ""


class TriageReporter:
    """崩溃 Triage 报告生成器。接收 TriageEntry 列表，输出结构化报告。

    报告模块:
      1. Executive Summary — 一线概述（总数/严重性分布/推荐动作）
      2. Crash Inventory — 按去重组排列的全量崩溃列表
      3. Exploitability Assessment — 可利用性评分分布
      4. Root Cause Clustering — 根因聚合
      5. Mitigation Gap Analysis — 缺失的缓解措施
      6. Actionable Recommendations — 可操作建议
    """

    def __init__(self):
        self._entries: List[TriageEntry] = []
        self._report_metadata: Dict[str, Any] = {}

    def add_entry(self, entry: TriageEntry) -> None:
        self._entries.append(entry)

    def add_entries(self, entries: List[TriageEntry]) -> None:
        self._entries.extend(entries)

    def set_metadata(self, **kwargs) -> None:
        self._report_metadata.update(kwargs)

    # ---- 报告生成 ----
    def generate_markdown(self) -> str:
        """生成 Markdown 格式的完整 triage 报告。"""
        if not self._entries:
            return "# Crash Triage Report\n\n(No crashes to report)\n"

        sections = []
        sections.append(self._md_header())
        sections.append(self._md_executive_summary())
        sections.append(self._md_crash_inventory())
        sections.append(self._md_exploitability())
        sections.append(self._md_root_cause())
        sections.append(self._md_recommendations())
        return '\n\n'.join(sections)

    def generate_json(self) -> str:
        """生成 JSON 格式的结构化报告。"""
        report = {
            'metadata': self._report_metadata,
            'generated_at': datetime.now().isoformat(),
            'summary': self._compute_summary(),
            'entries': [self._entry_to_dict(e) for e in self._entries],
            'dedup_groups': self._dedup_summary(),
            'exploitability_distribution': self._exploit_distribution(),
        }
        return json.dumps(report, indent=2, ensure_ascii=False)

    def generate_html(self) -> str:
        """生成自包含 HTML 报告（带内联 CSS，无需外部资源）。"""
        summary = self._compute_summary()
        html = f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>Crash Triage Report — {summary['total_crashes']} crashes</title>
<style>
body {{ font-family: system-ui, sans-serif; max-width: 960px; margin: 0 auto;
       padding: 20px; background: #0d1117; color: #c9d1d9; }}
h1 {{ border-bottom: 2px solid #30363d; padding-bottom: 8px; }}
table {{ width: 100%; border-collapse: collapse; margin: 12px 0; }}
th, td {{ text-align: left; padding: 8px 12px; border-bottom: 1px solid #21262d; }}
th {{ background: #161b22; }}
.sev-critical {{ color: #ff7b72; font-weight: bold; }}
.sev-high {{ color: #ffa657; font-weight: bold; }}
.sev-medium {{ color: #d2a8ff; }}
.sev-low {{ color: #7ee787; }}
.badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px;
         font-size: 0.85em; }}
.badge-critical {{ background: #490202; color: #ff7b72; }}
.badge-high {{ background: #341a00; color: #ffa657; }}
.badge-medium {{ background: #211740; color: #d2a8ff; }}
.badge-low {{ background: #04260f; color: #7ee787; }}
</style></head><body>
<h1>Crash Triage Report</h1>
<p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} |
{summary['total_crashes']} crashes, {summary['unique_groups']} unique groups</p>

<h2>Executive Summary</h2>
<table>
<tr><th>Metric</th><th>Value</th></tr>
<tr><td>Total crashes</td><td>{summary['total_crashes']}</td></tr>
<tr><td>Unique dedup groups</td><td>{summary['unique_groups']}</td></tr>
<tr><td>Exploitable (high)</td><td class="sev-critical">{summary['exploitable_high']}</td></tr>
<tr><td>Exploitable (medium)</td><td class="sev-high">{summary['exploitable_medium']}</td></tr>
<tr><td>Non-exploitable</td><td>{summary['non_exploitable']}</td></tr>
</table>

<h2>Crash Inventory</h2>
<table>
<tr><th>Crash ID</th><th>Type</th><th>Signal</th><th>Exploitability</th></tr>
'''
        for e in self._entries:
            sev_class = f'sev-{e.exploitability_verdict}'
            badge_class = f'badge-{e.exploitability_verdict}'
            html += (
                f'<tr><td>{e.crash_id}</td>'
                f'<td>{e.crash_type}</td>'
                f'<td>{e.signal_name}</td>'
                f'<td class="{sev_class}">'
                f'<span class="badge {badge_class}">'
                f'{e.exploitability_verdict.upper()} '
                f'({e.exploitability_score:.2f})</span></td></tr>\n')

        html += '</table>\n</body>\n</html>'
        return html

    # ---- 各报告模块 ----
    def _md_header(self) -> str:
        return (
            f"# Crash Triage Report\n\n"
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            f"---"
        )

    def _md_executive_summary(self) -> str:
        s = self._compute_summary()
        return (
            "## 1. Executive Summary\n\n"
            f"| Metric | Value |\n|--------|-------|\n"
            f"| Total crashes | {s['total_crashes']} |\n"
            f"| Unique dedup groups | {s['unique_groups']} |\n"
            f"| Exploitable (high confidence) | {s['exploitable_high']} |\n"
            f"| Exploitable (medium confidence) | {s['exploitable_medium']} |\n"
            f"| Likely non-exploitable | {s['non_exploitable']} |\n"
        )

    def _md_crash_inventory(self) -> str:
        lines = ["## 2. Crash Inventory", "", "| ID | Type | Signal | Score | Verdict |",
                 "|----|------|--------|-------|---------|"]
        for e in self._entries[:50]:
            lines.append(
                f"| {e.crash_id} | {e.crash_type} | {e.signal_name} "
                f"| {e.exploitability_score:.2f} | **{e.exploitability_verdict.upper()}** |")
        if len(self._entries) > 50:
            lines.append(f"| ... | ({len(self._entries) - 50} more entries) | | | |")
        return '\n'.join(lines)

    def _md_exploitability(self) -> str:
        dist = self._exploit_distribution()
        lines = ["## 3. Exploitability Assessment", ""]
        for cat, cnt in sorted(dist.items()):
            pct = cnt / max(1, len(self._entries)) * 100
            lines.append(f"- **{cat.upper()}**: {cnt} ({pct:.0f}%)")
        lines.append("")
        lines.append("### Top Exploitable Crashes")
        exploitable = sorted(
            [e for e in self._entries if e.exploitability_score >= 0.5],
            key=lambda e: -e.exploitability_score)[:5]
        for i, e in enumerate(exploitable, 1):
            lines.append(
                f"{i}. `{e.crash_id}` — {e.crash_type} "
                f"(score={e.exploitability_score:.2f})")
            if e.root_cause_hint:
                lines.append(f"   - Root cause: {e.root_cause_hint}")
            if e.stack_frames:
                lines.append(f"   - Top frame: `{e.stack_frames[0]}`")
        return '\n'.join(lines)

    def _md_root_cause(self) -> str:
        clusters = self._cluster_by_root_cause()
        lines = ["## 4. Root Cause Clustering", ""]
        for hint, entries in sorted(
                clusters.items(), key=lambda kv: -len(kv[1])):
            lines.append(
                f"- **{hint}**: {len(entries)} crash(es)")
        return '\n'.join(lines) if len(clusters) > 0 else (
            "## 4. Root Cause Clustering\n\n(Insufficient data for clustering)")

    def _md_recommendations(self) -> str:
        lines = ["## 5. Actionable Recommendations", ""]
        high_conf = [e for e in self._entries
                     if e.exploitability_score >= 0.7]
        if high_conf:
            lines.append(
                f"### Immediate Action ({len(high_conf)} high-confidence crashes)")
            lines.append("1. 隔离受影响二进制，阻断外部输入通道")
            lines.append("2. 对每个高危崩溃生成 PoC 并验证")
            lines.append("3. 回查相关 CVE，评估是否为已知漏洞的变种")
            lines.append("")
        lines.append("### Short-term (1-7 days)")
        lines.append("1. 对中等置信度的崩溃执行进一步 triage（补全符号化、裁减最小化）")
        lines.append("2. 交叉验证：将崩溃输入对同组件的不同版本执行差分测试")
        lines.append("3. 为所有 unique crash 创建 bug 跟踪条目")
        lines.append("")
        lines.append("### Long-term (1-4 weeks)")
        lines.append("1. 将崩溃语料纳入回归测试套件")
        lines.append("2. 更新 fuzzing 字典以覆盖触发崩溃的输入模式")
        lines.append("3. 评估编译时加固选项（CFI、Shadow Stack、PAC）")

        return '\n'.join(lines)

    # ---- 内部聚合 ----
    def _compute_summary(self) -> Dict[str, Any]:
        unique_groups = len({e.dedup_group for e in self._entries
                             if e.dedup_group})
        return {
            'total_crashes': len(self._entries),
            'unique_groups': unique_groups,
            'exploitable_high': sum(
                1 for e in self._entries
                if e.exploitability_verdict == 'high'),
            'exploitable_medium': sum(
                1 for e in self._entries
                if e.exploitability_verdict == 'medium'),
            'non_exploitable': sum(
                1 for e in self._entries
                if e.exploitability_verdict == 'low'),
        }

    def _dedup_summary(self) -> Dict[str, Dict]:
        groups: Dict[str, List] = {}
        for e in self._entries:
            key = e.dedup_group or 'ungrouped'
            groups.setdefault(key, []).append(e.crash_id)
        return {
            gid: {'count': len(ids), 'crash_ids': ids[:5]}
            for gid, ids in groups.items()
        }

    def _exploit_distribution(self) -> Dict[str, int]:
        from collections import Counter
        return dict(Counter(e.exploitability_verdict for e in self._entries))

    def _cluster_by_root_cause(self) -> Dict[str, List[TriageEntry]]:
        clusters: Dict[str, List] = {}
        for e in self._entries:
            hint = e.root_cause_hint or 'unclassified'
            clusters.setdefault(hint, []).append(e)
        return clusters

    @staticmethod
    def _entry_to_dict(e: TriageEntry) -> Dict[str, Any]:
        return {
            'crash_id': e.crash_id, 'signal': e.signal_name,
            'type': e.crash_type,
            'exploitability_score': e.exploitability_score,
            'verdict': e.exploitability_verdict,
            'root_cause': e.root_cause_hint,
            'dedup_group': e.dedup_group,
            'frames': e.stack_frames[:5],
        }

    def write_report(self, output_dir: str,
                     base_name: str = "crash_triage") -> Dict[str, str]:
        """同时写出 Markdown + JSON + HTML 三种格式。
        返回 {format: filepath} 字典。"""
        os.makedirs(output_dir, exist_ok=True)
        outputs = {}

        md_path = os.path.join(output_dir, f"{base_name}.md")
        with open(md_path, 'w', encoding='utf-8') as fh:
            fh.write(self.generate_markdown())
        outputs['markdown'] = md_path

        json_path = os.path.join(output_dir, f"{base_name}.json")
        with open(json_path, 'w', encoding='utf-8') as fh:
            fh.write(self.generate_json())
        outputs['json'] = json_path

        html_path = os.path.join(output_dir, f"{base_name}.html")
        with open(html_path, 'w', encoding='utf-8') as fh:
            fh.write(self.generate_html())
        outputs['html'] = html_path

        return outputs


# ---------------------------------------------------------------------------
# 便捷构建: 从 crash 对象列表快速生成报告
# ---------------------------------------------------------------------------
def triage_from_crash_infos(crashes: List[Any],
                            binary_path: str = "") -> TriageReporter:
    """从 crash 对象列表（需具有 signal / crash_type / stack_trace 等属性）
    构建 TriageReporter。兼容 CrashInfo 和 ExecutionResult 两种常见类型。"""
    reporter = TriageReporter()
    reporter.set_metadata(binary=binary_path, source='auto_triage')

    for i, crash in enumerate(crashes):
        entry = TriageEntry(
            crash_id=f"crash_{i:04d}",
            signal_num=getattr(crash, 'signal', 0),
            signal_name=_resolve_signal(getattr(crash, 'signal', 0)),
            crash_type=getattr(crash, 'crash_type', 'UNKNOWN'),
            exploitability_score=getattr(
                crash, 'exploitability_score', 0.0),
            exploitability_verdict=_verdict_from_score(
                getattr(crash, 'exploitability_score', 0.0)),
            stack_frames=getattr(crash, 'stack_trace', []),
            sanitizer_output=getattr(crash, 'sanitizer_output', ''),
            root_cause_hint=getattr(crash, 'root_cause_hint', ''),
            discovery_time=time.time(),
            binary_path=binary_path,
        )
        reporter.add_entry(entry)

    return reporter


def _resolve_signal(sig: int) -> str:
    names = {4: 'SIGILL', 6: 'SIGABRT', 7: 'SIGBUS', 8: 'SIGFPE',
             11: 'SIGSEGV', 13: 'SIGPIPE', 14: 'SIGALRM'}
    return names.get(sig, f'SIG({sig})')


def _verdict_from_score(score: float) -> str:
    if score >= 0.7:
        return 'high'
    elif score >= 0.4:
        return 'medium'
    return 'low'
