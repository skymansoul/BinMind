# core/report.py - 报告生成 (Markdown + JSON)
# FIX: 2026-08-15 补序列化规则 finding 与符号执行结果 —
# write_report 原仅输出逐函数分析结果, 规则检测器 (unified_heap_pipeline)
# 与符号执行 (symexec) 的产物只落 DB 不落报告, 导致 MD 摘要与 DB 记录矛盾。

import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List

from config import RESULTS_DIR

logger = logging.getLogger(__name__)


def _md_escape(text: str) -> str:
    """Markdown 转义: 竖线与换行。"""
    return text.replace('|', '\\|').replace('\n', '<br>')


def _collect_vulns(findings: List[Dict], rule_findings: List[Dict]) -> List[Dict]:
    """合并逐函数漏洞与规则检测 finding, 附排序键后返回。

    逐函数结果的漏洞在 analysis.vulnerabilities 内;
    规则 finding 为扁平的 {type, severity, function_name, ...} 结构。
    """
    all_vulns = []
    for f in findings:
        analysis = f.get('analysis', f)
        for v in analysis.get('vulnerabilities', []):
            v['_function'] = f.get('function_name', f.get('function', '?'))
            v['_severity_val'] = {'Critical': 0, 'High': 1, 'Medium': 2,
                                  'Low': 3, 'Unknown': 4}.get(
                                      v.get('severity', 'Unknown'), 5)
            all_vulns.append(v)
    # FIX: 2026-08-15 规则 finding 并入报告 — 此前仅存在于 DB 与 report_enhance JSON
    for v in (rule_findings or []):
        if not isinstance(v, dict):
            continue
        v['_function'] = v.get('function_name', v.get('function', '?'))
        v['_severity_val'] = {'Critical': 0, 'High': 1, 'Medium': 2,
                              'Low': 3, 'Unknown': 4}.get(
                                  v.get('severity', 'Unknown'), 5)
        all_vulns.append(v)
    all_vulns.sort(key=lambda x: x['_severity_val'])
    return all_vulns


def _md_symbolic_section(symbolic_result: Dict) -> List[str]:
    """符号执行结果摘要。"""
    if not symbolic_result:
        return []
    lines = ['### Symbolic Execution', '']
    if symbolic_result.get('success'):
        lines.append(
            f"- **Paths found:** {symbolic_result.get('paths_found', 0)}")
        lines.append(
            f"- **Constraints extracted:** {len(symbolic_result.get('constraints', []))}")
    else:
        lines.append(f"- **Status:** failed")
        lines.append(f"- **Error:** {symbolic_result.get('error', 'unknown')}")
    lines.append('')
    return lines


def generate_markdown(findings: List[Dict], binary_info: Dict,
                      crash_result: Dict = None,
                      rule_findings: List[Dict] = None,
                      symbolic_result: Dict = None) -> str:
    """生成 Markdown 报告。

    rule_findings: 规则检测器产物; symbolic_result: 符号执行返回 dict。
    """
    binary_name = os.path.basename(binary_info.get('path', 'unknown'))
    arch = binary_info.get('arch', 'unknown')
    bits = binary_info.get('bits', 64)

    lines = [
        f'# Binary Vulnerability Analysis Report',
        f'',
        f'**Binary:** `{binary_name}`  ',
        f'**Architecture:** {arch} ({bits}-bit)  ',
        f'**Format:** {binary_info.get("format", "unknown")}  ',
        f'**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}  ',
        f'',
        f'---',
        f'',
    ]

    all_vulns = _collect_vulns(findings, rule_findings)

    if not all_vulns:
        lines.append('## Summary')
        lines.append('')
        lines.append('No vulnerabilities found in the analyzed functions.')
        lines.extend(_md_symbolic_section(symbolic_result))
        return '\n'.join(lines)

    lines.append(f'## Summary')
    lines.append(f'')
    lines.append(f'- **Total vulnerabilities:** {len(all_vulns)}')
    sev_counts = {}
    for v in all_vulns:
        s = v.get('severity', 'Unknown')
        sev_counts[s] = sev_counts.get(s, 0) + 1
    for s in ('Critical', 'High', 'Medium', 'Low', 'Unknown'):
        if s in sev_counts:
            lines.append(f'- **{s}:** {sev_counts[s]}')
    lines.append('')

    if crash_result:
        lines.append('### Crash Information')
        lines.append(f'- Type: `{crash_result.get("crash_type", "?")}`')
        lines.append(f'- Severity: {crash_result.get("severity", "?")}')
        lines.append(f'- Exploitable: {crash_result.get("exploitable", False)}')
        lines.append('')

    lines.extend(_md_symbolic_section(symbolic_result))

    lines.append('---')
    lines.append('')
    lines.append('## Findings')
    lines.append('')

    for i, v in enumerate(all_vulns, 1):
        lines.append(f'### {i}. {v.get("type", "?")} [{v.get("severity", "?")}]')
        lines.append(f'- **Function:** `{v["_function"]}`')
        if v.get('cwe'):
            lines.append(f'- **CWE:** {v["cwe"]}')
        lines.append(f'- **Description:** {v.get("description", "no details")}')
        if v.get('location'):
            lines.append(f'- **Location:** {v["location"]}')
        if v.get('priority_score') is not None:
            lines.append(f'- **Priority score:** {v["priority_score"]}')
        if v.get('evidence'):
            lines.append(f'- **Evidence:** {v["evidence"]}')
        lines.append('')

    return '\n'.join(lines)


def generate_json(findings: List[Dict], binary_info: Dict,
                  crash_result: Dict = None,
                  rule_findings: List[Dict] = None,
                  symbolic_result: Dict = None) -> str:
    """JSON 报告。"""
    return json.dumps({
        'metadata': {
            'binary': binary_info.get('path', ''),
            'arch': binary_info.get('arch', ''),
            'bits': binary_info.get('bits', 64),
            'timestamp': datetime.now().isoformat(),
        },
        'findings': findings,
        # FIX: 2026-08-15 规则 finding 与符号执行结果入 JSON 报告
        'rule_findings': rule_findings or [],
        'symbolic_execution': symbolic_result,
        'crash': crash_result,
    }, indent=2, default=str)


def write_report(findings: List[Dict], binary_info: Dict,
                 crash_result: Dict = None, fmt: str = 'markdown',
                 rule_findings: List[Dict] = None,
                 symbolic_result: Dict = None) -> Dict[str, str]:
    """写报告到 RESULTS_DIR, 返回 {format: path}。

    参数向后兼容: rule_findings/symbolic_result 为可选追加项,
    缺省时行为与旧版一致。
    """
    os.makedirs(RESULTS_DIR, exist_ok=True)
    binary_stem = os.path.splitext(
        os.path.basename(binary_info.get('path', 'report')))[0]
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')

    paths = {}

    md_content = generate_markdown(findings, binary_info, crash_result,
                                   rule_findings, symbolic_result)
    md_path = os.path.join(RESULTS_DIR, f'{binary_stem}_{ts}.md')
    with open(md_path, 'w', encoding='utf-8') as f:
        f.write(md_content)
    paths['markdown'] = md_path

    json_content = generate_json(findings, binary_info, crash_result,
                                 rule_findings, symbolic_result)
    json_path = os.path.join(RESULTS_DIR, f'{binary_stem}_{ts}.json')
    with open(json_path, 'w', encoding='utf-8') as f:
        f.write(json_content)
    paths['json'] = json_path

    return paths
