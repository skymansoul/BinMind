"""
Report generation. Produces Markdown, JSON, and optionally HTML
reports from vulnerability findings.
"""

import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List

from config import RESULTS_DIR

logger = logging.getLogger(__name__)


def _md_escape(text: str) -> str:
    """Minimal Markdown escaping for report content."""
    return text.replace('|', '\\|').replace('\n', '<br>')


def generate_markdown(findings: List[Dict], binary_info: Dict,
                      crash_result: Dict = None) -> str:
    """
    Build a self-contained Markdown report.
    findings: list of per-function analysis results
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

    # collect all vulns across functions
    all_vulns = []
    for f in findings:
        analysis = f.get('analysis', f)
        for v in analysis.get('vulnerabilities', []):
            v['_function'] = f.get('function_name', f.get('function', '?'))
            v['_severity_val'] = {'Critical': 0, 'High': 1, 'Medium': 2,
                                  'Low': 3, 'Unknown': 4}.get(
                                      v.get('severity', 'Unknown'), 5)
            all_vulns.append(v)

    all_vulns.sort(key=lambda x: x['_severity_val'])

    if not all_vulns:
        lines.append('## Summary')
        lines.append('')
        lines.append('No vulnerabilities found in the analyzed functions.')
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
        lines.append('')

    return '\n'.join(lines)


def generate_json(findings: List[Dict], binary_info: Dict,
                  crash_result: Dict = None) -> str:
    """JSON-format report."""
    return json.dumps({
        'metadata': {
            'binary': binary_info.get('path', ''),
            'arch': binary_info.get('arch', ''),
            'bits': binary_info.get('bits', 64),
            'timestamp': datetime.now().isoformat(),
        },
        'findings': findings,
        'crash': crash_result,
    }, indent=2, default=str)


def write_report(findings: List[Dict], binary_info: Dict,
                 crash_result: Dict = None, fmt: str = 'markdown') -> Dict[str, str]:
    """
    Write report files to RESULTS_DIR. Returns {format: path} dict.
    """
    os.makedirs(RESULTS_DIR, exist_ok=True)
    binary_stem = os.path.splitext(
        os.path.basename(binary_info.get('path', 'report')))[0]
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')

    paths = {}

    md_content = generate_markdown(findings, binary_info, crash_result)
    md_path = os.path.join(RESULTS_DIR, f'{binary_stem}_{ts}.md')
    with open(md_path, 'w', encoding='utf-8') as f:
        f.write(md_content)
    paths['markdown'] = md_path

    json_content = generate_json(findings, binary_info, crash_result)
    json_path = os.path.join(RESULTS_DIR, f'{binary_stem}_{ts}.json')
    with open(json_path, 'w', encoding='utf-8') as f:
        f.write(json_content)
    paths['json'] = json_path

    return paths
