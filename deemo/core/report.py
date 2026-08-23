# core/report.py - 报告生成 (Markdown + JSON)
# write_report: 逐函数分析 + 规则检测 + 符号执行 + 程序画像全部纳入报告

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


def _classify_tier(v: Dict, has_symbolic: bool) -> str:
    """基于证据强度判定三档: verified / candidate / lead。

    verified: evidence 非空或有符号执行佐证;
    candidate: 规则检测命中但无符号佐证;
    lead: 仅 LLM 分析提及。
    """
    evidence = v.get('evidence')
    has_sym = has_symbolic or bool(v.get('symbolic_execution'))
    if (evidence is not None and str(evidence).strip()) or has_sym:
        return 'verified'
    if v.get('_source') == 'rule':
        return 'candidate'
    return 'lead'


def _tier_to_review(tier: str) -> str:
    """tier 映射审核状态: verified→confirmed, 其余→pending。"""
    return 'confirmed' if tier == 'verified' else 'pending'


def _collect_vulns(findings: List[Dict], rule_findings: List[Dict],
                   symbolic_result: Dict = None) -> List[Dict]:
    """合并逐函数漏洞与规则检测 finding, 附排序键后返回。

    逐函数结果的漏洞在 analysis.vulnerabilities 内;
    规则 finding 为扁平的 {type, severity, function_name, ...} 结构。
    三档分级在此统一设置, 避免 generate_* 重复 setdefault。
    """
    all_vulns = []
    for f in findings:
        analysis = f.get('analysis', f)
        for v in analysis.get('vulnerabilities', []):
            v['_source'] = 'analysis'
            v['_function'] = f.get('function_name', f.get('function', '?'))
            v['_severity_val'] = {'Critical': 0, 'High': 1, 'Medium': 2,
                                  'Low': 3, 'Unknown': 4}.get(
                                      v.get('severity', 'Unknown'), 5)
            all_vulns.append(v)
    for v in (rule_findings or []):
        if not isinstance(v, dict):
            continue
        v['_source'] = 'rule'
        v['_function'] = v.get('function_name', v.get('function', '?'))
        v['_severity_val'] = {'Critical': 0, 'High': 1, 'Medium': 2,
                              'Low': 3, 'Unknown': 4}.get(
                                  v.get('severity', 'Unknown'), 5)
        all_vulns.append(v)
    # 三档分级集中设置: verified/candidate/lead + review_status
    has_symbolic = bool(symbolic_result and symbolic_result.get('success'))
    for v in all_vulns:
        tier = _classify_tier(v, has_symbolic)
        v.setdefault('tier', tier)
        v.setdefault('review_status', _tier_to_review(tier))
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


def _md_binary_profile_section(profile: Dict) -> List[str]:
    """程序初步画像章节: 保护机制、PLT、ROP gadgets、关键字符串、libc 版本。各字段缺失时显式标注未获取。"""
    if not profile:
        return []
    lines = ['## 程序初步画像', '']
    cs = profile.get('checksec') or {}

    # 保护机制
    lines.append('### 保护机制')
    lines.append('')
    lines.append('| 机制 | 状态 |')
    lines.append('|------|------|')
    nx_val = cs.get('nx')
    lines.append(f'| NX | {"✓ 启用" if nx_val else "✗ 关闭" if nx_val is not None else "未获取到 NX 信息"} |')
    pie_val = cs.get('pie')
    lines.append(f'| PIE | {"✓ 启用" if pie_val else "✗ 关闭" if pie_val is not None else "未获取到 PIE 信息"} |')
    relro_val = cs.get('relro')
    lines.append(f'| RELRO | {relro_val if relro_val else "未获取到 RELRO 信息"} |')
    canary_val = cs.get('canary')
    lines.append(f'| Canary | {"✓ 启用" if canary_val else "✗ 关闭" if canary_val is not None else "未获取到 Canary 信息"} |')
    aslr_val = cs.get('aslr')
    lines.append(f'| ASLR | {"✓ 启用" if aslr_val else "✗ 关闭" if aslr_val is not None else "未获取到 ASLR 信息"} |')
    lines.append('')

    # PLT 函数列表
    plt_entries = profile.get('plt_entries') or []
    lines.append(f'### PLT 函数 (共 {profile.get("plt_count", 0)} 个, 展示前 20)')
    lines.append('')
    if plt_entries:
        for entry in plt_entries[:20]:
            name = entry.get('name', '?') if isinstance(entry, dict) else str(entry)
            lines.append(f'- `{name}`')
    else:
        lines.append('未获取到 PLT 函数信息')
    lines.append('')

    # ROP gadgets 摘要
    gadget_count = profile.get('gadget_count')
    gadget_types = profile.get('gadget_types') or {}
    lines.append('### ROP Gadgets 摘要')
    lines.append('')
    if gadget_count is not None and gadget_count > 0:
        lines.append(f'- **总数:** {gadget_count}')
        if gadget_types:
            lines.append('- **类型分布:**')
            for gtype, cnt in sorted(gadget_types.items(), key=lambda x: -x[1])[:10]:
                lines.append(f'  - `{gtype}`: {cnt}')
    else:
        lines.append('未获取到 ROP gadget 信息')
    lines.append('')

    # 关键字符串
    key_strings = profile.get('key_strings') or []
    suspect = profile.get('suspect_strings') or []
    lines.append('### 关键字符串 (展示前 20)')
    lines.append('')
    if key_strings:
        for s in key_strings[:20]:
            if isinstance(s, dict):
                s = s.get('string', str(s))
            lines.append(f'- {_md_escape(str(s))}')
    elif suspect:
        for s in suspect[:20]:
            if isinstance(s, dict):
                s = s.get('string', str(s))
            lines.append(f'- {_md_escape(str(s))}')
    else:
        lines.append('未获取到字符串信息')
    lines.append('')

    # libc 版本
    libc = profile.get('libc') or {}
    lines.append('### libc 版本信息')
    lines.append('')
    if libc:
        lines.append(f'- **版本:** {libc.get("version", "未知")}')
        if libc.get('path'):
            lines.append(f'- **路径:** `{libc["path"]}`')
        if libc.get('symbols'):
            lines.append(f'- **已知符号数:** {len(libc["symbols"])}')
    else:
        lines.append('未获取到 libc 版本信息')
    lines.append('')

    # 利用难度与推荐策略
    difficulty = profile.get('exploit_difficulty')
    if difficulty:
        lines.append(f'- **利用难度评估:** **{difficulty.upper()}**')
    approaches = profile.get('recommended_approach') or []
    if approaches:
        lines.append('- **推荐利用策略:**')
        for a in approaches:
            lines.append(f'  - {a}')
    if difficulty or approaches:
        lines.append('')

    return lines


def generate_markdown(findings: List[Dict], binary_info: Dict,
                      crash_result: Dict = None,
                      rule_findings: List[Dict] = None,
                      symbolic_result: Dict = None,
                      binary_profile: Dict = None) -> str:
    """生成 Markdown 报告。

    rule_findings: 规则检测器产物; symbolic_result: 符号执行返回 dict;
    binary_profile: build_binary_profile() 返回的程序画像, 注入"程序初步画像"章节。
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

    all_vulns = _collect_vulns(findings, rule_findings, symbolic_result)

    # 程序初步画像
    profile_lines = _md_binary_profile_section(binary_profile)
    if profile_lines:
        lines.extend(profile_lines)
        lines.append('---')
        lines.append('')

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
        # 审核状态与分级
        review = v.get('review_status', 'pending')
        tier = v.get('tier', 'lead')
        lines.append(f'- **Review:** {review}')
        lines.append(f'- **Tier:** {tier}')
        if v.get('simulation'):
            lines.append(f'- **Simulation:** true')
        lines.append('')

    return '\n'.join(lines)


def generate_json(findings: List[Dict], binary_info: Dict,
                  crash_result: Dict = None,
                  rule_findings: List[Dict] = None,
                  symbolic_result: Dict = None) -> str:
    """JSON 报告。"""
    all_vulns = _collect_vulns(findings, rule_findings, symbolic_result)
    for v in all_vulns:
        v.setdefault('simulation', False)

    return json.dumps({
        'metadata': {
            'binary': binary_info.get('path', ''),
            'arch': binary_info.get('arch', ''),
            'bits': binary_info.get('bits', 64),
            'timestamp': datetime.now().isoformat(),
        },
        'findings': all_vulns,
        'rule_findings': rule_findings or [],
        'symbolic_execution': symbolic_result,
        'crash': crash_result,
    }, indent=2, default=str)


def write_report(findings: List[Dict], binary_info: Dict,
                 crash_result: Dict = None, fmt: str = 'markdown',
                 rule_findings: List[Dict] = None,
                 symbolic_result: Dict = None,
                 output_dir: str = None,
                 binary_profile: Dict = None) -> Dict[str, str]:
    """写报告到 output_dir(缺省 RESULTS_DIR), 返回 {format: path}。

    参数向后兼容: rule_findings/symbolic_result 为可选追加项,
    output_dir 供 CLI -o 显式指定报告目录; binary_profile 透传给 generate_markdown。
    """
    out_dir = output_dir or RESULTS_DIR
    os.makedirs(out_dir, exist_ok=True)
    binary_stem = os.path.splitext(
        os.path.basename(binary_info.get('path', 'report')))[0]
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')

    paths = {}

    md_content = generate_markdown(findings, binary_info, crash_result,
                                   rule_findings, symbolic_result,
                                   binary_profile)
    md_path = os.path.join(out_dir, f'{binary_stem}_{ts}.md')
    with open(md_path, 'w', encoding='utf-8') as f:
        f.write(md_content)
    paths['markdown'] = md_path

    json_content = generate_json(findings, binary_info, crash_result,
                                 rule_findings, symbolic_result)
    json_path = os.path.join(out_dir, f'{binary_stem}_{ts}.json')
    with open(json_path, 'w', encoding='utf-8') as f:
        f.write(json_content)
    paths['json'] = json_path

    return paths
