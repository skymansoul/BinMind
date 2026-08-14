# core/report_enhancement.py - 报告增强 (findings → Markdown 摘要)
#
# 把 findings 关键字段压缩为紧凑 Markdown 列表: 类型、置信度
# (含污点验证与跨函数标注)、函数位置、证据首行。只做汇总呈现,
# 不改变 findings 本身。
#
# 字段约定参照 SARIF (OASIS) 的 level/location/message 结构。
# 启用方式: ENABLE_REPORT_ENHANCEMENT=1, 管线在报告生成后调用。
from typing import Any, Dict, List


def _confidence_line(v: Dict[str, Any]) -> str:
    parts = []
    conf = v.get('confidence')
    if conf is not None:
        parts.append(f"confidence={conf}")
    if v.get('taint_verified'):
        parts.append('taint=verified')
    srcs = v.get('taint_sources') or []
    if srcs:
        parts.append(f"sources={','.join(str(s) for s in srcs[:3])}")
    return '; '.join(parts) if parts else '-'


def build_enhanced_summary(findings: List[Dict],
                           binary_info: Dict = None) -> str:
    """生成告警摘要 Markdown 文本。无告警时返回占位说明。"""
    if not findings:
        return "## 告警摘要\n\n未检出漏洞。\n"

    lines = ["## 告警摘要", ""]
    for i, v in enumerate(findings, 1):
        vtype = v.get('type', '?')
        sev = v.get('severity', '?')
        func = v.get('function_name', v.get('location', '?'))
        lines.append(f"### {i}. {vtype} [{sev}] — {func}")
        conf = _confidence_line(v)
        if conf != '-':
            lines.append(f"- 置信度: {conf}")
        if v.get('llm_priority') is not None:
            lines.append(f"- LLM 优先度: {v['llm_priority']} "
                         f"(exploitable={v.get('llm_exploitable', False)})")
        desc = str(v.get('description', '')).strip()
        if desc:
            lines.append(f"- 描述: {desc[:200]}")
        ev = str(v.get('evidence', '')).strip()
        if ev:
            first_line = ev.splitlines()[0] if ev else ''
            lines.append(f"- 证据: {first_line[:200]}")
        lines.append("")
    return '\n'.join(lines).rstrip() + '\n'
