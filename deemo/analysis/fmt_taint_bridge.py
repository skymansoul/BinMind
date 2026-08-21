"""
格式串污点桥接器 — 将 fmt_taint_verifier (5-phase 污点传播) 和
fmt_parser_dfa (DFA-based 格式说明符解析) 接入 fmt_detector 的 regex-based 检测。

设计决策: 不做检测逻辑替代, 而是做后处理精化 —
  1. 对每个 finding, 用 DFA 解析器验证是否真含危险说明符
  2. 对标记为 EXTERNAL_INPUT 的 finding, 用污点传播验证是否真可达
  3. 无法验证的保持原样 (保守)

原则: 宁可误报, 不可漏报。只在可证明为良性时降级。
"""

import re
from typing import Any, Dict, List, Optional, Tuple

from analysis.fmt_parser_dfa import (
    FmtDanger, classify_fmt_danger,
)
from analysis.fmt_taint_verifier import (
    FmtTaintVerifier, FmtVerdict, FtvResult,
)


def refine_fmt_findings(
    findings: List[Dict[str, Any]],
    source: str,
) -> Dict[str, Any]:
    """对 fmt_detector 的发现做后处理精化。

    对每个 finding:
      1. 用 DFA 解析器确认格式说明符危险等级
      2. 用污点验证器确认 EXTERNAL_INPUT 是否真可达
      3. 常量格式串且无危险说明符 → SAFE (过滤)

    返回 {filtered_count, confirmed_count, detail}.
    """
    if not findings:
        return {'filtered_count': 0, 'confirmed_count': 0, 'detail': 'no findings'}

    # 初始化工具
    verifier = FmtTaintVerifier()

    try:
        ftv_results = verifier.verify(source)
        # 构建 {line_no: FtvResult} 映射
        ftv_by_line: Dict[int, FtvResult] = {}
        for r in ftv_results:
            if r.sink and r.sink.line_no:
                ftv_by_line[r.sink.line_no] = r
    except Exception:
        ftv_by_line = {}

    filtered = 0
    confirmed = 0
    detail_parts: List[str] = []

    for f in findings:
        line_no = f.get('line_no', 0)
        fmt_str_expr = f.get('fmt_str', f.get('fmt_expr', ''))
        arg_source = f.get('arg_source', '')

        # DFA 解析 (仅常量格式串)
        # 从 source 中提取字面量格式串并做危险等级分类
        if arg_source == 'CONSTANT' and line_no > 0:
            lines = source.splitlines()
            if line_no <= len(lines):
                raw_line = lines[line_no - 1]
                lit_match = re.search(r'"([^"]*%[^"]*)"', raw_line)
                if lit_match:
                    danger, has_positional = classify_fmt_danger(lit_match.group(1))
                    if danger in (FmtDanger.INFO, FmtDanger.LEAK):
                        f['_verdict'] = 'SAFE'
                        f['_filter_reason'] = f'DFA: const fmt, danger={danger.name}'
                        filtered += 1
                        detail_parts.append(
                            f'filter L{line_no}: DFA {danger.name} on const fmt')
                        continue
                    if danger in (FmtDanger.WRITE, FmtDanger.CODE_EXEC):
                        f['_confirmed_danger'] = danger.name
                        confirmed += 1
                        detail_parts.append(
                            f'confirm L{line_no}: DFA {danger.name}')

        # 污点验证
        if line_no in ftv_by_line:
            ftv = ftv_by_line[line_no]
            if ftv.verdict == FmtVerdict.SAFE:
                f['_verdict'] = 'SAFE'
                f['_filter_reason'] = f'FTV: {ftv.reason}'
                filtered += 1
                detail_parts.append(f'filter L{line_no}: FTV SAFE')
            elif ftv.verdict == FmtVerdict.VULNERABLE:
                f['_confirmed_taint'] = True
                f['_ftv_reason'] = ftv.reason
                confirmed += 1
                detail_parts.append(f'confirm L{line_no}: FTV VULN {ftv.reason}')

    return {
        'filtered_count': filtered,
        'confirmed_count': confirmed,
        'detail': '; '.join(detail_parts) if detail_parts else 'none',
    }
