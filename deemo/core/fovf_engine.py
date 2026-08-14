"""FOVF 组合引擎 — 串联调用点提取 → 参数值流分类 → 三值裁决, 对外提供 detect_fmt_fovf 入口。
格式调用点覆盖 printf/fprintf/sprintf/snprintf/dprintf/syslog/vsprintf/vsnprintf/vprintf/vfprintf;
snprintf 格式参数位置为 2, 其余按参数位置表取。"""

import re
import time
from typing import List, Tuple

from core.fovf_types import (
    ArgCategory, FmtCallSite, FmtEvidence, FmtVerdict, FovfStats,
)
from core.fovf_argflow import (
    FovfArgClassifier, _fmt_position, _split_top,
)
from core.hovf_write_extract import _strip_block_comments

_FMT_FUNCS = frozenset((
    'printf', 'fprintf', 'sprintf', 'snprintf', 'dprintf', 'syslog',
    'vsprintf', 'vsnprintf', 'vprintf', 'vfprintf',
))
_CALL_RE = re.compile(
    r'\b(printf|fprintf|sprintf|snprintf|dprintf|syslog|vsprintf|'
    r'vsnprintf|vprintf|vfprintf)\s*\(')
_FUNC_BODY = re.compile(r'^[A-Za-z_][\w \*]*\s*(\w+)\s*\(')


def _is_inside_function(line: str) -> bool:
    return bool(_FUNC_BODY.search(line))


def _extract_sites(ir: List[str]) -> List[FmtCallSite]:
    """提取危险格式化调用点.

    对每个 printf 系调用, 用括号匹配取其完整实参, 顶层切分后
    按参数位置表取格式参数.
    """
    sites: List[FmtCallSite] = []
    for pc, line in enumerate(ir):
        for m in _CALL_RE.finditer(line):
            fname = m.group(1)
            pos = _fmt_position(fname)
            inner = _paren_inner(line, m.end() - 1)
            if inner is None:
                continue
            args = _split_top(inner)
            if pos < len(args):
                sites.append(FmtCallSite(
                    pc=pc, func=fname, fmt_arg=args[pos], fmt_pos=pos,
                    line=line.strip()))
    return sites


def _paren_inner(line: str, open_idx: int) -> str | None:
    """取 open_idx 处 '(' 的匹配闭括号内部内容; 无匹配返回 None."""
    depth = 0
    for i in range(open_idx, len(line)):
        ch = line[i]
        if ch in '([{':
            depth += 1
        elif ch in ')]}':
            depth -= 1
            if depth == 0:
                return line[open_idx + 1:i]
    return None


def detect_fmt_fovf(ir_lines: List[str]) -> Tuple[
        List[FmtEvidence], FovfStats]:
    """FOVF 入口: 返回逐调用点证据与统计.

    FILTERED 证据从保留列表排除, 保留项为 CONFIRMED/UNCERTAIN.
    """
    t0 = time.perf_counter()
    ir = _strip_block_comments(list(ir_lines))
    sites = _extract_sites(ir)
    classifier = FovfArgClassifier(ir)
    evidence: List[FmtEvidence] = []
    stats = FovfStats(call_sites=len(sites))
    for site in sites:
        category, reasons = classifier.classify(site.fmt_arg)
        danger = classifier.danger_specs(site.fmt_arg)
        ev = FmtEvidence(
            verdict=FmtVerdict.UNCERTAIN, site=site, category=category,
            reasons=reasons, has_danger_spec=danger,
            confidence=0.50)
        if category in (ArgCategory.LITERAL, ArgCategory.CONST_BUFFER):
            ev.verdict = FmtVerdict.FILTERED
            ev.confidence = 0.05
            stats.filtered += 1
        elif category in (ArgCategory.USER, ArgCategory.TEMPLATE):
            ev.verdict = FmtVerdict.CONFIRMED
            ev.confidence = 0.85 if category == ArgCategory.USER else 0.70
            stats.confirmed += 1
        else:
            ev.verdict = FmtVerdict.UNCERTAIN
            stats.uncertain += 1
        evidence.append(ev)
    if stats.call_sites:
        stats.fp_reduction_ratio = stats.filtered / stats.call_sites
    stats.elapsed_ms = (time.perf_counter() - t0) * 1000
    return evidence, stats


def kept_evidence(evidence: List[FmtEvidence]) -> List[FmtEvidence]:
    """保留 CONFIRMED/UNCERTAIN 证据 (剔除 FILTERED)."""
    return [e for e in evidence if e.verdict != FmtVerdict.FILTERED]
