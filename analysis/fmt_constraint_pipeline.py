"""
格式串约束引擎 — 管线集成入口 + 模型提取 + 桥接函数。
"""


import re
from typing import List

from analysis.fmt_constraint_engine import (
    FmtCallModel, FormatArgModel, FmtPrimitive,
    CallingConventionModel, DefUseChainTracker, AttackSurfaceComputer,
    AttackSurface,
)

_RE_FMT_CALL = re.compile(
    r'(printf|fprintf|sprintf|snprintf|dprintf|syslog|err|warnx?)\s*'
    r'\(\s*([^,)]*(?:\([^)]*\)[^,)]*)?)')

_RE_FMT_SPEC = re.compile(
    r'%(\d+\$)?([-+ #0]*)(\d*|\*)(\.\d*|\.\*)?([hljztL]{0,2})([diouxXeEfFgGaAcspnS])')

_PRIMITIVE_MAP = {'d': 0, 'i': 0, 'u': 0, 'o': 0, 'x': 1, 'X': 1, 'p': 1,
    's': 2, 'n': 3, 'hn': 4, 'hhn': 4}


def analyze_format_string_deep(source: str) -> List[AttackSurface]:
    """深度格式串分析: DU链构建→约束建模→攻击面量化."""
    du = DefUseChainTracker().build(source)
    models = _extract_models(source, du)
    comp = AttackSurfaceComputer(du)
    return [comp.compute(m) for m in models]


def _extract_models(src: str, du: DefUseChainTracker) -> List[FmtCallModel]:
    models = []
    for i, line in enumerate(src.splitlines(), 1):
        m = _RE_FMT_CALL.search(line)
        if not m:
            continue
        func, raw = m.group(1), m.group(2).strip()
        comma = _comma_outside_parens(raw)
        fexpr = raw[:comma].strip() if comma > 0 else raw
        model = FmtCallModel(call_func=func, call_line=i)
        sm = re.match(r'^"([^"]*)"$', fexpr)
        if sm:
            model.fmt_source, model.fmt_string = "constant", sm.group(1)
        elif re.match(r'^\w[\w.]*$', fexpr):
            model.fmt_source = "external" if du.tainted(fexpr) else "variable"
            model.fmt_string = fexpr
        else:
            model.fmt_source, model.fmt_string = "unknown", fexpr
        ft = model.fmt_string if model.fmt_source == "constant" else ""
        cc = CallingConventionModel()
        si = 0
        for sm in _RE_FMT_SPEC.finditer(ft):
            ps = sm.group(1)
            lm = sm.group(5) or ''
            sc = sm.group(6)
            pos = int(ps[:-1]) if ps else si + 1
            prim = _PRIMITIVE_MAP.get(f'{lm}{sc}', _PRIMITIVE_MAP.get(sc, 0))
            slot = cc.slot(pos)
            model.args.append(FormatArgModel(
                spec_index=si, positional=pos, primitive=prim,
                stack_slot=slot, is_ctrl=cc.controllable(slot)))
            si += 1
        models.append(model)
    return models


def _comma_outside_parens(s: str) -> int:
    depth = 0
    for i, ch in enumerate(s):
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
        elif ch == ',' and depth == 0:
            return i
    return -1


def deep_score_exploitability(surface: AttackSurface) -> float:
    return surface.score


def enhance_with_constraints(solver_calls: List, source: str) -> List[AttackSurface]:
    """桥接: 将 fmt_constraint_solver 的 regex 结果提升为 AttackSurface."""
    du = DefUseChainTracker().build(source)
    comp = AttackSurfaceComputer(du)
    cc = CallingConventionModel()
    surfaces = []
    for call in solver_calls:
        m = FmtCallModel(
            call_func=call.func, call_line=call.lineno,
            fmt_string=call.fmt_arg,
            fmt_source=call.fmt_source.value if hasattr(call.fmt_source, 'value')
            else str(call.fmt_source))
        if call.fmt_text:
            m.fmt_source, m.fmt_string = "constant", call.fmt_text
            si = 0
            for sm in _RE_FMT_SPEC.finditer(call.fmt_text):
                ps = sm.group(1)
                lm = sm.group(5) or ''
                sc = sm.group(6)
                pos = int(ps[:-1]) if ps else si + 1
                prim = _PRIMITIVE_MAP.get(f'{lm}{sc}', _PRIMITIVE_MAP.get(sc, 0))
                slot = cc.slot(pos)
                m.args.append(FormatArgModel(
                    spec_index=si, positional=pos,
                    primitive=prim, stack_slot=slot,
                    is_ctrl=cc.controllable(slot)))
                si += 1
        surfaces.append(comp.compute(m))
    return surfaces
