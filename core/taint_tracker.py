"""函数内 use-def 污点传播 — 区分用户输入与内部数据流。
按行序做标签传播: 标记污点源(read/recv/fgets/scanf/getenv) → 赋值传播 →
到达 sink (strcpy/printf/system) 时检查标签, 无标签则降级置信度。复杂度 O(N·V)。
"""


import re
from typing import Dict, List, Set

from core.detection_shared import (
    TaintSource, TaintSink, TaintPath, is_source, is_sink,
)

# 赋值模式
_RE_FUNC_ASSIGN = re.compile(r'(\w[\w.]*)\s*=\s*(\w+)\s*\(')
_RE_VAR_ASSIGN = re.compile(r'(\w[\w.]*)\s*=\s*(\w[\w.]*)')
# 函数调用模式
_RE_ANY_CALL = re.compile(r'(\w+)\s*\(([^)]*)\)')


def track_taint_intraprocedural(
    pseudocode: str,
    func_name: str,
) -> list[TaintPath]:
    """在单个函数内做 use-def 污点传播。

    输入: 反编译伪代码文本。
    返回: TaintPath 列表，按置信度降序。
    """
    lines = pseudocode.split('\n')
    paths: list[TaintPath] = []

    sources = _find_sources(lines, func_name)
    if not sources:
        return paths

    sinks = _find_sinks(lines, func_name)
    if not sinks:
        return paths

    # 标签传播: var → 源索引集合
    labels: dict[str, set[int]] = {}

    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith('//') or stripped.startswith('#'):
            continue

        # 污点源标记
        for si, src in enumerate(sources):
            if src.kind in stripped.lower():
                m = _RE_ANY_CALL.search(stripped)
                if m:
                    args = [a.strip().lstrip('&*') for a in m.group(2).split(',')]
                    for a in args:
                        if a and not a.startswith('"') and not a[0].isdigit():
                            labels.setdefault(a, set()).add(si)
                    # 如果有赋值左值
                    assign_m = _RE_FUNC_ASSIGN.search(stripped)
                    if assign_m:
                        labels.setdefault(assign_m.group(1), set()).add(si)

        # 传播: x = y
        var_m = _RE_VAR_ASSIGN.search(stripped)
        if var_m:
            lhs, rhs = var_m.group(1), var_m.group(2)
            if rhs in labels:
                labels.setdefault(lhs, set()).update(labels[rhs])

        # Sink 检查
        for sink in sinks:
            if sink.kind in stripped.lower():
                m = _RE_ANY_CALL.search(stripped)
                if m:
                    call_args = [a.strip().lstrip('&*') for a in m.group(2).split(',')]
                    for arg in call_args:
                        if arg and arg in labels and labels[arg]:
                            for si in labels[arg]:
                                paths.append(TaintPath(
                                    source=sources[si],
                                    sink=TaintSink(
                                        kind=sink.kind, var_name=arg,
                                        func_name=func_name, lineno=lineno,
                                    ),
                                    hops=[arg],
                                    confidence=(
                                        0.8 if len(labels[arg]) == 1 else 0.55
                                    ),
                                ))

    paths.sort(key=lambda p: p.confidence, reverse=True)
    return paths


def _find_sources(lines: list[str], func_name: str) -> list[TaintSource]:
    source_kinds = ['read', 'recv', 'fgets', 'gets', 'scanf', 'fscanf', 'getenv']
    found: list[TaintSource] = []
    for i, line in enumerate(lines, start=1):
        lower = line.lower()
        for kind in source_kinds:
            if kind in lower and f'{kind}(' in lower:
                found.append(TaintSource(
                    kind=kind, var_name='?', func_name=func_name, lineno=i,
                ))
                break
    return found


def _find_sinks(lines: list[str], func_name: str) -> list[TaintSink]:
    sink_kinds = ['strcpy', 'sprintf', 'printf', 'system', 'memcpy', 'strcat']
    found: list[TaintSink] = []
    for i, line in enumerate(lines, start=1):
        lower = line.lower()
        for kind in sink_kinds:
            if kind in lower and f'{kind}(' in lower:
                found.append(TaintSink(
                    kind=kind, var_name='?', func_name=func_name, lineno=i,
                ))
                break
    return found


def filter_by_taint(
    findings: list[dict],
    pseudocode: str,
    func_name: str,
) -> list[dict]:
    """用污点分析过滤 finding 列表。

    有污点路径 → 保留或提升置信度
    无污点路径(format-string/stack-overflow) → 降 severity 为 Medium 附加说明
    heap-corruption → 不过滤（UAF 的 free/malloc 不在 sink 集合中）
    """
    paths = track_taint_intraprocedural(pseudocode, func_name)
    tainted_vars: set[str] = set()
    for p in paths:
        tainted_vars.add(p.sink.var_name)
        tainted_vars.update(p.hops)

    filtered: list[dict] = []
    for f in findings:
        vtype = f.get('type', '')
        if vtype not in ('format-string', 'format_string', 'stack-overflow', 'stack_overflow'):
            filtered.append(f)
            continue

        desc = f.get('description', '')
        fmt_arg = f.get('format_arg', '')
        has_taint = any(v in desc or v == fmt_arg for v in tainted_vars)

        if has_taint:
            f['taint_verified'] = True
            f['taint_paths'] = [
                {'source': p.source.kind, 'sink': p.sink.kind, 'hops': p.hops}
                for p in paths
                if p.sink.var_name in desc or p.sink.var_name == fmt_arg
            ]
        elif paths:
            f['severity'] = 'Medium'
            f['taint_verified'] = False
            f['description'] += ' [taint: no user-input path to this sink]'
        filtered.append(f)
    return filtered
