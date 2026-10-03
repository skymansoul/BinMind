"""FPE 判定过滤器 — 格式溯源等价分类.

用途: 对追踪器产出的格式调用, 按格式参数溯源分类:

  - .rdata/.const → 常量格式串 → SAFE_CONST (滤除)
  - argN → 参数提供 → VULN_PARAM (保守保留)
  - stack/unknown → VULN_LOCAL / UNCERTAIN (保留)

设计决策:
  - 常量格式串 `printf("...")` 无漏洞: 即使格式串含 % 占位符, 参数
    由编译器按常量串约定配对, 无用户控制格式串的可能。
  - 参数溯源无法在函数内判定其是否最终为常量 (调用方可能传常量串),
    保守保留为 VULN_PARAM, 不滤除。
"""

from typing import List

from modules.vuln.detection.heap_analysis.fmt_fpe.fmt_types import (
    FmtCall, FmtVerdict, FmtVerdictRecord, FuncFmtResult)

_SAFE_LABELS = {'.rdata', '.rodata', 'const'}


def evaluate_call(call: FmtCall) -> FmtVerdictRecord:
    if call.fmt_label in _SAFE_LABELS:
        return FmtVerdictRecord(
            func_name=call.func_name, addr=call.addr,
            fmt_func=call.fmt_func, fmt_label=call.fmt_label,
            verdict=FmtVerdict.SAFE_CONST,
            reasoning=(f'format from {call.fmt_label} constant pool — '
                       f'constant format string'),
            confidence=0.90, fp_probability=0.90)
    if call.fmt_label.startswith('arg'):
        return FmtVerdictRecord(
            func_name=call.func_name, addr=call.addr,
            fmt_func=call.fmt_func, fmt_label=call.fmt_label,
            verdict=FmtVerdict.VULN_PARAM,
            reasoning=(f'format from parameter {call.fmt_label} — '
                       f'potentially user-controlled'),
            confidence=0.55, fp_probability=0.35)
    if call.fmt_label == 'stack':
        return FmtVerdictRecord(
            func_name=call.func_name, addr=call.addr,
            fmt_func=call.fmt_func, fmt_label=call.fmt_label,
            verdict=FmtVerdict.VULN_LOCAL,
            reasoning='format from stack/local buffer — cannot prove constant',
            confidence=0.50, fp_probability=0.50)
    return FmtVerdictRecord(
        func_name=call.func_name, addr=call.addr,
        fmt_func=call.fmt_func, fmt_label=call.fmt_label,
        verdict=FmtVerdict.UNCERTAIN,
        reasoning=f'format provenance unknown: {call.fmt_label}',
        confidence=0.50, fp_probability=0.50)


def run_filter(result: FuncFmtResult) -> List[FmtVerdictRecord]:
    verdicts = [evaluate_call(c) for c in result.calls]
    result.verdicts = verdicts
    return verdicts


def summarize(verdicts: List[FmtVerdictRecord]) -> dict:
    counts = {v: 0 for v in FmtVerdict}
    for rec in verdicts:
        counts[rec.verdict] += 1
    total = len(verdicts)
    kept = counts[FmtVerdict.VULN_PARAM] + counts[FmtVerdict.VULN_LOCAL] \
        + counts[FmtVerdict.UNCERTAIN]
    safe = counts[FmtVerdict.SAFE_CONST]
    return {
        'total': total,
        'safe_const': safe,
        'vuln_param': counts[FmtVerdict.VULN_PARAM],
        'vuln_local': counts[FmtVerdict.VULN_LOCAL],
        'uncertain': counts[FmtVerdict.UNCERTAIN],
        'kept': kept,
        'fp_reduction_pct': round(safe / total * 100, 1) if total else 0.0,
    }


# 自检
def _check():
    c1 = FmtCall(0x100, 'f', 'printf', '.rdata', 'rcx')
    r1 = evaluate_call(c1)
    assert r1.verdict == FmtVerdict.SAFE_CONST, r1
    c2 = FmtCall(0x120, 'f', 'printf', 'arg2', 'rdx')
    r2 = evaluate_call(c2)
    assert r2.verdict == FmtVerdict.VULN_PARAM, r2
    c3 = FmtCall(0x140, 'f', 'sprintf', 'stack', 'rcx')
    r3 = evaluate_call(c3)
    assert r3.verdict == FmtVerdict.VULN_LOCAL, r3
    s = summarize([r1, r2, r3])
    assert s['safe_const'] == 1 and s['kept'] == 2, s
    print('[OK] fmt_filter passed')


if __name__ == '__main__':
    _check()
