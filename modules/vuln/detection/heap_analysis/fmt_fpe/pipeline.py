"""FPE 顶层管线 — objdump → 函数分组 → 格式溯源追踪 → 判定 → 报告.

用途: 格式字符串漏洞误报削减管线的统一入口。
"""

from dataclasses import dataclass, field
from typing import List

from modules.vuln.detection.heap_analysis.insn_parser import (
    disassemble, parse_instructions, is_user_function)

from modules.vuln.detection.heap_analysis.fmt_fpe.fmt_tracker import FmtTracker
from modules.vuln.detection.heap_analysis.fmt_fpe.fmt_filter import (
    run_filter, summarize)
from modules.vuln.detection.heap_analysis.fmt_fpe.fmt_types import (
    FmtVerdictRecord)


@dataclass
class FpeBinaryReport:
    binary_path: str
    verdicts: List[FmtVerdictRecord] = field(default_factory=list)
    functions_analyzed: int = 0
    elapsed_sec: float = 0.0
    error: str = ''

    @property
    def summary(self) -> dict:
        return summarize(self.verdicts)

    def to_dict(self) -> dict:
        s = self.summary
        return {
            'binary': self.binary_path,
            'error': self.error,
            'functions_analyzed': self.functions_analyzed,
            'elapsed_sec': self.elapsed_sec,
            'summary': s,
            'findings': [
                {
                    'func': v.func_name,
                    'addr': v.addr,
                    'fmt_func': v.fmt_func,
                    'fmt_label': v.fmt_label,
                    'verdict': v.verdict.value,
                    'reasoning': v.reasoning,
                } for v in self.verdicts
            ],
        }


def analyze_functions(functions) -> List[FmtVerdictRecord]:
    verdicts: List[FmtVerdictRecord] = []
    tracker = FmtTracker()
    for fn in functions:
        if not is_user_function(fn.name):
            continue
        result = tracker.analyze_function(fn.name, fn.insns)
        verdicts.extend(run_filter(result))
    return verdicts


def fpe_analyze_binary(binary_path: str,
                       timeout_s: int = 30) -> FpeBinaryReport:
    import time
    report = FpeBinaryReport(binary_path=binary_path)
    t0 = time.time()
    try:
        asm = disassemble(binary_path, timeout_s)
        if not asm:
            report.error = 'disassembly failed'
            return report
        functions = parse_instructions(asm)
        report.functions_analyzed = len(functions)
        report.verdicts = analyze_functions(functions)
    except Exception as exc:
        report.error = f'{type(exc).__name__}: {exc}'
    report.elapsed_sec = round(time.time() - t0, 3)
    return report


def main():
    import json
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else None
    if not path:
        print(json.dumps({'error': 'usage: python pipeline.py <binary>'}))
        return
    rep = fpe_analyze_binary(path)
    print(json.dumps(rep.to_dict(), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
