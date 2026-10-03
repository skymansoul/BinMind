"""ALPR 顶层管线 — objdump → 函数分组 → 生命周期追踪 → 重绑定过滤 → 报告.

用途: UAF 误报削减管线的统一入口。对单个二进制输出:
      - 每次 use 的 (判定, 推理)
      - 函数级汇总 (确认/存疑/重绑定滤除)
      - 误报削减率 (SAFE_REBOUND 占比)
"""

from dataclasses import dataclass, field
from typing import List

from modules.vuln.detection.heap_analysis.insn_parser import (
    disassemble, parse_instructions, is_user_function)

from modules.vuln.detection.heap_analysis.uaf_alpr.lifetime_tracker import (
    LifetimeTracker)
from modules.vuln.detection.heap_analysis.uaf_alpr.interproc import (
    build_summaries)
from modules.vuln.detection.heap_analysis.uaf_alpr.rebound_filter import (
    run_filter, summarize)
from modules.vuln.detection.heap_analysis.uaf_alpr.uaf_types import (
    UafVerdictRecord)


@dataclass
class AlprBinaryReport:
    binary_path: str
    verdicts: List[UafVerdictRecord] = field(default_factory=list)
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
                    'use_addr': v.use_addr,
                    'ptr_reg': v.ptr_reg,
                    'use_kind': v.use_kind.value,
                    'freed_label': v.freed_label,
                    'use_label': v.use_label,
                    'verdict': v.verdict.value,
                    'reasoning': v.reasoning,
                    'confidence': v.confidence,
                } for v in self.verdicts
            ],
        }


def analyze_functions(functions) -> List[UafVerdictRecord]:
    verdicts: List[UafVerdictRecord] = []
    tracker = LifetimeTracker()
    # 第一遍: 函数级摘要 (过程间 free/use 参数)
    summaries = build_summaries(functions, tracker)
    # 第二遍: 带摘要展开的完整分析
    for fn in functions:
        if not is_user_function(fn.name):
            continue
        result = tracker.analyze_function(fn.name, fn.insns, summaries)
        verdicts.extend(run_filter(result))
    return verdicts


def alpr_analyze_binary(binary_path: str,
                        timeout_s: int = 30) -> AlprBinaryReport:
    import time
    report = AlprBinaryReport(binary_path=binary_path)
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
    rep = alpr_analyze_binary(path)
    print(json.dumps(rep.to_dict(), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
