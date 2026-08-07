"""ACPE 顶层管线 — objdump → 函数分组 → 符号追踪 → 守卫分析 → 判定报告.

创建: 2026-04-22
用途: ACPE 堆溢出误报削减管线的统一入口。对单个二进制输出:
      - 每次写入的 (关系, 判定, 推理)
      - 样本级汇总 (滤除/保留/确定/存疑)
      - 与基线(仅靠污点+边界)的对照, 计算误报削减率

调用:
      report = acpe_analyze_binary('sample.exe')
      report['summary'] → {'fp_reduction_pct': ...}

objdump 定位: 优先环境变量 OBJDUMP, 其次 PATH 中的 objdump。
"""

from dataclasses import dataclass, field
from typing import List

from modules.vuln.detection.heap_analysis.insn_parser import (
    disassemble, parse_instructions, is_user_function)

from modules.vuln.detection.heap_analysis.acpe.sym_size_tracker import (
    SymSizeTracker, match_write_alloc, FuncSymResult)

from modules.vuln.detection.heap_analysis.acpe.guard_dominance import (
    analyze_guards_for_write)

from modules.vuln.detection.heap_analysis.acpe.verdict import (
    AcpeVerdict, evaluate, summarize)


@dataclass
class AcpeBinaryReport:
    binary_path: str
    verdicts: List[AcpeVerdict] = field(default_factory=list)
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
                    'write_addr': v.write_addr,
                    'write_func': v.write_func,
                    'alloc_expr': v.alloc_expr.canonical(),
                    'write_expr': v.write_expr.canonical(),
                    'relation': v.relation,
                    'verdict': v.verdict.value,
                    'reasoning': v.reasoning,
                    'confidence': v.confidence,
                } for v in self.verdicts
            ],
        }


def analyze_functions(functions) -> List[AcpeVerdict]:
    """对所有用户函数运行符号追踪 + 判定."""
    verdicts: List[AcpeVerdict] = []
    tracker = SymSizeTracker()

    for fn in functions:
        if not is_user_function(fn.name):
            continue
        result: FuncSymResult = tracker.analyze_function(fn.name, fn.insns)
        for w in result.writes:
            if w.dst_is_stack:
                # 目标为栈/局部地址, 非堆写入, 不构成堆溢出候选
                continue
            alloc = match_write_alloc(w, result.allocs)
            if alloc is None:
                continue
            guard_ev = analyze_guards_for_write(
                w.addr, w.size_expr.base if w.size_expr.is_symbolic() else '',
                result.guards, result.insns)
            vd = evaluate(
                alloc_expr=alloc.size_expr,
                write_expr=w.size_expr,
                write_unbounded=w.unbounded,
                guard_ev=guard_ev,
                insns=result.insns,
                func_name=result.name,
                write_addr=w.addr,
                write_func=w.write_func,
                write_offset=w.dst_offset,
                offset_unknown=w.dst_offset_unknown,
            )
            verdicts.append(vd)
    return verdicts


def acpe_analyze_binary(binary_path: str, timeout_s: int = 30) -> AcpeBinaryReport:
    """完整分析一个二进制."""
    import time
    report = AcpeBinaryReport(binary_path=binary_path)
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


# CLI
def main():
    import json
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else None
    if not path:
        print(json.dumps({'error': 'usage: python pipeline.py <binary>'}))
        return
    rep = acpe_analyze_binary(path)
    print(json.dumps(rep.to_dict(), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
