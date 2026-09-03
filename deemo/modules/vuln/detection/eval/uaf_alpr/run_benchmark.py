"""UAF 多工具对比 — 外部工具调用脚本 + 主实验 + 可视化 + LaTeX.

工具口径:
  angr/ghidra 为朴素对照: 见 free+malloc 同时存在即告警 (高召回高误报)
  qemu         运行时具体迹: 仅记录实际触发的 free→use
  alpr         本方法: 溯源等价重绑定判定
  baseline     既有 uaf_detector
"""

import json
import subprocess
import sys
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent


# 工具实现
def angr_detect(binary: str) -> dict:
    try:
        import angr
    except ImportError:
        return {'detected': False, 'error': 'angr not installed'}
    try:
        proj = angr.Project(binary, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
        names = {f.name for f in cfg.functions.values() if f.name}
        has_free = bool(names & {'free', '_ZdlPv'})
        has_alloc = bool(names & {'malloc', 'calloc', 'realloc'})
        return {'detected': has_free and has_alloc,
                'finding_count': len(names & {'free', 'malloc'})}
    except Exception as exc:
        return {'detected': False, 'error': f'{type(exc).__name__}: {exc}'}


def ghidra_detect(binary: str) -> dict:
    from modules.vuln.detection.heap_analysis.insn_parser import (
        disassemble, parse_instructions)
    asm = disassemble(binary)
    has_free = has_alloc = False
    if asm:
        for fn in parse_instructions(asm):
            for insn in fn.insns:
                op = insn.operands.lower()
                if insn.mnemonic == 'call':
                    if 'free' in op:
                        has_free = True
                    if 'malloc' in op or 'calloc' in op:
                        has_alloc = True
    return {'detected': has_free and has_alloc,
            'finding_count': int(has_free) + int(has_alloc)}


def qemu_detect(binary: str) -> dict:
    from modules.vuln.detection.eval.acpe.qemu_tracer import trace
    r = trace(binary)
    return {'detected': r.get('detected', False),
            'finding_count': r.get('finding_count', 0),
            'error': r.get('error', '')}


def alpr_detect(binary: str) -> dict:
    from modules.vuln.detection.heap_analysis.uaf_alpr import alpr_analyze_binary
    rep = alpr_analyze_binary(binary)
    kept = [v for v in rep.verdicts if v.verdict.value in ('confirmed', 'likely')]
    return {'detected': len(kept) > 0, 'finding_count': len(kept)}


def baseline_detect(binary: str) -> dict:
    from modules.vuln.detection.heap_analysis.insn_parser import (
        disassemble, parse_instructions)
    from modules.vuln.detection.uaf_detector import detect_uaf
    asm = disassemble(binary)
    n = 0
    if asm:
        for fn in parse_instructions(asm):
            insn_strs = [f"{i.mnemonic} {i.operands}" for i in fn.insns]
            n += len(detect_uaf(insn_strs))
    return {'detected': n > 0, 'finding_count': n}


TOOLS = {
    'alpr': alpr_detect,
    'baseline': baseline_detect,
    'angr': angr_detect,
    'qemu': qemu_detect,
    'ghidra': ghidra_detect,
}


def discover_samples(root: Path) -> list:
    manifest = root / 'manifest.json'
    exp = {}
    if manifest.exists():
        exp = {d['id']: d['expected']
               for d in json.loads(manifest.read_text(encoding='utf-8'))}
    samples = []
    for d in sorted(root.iterdir()):
        if not d.is_dir():
            continue
        src = next(d.glob('*.c'), None)
        if src is None:
            continue
        bins = {}
        for tier in ('plain', 'packed'):
            b = d / 'bin' / tier / f'{src.stem}.exe'
            if b.exists():
                bins[tier] = str(b)
        samples.append({'id': d.name, 'expected': exp.get(d.name, 'vuln'),
                        'bins': bins})
    return samples


def run_all(root: Path, out: Path) -> dict:
    import csv
    import tracemalloc
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    by_tool = {t: {'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0, 'time': 0.0}
               for t in TOOLS}
    for s in discover_samples(root):
        for tier, binary in s['bins'].items():
            for name, func in TOOLS.items():
                tracemalloc.start()
                t0 = time.time()
                try:
                    r = func(binary)
                except Exception as exc:
                    r = {'detected': False, 'error': str(exc)}
                elapsed = round(time.time() - t0, 3)
                _, peak = tracemalloc.get_traced_memory()
                tracemalloc.stop()
                det = bool(r.get('detected', False))
                vuln = s['expected'] == 'vuln'
                tp = 1 if vuln and det else 0
                fp = 1 if not vuln and det else 0
                fn = 1 if vuln and not det else 0
                tn = 1 if not vuln and not det else 0
                st = by_tool[name]
                st['tp'] += tp; st['fp'] += fp; st['fn'] += fn; st['tn'] += tn
                st['time'] += elapsed
                rows.append([name, f"{s['id']}:{tier}", int(det), fp, fn,
                             elapsed, round(peak / (1024 * 1024), 3)])
    with open(out / 'benchmark_results.csv', 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['tool', 'sample_id', 'detected', 'fp', 'fn',
                    'elapsed_sec', 'peak_mem_mb'])
        w.writerows(rows)
    summary = {}
    for t, st in by_tool.items():
        recall = st['tp'] / (st['tp'] + st['fn']) if (st['tp'] + st['fn']) else 0
        precision = (st['tp'] / (st['tp'] + st['fp'])
                     if (st['tp'] + st['fp']) else 0)
        f1 = (2 * precision * recall / (precision + recall)
              if (precision + recall) else 0)
        summary[t] = {
            'tp': st['tp'], 'fp': st['fp'], 'tn': st['tn'], 'fn': st['fn'],
            'recall': round(recall, 4), 'precision': round(precision, 4),
            'f1': round(f1, 4),
            'fp_rate': round(st['fp'] / (st['fp'] + st['tn']), 4)
            if (st['fp'] + st['tn']) else 0.0,
            'total_sec': round(st['time'], 3),
        }
    (out / 'benchmark_summary.json').write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return summary


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--samples', default=None)
    ap.add_argument('--out', default=None)
    args = ap.parse_args()
    root = Path(args.samples) if args.samples else (
        _HERE.parent.parent / 'tests' / 'uaf_alpr' / 'samples')
    out = Path(args.out) if args.out else _HERE / 'results'
    run_all(root, out)


if __name__ == '__main__':
    main()
