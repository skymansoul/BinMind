"""FPE 格式字符串多工具对比 — 主实验 + 可视化 + LaTeX.

创建: 2024-12-09
工具口径:
  angr/ghidra 朴素对照: 见 printf 族调用即告警 (高召回高误报)
  qemu         运行时具体迹
  fpe          本方法: 格式溯源等价判定
  baseline     既有 format_string_detector
"""

import argparse
import csv
import json
import sys
import time
import tracemalloc
from collections import defaultdict
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_FMT_SYMS = {'printf', 'fprintf', 'sprintf', 'snprintf', 'dprintf',
             'syslog', 'vprintf', 'vfprintf', 'vsprintf', 'vsnprintf'}


def angr_detect(binary: str) -> dict:
    try:
        import angr
        proj = angr.Project(binary, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
        names = {f.name for f in cfg.functions.values() if f.name}
        found = names & _FMT_SYMS
        return {'detected': len(found) > 0, 'finding_count': len(found)}
    except Exception as exc:
        return {'detected': False, 'error': f'{type(exc).__name__}: {exc}'}


def ghidra_detect(binary: str) -> dict:
    from modules.vuln.detection.heap_analysis.insn_parser import (
        disassemble, parse_instructions)
    asm = disassemble(binary)
    n = 0
    if asm:
        for fn in parse_instructions(asm):
            for insn in fn.insns:
                op = insn.operands.lower()
                if insn.mnemonic in ('call', 'jmp') and '<' in op:
                    callee = op.split('<')[-1].split('>')[0].replace('__mingw_', '')
                    if callee in _FMT_SYMS:
                        n += 1
    return {'detected': n > 0, 'finding_count': n}


def qemu_detect(binary: str) -> dict:
    from modules.vuln.detection.eval.acpe.qemu_tracer import trace
    r = trace(binary)
    return {'detected': r.get('detected', False),
            'finding_count': r.get('finding_count', 0)}


def fpe_detect(binary: str) -> dict:
    from modules.vuln.detection.heap_analysis.fmt_fpe import fpe_analyze_binary
    rep = fpe_analyze_binary(binary)
    kept = [v for v in rep.verdicts if v.verdict.value != 'safe_const']
    return {'detected': len(kept) > 0, 'finding_count': len(kept)}


def baseline_detect(binary: str) -> dict:
    from modules.vuln.detection.heap_analysis.insn_parser import (
        disassemble, parse_instructions)
    from modules.vuln.detection.format_string_detector import (
        detect_format_string)
    asm = disassemble(binary)
    n = 0
    if asm:
        for fn in parse_instructions(asm):
            insn_strs = [f"{i.mnemonic} {i.operands}" for i in fn.insns]
            n += len(detect_format_string(insn_strs))
    return {'detected': n > 0, 'finding_count': n}


TOOLS = {'fpe': fpe_detect, 'baseline': baseline_detect,
         'angr': angr_detect, 'qemu': qemu_detect, 'ghidra': ghidra_detect}


def discover_samples(root: Path) -> list:
    manifest = root / 'manifest.json'
    exp = {}
    if manifest.exists():
        exp = {d['id']: d['expected']
               for d in json.loads(manifest.read_text(encoding='utf-8'))}
    sources = {d['id']: d['source'] for d in
               json.loads(manifest.read_text(encoding='utf-8'))} if manifest.exists() else {}
    samples = []
    for d in sorted(root.iterdir()):
        if not d.is_dir():
            continue
        src = root / sources.get(d.name, '') if d.name in sources else None
        if src is None or not src.exists():
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
    ap = argparse.ArgumentParser()
    ap.add_argument('--samples', default=None)
    ap.add_argument('--out', default=None)
    args = ap.parse_args()
    root = Path(args.samples) if args.samples else (
        _HERE.parent.parent / 'tests' / 'fmt_fpe' / 'samples')
    out = Path(args.out) if args.out else _HERE / 'results'
    run_all(root, out)


if __name__ == '__main__':
    main()
