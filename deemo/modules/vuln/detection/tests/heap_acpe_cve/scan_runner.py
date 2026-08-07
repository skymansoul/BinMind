"""ACPE 样本扫描器 — 对每个样本运行 ACPE 与基线(DP-TVRA)双检测.

创建: 2026-07-14
对每个样本的编译产物:
  ACPE:   acpe_analyze_binary → 逐写入判定 (SAFE/CONFIRMED/LIKELY/UNCERTAIN)
  基线:   reg_tracker + fp_filter_v2 (现有 DP-TVRA 三阶段管线)
输出:    results/<sample_id>.json (双检测的逐写入结果与样本级判定)

样本级判定:
  detected = 存在任一保留的写入 (ACPE: verdict!=SAFE; 基线: kept)
用法:
  python scan_runner.py [样本根目录] [--objs-dir bin/plain]
"""

import argparse
import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve()
for _anchor in _HERE.parents:
    if (_anchor / 'modules').exists():
        sys.path.insert(0, str(_anchor))
        break

from modules.vuln.detection.heap_analysis.insn_parser import (
    disassemble, parse_instructions)
from modules.vuln.detection.heap_analysis.reg_tracker import analyze_function
from modules.vuln.detection.heap_analysis.fp_filter_v2 import (
    run_pipeline, FilterDecision)
from modules.vuln.detection.heap_analysis.acpe import acpe_analyze_binary


def baseline_detect(binary: str) -> dict:
    """现有 DP-TVRA 基线: reg_tracker 提取 alloc/write, fp_filter_v2 过滤."""
    asm = disassemble(binary)
    findings = []
    if asm:
        functions = parse_instructions(asm)
        fa_list = [analyze_function(fn.name, fn.insns) for fn in functions]
        alloc_records = {}
        for fa in fa_list:
            for a in fa.allocs:
                alloc_records[a.addr] = a
        report = run_pipeline(fa_list, alloc_records)
        findings = [
            {
                'func': ff.func_name,
                'addr': ff.insn_addr,
                'decision': ff.decision.value,
                'phase': ff.decisive_phase.value,
                'reasoning': ff.reasoning,
                'alloc_size': ff.alloc_size,
                'write_size': ff.write_size,
            }
            for ff in report.findings
            if ff.decision != FilterDecision.SAFE_FILTERED
        ]
    return {
        'detected': len(findings) > 0,
        'kept': len(findings),
        'findings': findings,
    }


def acpe_detect(binary: str) -> dict:
    report = acpe_analyze_binary(binary)
    kept = [v for v in report.verdicts if v.verdict.value != 'safe']
    return {
        'detected': len(kept) > 0,
        'kept': len(kept),
        'error': report.error,
        'findings': [
            {
                'func': v.func_name,
                'addr': v.write_addr,
                'write_func': v.write_func,
                'relation': v.relation,
                'verdict': v.verdict.value,
                'reasoning': v.reasoning,
            }
            for v in report.verdicts
        ],
    }


def scan_sample(sample_dir: Path, subdir: str) -> dict:
    name = sample_dir.name
    src = next(sample_dir.glob('*.c'), None)
    stem = src.stem if src else name
    bin_path = sample_dir / 'bin' / subdir / f'{stem}.exe'
    result = {'id': name, 'binary': '', 'acpe': {}, 'baseline': {}}
    if not bin_path.exists():
        result['error'] = 'binary not compiled'
        return result
    result['binary'] = str(bin_path)
    result['acpe'] = acpe_detect(str(bin_path))
    result['baseline'] = baseline_detect(str(bin_path))
    return result


def scan_all(root: Path, subdir: str, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    for d in sorted(root.iterdir()):
        if not d.is_dir():
            continue
        res = scan_sample(d, subdir)
        rows.append(res)
        (out / f'{res["id"]}.json').write_text(
            json.dumps(res, ensure_ascii=False, indent=2), encoding='utf-8')
        a, b = res.get('acpe', {}), res.get('baseline', {})
        print(f"[scan] {res['id']:22s} acpe_det={a.get('detected')} "
              f"baseline_det={b.get('detected')} "
              f"acpe_kept={a.get('kept')} base_kept={b.get('kept')}")
    (out / '_all_results.json').write_text(
        json.dumps(rows, ensure_ascii=False, indent=2), encoding='utf-8')


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('root', nargs='?', default=None)
    ap.add_argument('--objs', default='plain')
    ap.add_argument('--out', default='results')
    args = ap.parse_args()
    here = Path(__file__).resolve().parent
    root = Path(args.root) if args.root else here / 'samples'
    scan_all(root, args.objs, here / args.out)


if __name__ == '__main__':
    main()
