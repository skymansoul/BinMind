"""ALPR UAF 扫描器 — 对每个样本运行 ALPR 与既有 uaf_detector 基线.

创建: 2025-06-09
样本级判定:
  detected = 存在任一保留的 UAF 告警
  ALPR:     CONFIRMED / LIKELY 为告警, SAFE_REBOUND 为滤除
  基线:     既有 detect_uaf 的输出非空
用法:
  python scan_runner.py [样本根目录] [--objs plain] [--out results]
"""

import argparse
import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
for _anchor in _HERE.parents:
    if (_anchor / 'modules').exists():
        sys.path.insert(0, str(_anchor))
        break

from modules.vuln.detection.heap_analysis.insn_parser import (
    disassemble, parse_instructions)
from modules.vuln.detection.uaf_detector import detect_uaf
from modules.vuln.detection.heap_analysis.uaf_alpr import alpr_analyze_binary


def baseline_detect(binary: str) -> dict:
    """既有 UAF 基线: 指令字符串列表喂给 detect_uaf."""
    asm = disassemble(binary)
    findings = []
    if asm:
        functions = parse_instructions(asm)
        for fn in functions:
            insn_strs = [f"{i.mnemonic} {i.operands}" for i in fn.insns]
            findings.extend(detect_uaf(insn_strs))
    return {
        'detected': len(findings) > 0,
        'kept': len(findings),
        'findings': [f.__dict__ for f in findings],
    }


def alpr_detect(binary: str) -> dict:
    report = alpr_analyze_binary(binary)
    kept = [v for v in report.verdicts
            if v.verdict.value in ('confirmed', 'likely')]
    return {
        'detected': len(kept) > 0,
        'kept': len(kept),
        'error': report.error,
        'findings': [
            {
                'func': v.func_name,
                'use_addr': v.use_addr,
                'verdict': v.verdict.value,
                'reasoning': v.reasoning,
            } for v in report.verdicts
        ],
    }


def scan_sample(sample_dir: Path, subdir: str) -> dict:
    src = next(sample_dir.glob('*.c'), None)
    stem = src.stem if src else sample_dir.name
    bin_path = sample_dir / 'bin' / subdir / f'{stem}.exe'
    result = {'id': sample_dir.name, 'binary': '',
              'alpr': {}, 'baseline': {}}
    if not bin_path.exists():
        result['error'] = 'binary not compiled'
        return result
    result['binary'] = str(bin_path)
    result['alpr'] = alpr_detect(str(bin_path))
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
        a, b = res.get('alpr', {}), res.get('baseline', {})
        print(f"[scan] {res['id']:22s} alpr_det={a.get('detected')} "
              f"base_det={b.get('detected')} "
              f"alpr_kept={a.get('kept')} base_kept={b.get('kept')}")
    (out / '_all_results.json').write_text(
        json.dumps(rows, ensure_ascii=False, indent=2), encoding='utf-8')


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('root', nargs='?', default=None)
    ap.add_argument('--objs', default='plain')
    ap.add_argument('--out', default='results')
    args = ap.parse_args()
    root = Path(args.root) if args.root else _HERE / 'samples'
    scan_all(root, args.objs, _HERE / args.out)


if __name__ == '__main__':
    main()
