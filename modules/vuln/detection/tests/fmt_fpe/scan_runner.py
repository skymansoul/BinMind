"""FPE 格式字符串扫描器 — 对每个样本运行 FPE 与既有 format_string_detector 基线.

创建: 2025-06-09
样本级判定:
  FPE:     SAFE_CONST 为滤除, 其余为告警
  基线:    既有 detect_format_string 输出非空
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
from modules.vuln.detection.format_string_detector import detect_format_string
from modules.vuln.detection.heap_analysis.fmt_fpe import fpe_analyze_binary


def baseline_detect(binary: str) -> dict:
    asm = disassemble(binary)
    findings = []
    if asm:
        for fn in parse_instructions(asm):
            insn_strs = [f"{i.mnemonic} {i.operands}" for i in fn.insns]
            findings.extend(detect_format_string(insn_strs))
    return {'detected': len(findings) > 0, 'kept': len(findings),
            'findings': [f.__dict__ for f in findings]}


def fpe_detect(binary: str) -> dict:
    report = fpe_analyze_binary(binary)
    kept = [v for v in report.verdicts
            if v.verdict.value != 'safe_const']
    return {'detected': len(kept) > 0, 'kept': len(kept),
            'error': report.error,
            'findings': [{'func': v.func_name, 'addr': v.addr,
                          'fmt_func': v.fmt_func, 'fmt_label': v.fmt_label,
                          'verdict': v.verdict.value}
                         for v in report.verdicts]}


def scan_sample(sample_dir: Path, subdir: str, source_map: dict) -> dict:
    src = source_map.get(sample_dir.name)
    src = Path(src) if src else next(sample_dir.glob('*.c'), None)
    stem = src.stem if src else sample_dir.name
    bin_path = sample_dir / 'bin' / subdir / f'{stem}.exe'
    result = {'id': sample_dir.name, 'binary': '', 'fpe': {}, 'baseline': {}}
    if not bin_path.exists():
        result['error'] = 'binary not compiled'
        return result
    result['binary'] = str(bin_path)
    result['fpe'] = fpe_detect(str(bin_path))
    result['baseline'] = baseline_detect(str(bin_path))
    return result


def scan_all(root: Path, subdir: str, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    source_map = {}
    manifest = root / 'manifest.json'
    if manifest.exists():
        for d in json.loads(manifest.read_text(encoding='utf-8')):
            source_map[d['id']] = d['source']
    rows = []
    for d in sorted(root.iterdir()):
        if not d.is_dir():
            continue
        res = scan_sample(d, subdir, source_map)
        rows.append(res)
        (out / f'{res["id"]}.json').write_text(
            json.dumps(res, ensure_ascii=False, indent=2), encoding='utf-8')
        a, b = res.get('fpe', {}), res.get('baseline', {})
        print(f"[scan] {res['id']:22s} fpe_det={a.get('detected')} "
              f"base_det={b.get('detected')} "
              f"fpe_kept={a.get('kept')} base_kept={b.get('kept')}")
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
