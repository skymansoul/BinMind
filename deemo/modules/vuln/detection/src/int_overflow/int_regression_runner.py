"""整数溢出回归测试运行器 — 编译→区间分析→溢出检测→收集结果.

创建: 2024-10-11
用途: 对 int_samples/ 中每个样本: 编译 → objdump → IntervalPropagationEngine → 判定.
      核心检测引擎: interval_domain.py + int_interval_engine.py.

使用: python int_regression_runner.py [--quick] [--verbose] [--json PATH]
"""

import json
import re
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Tuple

try:
    from .interval_domain import Interval, interval_can_overflow
    from .int_interval_engine import IntervalPropagationEngine
except ImportError:
    from interval_domain import Interval, interval_can_overflow
    from int_interval_engine import IntervalPropagationEngine

_HERE = Path(__file__).resolve().parent
_SAMPLES = _HERE / 'int_samples'

GROUND_TRUTH: Dict[str, str] = {
    'sample01_add_overflow': 'TP',
    'sample02_mul_overflow': 'TP',
    'sample03_shl_overflow': 'TP',
    'sample04_alloc_size_overflow': 'TP',
    'sample05_signed_unsigned_confusion': 'TP',
    'sample06_16bit_truncation': 'TP',
    'sample07_sub_underflow': 'TP',
    'sample08_callc_overflow': 'TP',
    'sample09_loop_accumulate': 'TP',
    'sample10_realloc_size_overflow': 'TP',
    'sample11_imul_overflow': 'TP',
    'sample12_cross_func_overflow': 'TP',
    'sample13_guard_safe': 'TN',
    'sample14_bounds_check_safe': 'TN',
    'sample15_constant_safe': 'TN',
    'sample16_checked_arithmetic_safe': 'TN',
}


def disassemble_elf(elf_path: Path) -> List[Tuple[str, List[str], List[int]]]:
    """反汇编 ELF → [(func_name, [insns], [addrs])]."""
    r = subprocess.run(
        ['objdump', '-d', '-M', 'intel', str(elf_path)],
        capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        return []
    current_func = ''
    current_insns: List[str] = []
    current_addrs: List[int] = []
    functions = []
    for line in r.stdout.split('\n'):
        line = line.rstrip()
        if not line:
            continue
        if line.endswith('>:') and not line.startswith(' '):
            if current_insns:
                functions.append((current_func, current_insns, current_addrs))
            current_func = line.strip('<:>').split('<')[-1].rstrip('>:')
            current_insns = []
            current_addrs = []
            continue
        if ':\t' in line and not line.startswith('Disassembly'):
            parts = line.split(':\t', 1)
            try:
                addr = int(parts[0].strip(), 16)
                instr = parts[1].split('\t')[-1].strip()
            except ValueError:
                continue
            current_insns.append(instr)
            current_addrs.append(addr)
    if current_insns:
        functions.append((current_func, current_insns, current_addrs))
    return functions


def parse_instruction(instr: str) -> Tuple[str, str]:
    """解析 objdump 一行 → (mnemonic, op_str)."""
    parts = instr.split(maxsplit=1)
    if len(parts) == 0:
        return ('', '')
    if len(parts) == 1:
        return (parts[0].lower(), '')
    return (parts[0].lower(), parts[1])


_CRT_NOISE_RE = re.compile(
    r'^(__|_\.|\.|_main$|_tmain$|_WinMain$|_wmain$)|'
    r'CRT|Startup|mingw|managed_app|safe_flush|safe_alloc|'
    r'global_[dc]tors|acrt|amsg|cexit|onexit|p\.\d|l_start|l_end|'
    r'pseudo_reloc|section_writable|modified_sections|'
    r'ppstrings|register_frame|fpreg|bitstob|dtoa|DBCSLeadByte|'
    r'thunk|handler$|relocator$')


def _is_user_func(name: str, insn_count: int = 999) -> bool:
    """用户函数 (非 CRT/库噪声)."""
    if name == 'main':
        return True
    if name.startswith('_') or name.startswith('.'):
        return False
    if insn_count <= 3:
        return False
    return not _CRT_NOISE_RE.search(name)


def detect_int_overflow(funcs: List[Tuple[str, List[str], List[int]]]) -> dict:
    """用 IntervalPropagationEngine 对反汇编结果做溢出检测 — 逐函数分析."""
    all_findings = []
    main_detected = False
    lib_findings = 0
    total_candidates = 0

    for func_name, insns, addrs in funcs:
        engine = IntervalPropagationEngine()
        for instr, addr in zip(insns, addrs):
            mnem, op_str = parse_instruction(instr)
            engine.feed_instruction(mnem, op_str, addr, mark_alloc_args=True)

        candidates = engine.detect_overflows(width_bits=32, min_risk='medium')
        func_findings = [{
            'addr': c.insn_addr,
            'insn': c.insn_text,
            'op': c.operation,
            'width': c.width_bits,
            'risk': c.risk_level,
            'in_alloc_context': c.used_in_alloc,
            'func': func_name,
        } for c in candidates]

        total_candidates += len(candidates)
        if _is_user_func(func_name, len(insns)):
            all_findings.extend(func_findings)
            if candidates:
                main_detected = True
        elif candidates:
            lib_findings += len(candidates)

    return {
        'findings': all_findings,
        'n_findings': len(all_findings),
        'detected': main_detected,
        'lib_noise': lib_findings,
        'total_candidates': total_candidates,
    }


def compile_sample(sample_dir: Path) -> bool:
    """编译单个样本 — 优先 Makefile, 否则直接 gcc."""
    main_c = sample_dir / 'main.c'
    if not main_c.exists():
        return False
    makefile = sample_dir / 'Makefile'
    if makefile.exists():
        r = subprocess.run(['make', '-C', str(sample_dir)],
                          capture_output=True, text=True, timeout=15)
        if r.returncode == 0:
            return True
    r = subprocess.run(
        ['gcc', '-Wall', '-g', '-O0', '-o',
         str(sample_dir / 'main'), str(main_c)],
        capture_output=True, text=True, timeout=15)
    return r.returncode == 0


def main():
    import argparse
    ap = argparse.ArgumentParser(description='Integer Overflow Regression Runner')
    ap.add_argument('--quick', action='store_true', help='Skip compilation')
    ap.add_argument('--verbose', '-v', action='store_true')
    ap.add_argument('--json', type=str, default=None, help='Output JSON path')
    args = ap.parse_args()

    samples = sorted([d for d in _SAMPLES.iterdir()
                     if d.is_dir() and d.name.startswith('sample')],
                    key=lambda d: d.name)

    if not samples:
        print('No integer overflow samples found. Run gen_int_samples.py first.')
        return

    results = {}
    tp = tn = fp = fn = 0
    total_time = 0.0

    for d in samples:
        expected = GROUND_TRUTH.get(d.name, 'TP')
        elf = d / 'main'
        if not elf.exists():
            elf_exe = d / 'main.exe'
            if elf_exe.exists():
                elf = elf_exe

        if not args.quick and not elf.exists():
            compile_sample(d)

        if not elf.exists():
            print(f'  [{d.name}] NO BINARY')
            continue

        t0 = time.perf_counter()
        funcs = disassemble_elf(elf)
        scan = detect_int_overflow(funcs)
        detected = scan['detected']
        elapsed = time.perf_counter() - t0
        total_time += elapsed

        if expected == 'TP':
            verdict = 'TP' if detected else 'FN'
            tp += 1 if detected else 0
            fn += 0 if detected else 1
        else:
            verdict = 'FP' if detected else 'TN'
            fp += 1 if detected else 0
            tn += 0 if detected else 1

        status = 'OK' if verdict in ('TP', 'TN') else 'MISS'
        top_risk = max((f['risk'] for f in scan['findings']),
                       key=lambda r: {'critical': 3, 'high': 2, 'medium': 1, 'low': 0}.get(r, 0),
                       default='none')
        lib_info = f', lib_noise={scan.get("lib_noise", 0)}' if 'lib_noise' in scan else ''
        print(f'  [{d.name}] expected={expected} → {verdict} '
              f'(main_findings={scan["n_findings"]}, top_risk={top_risk}'
              f'{lib_info}, {elapsed*1000:.0f}ms) {status}')

        results[d.name] = {
            'expected': expected, 'verdict': verdict,
            'detected': detected, 'n_findings': scan['n_findings'],
            'top_risk': top_risk, 'lib_noise': scan.get('lib_noise', 0),
            'time_ms': round(elapsed * 1000, 1),
        }

    total = tp + tn + fp + fn
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = 2 * precision * recall / max(0.001, precision + recall)

    print(f'\n{"="*60}')
    print(f'INTEGER OVERFLOW REGRESSION: {total} samples')
    print(f'  TP={tp}  TN={tn}  FP={fp}  FN={fn}')
    print(f'  Precision={precision:.1%}  Recall={recall:.1%}  F1={f1:.3f}')
    print(f'  Avg time: {total_time/max(1,total)*1000:.0f}ms/sample')

    summary = {
        'tp': tp, 'tn': tn, 'fp': fp, 'fn': fn,
        'precision': round(precision, 4),
        'recall': round(recall, 4),
        'f1': round(f1, 4),
        'avg_time_ms': round(total_time / max(1, total) * 1000, 0),
        'per_sample': results,
    }

    out_file = _HERE / 'int_scan_results.json'
    out_file.write_text(json.dumps(summary, indent=2, ensure_ascii=False))
    print(f'Saved: {out_file}')

    if args.json:
        json_path = Path(args.json)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
