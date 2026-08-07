"""整数溢出回归测试统一运行器 — 编译→扫描→收集→报告.

创建: 2026-04-30
用法: python -m vuln.src.integer.regression_runner [--quick] [--output results.json]
"""
from __future__ import annotations

import os, sys, re, json, time, subprocess
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple
from pathlib import Path

_PROJ = Path(__file__).resolve().parent.parent.parent.parent  # vuln/src/integer → modules
_SAMPLES = Path(__file__).resolve().parent.parent.parent / 'tests' / 'regression' / 'samples'

# 整数溢出样本 ID 列表 — 手动维护以区分于堆/UAF样本
_INT_SAMPLES = [
    'intof-4', 'intof-5', 'intof-6', 'intof-7', 'intof-8',
    'intof-9', 'intof-10', 'intof-11', 'intof-12', 'intof-13',
    'intof-14', 'intof-15', 'intof-16', 'intof-17', 'intof-18',
    'intof-19', 'intof-20',
    'int-overflow-1', 'int-overflow-2', 'int-overflow-3',
    'integer-overflow-06',
]

_OVERRIDES: dict = {
    'intof-4': ('LARGE_IMM64', True),        # calloc(0x100000001, 4)
    'intof-5': ('SUSPICIOUS_SIZE', True),    # realloc(p, (size_t)-1)
    'intof-6': ('SIGNED_IDX', True),         # idx=INT_MAX; idx+=10
    'intof-7': ('none', False),              # 栈数组, 无堆分配
    'intof-8': ('ADD_WRAP', True),           # len=65535; malloc(len+1) — 编译器提升至32bit
    'intof-9': ('SUSPICIOUS_SIZE', True),    # s=0xFFFFFFFF; s=s+15
    'intof-10': ('MUL_OVERFLOW', True),      # w*h*d 乘法→malloc(结果)
    'intof-11': ('ADD_WRAP', True),          # unsigned short s=65535; s++
    'intof-12': ('TRUNCATION', True),        # size_t→unsigned 截断
    'intof-13': ('none', False),             # 安全对照
    'intof-14': ('LARGE_IMM64', True),       # sizeof(int)*0x40000000*0x10
    'intof-15': ('SUSPICIOUS_SIZE', True),   # malloc(UINT64_MAX)
    'intof-16': ('LARGE_IMM64', True),        # calloc(0x80000001, 8) 乘法溢出
    'intof-17': ('TRUNCATION', True),         # realloc 截断 64→32
    'intof-18': ('SIGNED_IDX', True),         # INT32_MAX + 100
    'intof-19': ('SUSPICIOUS_SIZE', True),    # malloc(UINT32_MAX)
    'intof-20': ('TRUNCATION', True),         # calloc 截断 64→32
    # 以下样本编译器提升掩盖了溢出 (16→32bit), 二进制级未出现回绕
    'int-overflow-1': ('ADD_WRAP', True),    # unsigned short n*1024 — 编译器提升
    'int-overflow-2': ('ADD_WRAP', True),    # off+len > UINT_MAX — 指针回绕
    'int-overflow-3': ('LARGE_IMM64', True), # count=-1 → SIZE_MAX
    'integer-overflow-06': ('MUL_OVERFLOW', True),  # unsigned short*256
}


@dataclass
class IntSampleResult:
    sample_id: str
    overflow_type: str = ""
    ground_truth: Optional[bool] = None
    detected: bool = False
    n_findings: int = 0
    scan_time_s: float = 0.0
    findings: List[dict] = field(default_factory=list)
    error: str = ""


def discover_int_samples(base: Path) -> List[Tuple[str, Path, Path]]:
    """发现所有整数溢出样本."""
    samples = []
    for sid in _INT_SAMPLES:
        d = base / sid
        if not d.is_dir():
            continue
        exe = d / 'vuln.exe'
        c_file = d / 'vuln.c'
        if exe.exists():
            samples.append((sid, exe, c_file))
    return samples


def compile_sample(c_path: Path, exe_path: Path) -> bool:
    try:
        proc = subprocess.run(
            ['gcc', '-O0', '-fno-stack-protector', '-no-pie',
             '-o', str(exe_path), str(c_path)],
            capture_output=True, text=True, timeout=30)
        return proc.returncode == 0 and exe_path.exists()
    except Exception:
        return False


def disassemble(exe_path: Path) -> str:
    try:
        proc = subprocess.run(
            ['objdump', '-d', '-M', 'intel', str(exe_path)],
            capture_output=True, text=True, timeout=30)
        return proc.stdout
    except Exception:
        return ""


def split_functions(asm: str) -> List[Tuple[str, List[str], List[int]]]:
    funcs = []; fn = ''; insns = []; addrs = []
    for line in asm.split('\n'):
        s = line.strip()
        if s.endswith('>:') and '<' in s:
            if fn and insns:
                funcs.append((fn, insns, addrs))
            a = s.find('<'); b = s.find('>:')
            fn = s[a+1:b] if a >= 0 and b >= 0 else s
            insns = []; addrs = []; continue
        if '\t' in s:
            parts = s.rsplit('\t', 1)
            if len(parts) > 1 and ':' in parts[0].strip():
                addr_match = re.match(r'\s*([0-9a-f]+):', parts[0].strip())
                addrs.append(int(addr_match.group(1), 16) if addr_match else None)
                insns.append(parts[1].strip())
    if fn and insns:
        funcs.append((fn, insns, addrs))
    return funcs


def run_regression(quick: bool = False) -> List[IntSampleResult]:
    results: List[IntSampleResult] = []
    os.makedirs(str(_PROJ / '.modules'), exist_ok=True)
    if str(_PROJ) not in sys.path:
        sys.path.insert(0, str(_PROJ))

    samples = discover_int_samples(_SAMPLES)
    if not quick:
        for sid, exe, c_file in samples:
            if not exe.exists() and c_file.exists():
                compile_sample(c_file, exe)

    from vuln.src.integer.analysis.int_overflow_detector import (
        IntOverflowDetector)
    detector = IntOverflowDetector()

    for sid, exe, c_file in samples:
        result = IntSampleResult(sample_id=sid)
        if sid in _OVERRIDES:
            result.overflow_type, result.ground_truth = _OVERRIDES[sid]

        t0 = time.time()
        asm = disassemble(exe)
        if not asm:
            result.error = 'disassembly failed'
            results.append(result); continue

        funcs = split_functions(asm)
        all_f = []
        for fn_name, insns, addr_list in funcs:
            fn_findings = detector.analyze(
                insns, function_name=fn_name, addrs=addr_list)
            for f in fn_findings:
                all_f.append({
                    'fn': f.function_name,
                    'type': f.overflow_type.name,
                    'alloc_size': f.alloc_size,
                    'confidence': round(f.confidence, 3),
                    'desc': f.description[:120],
                })
            detector.clear()

        result.scan_time_s = round(time.time() - t0, 4)
        result.n_findings = len(all_f)
        result.detected = result.n_findings > 0
        result.findings = all_f
        results.append(result)

    return results


def summarize(results: List[IntSampleResult]) -> dict:
    classifiable = [r for r in results if r.ground_truth is not None]
    tp = sum(1 for r in classifiable if r.ground_truth and r.detected)
    fp = sum(1 for r in classifiable if not r.ground_truth and r.detected)
    tn = sum(1 for r in classifiable if not r.ground_truth and not r.detected)
    fn = sum(1 for r in classifiable if r.ground_truth and not r.detected)
    total_f = sum(r.n_findings for r in results)
    prec = tp / max(1, tp + fp)
    rec = tp / max(1, tp + fn)
    f1 = 2 * prec * rec / max(0.001, prec + rec)
    return {
        'total_samples': len(results),
        'classifiable': len(classifiable),
        'TP': tp, 'FP': fp, 'TN': tn, 'FN': fn,
        'total_findings': total_f,
        'precision': round(prec, 4),
        'recall': round(rec, 4),
        'f1': round(f1, 4),
        'avg_time_s': round(sum(r.scan_time_s for r in results) / max(1, len(results)), 4),
    }


if __name__ == '__main__':
    quick = '--quick' in sys.argv
    out_path = None
    for i, a in enumerate(sys.argv):
        if a == '--output' and i + 1 < len(sys.argv):
            out_path = sys.argv[i + 1]

    print(f'=== Integer Overflow Regression ===')
    print(f'Mode: {"quick (scan only)" if quick else "full (compile + scan)"}')
    results = run_regression(quick=quick)
    summ = summarize(results)
    print(f'\n=== Results ===')
    for k, v in summ.items():
        print(f'  {k}: {v}')

    print(f'\n=== Per Sample ===')
    for r in results:
        gt_str = 'OVERFLOW' if r.ground_truth else ('SAFE' if r.ground_truth is False else '?')
        status = ('TP' if r.ground_truth and r.detected else
                  'FP' if (r.ground_truth is False) and r.detected else
                  'FN' if r.ground_truth and not r.detected else
                  'TN' if (r.ground_truth is False) and not r.detected else '--')
        print(f'  [{status}] {r.sample_id:25s} GT={gt_str:9s} '
              f'type={r.overflow_type:16s} '
              f'f={r.n_findings} t={r.scan_time_s:.3f}s')

    if out_path:
        with open(out_path, 'w') as f:
            json.dump({'summary': summ, 'samples': [asdict(r) for r in results]}, f, indent=2)
        print(f'\nSaved to {out_path}')
