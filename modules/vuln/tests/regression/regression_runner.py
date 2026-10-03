"""堆溢出回归测试统一运行器 — 一键: 编译→扫描→收集→报告.

创建: 2024-10-11
用法: python regression_runner.py [--quick] [--output results.json]
      --quick: 跳过编译, 只扫描已有 exe
"""
from __future__ import annotations

import os, sys, re, json, time, subprocess, hashlib
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple
from pathlib import Path

# 项目根 — 从此文件向上4级
_PROJ = Path(__file__).resolve().parent.parent.parent.parent
_SAMPLES = Path(__file__).resolve().parent / 'samples'


@dataclass
class SampleResult:
    sample_id: str
    vuln_type: str = "heap_overflow"
    # Source analysis
    ground_truth: Optional[bool] = None
    alloc_sz: int = 0
    write_sz: int = 0
    # Detection
    detected: bool = False
    n_findings: int = 0
    n_true_positives: int = 0
    n_false_positives: int = 0
    best_score: float = 0.0
    # Performance
    scan_time_s: float = 0.0
    # Details
    findings: List[dict] = field(default_factory=list)
    error: str = ""


def parse_ground_truth(src: str, sample_id: str = "") -> Tuple[Optional[bool], int, int, int]:
    """从源码提取 ground truth: (has_overflow, alloc_sz, write_sz, offset).

    支持: 简单malloc+memcpy/memset, sprintf, 循环累积写入, 跨函数.
    显式覆盖: 整数溢出/三元分配/跨函数等复杂模式.
    """
    # 显式覆盖表 — 处理 regex 无法解析的复杂模式
    _OVERRIDES: dict = {
        'heap-cve-02': (True, 0, 512, 0),     # 整数溢出 malloc(0xFFFF+1)→malloc(0), memcpy 512B
        'heap-cve-11': (True, 32, 128, 0),    # 三元分配 malloc(argc>1?256:32), memset 128B > min=32
        'heap-cve-14': (True, 64, 256, 0),    # 跨函数: main malloc(64), process_buffer(p, 256)
        'heap-cve-15': (False, 128, 0, 0),    # double-free — 不是堆溢出, 验证分类准确性
    }
    if sample_id in _OVERRIDES:
        return _OVERRIDES[sample_id]

    alloc_sz = 0; write_sz = 0; offset = 0
    for m in re.finditer(r'malloc\s*\(\s*(\d+)', src):
        alloc_sz = int(m.group(1))
    for m in re.finditer(r'calloc\s*\(\s*[\d\w]+,\s*(\d+)', src):
        alloc_sz = int(m.group(1))
    for m in re.finditer(r'realloc\s*\([^,]+,\s*(\d+)', src):
        alloc_sz = int(m.group(1))
    for m in re.finditer(r'memcpy\s*\([^,]+,\s*[^,]+,\s*(\d+)\s*\)', src):
        write_sz = int(m.group(1))
    for m in re.finditer(r'memset\s*\([^,]+,\s*[^,]+,\s*(\d+)\s*\)', src):
        write_sz = int(m.group(1))
    for m in re.finditer(r'strncpy\s*\([^,]+,\s*[^,]+,\s*(\d+)\s*\)', src):
        write_sz = int(m.group(1))
    m_off = re.search(r'[pb]\s*\+\s*(\d+)', src)
    if m_off: offset = int(m_off.group(1))
    # 循环累积: for (i=0; i<N; i++) memcpy(ptr+i*S, ..., S)
    m_loop = re.search(r'i\s*<\s*(\d+).*?memcpy.*?,\s*(\d+)\s*\)', src, re.DOTALL)
    if m_loop and alloc_sz > 0:
        n_iters = int(m_loop.group(1))
        loop_sz = int(m_loop.group(2))
        return (n_iters * loop_sz) > alloc_sz, alloc_sz, n_iters * loop_sz, 0
    # sprintf: alloc < 写入 (固定模式: 21B > 8B for heap-cve-12)
    if 'sprintf' in src and alloc_sz > 0 and alloc_sz < 20:
        return True, alloc_sz, alloc_sz + 1, 0
    if alloc_sz > 0 and write_sz > 0:
        return (offset + write_sz) > alloc_sz, alloc_sz, write_sz, offset
    if any(k in src.lower() for k in ('read(', 'size', 'argv')):
        return None, alloc_sz, write_sz, offset
    return None, alloc_sz, write_sz, offset


def discover_samples(base: Path) -> List[Tuple[str, Path, Path]]:
    """发现所有样本: 返回 [(sample_id, exe_path, c_path), ...]."""
    samples = []
    for d in sorted(base.iterdir()):
        if not d.is_dir(): continue
        exe = d / 'vuln.exe'
        c_file = d / 'vuln.c'
        if exe.exists():
            samples.append((d.name, exe, c_file))
    return samples


def compile_sample(c_path: Path, exe_path: Path) -> bool:
    """编译单个样本 (MinGW gcc)."""
    try:
        proc = subprocess.run(
            ['gcc', '-O0', '-fno-stack-protector', '-no-pie',
             '-o', str(exe_path), str(c_path)],
            capture_output=True, text=True, timeout=30)
        return proc.returncode == 0 and exe_path.exists()
    except Exception:
        return False


def disassemble(exe_path: Path) -> str:
    """objdump 反汇编."""
    try:
        proc = subprocess.run(
            ['objdump', '-d', '-M', 'intel', str(exe_path)],
            capture_output=True, text=True, timeout=30)
        return proc.stdout
    except Exception:
        return ""


def split_functions(asm: str) -> List[Tuple[str, List[str]]]:
    """将 objdump 输出按函数拆分, 同时提取指令地址."""
    funcs = []; fn = ''; insns = []; addrs = []
    for line in asm.split('\n'):
        s = line.strip()
        if s.endswith('>:') and '<' in s:
            if fn and insns: funcs.append((fn, insns, addrs))
            a = s.find('<'); b = s.find('>:')
            fn = s[a+1:b] if a >= 0 and b >= 0 else s
            insns = []; addrs = []; continue
        if '\t' in s:
            parts = s.rsplit('\t', 1)
            if len(parts) > 1 and ':' in parts[0].strip():
                addr_match = re.match(r'\s*([0-9a-f]+):', parts[0].strip())
                addrs.append(int(addr_match.group(1), 16) if addr_match else None)
                insns.append(parts[1].strip())
    if fn and insns: funcs.append((fn, insns, addrs))
    return funcs


def run_regression(quick: bool = False) -> List[SampleResult]:
    """运行完整回归测试."""
    results: List[SampleResult] = []
    os.makedirs(str(_PROJ / '.modules'), exist_ok=True)
    if str(_PROJ) not in sys.path:
        sys.path.insert(0, str(_PROJ))

    samples = discover_samples(_SAMPLES)
    if not quick:
        for sid, exe, c_file in samples:
            if not exe.exists() and c_file.exists():
                ok = compile_sample(c_file, exe)
                if not ok: print(f'  [FAIL] compile {sid}')

    from vuln.src.heap.analysis.heap_overflow_detector import (
        ImprovedHeapOverflowDetector)
    detector = ImprovedHeapOverflowDetector()

    for sid, exe, c_file in samples:
        result = SampleResult(sample_id=sid)
        # Ground truth
        src = ''
        if c_file.exists():
            try:
                with open(c_file, encoding='utf-8') as f: src = f.read()
            except:
                with open(c_file, encoding='latin-1') as f: src = f.read()
            gt, alloc, write, off = parse_ground_truth(src, sample_id=sid)
            result.ground_truth = gt
            result.alloc_sz = alloc; result.write_sz = write

        t0 = time.time()
        asm = disassemble(exe)
        if not asm:
            result.error = 'disassembly failed'
            results.append(result); continue

        funcs = split_functions(asm)
        all_f = []
        for fn_name, insns, addr_list in funcs:
            fn_findings = detector.analyze(
                insns, function_name=fn_name,
                addrs=addr_list if addr_list else None)
            for f in fn_findings:
                all_f.append({
                    'fn': f.function_name, 'overflow': f.overflow_bytes,
                    'alloc_req': f.alloc_size_requested,
                    'alloc_usable': f.alloc_size_usable,
                    'score': round(f.semantic_score, 3),
                    'is_fp': f.is_likely_fp,
                    'desc': f.description[:120],
                })
            detector.clear()

        result.scan_time_s = round(time.time() - t0, 4)
        result.n_findings = len(all_f)
        result.n_true_positives = sum(1 for f in all_f if not f['is_fp'])
        result.n_false_positives = sum(1 for f in all_f if f['is_fp'])
        result.detected = result.n_true_positives > 0
        result.best_score = max((f['score'] for f in all_f), default=0.0)
        result.findings = all_f
        results.append(result)

    return results


def summarize(results: List[SampleResult]) -> dict:
    """汇总指标."""
    classifiable = [r for r in results if r.ground_truth is not None]
    tp = sum(1 for r in classifiable if r.ground_truth and r.detected)
    fp = sum(1 for r in classifiable if not r.ground_truth and r.detected)
    tn = sum(1 for r in classifiable if not r.ground_truth and not r.detected)
    fn = sum(1 for r in classifiable if r.ground_truth and not r.detected)
    total_f = sum(r.n_findings for r in results)
    total_tp = sum(r.n_true_positives for r in results)
    total_fp = sum(r.n_false_positives for r in results)
    prec = tp / max(1, tp + fp)
    rec = tp / max(1, tp + fn)
    f1 = 2 * prec * rec / max(0.001, prec + rec)
    return {
        'total_samples': len(results),
        'classifiable': len(classifiable),
        'dynamic_unclassified': len(results) - len(classifiable),
        'TP': tp, 'FP': fp, 'TN': tn, 'FN': fn,
        'total_findings': total_f, 'total_TP_findings': total_tp,
        'total_FP_findings': total_fp,
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

    print(f'=== Heap Overflow Regression ===')
    print(f'Mode: {"quick (scan only)" if quick else "full (compile + scan)"}')
    results = run_regression(quick=quick)

    summ = summarize(results)
    print(f'\n=== Results ===')
    for k, v in summ.items():
        print(f'  {k}: {v}')

    print(f'\n=== Per Sample ===')
    for r in results:
        gt_str = 'OVERFLOW' if r.ground_truth else ('SAFE' if r.ground_truth is False else '?')
        status = 'TP' if r.ground_truth and r.detected else (
            'FP' if (r.ground_truth is False) and r.detected else (
            'FN' if r.ground_truth and not r.detected else (
            'TN' if (r.ground_truth is False) and not r.detected else '--')))
        print(f'  [{status}] {r.sample_id:25s} GT={gt_str:9s} '
              f'alloc={r.alloc_sz:4d} write={r.write_sz:4d} '
              f'f=({r.n_true_positives}T+{r.n_false_positives}F) '
              f't={r.scan_time_s:.3f}s')

    if out_path:
        out_data = {
            'summary': summ,
            'samples': [asdict(r) for r in results],
        }
        with open(out_path, 'w') as f:
            json.dump(out_data, f, indent=2, ensure_ascii=False)
        print(f'\nSaved to {out_path}')
