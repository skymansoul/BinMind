#!/usr/bin/env python3
# coding: utf-8
"""
多工具对比实验 — 对所有样本调用 BinMind/Angr/QEMU/Ghidra,
输出统一格式 CSV (工具名、样本ID、加壳分组、检出数、误报/漏报、
耗时、峰值内存) 与对比 JSON.

用法:
  python run_benchmark.py --samples ../tests/cve_samples \
      --packed ../tests/cve_samples_packed --output ../benchmark_results
"""

import os, sys, json, time, csv, argparse, tracemalloc, psutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_MODULE_ROOT = Path(__file__).resolve().parent.parent
_DEEMO = _MODULE_ROOT.parent.parent
for p in (_DEEMO, _MODULE_ROOT):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

_GT_KEYS = ['heap_overflow', 'is_vuln', 'vulnerable']


def find_binaries(samples_dir: str) -> List[Tuple[str, str, bool]]:
    """递归查找二进制, 返回 [(sample_id, 路径, packed)]; 按样本去重."""
    found: Dict[str, Tuple[str, bool]] = {}
    for root, dirs, files in os.walk(samples_dir):
        for f in sorted(files):
            if f.endswith('.exe') or f.endswith('.elf'):
                sid = f[:f.rfind('.')]
                packed = '_packed' in sid or 'packed' in root
                path = os.path.join(root, f)
                if 'build' in root.split(os.sep):
                    continue  # 排除批量编译副本, 保留样本目录自身
                if sid not in found:
                    found[sid] = (path, packed)
    return sorted((sid, path, packed) for sid, (path, packed) in found.items())


def load_gt(path: str) -> Dict[str, bool]:
    gt: Dict[str, bool] = {}
    if not path or not os.path.exists(path):
        return gt
    with open(path, 'r', encoding='utf-8') as f:
        raw = json.load(f)
    for sid, info in raw.items():
        if isinstance(info, dict):
            v = any(info.get(k, False) for k in _GT_KEYS)
        else:
            v = bool(info)
        gt[sid] = v
    return gt


def measure(fn, *args):
    """执行并测量 (结果, 耗时ms, 峰值内存MB)."""
    tracemalloc.start()
    t0 = time.perf_counter()
    try:
        res = fn(*args)
        ok = True
    except Exception as e:
        res = {'error': str(e)[:200], 'success': False}
        ok = False
    wall = (time.perf_counter() - t0) * 1000
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return res, wall, peak / (1024 * 1024)


def run_binmind(exe: str) -> Dict:
    from modules.core.compat.deep_heap_orchestrator import DeepHeapOrchestrator
    orch = DeepHeapOrchestrator()
    rep = orch.run(exe)
    return {
        'success': True,
        'sample_id': os.path.basename(exe)[:os.path.basename(exe).rfind('.')],
        'candidates': len(rep.candidates),
        'exploitable': rep.exploitable,
        'layers': [{'name': s.name, 'input': s.input_count,
                    'filtered': s.filtered, 'retained': s.retained}
                   for s in rep.layer_stats],
        'error': '',
    }


def run_angr(exe: str) -> Dict:
    from eval.angr_explorer import analyze_with_angr
    r = analyze_with_angr(exe)
    return {'success': r['success'], 'sample_id': r['sample_id'],
            'candidates': r['dangerous_calls'],
            'exploitable': r['heap_overflow_candidates'],
            'error': r.get('error', '')}


def run_qemu(exe: str) -> Dict:
    from eval.qemu_tracer import trace_with_qemu
    r = trace_with_qemu(exe)
    return {'success': r['success'], 'sample_id': r['sample_id'],
            'candidates': r['total_allocs'],
            'exploitable': r['total_writes'],
            'error': r.get('error', '')}


def run_ghidra(exe: str) -> Dict:
    from eval.ghidra_headless import analyze_with_ghidra
    r = analyze_with_ghidra(exe)
    return {'success': r['success'], 'sample_id': r['sample_id'],
            'candidates': r['candidates'],
            'exploitable': r['heap_overflow_candidates'],
            'error': r.get('error', '')}


_RUNNERS = {'binmind': run_binmind, 'angr': run_angr,
            'qemu': run_qemu, 'ghidra': run_ghidra}


def detected(res: Dict) -> bool:
    """工具的检出信号: 任一候选/可利用计数 > 0 视为有告警."""
    return (res.get('candidates', 0) or 0) > 0 or (res.get('exploitable', 0) or 0) > 0


def run_all(binaries: List[Tuple[str, str, bool]], tools: List[str]
            ) -> List[Dict]:
    rows = []
    for sid, exe, packed in binaries:
        for tool in tools:
            fn = _RUNNERS.get(tool)
            if fn is None:
                continue
            res, wall, mem = measure(fn, exe)
            res.setdefault('sample_id', sid)
            rows.append({
                'tool': tool, 'sample_id': res.get('sample_id', sid),
                'packed': packed, 'binary': exe,
                'candidates': res.get('candidates', 0) or 0,
                'exploitable': res.get('exploitable', 0) or 0,
                'detected': detected(res),
                'wall_time_ms': round(wall, 2),
                'peak_mem_mb': round(mem, 2),
                'success': res.get('success', False),
                'error': res.get('error', '')[:120],
            })
    return rows


def compute_metrics(rows: List[Dict], gt: Dict[str, bool],
                    group: str = 'all') -> Dict[str, Dict]:
    """按工具计算 (分 pack 组) 的 TP/FP/TN/FN 与指标."""
    # TODO: qemu/ghidra 未安装时整体 N/A; 后续可接入动态执行的 ground truth
    by_tool: Dict[str, List[Dict]] = {}
    for r in rows:
        if group == 'packed' and not r['packed']:
            continue
        if group == 'unpacked' and r['packed']:
            continue
        by_tool.setdefault(r['tool'], []).append(r)

    metrics: Dict[str, Dict] = {}
    for tool, rs in by_tool.items():
        # 工具整体不可用 (qemu/ghidra 未安装) 时不纳入指标
        if rs and not any(r['success'] for r in rs):
            metrics[tool] = {'available': False, 'samples': len(rs),
                             'error': rs[0].get('error', '')}
            continue
        tp = fp = tn = fn = 0
        for r in rs:
            exp = gt.get(r['sample_id'], False)
            if exp and r['detected']: tp += 1
            elif not exp and r['detected']: fp += 1
            elif not exp and not r['detected']: tn += 1
            else: fn += 1
        p = tp / max(1, tp + fp)
        rec = tp / max(1, tp + fn)
        metrics[tool] = {
            'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
            'precision': round(p, 4), 'recall': round(rec, 4),
            'f1': round(2 * p * rec / max(0.001, p + rec), 4),
            'fp_rate': round(fp / max(1, fp + tn), 4),
            'samples': len(rs),
        }
    return metrics


def write_csv(rows: List[Dict], path: str):
    fieldnames = ['tool', 'sample_id', 'packed', 'candidates', 'exploitable',
                  'detected', 'wall_time_ms', 'peak_mem_mb', 'success', 'error']
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        w.writeheader()
        for r in rows:
            w.writerow(r)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--samples', default=str(
        _MODULE_ROOT / 'tests' / 'cve_samples'))
    ap.add_argument('--packed', default=str(
        _MODULE_ROOT / 'tests' / 'cve_samples_packed'))
    ap.add_argument('--ground-truth', nargs='+', default=[
        str(_MODULE_ROOT / 'tests' / 'cve_samples' / 'ground_truth.json'),
        str(_MODULE_ROOT / 'tests' / 'cve_samples_packed' / 'ground_truth.json')])
    ap.add_argument('--tools', nargs='+',
                    default=['binmind', 'angr', 'qemu', 'ghidra'])
    ap.add_argument('--output', default=str(
        _MODULE_ROOT / 'benchmark_results'))
    args = ap.parse_args()

    os.makedirs(args.output, exist_ok=True)
    binaries = find_binaries(args.samples) + find_binaries(args.packed)
    print(f'Found {len(binaries)} binaries, tools={args.tools}')
    gt: Dict[str, bool] = {}
    for gtp in args.ground_truth:
        gt.update(load_gt(gtp))
    for sid, _exe, _pk in binaries:
        if sid not in gt:
            gt[sid] = False

    rows = []
    for i, (sid, exe, packed) in enumerate(binaries):
        tag = 'P' if packed else 'U'
        print(f'[{i+1}/{len(binaries)}] ({tag}) {sid}')
        rows.extend(run_all([(sid, exe, packed)], args.tools))

    csv_path = os.path.join(args.output, 'benchmark_comparison.csv')
    write_csv(rows, csv_path)

    comparison = {
        'all': compute_metrics(rows, gt, 'all'),
        'unpacked': compute_metrics(rows, gt, 'unpacked'),
        'packed': compute_metrics(rows, gt, 'packed'),
    }
    with open(os.path.join(args.output, 'tool_comparison.json'), 'w',
              encoding='utf-8') as f:
        json.dump(comparison, f, indent=2)

    print(f'\n=== COMPARISON (all) ===')
    for tool, m in comparison['all'].items():
        if not m.get('available', True):
            print(f'  {tool:8s} N/A ({m.get("error", "tool unavailable")})')
            continue
        print(f'  {tool:8s} P={m["precision"]:.1%} R={m["recall"]:.1%} '
              f'F1={m["f1"]:.3f} FP_rate={m["fp_rate"]:.1%} '
              f'(TP={m["tp"]} FP={m["fp"]} TN={m["tn"]} FN={m["fn"]})')
    print(f'\nCSV: {csv_path}')
    print(f'JSON: {os.path.join(args.output, "tool_comparison.json")}')


if __name__ == '__main__':
    main()
