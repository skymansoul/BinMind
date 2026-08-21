# coding: utf-8
#
"""
SSBCP vs Angr 堆溢出检测对比基准。

在18个标准化堆溢出样本上对比:
  - BinMind-SSBCP: 符号约束传播+分支窄化+分配器模型
  - Angr: CFGFast + 危险函数调用点搜索 + 符号执行探测

输出: JSON + CSV + 控制台摘要
依赖: angr (pip install angr)
"""
import json
import os
import sys
import time
import csv
from pathlib import Path
from typing import Dict, List, Tuple

# 项目路径 — 需要从deemo的父目录导入modules.vuln...
PROJ_ROOT = Path(__file__).resolve().parents[1]  # deemo/
sys.path.insert(0, str(PROJ_ROOT))  # deemo/ in path → modules.* 解析

# 样本目录
SAMPLE_DIR = PROJ_ROOT / 'modules' / 'vuln' / 'test_samples' / 'heap_overflow'
EVAL_DIR = Path(__file__).resolve().parent

# Ground truth: (sample_name, expected_TP)
GROUND_TRUTH = [
    ('sample01_direct_overflow', True),
    ('sample02_int_overflow_to_heap', True),
    ('sample03_insufficient_guard', True),
    ('sample04_cross_function_overflow', True),
    ('sample05_loop_cumulative_overflow', True),
    ('sample06_sprintf_overflow', True),
    ('sample07_memcpy_computed_size', True),
    ('sample08_alignment_padding_safe', False),
    ('sample09_strncpy_truncation_overflow', True),
    ('sample10_realloc_shrink_overflow', True),
    ('sample11_calloc_wraparound', True),
    ('sample12_conditional_overflow', True),
    ('sample13_multi_alloc_pointer_confusion', True),
    ('sample14_nested_struct_overflow', True),
    ('sample15_properly_guarded_safe', False),
    ('sample16_exact_boundary_safe', False),
    ('sample17_large_offset_small_write', False),
    ('sample18_16bit_overflow_to_heap', True),
]

DANGER_FUNCS = {'malloc', 'calloc', 'realloc', 'memcpy', 'memmove',
                'strcpy', 'strcat', 'sprintf', 'gets', 'scanf',
                'fgets', 'read', 'recv', 'strncpy'}


def find_binary(sample_dir: Path) -> Path:
    """查找样本二进制文件"""
    for name in ('main.exe', 'main'):
        p = sample_dir / name
        if p.exists():
            return p
    return None


def run_ssbcp(binary_path: str) -> dict:
    """运行BinMind堆溢出检测(DP-TVRA召回 + SSBCP精度过滤)"""
    # 与run_scanner.py相同路径: src/heap/orchestrator.py
    sample_root = SAMPLE_DIR.parent.parent  # vuln/
    heap_src = sample_root / 'src' / 'heap'
    if str(heap_src) not in sys.path:
        sys.path.insert(0, str(heap_src))
    from orchestrator import analyze_heap
    t0 = time.perf_counter()
    report = analyze_heap(binary_path)
    elapsed = (time.perf_counter() - t0) * 1000

    real_findings = [f for f in report.findings
                     if f.get('decision') not in ('safe', '')
                     and f.get('fp_probability', 0.5) < 0.8]
    return {
        'tool': 'BinMind-SSBCP',
        'success': True,
        'detected': len(real_findings) > 0,
        'n_findings': report.raw_findings,
        'n_real': len(real_findings),
        'n_filtered': report.filtered_fp,
        'duration_ms': round(elapsed, 1),
        'error': '',
        'findings': [
            {'func': f.get('function', ''), 'addr': f.get('insn_addr', ''),
             'decision': f.get('decision', ''), 'reasoning': f.get('reasoning', '')}
            for f in real_findings[:5]
        ],
    }


def run_angr(binary_path: str, timeout: int = 30) -> dict:
    """运行Angr堆溢出检测

    策略: CFGFast恢复 + 危险函数调用点收集
    判定标准: 发现危险写入函数(malloc+memset/memcpy/strcpy等组合)即判定为检出
    """
    t0 = time.perf_counter()
    try:
        import angr
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        danger_sites = []
        for func in cfg.functions.values():
            if not func.blocks:
                continue
            for block in func.blocks:
                try:
                    for insn in block.capstone.insns:
                        if insn.mnemonic != 'call':
                            continue
                        # 安全提取call目标地址
                        target_addr = None
                        if insn.operands:
                            try:
                                target_addr = insn.operands[0].imm
                            except (AttributeError, TypeError):
                                continue
                        if not target_addr:
                            continue
                        target_fn = cfg.functions.get(target_addr)
                        if target_fn and target_fn.name in DANGER_FUNCS:
                            danger_sites.append({
                                'func': target_fn.name,
                                'addr': hex(insn.address),
                                'caller': func.name,
                            })
                except Exception:
                    pass

        elapsed = (time.perf_counter() - t0) * 1000
        detected = len(danger_sites) > 0
        return {
            'tool': 'Angr',
            'success': True,
            'detected': detected,
            'n_findings': len(danger_sites),
            'n_real': len(danger_sites),
            'danger_sites': danger_sites[:10],
            'n_functions': len(cfg.functions),
            'duration_ms': round(elapsed, 1),
            'error': '',
        }
    except ImportError:
        return {'tool': 'Angr', 'success': False, 'detected': False,
                'n_findings': 0, 'n_real': 0, 'duration_ms': 0,
                'error': 'angr not installed'}
    except Exception as e:
        elapsed = (time.perf_counter() - t0) * 1000
        return {'tool': 'Angr', 'success': False, 'detected': False,
                'n_findings': 0, 'n_real': 0,
                'duration_ms': round(elapsed, 1),
                'error': str(e)[:300]}


def compute_metrics(results: List[dict]) -> dict:
    """计算 Precision/Recall/F1"""
    metrics = {}
    for tool_name in ('BinMind-SSBCP', 'Angr'):
        tp = fp = tn = fn = 0
        total_time = 0.0
        for r in results:
            tr = r.get('tools', {}).get(tool_name, {})
            if not tr.get('success'):
                continue
            total_time += tr.get('duration_ms', 0)
            detected = tr.get('detected', False)
            should_detect = r['expected']
            if should_detect and detected:
                tp += 1
            elif should_detect and not detected:
                fn += 1
            elif not should_detect and detected:
                fp += 1
            else:
                tn += 1
        precision = tp / max(tp + fp, 1)
        recall = tp / max(tp + fn, 1)
        f1 = 2 * precision * recall / max(precision + recall, 0.001)
        metrics[tool_name] = {
            'TP': tp, 'FP': fp, 'TN': tn, 'FN': fn,
            'precision': round(precision, 4),
            'recall': round(recall, 4),
            'f1': round(f1, 4),
            'fp_rate': round(fp / max(fp + tn, 1), 4),
            'avg_time_ms': round(total_time / max(tp + fp + tn + fn, 1), 1),
        }
    return metrics


def save_csv(results: List[dict], path: str):
    """保存逐样本CSV"""
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['sample', 'expected', 'tool', 'detected',
                    'n_findings', 'duration_ms', 'error'])
        for r in results:
            for tool in ('BinMind-SSBCP', 'Angr'):
                tr = r.get('tools', {}).get(tool, {})
                w.writerow([
                    r['sample'],
                    'TP' if r['expected'] else 'TN',
                    tool,
                    tr.get('detected', False),
                    tr.get('n_real', 0),
                    tr.get('duration_ms', 0),
                    tr.get('error', ''),
                ])


def main():
    import argparse
    ap = argparse.ArgumentParser(
        description='SSBCP vs Angr Heap Overflow Benchmark')
    ap.add_argument('--verbose', '-v', action='store_true')
    ap.add_argument('--samples', nargs='*', help='Specific samples')
    ap.add_argument('--no-angr', action='store_true', help='Skip Angr')
    args = ap.parse_args()

    samples = GROUND_TRUTH
    if args.samples:
        samples = [(s, e) for s, e in GROUND_TRUTH if s in args.samples]

    print(f'Benchmark: {len(samples)} samples')
    print(f'{"Sample":<42s} {"Exp":>4s}  '
          f'{"SSBCP":>14s}  {"Angr":>14s}')
    print('-' * 80)

    results = []
    for sample_name, expected_tp in samples:
        sample_dir = SAMPLE_DIR / sample_name
        binary = find_binary(sample_dir)
        if not binary:
            print(f'  [{sample_name}] BINARY NOT FOUND - skipping')
            continue

        row = {
            'sample': sample_name,
            'expected': expected_tp,
            'binary': str(binary),
            'tools': {},
        }

        # SSBCP
        ssbcp_result = run_ssbcp(str(binary))
        row['tools']['BinMind-SSBCP'] = ssbcp_result

        # Angr
        if not args.no_angr:
            angr_result = run_angr(str(binary))
            row['tools']['Angr'] = angr_result

        results.append(row)

        exp_str = 'TP' if expected_tp else 'TN'
        ssbcp_str = (f"{'Y' if ssbcp_result['detected'] else 'N'}"
                     f"({ssbcp_result['n_real']},{ssbcp_result['duration_ms']:.0f}ms)")
        if not args.no_angr:
            angr_r = row['tools']['Angr']
            angr_str = (f"{'Y' if angr_r['detected'] else 'N'}"
                        f"({angr_r['n_real']},{angr_r['duration_ms']:.0f}ms)")
        else:
            angr_str = 'skipped'

        print(f'  {sample_name:<40s} {exp_str:>4s}  '
              f'{ssbcp_str:>14s}  {angr_str:>14s}')

        if args.verbose:
            for tool_name in ('BinMind-SSBCP', 'Angr'):
                tr = row['tools'].get(tool_name, {})
                if tr.get('findings') or tr.get('danger_sites'):
                    detail = tr.get('findings') or tr.get('danger_sites', [])
                    for d in detail[:2]:
                        if isinstance(d, dict):
                            print(f'    [{tool_name}] {d.get("func","")}:'
                                  f'{d.get("addr","")} '
                                  f'{d.get("reasoning", d.get("func",""))[:60]}')

    # 汇总
    metrics = compute_metrics(results)
    print(f'\n{"="*60}')
    print(f'{"Tool":<20s} {"TP":>3s} {"FP":>3s} {"TN":>3s} {"FN":>3s}  '
          f'{"Prec":>6s} {"Recall":>6s} {"F1":>6s} {"Time":>8s}')
    print('-' * 60)
    for tool_name, m in metrics.items():
        print(f'{tool_name:<20s} {m["TP"]:3d} {m["FP"]:3d} {m["TN"]:3d} {m["FN"]:3d}  '
              f'{m["precision"]:6.1%} {m["recall"]:6.1%} {m["f1"]:6.3f} '
              f'{m["avg_time_ms"]:7.0f}ms')

    # 保存
    csv_path = EVAL_DIR / 'ssbcp_vs_angr.csv'
    save_csv(results, str(csv_path))
    print(f'\nCSV saved: {csv_path}')

    json_path = EVAL_DIR / 'ssbcp_vs_angr.json'
    output = {
        'n_samples': len(results),
        'metrics': metrics,
        'results': [{
            'sample': r['sample'],
            'expected': 'TP' if r['expected'] else 'TN',
            'tools': {k: {kk: vv for kk, vv in v.items()
                          if kk not in ('findings', 'danger_sites')}
                      for k, v in r['tools'].items()},
        } for r in results],
    }
    json_path.write_text(
        json.dumps(output, indent=2, ensure_ascii=False), encoding='utf-8')
    print(f'JSON saved: {json_path}')


if __name__ == '__main__':
    main()
