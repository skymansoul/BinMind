# 修改记录:
# 2025-08-23 10:00 - 初始创建: 扫描结果解析与统计模块

"""扫描结果解析模块 — 汇总 scan_runner.py 输出, 计算检出率/误报率/漏报率"""

import json
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Tuple

RESULTS_ROOT = Path(__file__).parent / 'results'

@dataclass
class DetectionStats:
    total_samples: int
    true_positives: int
    false_positives: int
    false_negatives: int
    detection_rate: float          # TP / (TP + FN)
    false_positive_rate: float     # FP / (FP + TN)
    avg_time_ms: float
    avg_memory_mb: float

def parse_results() -> List[Dict]:
    path = RESULTS_ROOT / 'scan_results.json'
    if not path.exists():
        print(f'Results not found: {path}. Run scan_runner.py first.')
        return []
    with open(path) as f:
        return json.load(f)

def compute_stats(results: List[Dict]) -> DetectionStats:
    n = len(results)
    tp = sum(1 for r in results if r.get('tp'))
    fp = sum(1 for r in results if r.get('fp'))
    fn = sum(1 for r in results if r.get('fn'))
    dr = tp / max(1, tp + fn)
    fpr = fp / max(1, n)
    avg_t = sum(r.get('time_ms', 0) for r in results) / max(1, n)
    avg_m = sum(r.get('mem_mb', 0) for r in results) / max(1, n)
    return DetectionStats(
        total_samples=n, true_positives=tp, false_positives=fp, false_negatives=fn,
        detection_rate=round(dr, 4), false_positive_rate=round(fpr, 4),
        avg_time_ms=round(avg_t, 1), avg_memory_mb=round(avg_m, 1),
    )

def stats_by_compiler(results: List[Dict]) -> Dict[str, DetectionStats]:
    groups: Dict[str, List[Dict]] = {}
    for r in results:
        cc = r.get('compiler', 'unknown')
        groups.setdefault(cc, []).append(r)
    return {cc: compute_stats(g) for cc, g in groups.items()}

def stats_by_opt(results: List[Dict]) -> Dict[str, DetectionStats]:
    groups: Dict[str, List[Dict]] = {}
    for r in results:
        opt = r.get('opt', 'unknown')
        groups.setdefault(opt, []).append(r)
    return {opt: compute_stats(g) for opt, g in groups.items()}

def latex_table(results: List[Dict]) -> str:
    """生成 LaTeX 表格"""
    overall = compute_stats(results)
    rows = [
        r'\begin{table}[h]',
        r'\centering',
        r'\caption{Detection Results Across Compilers and Optimization Levels}',
        r'\label{tab:detection_results}',
        r'\begin{tabular}{lcccccc}',
        r'\toprule',
        r'Tool & Samples & Det.\ Rate & FP Rate & FN Rate & Time(ms) & Mem(MB) \\',
        r'\midrule',
    ]
    # 每编译器一行
    for cc, stats in stats_by_compiler(results).items():
        rows.append(
            f'{cc} & {stats.total_samples} & {stats.detection_rate:.2f} & '
            f'{stats.false_positive_rate:.2f} & '
            f'{1.0-stats.detection_rate:.2f} & {stats.avg_time_ms:.0f} & {stats.avg_memory_mb:.1f} \\\\'
        )
    rows.append(f'Overall & {overall.total_samples} & {overall.detection_rate:.2f} & '
                f'{overall.false_positive_rate:.2f} & {1.0-overall.detection_rate:.2f} & '
                f'{overall.avg_time_ms:.0f} & {overall.avg_memory_mb:.1f} \\\\')
    rows.extend([r'\bottomrule', r'\end{tabular}', r'\end{table}'])
    return '\n'.join(rows)

def print_summary(results: List[Dict]):
    stats = compute_stats(results)
    print(f'Samples: {stats.total_samples}')
    print(f'Detection Rate: {stats.detection_rate:.1%}')
    print(f'FP Rate: {stats.false_positive_rate:.1%}')
    print(f'Avg Time: {stats.avg_time_ms:.1f}ms')
    print(f'Avg Memory: {stats.avg_memory_mb:.1f}MB')
    print()
    print(latex_table(results))

if __name__ == '__main__':
    results = parse_results()
    if results:
        print_summary(results)
