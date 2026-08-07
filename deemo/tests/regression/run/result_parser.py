"""结果解析模块 — TP/FP/FN 统计 + JSON 汇总.

创建: 2026-06-01 17:08
用途: 读取 scan_runner 的扫描结果 + ground truth 标注, 计算检出率/误报率/漏报率。

ground truth 格式 (每个样本目录下的 truth.json):
  {"cve": "CVE-XXXX-XXXXX", "type": "format_string|heap_overflow|uaf",
   "vuln_functions": ["fn_a", "fn_b"], "vuln_count": 2}
"""

import json
import os
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .scan_runner import ScanResult


@dataclass
class EvalResult:
    """一个样本×工具的评估结果."""
    sample_name: str
    tool: str
    true_positive: int       # 正确检出
    false_positive: int      # 误报 (检测到但实际不是漏洞)
    false_negative: int      # 漏报 (实际是漏洞但未检测到)
    precision: float         # TP/(TP+FP)
    recall: float            # TP/(TP+FN)
    f1: float                # 2*P*R/(P+R)
    elapsed_sec: float


def load_ground_truth(samples_dir: str) -> Dict[str, dict]:
    """从各样本目录加载 ground truth."""
    gt = {}
    root = Path(samples_dir)
    for item in root.iterdir():
        if not item.is_dir():
            continue
        truth_file = item / 'truth.json'
        if truth_file.exists():
            with open(truth_file, 'r', encoding='utf-8') as f:
                gt[item.name] = json.load(f)
    return gt


def evaluate(results: List[ScanResult],
             ground_truth: Dict[str, dict]) -> List[EvalResult]:
    """计算各样本的 TP/FP/FN."""
    eval_results = []
    # 按 (sample_name, tool) 分组
    grouped = defaultdict(list)
    for r in results:
        grouped[(r.sample_name, r.tool)].append(r)

    for (name, tool), scans in grouped.items():
        gt = ground_truth.get(name, {})
        gt_funcs = set(gt.get('vuln_functions', []))
        gt_count = gt.get('vuln_count', len(gt_funcs))

        # 收集检测到的函数
        detected_funcs = set()
        for s in scans:
            for v in s.vulns:
                fn = v.get('func', '')
                if fn:
                    detected_funcs.add(fn)

        # 计算指标
        tp = len(detected_funcs & gt_funcs)
        fp = len(detected_funcs - gt_funcs)
        fn = len(gt_funcs - detected_funcs)
        # 如果 ground truth 只给 count 没给函数名
        if not gt_funcs and gt_count > 0:
            tp = min(len(detected_funcs), gt_count)
            fp = max(0, len(detected_funcs) - gt_count)
            fn = max(0, gt_count - len(detected_funcs))

        precision = tp / max(1, tp + fp)
        recall = tp / max(1, tp + fn)
        f1 = (2 * precision * recall / max(0.01, precision + recall)
              if (precision + recall) > 0 else 0.0)

        eval_results.append(EvalResult(
            sample_name=name, tool=tool,
            true_positive=tp, false_positive=fp, false_negative=fn,
            precision=round(precision, 4), recall=round(recall, 4),
            f1=round(f1, 4),
            elapsed_sec=sum(s.elapsed_sec for s in scans)))

    return eval_results


def aggregate_by_tool(eval_results: List[EvalResult]) -> Dict[str, dict]:
    """按工具汇总指标."""
    agg = defaultdict(lambda: {'tp': 0, 'fp': 0, 'fn': 0, 'time': 0.0, 'n': 0})
    for r in eval_results:
        a = agg[r.tool]
        a['tp'] += r.true_positive
        a['fp'] += r.false_positive
        a['fn'] += r.false_negative
        a['time'] += r.elapsed_sec
        a['n'] += 1

    summary = {}
    for tool, a in agg.items():
        p = a['tp'] / max(1, a['tp'] + a['fp'])
        r = a['tp'] / max(1, a['tp'] + a['fn'])
        f1 = 2*p*r/max(0.01, p+r) if (p+r)>0 else 0.0
        summary[tool] = {
            'n_samples': a['n'], 'TP': a['tp'], 'FP': a['fp'], 'FN': a['fn'],
            'precision': round(p, 4), 'recall': round(r, 4), 'F1': round(f1, 4),
            'avg_time_s': round(a['time']/a['n'], 2),
            'total_time_s': round(a['time'], 2),
        }
    return summary


def export_json(eval_results: List[EvalResult],
                output_path: str) -> None:
    """导出评估结果为 JSON."""
    summary = aggregate_by_tool(eval_results)
    output = {
        'summary': summary,
        'details': [
            {'sample': r.sample_name, 'tool': r.tool,
             'TP': r.true_positive, 'FP': r.false_positive,
             'FN': r.false_negative, 'F1': r.f1, 'time_s': r.elapsed_sec}
            for r in eval_results
        ],
    }
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2)


if __name__ == '__main__':
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    samples = os.path.join(base, 'samples')
    output = os.path.join(base, 'results.json')
    gt = load_ground_truth(samples)
    print(f'Loaded ground truth for {len(gt)} samples')
    # 实际运行时需要先调用 scan_runner 获取 results
    print('Ground truth loaded. Run scan_runner first, then call evaluate().')
