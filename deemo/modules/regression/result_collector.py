"""
回归测试 — 结果收集与对比模块.

负责: 汇总编译/扫描两阶段产物, 输出统一 JSON/CSV 报告,
并与基线对比 (基线 = 无 HFP 过滤的机械比较). 对比口径:
  基线: offset >= alloc_size 即告警 (未做对齐/守卫/污点分析)
  HFP:  三态判定后仅保留 OVERFLOW/POTENTIAL
输出字段: sample, ground_truth, baseline_detected, hfp_detected,
          verdicts, elapsed_ms, 用于 run_benchmark 绘制图表.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Dict, List

from .scan_scheduler import ScanResult, is_vuln_sample

BASE = Path(__file__).resolve().parent.parent
RESULT_DIR = BASE / 'results'


def write_json_report(stats: Dict, path: str = '') -> str:
    if not path:
        path = str(RESULT_DIR / 'regression_hfp.json')
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(stats, indent=2, ensure_ascii=False),
                 encoding='utf-8')
    return str(p)


def write_csv_report(rows: List[Dict], path: str = '') -> str:
    if not path:
        path = str(RESULT_DIR / 'regression_hfp.csv')
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        p.write_text('', encoding='utf-8')
        return str(p)
    with open(p, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    return str(p)


def build_comparison_rows(results: List[ScanResult],
                          baseline_map: Dict[str, bool]) -> List[Dict]:
    """合并 HFP 结果与基线结果, 生成逐样本对比行."""
    rows = []
    for r in results:
        vuln = is_vuln_sample(r.sample)
        base_det = baseline_map.get(r.sample, False)
        verdicts = [f.get('verdict', '') for f in r.findings]
        rows.append({
            'sample': r.sample,
            'ground_truth': 'VULN' if vuln else 'SAFE',
            'baseline_detected': base_det,
            'hfp_detected': r.detected,
            'hfp_findings': len(r.findings),
            'verdicts': '|'.join(verdicts),
            'elapsed_ms': r.elapsed_ms,
            'baseline_is_fp': (not vuln) and base_det,
            'hfp_is_fp': (not vuln) and r.detected,
            'hfp_suppressed_fp': (not vuln) and base_det and not r.detected,
        })
    return rows


def aggregate_comparison(rows: List[Dict]) -> Dict:
    """计算对比聚合指标 (检出率/误报率/抑制率)."""
    total = len(rows)
    if total == 0:
        return {'total': 0}
    vuln_rows = [r for r in rows if r['ground_truth'] == 'VULN']
    safe_rows = [r for r in rows if r['ground_truth'] == 'SAFE']
    base_recall = (sum(1 for r in vuln_rows if r['baseline_detected'])
                   / len(vuln_rows)) if vuln_rows else 0.0
    hfp_recall = (sum(1 for r in vuln_rows if r['hfp_detected'])
                  / len(vuln_rows)) if vuln_rows else 0.0
    base_fpr = (sum(1 for r in safe_rows if r['baseline_detected'])
                / len(safe_rows)) if safe_rows else 0.0
    hfp_fpr = (sum(1 for r in safe_rows if r['hfp_detected'])
               / len(safe_rows)) if safe_rows else 0.0
    suppressed = sum(1 for r in rows if r['hfp_suppressed_fp'])
    return {
        'total': total,
        'vuln_count': len(vuln_rows),
        'safe_count': len(safe_rows),
        'baseline_recall': round(base_recall, 4),
        'hfp_recall': round(hfp_recall, 4),
        'baseline_fpr': round(base_fpr, 4),
        'hfp_fpr': round(hfp_fpr, 4),
        'fp_suppressed': suppressed,
        'fpr_reduction_pct': round(
            (base_fpr - hfp_fpr) / base_fpr * 100, 1) if base_fpr > 0 else 0.0,
    }
