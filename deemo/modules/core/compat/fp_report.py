# coding: utf-8
"""
误报校准辅助 — 默认检测函数 + Markdown 报告生成.

"""

from typing import Any, Dict, List

from modules.core.compat.fp_calibrator import CalibrationConfig


def default_detection_fn(config: CalibrationConfig,
                         sample_path: str) -> List[Dict]:
    """默认检测函数 — 对单个样本执行完整管线.

    这是一个模板, 实际使用时替换为真实的管线调用.
    """
    from modules.core.compat.scan_pipeline import run_pipeline_minimal
    result = run_pipeline_minimal(sample_path)
    candidates = []
    for vuln in result.findings.vulns:
        if vuln.vuln_type == 'heap_overflow':
            candidates.append({
                'overflow_site': vuln.primary_addr,
                'vuln_type': vuln.vuln_type,
                'confidence': vuln.confidence,
                'exploitable': vuln.exploitable,
                'description': vuln.description,
            })
    return candidates


def calibration_report_to_markdown(report: Dict[str, Any]) -> str:
    """将校准报告格式化为 Markdown."""
    lines = ['# FP Calibration Report', '']
    lines.append(f'- Total evaluations: {report["total_evaluations"]}')
    lines.append(f'- Best FP rate: {report["best_fp_rate"]}')
    lines.append(f'- Best recall: {report["best_recall"]}')
    lines.append(f'- Best F1: {report["best_f1"]}')
    lines.append('')
    lines.append('## Pareto Frontier')
    lines.append('')
    lines.append('| FP Rate | Recall | F1 | Taint Dist | Alloc Margin | VR Depth |')
    lines.append('|---------|--------|----|------------|-------------|----------|')
    for p in report.get('pareto_frontier', []):
        cfg = p['config']
        lines.append(f'| {p["fp_rate"]} | {p["recall"]} | {p["f1"]} | '
                    f'{cfg["taint_distance_threshold"]} | '
                    f'{cfg["alloc_margin_factor"]} | '
                    f'{cfg["value_range_depth"]} |')
    return '\n'.join(lines)
