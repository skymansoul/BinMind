"""
指标计算器 — TP/FP/TN/FN/Precision/Recall/F1 统计。
"""
from typing import Dict


def compute_tool_metrics(results: list, tools: list,
                         timeout_per_sample: int = 120) -> dict:
    """构建汇总统计, 含每个工具的 TP/FP/TN/FN/Precision/Recall/F1。"""
    total = len(results)
    if total == 0:
        return {'total': 0, 'tools': {}}

    # 集体预期映射 (从 cross_type_benchmark EXPECTED)
    EXPECTED = _build_expected_map(results)

    tool_stats = {}
    for tool_name in tools:
        tp = fp = tn = fn_count = 0
        successes = 0
        total_time = 0

        for r in results:
            tr = r.get('tools', {}).get(tool_name, {})
            if not tr.get('success'):
                continue
            successes += 1
            total_time += tr.get('duration_ms', 0)

            should_detect = r.get('should_detect', True)
            name = r['sample']
            if name in EXPECTED:
                should_detect = EXPECTED[name]
            elif r['category'] == 'heap-fp-reduction':
                should_detect = False

            detected = tr.get('detections', tr.get('dangerous_calls', 0)) > 0

            if should_detect and detected:
                tp += 1
            elif should_detect and not detected:
                fn_count += 1
            elif not should_detect and detected:
                fp += 1
            else:
                tn += 1

        denom_valid = max(tp + fp + tn + fn_count, 1)
        tool_stats[tool_name] = {
            'success_count': successes,
            'success_rate': successes / max(total, 1),
            'TP': tp, 'FP': fp, 'TN': tn, 'FN': fn_count,
            'precision': tp / max(tp + fp, 1),
            'recall': tp / max(tp + fn_count, 1),
            'f1': 0.0,
            'fp_rate': fp / max(fp + tn, 1),
            'avg_time_ms': total_time / max(successes, 1),
            'valid_samples': denom_valid,
        }
        p = tool_stats[tool_name]['precision']
        r2 = tool_stats[tool_name]['recall']
        if p + r2 > 0:
            tool_stats[tool_name]['f1'] = round(2 * p * r2 / (p + r2), 4)

    return {'total': total, 'tools': tool_stats, 'results': results}


def _build_expected_map(results: list) -> Dict[str, bool]:
    """从跨类型基准导入预期值 (若不可用则默认全部为应检出)。"""
    try:
        from eval.cross_type_benchmark import EXPECTED
        return {k: bool(v) for k, v in EXPECTED.items()}
    except (ImportError, AttributeError):
        pass
    return {}
