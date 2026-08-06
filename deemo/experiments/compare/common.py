"""对比实验共享数据结构 + 结果收集."""

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class ExperimentResult:
    tool_name: str
    sample_name: str
    opt_level: str = ''
    # 检测结果
    vulns_found: int = 0
    vulns_list: List[str] = field(default_factory=list)
    # 性能
    elapsed_sec: float = 0.0
    peak_memory_mb: float = 0.0
    # ground truth 比对
    true_positive: int = 0
    false_positive: int = 0
    false_negative: int = 0
    # 状态
    success: bool = True
    error_msg: str = ''


def compute_metrics(results: List[ExperimentResult]) -> Dict[str, float]:
    """从结果列表计算聚合指标."""
    total_tp = sum(r.true_positive for r in results)
    total_fp = sum(r.false_positive for r in results)
    total_fn = sum(r.false_negative for r in results)
    total_time = sum(r.elapsed_sec for r in results)
    n = len(results)

    precision = total_tp / max(1, total_tp + total_fp)
    recall = total_tp / max(1, total_tp + total_fn)
    f1 = (2 * precision * recall / max(0.01, precision + recall)
          if (precision + recall) > 0 else 0.0)

    return {
        'n_samples': n, 'TP': total_tp, 'FP': total_fp, 'FN': total_fn,
        'precision': round(precision, 4), 'recall': round(recall, 4),
        'F1': round(f1, 4),
        'avg_time_s': round(total_time / max(1, n), 2),
        'total_time_s': round(total_time, 2),
        'mean_memory_mb': round(
            sum(r.peak_memory_mb for r in results) / max(1, n), 1),
    }
