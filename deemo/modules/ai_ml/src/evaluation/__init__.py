# 2026-07-18
# evaluation 子包入口 —— 指标 + 报告，评估流水线统一出口

from .metrics import (
    mrr_score,
    recall_at_k,
    precision_at_k,
    ndcg_at_k,
    average_precision,
)

from .reporter import (
    classification_report,
    ascii_confusion_matrix,
    EvalReporter,
)

__all__ = [
    "mrr_score",
    "recall_at_k",
    "precision_at_k",
    "ndcg_at_k",
    "average_precision",
    "classification_report",
    "ascii_confusion_matrix",
    "EvalReporter",
]
