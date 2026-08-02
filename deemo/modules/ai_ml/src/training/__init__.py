# 2026-07-17
# 训练模块导出：对比学习 + 训练器基础设施
# 对比损失和多阶段训练适合小样本二进制分析场景

from .contrastive import (
    InfoNCELoss,
    TripletMarginLoss,
    gravity_edge_dropout,
    two_phase_train,
    _sgd_update_numpy,
)

from .trainer import (
    SupervisedTrainer,
    EarlyStopping,
    CosineAnnealingLR,
)

__all__ = [
    "InfoNCELoss",
    "TripletMarginLoss",
    "gravity_edge_dropout",
    "two_phase_train",
    "_sgd_update_numpy",
    "SupervisedTrainer",
    "EarlyStopping",
    "CosineAnnealingLR",
]
