# 训练模块导出：对比学习 + 困难负样本挖掘 + 训练器基础设施
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

# 困难负样本挖掘 — CFG结构感知 + 课程学习 (2025-08-02)
from .hard_negative_mining import (
    cfg_structure_distance,
    StructureAwareNegativeSampler,
    CFGMixUpNegatives,
    CurriculumHardnessScheduler,
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
    "cfg_structure_distance",
    "StructureAwareNegativeSampler",
    "CFGMixUpNegatives",
    "CurriculumHardnessScheduler",
]
