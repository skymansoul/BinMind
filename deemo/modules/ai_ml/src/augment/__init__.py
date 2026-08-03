# augment/__init__.py
# 图数据增强：提高GNN在少样本场景下的鲁棒性

from .augmentor import (
    node_drop, edge_perturb, feature_mask, subgraph_sample, AugmentationPipeline,
)

# BEGA 重力模型图增强 (2026-08-02)
from .bega_gravity import (
    compute_node_mass, compute_gravity_forces,
    bega_edge_augment, BEGAGravityAugmenter,
)

__all__ = [
    "node_drop", "edge_perturb", "feature_mask",
    "subgraph_sample", "AugmentationPipeline",
    # BEGA
    "compute_node_mass", "compute_gravity_forces",
    "bega_edge_augment", "BEGAGravityAugmenter",
]
