# GNN模块入口 — 纯NumPy图神经网络，零框架依赖
# 设计理念：不引入PyTorch/Scipy重型依赖，手工实现稀疏操作以保持审计可控性

from .layers import GraphConv, GATConv, SAGPool, LaplacianPE

from .models import GCNBinaryClassifier, GATVulnDetector, SiameseBinaryMatcher

# GraphMoCo 动量对比学习 (2025-08-02)
from .moco import (
    MomentumEncoder, NegativeQueue, moco_contrastive_loss,
    l2_normalize, cosine_similarity,
)

# 位置/结构编码 — 增强 GNN 拓扑感知 (2025-07-28)
from .positional_encoding import (
    MultiScaleLPE, RandomWalkSE, CFGPositionalEncoder,
)

# 异构图元路径编码 (2025-07-18)
from .hetero_meta_path import (
    HeteroMetaPathEncoder, build_hetero_edges_from_cfg,
    NodeType, EdgeType,
)

# ---- 对外暴露的核心符号 ----
__all__ = [
    # 层
    "GraphConv", "GATConv", "SAGPool", "LaplacianPE",
    # 模型
    "GCNBinaryClassifier", "GATVulnDetector", "SiameseBinaryMatcher",
    # GraphMoCo
    "MomentumEncoder", "NegativeQueue", "moco_contrastive_loss",
    "l2_normalize", "cosine_similarity",
    # 位置/结构编码
    "MultiScaleLPE", "RandomWalkSE", "CFGPositionalEncoder",
    # 异构图元路径编码 (2025-07)
    "HeteroMetaPathEncoder", "build_hetero_edges_from_cfg",
    "NodeType", "EdgeType",
]
