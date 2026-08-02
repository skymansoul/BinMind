# 2026-07-15
# GNN模块入口 — 纯NumPy图神经网络，零框架依赖
# 设计理念：不引入PyTorch/Scipy重型依赖，手工实现稀疏操作以保持审计可控性

from .layers import GraphConv, GATConv, SAGPool, LaplacianPE

from .models import GCNBinaryClassifier, GATVulnDetector, SiameseBinaryMatcher

# ---- 对外暴露的核心符号 ----
__all__ = [
    # 层
    "GraphConv",
    "GATConv",
    "SAGPool",
    "LaplacianPE",
    # 模型
    "GCNBinaryClassifier",
    "GATVulnDetector",
    "SiameseBinaryMatcher",
]
