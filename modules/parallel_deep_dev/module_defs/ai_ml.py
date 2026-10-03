"""ai_ml 模块定义 — AI/ML 引擎。"""
AI_ML = {
    "name": "AI/ML 引擎",
    "description": (
        "端到端 AI/ML 管道，用于二进制分析：原始字节嵌入、图神经网络(GCN/GAT/SiameseGNN)"
        "漏洞检测、对比学习对齐、扩散异常检测、自适应模型路由(Thompson采样/UCB/ε-greedy)、"
        "LLM 集成。核心算法用纯 NumPy 实现，无 PyTorch/TF 依赖。"
    ),
    "key_files": [
        "gnn_vulnerability_detector.py", "hex_byte_embedder.py",
        "diffusion_anomaly.py", "adaptive_ai_model.py",
        "src/gnn/models.py", "src/gnn/layers.py",
        "src/data/graph_builder.py", "src/training/trainer.py",
        "src/training/contrastive.py", "llm_agent_binary.py",
    ],
    "core_keywords": ["graph neural network", "contrastive learning", "binary embedding", "vulnerability detection"],
    "innovation": {
        "title": "基于 GraphMoCo 动量对比学习的跨架构二进制函数嵌入",
        "rationale": (
            "当前 ai_ml 模块的 GNN 模型使用纯 NumPy 实现，训练依赖 InfoNCE 对比损失。"
            "通过引入 GraphMoCo 的动量编码器架构和 IRBinDiff 的 LLVM-IR 中间表示提升，"
            "可以实现：(1) 动量更新的目标编码器，避免端到端对比学习中的表示坍缩；"
            "(2) 大字典大小的负样本队列，不需要大批量训练；"
            "(3) BEGA 的重力模型图增强策略，生成多种编译器优化级别的增强视图。"
            "差异点：现有 ContraBin 的三模态对齐使用随机投影矩阵，而 GraphMoCo 的动量"
            "队列机制提供了更稳定的对比信号，且 BEGA 的重力模型增强可模拟真实编译器变换。"
        ),
        "papers": [
            {"id": "GraphMoCo", "title": "GraphMoCo: a Graph Momentum Contrast Model for Large-Scale Binary Function Representation Learning",
             "venue": "Neurocomputing 2024", "key_idea": "动量对比学习 + CNN块编码器 + 预洗牌机制防止信息泄露"},
            {"id": "", "title": "IRBinDiff: Binary Code Similarity Detection via Graph Contrastive Learning on Intermediate Representations",
             "venue": "arXiv 2024", "key_idea": "LLVM-IR 提升 + BERT + GGNN + MoCo 对比学习"},
            {"id": "BEGA", "title": "BEGA: Binary Code Embedding Based on Gravity-Model Augmentation Graph Contrastive Learning",
             "venue": "IEEE 2025", "key_idea": "重力模型图增强策略，模拟编译器优化扰动"},
            {"id": "Binary2vec", "title": "Binary2vec: Cross-Architecture Binary Embeddings with Global Attention-Enhanced GNN",
             "venue": "Array 2025", "key_idea": "GPS架构(GINE+Performer注意力) + 边距对比损失"},
        ],
    },
}
