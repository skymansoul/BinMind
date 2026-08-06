"""multimodal 模块定义 — 多模态分析引擎。"""
MULTIMODAL = {
    "name": "多模态分析引擎",
    "description": (
        "纯 Python 多模态机器学习工具包：早/晚/门控/张量/双线性融合策略、"
        "多头注意力机制(自定义 matmul/softmax/LayerNorm)、SimCLR 对比学习对齐"
        "(NT-Xent损失+BYOL动量编码器)、贝叶斯置信度校准(Beta(2,2)先验)、"
        "LSH 跨模态检索、共形预测(有限样本校正)、Kaplan-Meier 生存分析。"
    ),
    "key_files": [
        "multi_modal_fusion.py", "multi_modal_attention.py",
        "multi_modal_alignment.py", "multi_modal_confidence.py",
        "multi_modal_retrieval.py", "multi_modal_conformal.py",
    ],
    "core_keywords": ["multimodal fusion", "contrastive learning", "attention mechanism", "uncertainty quantification"],
    "innovation": {
        "title": "基于重力模型增强的图对比学习多模态对齐 (BEGA + FuseBinRepr)",
        "rationale": (
            "当前 multi_modal_alignment.py 使用 SimCLR 风格的 NT-Xent 对比损失，"
            "但增强策略仅限于随机 dropout。借鉴 BEGA 的重力模型图增强和 FuseBinRepr "
            "的文本-图跨模态融合：(1) BEGA 重力增强：为 CFG 节点分配质量和重力，"
            "模拟编译器优化扰动生成增强视图(比随机 dropout 更真实)；"
            "(2) FuseBinRepr 三任务训练：文本-图对齐(TGA) + 图掩码恢复(GMR) + "
            "对比学习(CL)，使嵌入空间同时捕获模态间和模态内关系；"
            "(3) 自适应温度调度：在训练过程中根据对齐质量动态调整 NT-Xent 的温度参数。"
            "差异点：当前实现使用单一的随机增强，BEGA 的重力模型提供语义上有意义的增强。"
        ),
        "papers": [
            {"id": "BEGA", "title": "BEGA: Binary Code Embedding Based on Gravity-Model Augmentation Graph Contrastive Learning",
             "venue": "IEEE 2025", "key_idea": "重力模型CFG增强 + 图对比学习"},
            {"id": "FuseBinRepr", "title": "Fusing Multimodal Binary Code Representations for Enhanced Similarity Detection",
             "venue": "IEEE 2025", "key_idea": "文本-图交叉注意力 + 三任务训练，40.8% MRR提升"},
            {"id": "GraphMoCo", "title": "GraphMoCo: a Graph Momentum Contrast Model",
             "venue": "Neurocomputing 2024", "key_idea": "动量队列 + 预洗牌机制"},
        ],
    },
}
