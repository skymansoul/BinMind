"""vuln 模块定义 — 漏洞生命周期管理。"""
VULN = {
    "name": "漏洞生命周期管理",
    "description": (
        "最大最复杂模块(51文件, ~19K LOC)：双重后端(SQLite/PostgreSQL)漏洞知识库"
        "(精确哈希+Jaccard模糊+余弦语义搜索)、CRDT 风格多源去重合并器"
        "(CVE ID→函数名→地址邻近三轮匹配)、LLM 漏洞检测(ANVIL 异常评分范式)、"
        "图二进制嵌入(函数图+基本块节点+跨架构对齐器)、模糊测试编排、"
        "多模态证据融合(证据冲突计算)、运行时漏洞验证(GDB+ASAN)、"
        "漏洞链分析、补丁质量评估。"
    ),
    "key_files": [
        "vuln_db.py", "vuln_dedup_merger.py",
        "detection/llm_vuln_detector.py", "detection/graph_binary_embedder.py",
        "detection/multimodal_vuln_fusion.py", "detection/runtime_vuln_verifier.py",
        "detection/vuln_chain_analyzer.py",
    ],
    "core_keywords": ["vulnerability detection", "LLM", "graph embedding", "exploit verification", "vuln chain"],
    "innovation": {
        "title": "ANVIL 增强异常评分 + 五模态证据融合 (DeBinVul + FuseBinRepr 集成)",
        "rationale": (
            "当前 LLM 漏洞检测使用 ANVIL 的困惑度异常评分，但仅使用单一 LLM 信号。"
            "多模态融合支持证据冲突计算但模态数量有限。创新点："
            "(1) DeBinVul 增强数据集：使用 DeBinVul 的 150K 多架构/多优化样本对 LLM "
            "检测器进行领域微调，将漏洞分类准确率从基线提升 19-24%；"
            "(2) 五模态融合扩展：在现有的静态+动态+LLM 三模态基础上，增加来自"
            "fuzzing 的覆盖率信号和来自符号执行的约束可达性信号；"
            "(3) ANVIL 2.0 自适应阈值：使用共形预测替代固定困惑度阈值，"
            "提供具有有限样本覆盖率保证的异常标记。"
            "差异点：当前单模态 LLM 检测受限于通用模型的零样本能力，领域微调可大幅提升。"
        ),
        "papers": [
            {"id": "", "title": "DeBinVul: Benchmarking LLMs for Vulnerability Analysis in Decompiled Binaries",
             "venue": "arXiv 2024", "key_idea": "150K样本→CodeLlama+19%/Llama3+24%/CodeGen2+21%"},
            {"id": "", "title": "IRBinDiff: Binary Code Similarity Detection via Graph Contrastive Learning on IR",
             "venue": "arXiv 2024", "key_idea": "LLVM-IR+GGNN+MoCo对比学习"},
            {"id": "FuseBinRepr", "title": "Fusing Multimodal Binary Code Representations for Enhanced Similarity Detection",
             "venue": "IEEE 2025", "key_idea": "文本-图交叉注意力 + 三任务训练"},
        ],
    },
}
