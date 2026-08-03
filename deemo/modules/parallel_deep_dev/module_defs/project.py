"""project 模块定义 — 项目编排与管理。"""
PROJECT = {
    "name": "项目编排与管理",
    "description": (
        "最高层编排模块：DAG 扫描编排器(Kahn拓扑排序+层级并行执行)、"
        "事件总线(MQTT风格通配符+死信队列+重试)、项目生命周期管理"
        "(内容寻址存储+检查点增量分析)、二进制语义差异引擎"
        "(SHA-256段匹配+MinHash模糊聚类)、可利用性评分"
        "(CVSS+EPSS+可达性+PoC存在性，逻辑回归+时间衰减)。"
    ),
    "key_files": [
        "scan_orchestrator.py", "event_bus.py", "project_manager.py",
        "binary_diff_engine.py", "exploitability_scorer.py",
        "plugin_manager.py",
    ],
    "core_keywords": ["orchestration", "DAG", "CI/CD", "project management", "scoring"],
    "innovation": {
        "title": "DAG 驱动的渐进式扫描编排 + 时间衰减可利用性评分",
        "rationale": (
            "当前 ScanOrchestrator 使用静态 DAG 和 Kahn 算法，但扫描任务的依赖关系是"
            "硬编码的。ExploitabilityScorer 使用逻辑回归但训练数据有限。"
            "创新点：(1) 动态 DAG 重构：扫描过程中根据中间结果自动插入/移除扫描任务"
            "(如发现加密函数后自动添加密码误用扫描)，实现自适应扫描管道；"
            "(2) Baird & Moin 启发的级联评分：从 SBOM 依赖图计算漏洞的可达性概率，"
            "将传递性风险集成到 EPSS+CVSS 评分中；"
            "(3) 多源评分融合：使用贝叶斯模型平均(BMA)融合 NVD/EPSS/ExploitDB/GHSA "
            "四个来源的评分，每个来源的权重由其历史预测准确度决定。"
            "差异点：现有 DAG 是静态的，可利用性评分未考虑依赖链的传递风险。"
        ),
        "papers": [
            {"id": "arXiv:2604.04977", "title": "Towards Predicting Multi-Vulnerability Attack Chains from SBOM Graphs",
             "venue": "FSE 2026", "key_idea": "HGAT + 依赖图 + 漏洞链预测"},
            {"id": "arXiv:2605.05000", "title": "Slyp: Agentic Vulnerability Reasoning on COTS Binaries",
             "venue": "arXiv 2026", "key_idea": "可扩展MCP工具服务器 + ReAct管道 → DAG编排参考"},
            {"id": "VDGraph", "title": "VDGraph: A Graph-Theoretic Approach to Unlock Insights from SBOM and SCA Data",
             "venue": "arXiv 2025", "key_idea": "知识图谱方法 → 依赖链漏洞传播分析"},
        ],
    },
}
