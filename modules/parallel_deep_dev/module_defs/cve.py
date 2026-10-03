"""cve 模块定义 — CVE 漏洞知识模块。"""
CVE = {
    "name": "CVE 漏洞知识模块",
    "description": (
        "综合 CVE 管理和匹配管道：SQLite 知识库 + NVD API 摄入、多源丰富化"
        "(EPSS/CISA KEV/ExploitDB/GHSA/OSV)、5 阶段 SBOM 组件匹配(PURL→CPE→"
        "精确名称→Jaccard模糊→关键词)、CVSS 4.0 支持、SSVC 决策评估、"
        "BM25 语义搜索、CJK FTS5 全文搜索、攻击图构建、VEX 文档生成。"
    ),
    "key_files": [
        "src/cve_models.py", "src/cve_kb.py", "src/cve_analyzer.py",
        "src/cve_sbom_matcher.py", "src/cve_attack_graph.py",
        "src/cve_epss.py", "src/cve_ssvc.py", "src/cve_embeddings.py",
    ],
    "core_keywords": ["CVE", "SBOM", "vulnerability matching", "knowledge graph", "supply chain"],
    "innovation": {
        "title": "异构图注意力网络的 SBOM 漏洞链预测 (HGAT-SBOM)",
        "rationale": (
            "当前 cve_attack_graph.py 构建的 CVE-to-CVE 攻击图使用简单的共现关系，"
            "cve_sbom_matcher.py 使用 5 阶段流水线但缺乏组件间依赖关系的建模。"
            "借鉴 Baird & Moin 的 HGAT 模型和 VDGraph 的知识图谱方法："
            "(1) 将 CycloneDX SBOM 转换为异构图：节点类型={组件, CVE, CWE}，"
            "边类型={DEPENDS_ON, HAS_VULNERABILITY, HAS_CWE}；"
            "(2) 使用异构图注意力网络(HGAT)学习节点嵌入，预测组件是否关联已知漏洞"
            "(报告91.03%准确率)；"
            "(3) 级联发现模型：MLP CVE对链接预测器(0.93 ROC-AUC)，预测多漏洞攻击链。"
            "差异点：现有攻击图仅用共现关系，HGAT 可捕获依赖结构中的传递性漏洞信号。"
        ),
        "papers": [
            {"id": "", "title": "Towards Predicting Multi-Vulnerability Attack Chains in Software Supply Chains from SBOM Graphs",
             "venue": "FSE 2026", "key_idea": "HGAT + SBOM异构图 + CVE对链接预测，91.03%准确率"},
            {"id": "", "title": "VDGraph: A Graph-Theoretic Approach to Unlock Insights from SBOM and SCA Data",
             "venue": "arXiv 2025", "key_idea": "知识图谱方法集成漏洞和依赖数据"},
            {"id": "SOMVE", "title": "SOMVE: SBOM and CVE Integration via Machine Learning",
             "venue": "ICMLC 2025", "key_idea": "Random Forest 97% CVE ID映射准确率"},
        ],
    },
}
