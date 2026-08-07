"""output 模块定义 — 报告生成与 Web API。"""
OUTPUT = {
    "name": "报告生成与 Web API",
    "description": (
        "BinMind 的表示层：多格式报告生成(Markdown/HTML/JSON)、"
        "FastAPI REST API(分析任务提交/漏洞查询/结果检索)、"
        "LLM 驱动的摘要生成(使用 prompts.REPORT_SUMMARY_TEMPLATE)。"
    ),
    "key_files": ["report.py", "web_api.py"],
    "core_keywords": ["report generation", "REST API", "FastAPI", "summarization"],
    "innovation": {
        "title": "自适应多格式报告引擎 + 证据链驱动的 AI 摘要生成",
        "rationale": (
            "当前 ReportGenerator 使用模板驱动的报告生成，LLM 摘要仅用于总结部分。"
            "创新点：(1) 证据链追踪：报告的每个发现自动关联其分析路径(哪个模块产生、"
            "哪些中间结果支撑、置信度如何)，在报告中呈现为可折叠的证据链；"
            "(2) 自适应格式优化：根据报告类型(高管摘要 vs 技术深度分析 vs 合规审计)"
            "自动调整详细程度、技术深度和格式样式；"
            "(3) RAG 增强摘要：使用 CVE 描述、相关漏洞报告和修复指南作为检索语料库，"
            "LLM 生成可操作的安全建议而非简单的事实陈述。"
            "差异点：当前报告是线性的模板填充，缺乏受众自适应和证据溯源。"
        ),
        "papers": [
            {"id": "", "title": "RAVEN: Retrieval-Augmented Vulnerability Exploration Network",
             "venue": "arXiv 2026", "key_idea": "4-agent RAG框架 → Google Project Zero RCA模板报告，15种CWE评估"},
            {"id": "", "title": "Veritas: Grounding LLM Agents for Reliable Vulnerability Reasoning over Stripped Binaries",
             "venue": "arXiv 2026", "key_idea": "证据驱动三段式验证: 静态切片+LLM发现+多代理验证 → 90%召回,零误报"},
        ],
    },
}
