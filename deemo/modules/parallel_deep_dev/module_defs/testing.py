"""testing 模块定义 — 差分测试与模糊测试框架。"""
TESTING = {
    "name": "差分测试与模糊测试框架",
    "description": (
        "综合测试编排引擎：DAG 工作流调度(Kahn拓扑+层级并行)、自适应超时(EMA历史执行时间)、"
        "饥饿预防优先级队列、工作流二分搜索定位、差分测试(跨版本/跨实现)、"
        "模糊测试子系统(AFL持久模式/LibFuzzer/socket harness生成)、"
        "崩溃去重、Markov链模糊测试、定向模糊测试、能量调度、并发模糊测试。"
    ),
    "key_files": [
        "test_orchestrator.py", "differential_tester.py",
        "src/fuzzing/fuzzer.py", "src/fuzzing/campaign.py",
        "src/markov_fuzz.py", "src/directed_fuzz.py",
    ],
    "core_keywords": ["differential testing", "test orchestration", "fuzzing harness", "crash analysis"],
    "innovation": {
        "title": "基于汤普森采样的多臂老虎机差分测试选择 + 自适应 Harness 生成",
        "rationale": (
            "当前测试编排器使用固定配置文件选择测试策略，模糊测试 harness 生成是模板化的。"
            "创新点：(1) 汤普森采样测试选择：将每种测试策略(差分/模糊/符号/并发)建模为"
            "多臂老虎机的臂，根据历史漏洞发现率使用 Beta 分布选择最优策略组合；"
            "(2) 自适应 harness 生成：HarnessGenerator 分析目标的实际接口(参数类型/"
            "缓冲区大小/返回值语义)而非仅使用模板，生成更精确的 harness；"
            "(3) 崩溃因果推断：使用反事实推理判断崩溃是否由特定变异引起，减少误报。"
            "差异点：当前测试选择是静态配置，缺乏运行时自适应的策略优化。"
        ),
        "papers": [
            {"id": "arXiv:2507.10845", "title": "BandFuzz: An ML-powered Collaborative Fuzzing Framework",
             "venue": "arXiv 2025", "key_idea": "ML驱动协同模糊测试 + Cupid自动模糊器选择"},
            {"id": "arXiv:2605.21779", "title": "FuzzingBrain V2: Multi-Agent LLM System for Automated Vulnerability Discovery",
             "venue": "arXiv 2026", "key_idea": "可疑点抽象+两层模糊测试 → 90%检测率, 41个0day"},
            {"id": "arXiv:2602.11209", "title": "SAFuzz: Semantic-Guided Adaptive Fuzzing for LLM-Generated Code",
             "venue": "arXiv 2026", "key_idea": "语义预言机 → 85.7%精确率, 1.71x加速"},
        ],
    },
}
