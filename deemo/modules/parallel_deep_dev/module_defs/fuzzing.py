"""fuzzing 模块定义 — 覆盖率引导模糊测试框架。"""
FUZZING = {
    "name": "覆盖率引导模糊测试框架",
    "description": (
        "受 AFL 启发的模块化模糊测试框架：64KB 共享内存覆盖率位图、边覆盖率元组哈希、"
        "种子调度(能量分配+队列剔除)、多臂老虎机变异策略选择(BanditScheduler)、"
        "崩溃聚类去重、结构感知变异、输入最小化(Delta调试)、差分测试、"
        "符号执行桥接、污点引导变异、语法推断、语料库优化、定向模糊测试(AFLGo风格)。"
    ),
    "key_files": [
        "src/core.py", "src/coverage.py", "src/scheduler.py",
        "fuzz_bandit_scheduler.py", "fuzz_crash_triage.py",
        "fuzz_structure_mutator.py", "fuzz_directed.py",
    ],
    "core_keywords": ["fuzzing", "coverage-guided", "mutation", "crash triage", "seed scheduling"],
    "innovation": {
        "title": "多臂老虎机自适应变异调度 + 语义感知种子进化 (BandFuzz + R1-Fuzz 融合)",
        "rationale": (
            "当前 BanditScheduler 使用基础 MAB 选择变异算子，但未利用 RL 后训练"
            "和语义感知。借鉴 R1-Fuzz 的 GRPO 强化学习后训练和 FuzzingBrain V2 的"
            "可疑点抽象：(1) GRPO 策略梯度变异选择：将变异算子选择建模为策略梯度问题，"
            "使用覆盖率增益作为奖励信号，GRPO 后训练一个 7B 参数模型选择最优变异序列；"
            "(2) 可疑点引导的定向变异：借鉴 FuzzingBrain V2 的 SP 抽象，对二进制中的"
            "可疑点(危险函数调用、循环边界、内存分配)进行加权，优先变异能到达这些点的种子；"
            "(3) SAFuzz 语义预言机：在结构感知变异中集成语义预言机，检测生成代码"
            "特有的漏洞模式(幻觉资源释放、不一致错误处理)。"
            "差异点：现有 BanditScheduler 的 MAB 是无状态的，GRPO 可学习变异序列的长期依赖。"
        ),
        "papers": [
            {"id": "", "title": "BandFuzz: An ML-powered Collaborative Fuzzing Framework",
             "venue": "arXiv 2025", "key_idea": "ML驱动协同模糊测试，Cupid自动模糊器选择"},
            {"id": "", "title": "R1-Fuzz: Reinforcement Learning for Fuzzing Input Generation",
             "venue": "arXiv 2025", "key_idea": "GRPO后训练7B模型 → 75%覆盖率提升，29个新漏洞"},
            {"id": "", "title": "FuzzingBrain V2: A Multi-Agent LLM System for Automated Vulnerability Discovery",
             "venue": "arXiv 2026", "key_idea": "可疑点抽象+两层模糊测试，90%检测率，41个0day"},
            {"id": "", "title": "SAFuzz: Semantic-Guided Adaptive Fuzzing for LLM-Generated Code",
             "venue": "arXiv 2026", "key_idea": "语义预言机+LLM引导自适应变异，85.7%精确率"},
        ],
    },
}
