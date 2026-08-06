"""analysis 模块定义 — 二进制分析引擎。"""
ANALYSIS = {
    "name": "二进制分析引擎",
    "description": (
        "分层分析管道：静态数据流分析(Use-Def链/整数溢出/格式字符串/污点分析)、"
        "动态沙箱执行(API Hook/熵检测/MITRE ATT&CK映射/贝叶斯风险评分)、"
        "符号执行(angr路径探索/崩溃输入生成)、AI辅助反编译、反混淆"
        "(控制流平坦化恢复/不透明谓词消除/MBA求解)。"
    ),
    "key_files": [
        "static/static_analysis.py", "dynamic/engine/dynamic_analysis_engine.py",
        "symbolic/symbolic_exe.py", "decompiler/ai_decompiler.py",
        "deobfuscation/deobfuscator.py",
    ],
    "core_keywords": ["binary analysis", "symbolic execution", "taint analysis", "deobfuscation", "decompilation"],
    "innovation": {
        "title": "LLM 引导的混合符号执行路径探索",
        "rationale": (
            "当前 symbolic_exe.py 使用 angr 的 simulation_manager.explore 进行路径探索，"
            "采用 BFS/DFS 策略，易受路径爆炸影响。通过集成 FoC 的 LLM 二进制函数摘要能力"
            "和 ReCopilot 的领域特化 LLM，可以实现：(1) LLM 预筛选：在符号执行前用 LLM "
            "识别语义上有趣的函数（加密、认证绕过、命令注入），生成优先级评分；"
            "(2) 语义路径排序：LLM 分析反编译代码，预测哪些分支更可能包含漏洞模式；"
            "(3) 自适应搜索策略切换：根据覆盖增长率自动在 BFS/DFS/随机/LLM引导 间切换。"
            "差异点：现有分析依赖纯静态启发式，ReCopilot/FoC 的 LLM 辅助可提供语义级"
            "路径优先级，比传统的覆盖率导向探索准确度更高。"
        ),
        "papers": [
            {"id": "FoC", "title": "FoC: Figure Out the Cryptographic Functions in Stripped Binaries with LLMs",
             "venue": "ACM TOSEM 2025", "key_idea": "LLM 生成二进制函数摘要 + 相似性检测，ROUGE-L 提升14.61%"},
            {"id": "arXiv:2505.16366", "title": "ReCopilot: Reverse Engineering Copilot in Binary Analysis",
             "venue": "arXiv 2025", "key_idea": "领域特化LLM(CPT+SFT+DPO) + 数据流上下文 + 测试时扩展"},
            {"id": "PwnGPT", "title": "PwnGPT: LLM-Based Automated Exploit Generation",
             "venue": "ACL 2025", "key_idea": "LLM代理技术 + RAG调用约定 + 内存状态理解"},
            {"id": "arXiv:2404.19631", "title": "On Training a Neural Network to Explain Binaries",
             "venue": "arXiv 2024", "key_idea": "EDC数据集质量检测 + 1.1M条目Stack Overflow数据集"},
        ],
    },
}
