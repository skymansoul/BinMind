"""core 模块定义 — 基础设施层。"""
CORE = {
    "name": "基础设施层",
    "description": (
        "提供 Hook/插件系统(HookManager: 8个钩子点)和 47 个兼容性适配器模块"
        "(core/compat/)，桥接新旧模块化架构。Hook 支持用户自编写 Python 脚本，"
        "动态加载(importlib.util)，运行时热重载。"
    ),
    "key_files": ["hooks.py"] + [f"compat/{f}" for f in [
        "binary_embedding.py", "taint_flow.py", "gadget_scan.py",
        "packer_detect.py", "value_set_analysis.py", "binary_simhash.py",
        "knowledge_graph.py", "vm_unvirtualizer.py",
    ]],
    "core_keywords": ["plugin system", "hook", "compatibility", "middleware", "event-driven"],
    "innovation": {
        "title": "自适应事件驱动 Hook 管道 (CVE-GENIE 多智能体模式)",
        "rationale": (
            "当前 HookManager 使用线性的 pre/post 钩子执行模型，钩子按注册顺序依次调用。"
            "借鉴 CVE-GENIE 的多智能体 EAGER 框架，引入：(1) 钩子优先级 DAG：钩子间"
            "声明依赖关系，拓扑排序后分层并行执行；(2) 条件触发链：钩子可根据上一个钩子"
            "的输出决定是否激活，实现链式推理；(3) 钩子执行遥测：记录每个钩子的延迟、"
            "成功率和副作用，用于运行时优化调度。"
            "差异点：现有 HookManager 的顺序执行无法利用多核，且缺乏钩子间协作机制。"
        ),
        "papers": [
            {"id": "", "title": "CVE-GENIE: From CVE Entries to Verifiable Exploits — An Automated Multi-Agent Framework",
             "venue": "arXiv 2025", "key_idea": "EAGER多智能体框架(Exploit/Assessment/Generalization/End-to-end/Rebuilding)"},
            {"id": "", "title": "Slyp: Agentic Vulnerability Reasoning on COTS Binaries",
             "venue": "arXiv 2026", "key_idea": "ReAct代理管道 + MCP工具服务器 → 39个0day, 23个CVE, $203K赏金"},
            {"id": "", "title": "Implicit Patterns in LLM-Based Binary Analysis",
             "venue": "arXiv 2026", "key_idea": "521个二进制/99K推理步骤 → 四种涌现模式：早剪枝(83.5%)/路径锁定(97.6%)"},
        ],
    },
}
