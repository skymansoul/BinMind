"""patching 模块定义 — 二进制补丁分析。"""
PATCHING = {
    "name": "二进制补丁分析",
    "description": (
        "全生命周期二进制补丁工具链：漏洞检测→根因分析→补丁规范生成→补丁应用→"
        "安全验证(VeriBin三级验证：A.指令边界 B.Z3约束 C.回归风险)→"
        "影响分析(函数指纹+调用者/被调用者依赖图)→质量评估→测试生成。"
        "含规则引擎(10+操作符)、自愈重写器、补丁冲突解决器。"
    ),
    "key_files": [
        "auto_patcher.py", "auto_patch_spec.py", "auto_root_cause.py",
        "patch_safety_verifier.py", "gadget_chain_analyzer.py",
        "bounded_model_checker.py", "patch_impact_analyzer.py",
    ],
    "core_keywords": ["binary patching", "vulnerability fix", "patch verification", "root cause analysis"],
    "innovation": {
        "title": "VeriBin 增强三级安全验证 + ARCANIST 小配件链防御评分",
        "rationale": (
            "当前 patch_safety_verifier.py 实现 VeriBin 三级验证但 Z3 约束求解是可选的，"
            "gadget_chain_analyzer.py 实现 ARCANIST 小配件分析但防御评分仅考虑数量。"
            "创新点：(1) 约束求解降级策略：当 Z3 不可用时，使用轻量级区间分析替代，"
            "提供近似的边界检查验证(精度略低但零依赖)；"
            "(2) ARCANIST 增强防御评分：不仅统计小配件数量，还计算可达链的"
            "最小复杂度(Turing 完备性阈值)、关键小配件稀缺性和 ASLR 熵降低因子；"
            "(3) 补丁回归测试生成：自动对比补丁前后的函数指纹，对每个修改的函数"
            "生成最小化的回归测试输入。"
            "差异点：现有实现中 Z3 不可用时直接跳过 B 级验证，区间分析填补了这一空缺。"
        ),
        "papers": [
            {"id": "VeriBin", "title": "VeriBin: Verified Binary Patching",
             "venue": "NDSS 2025", "key_idea": "三级验证(A结构/B约束/C风险)"},
            {"id": "ARCANIST", "title": "ARCANIST: Analyzing ROP Chains in Binary",
             "venue": "USENIX Security 2025", "key_idea": "小配件分类+可达链分析+防御评分"},
            {"id": "ESBMC-AI", "title": "ESBMC-AI: Bounded Model Checking for AI-Generated Code",
             "venue": "AST 2025", "key_idea": "断言验证：数组边界/空指针/整数溢出/资源泄漏"},
        ],
    },
}
