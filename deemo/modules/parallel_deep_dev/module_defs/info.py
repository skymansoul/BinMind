"""info 模块定义 — 二进制情报收集。"""
INFO = {
    "name": "二进制情报收集",
    "description": (
        "纯 Python PE/ELF/Mach-O 解析器(仅 struct + os + re，零外部依赖)。"
        "提取：机器架构(30+架构映射)、节信息、导入/导出表、入口点、编译时间戳、"
        "ASLR/PIE/DEP/SEH 标志、TLS 回调。加权严重性评分的关键发现提取。"
        "检测：PII 扫描、进程注入(DLL/Process Hollowing/APC/线程劫持/反射DLL)、"
        "横向移动(WMI/PsExec/SMB/RDP/WinRM/SSH)、持久化机制、进程欺骗、TLS 回调。"
    ),
    "key_files": [
        "info_collection/src/binary_info.py", "info_collection/src/findings.py",
        "info_collection/src/injection_detect.py", "info_collection/src/lateral.py",
        "info_collection/src/persistence.py", "info_collection/src/spoofing.py",
    ],
    "core_keywords": ["PE parsing", "ELF parsing", "malware detection", "indicator extraction", "forensics"],
    "innovation": {
        "title": "基于 LLM 的恶意意图推断与行为摘要生成",
        "rationale": (
            "当前 info 模块检测已知模式(注入/持久化/横向移动)，但缺乏对未知威胁和"
            "模糊行为链的语义理解。借鉴 ReCopilot 的领域 LLM 和 DeBinVul 的漏洞描述"
            "生成能力：(1) LLM 行为摘要：对反编译的二进制代码段，使用 LLM 生成自然语言"
            "行为摘要；"
            "(2) 恶意意图评分：基于 LLM 摘要，对行为链进行意图推理(侦察→持久化→C2通信)，"
            "生成杀伤链阶段标注；"
            "(3) 未知威胁标记：对于不匹配任何已知模式的异常行为，生成语义描述并标记为"
            "待分析。"
            "差异点：现有检测是基于规则的模式匹配，LLM 可提供语义级意图理解。"
        ),
        "papers": [
            {"id": "", "title": "ReCopilot: Reverse Engineering Copilot in Binary Analysis",
             "venue": "arXiv 2025", "key_idea": "领域特化LLM + 数据流上下文增强"},
            {"id": "", "title": "DeBinVul: Enhancing Reverse Engineering — Benchmarking LLMs for Vulnerability Analysis in Decompiled Binaries",
             "venue": "arXiv 2024", "key_idea": "150K样本多架构数据集，80-90%分类准确率"},
        ],
    },
}
