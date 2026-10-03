"""platform 模块定义 — 平台安全分析。"""
PLATFORM = {
    "name": "平台安全分析",
    "description": (
        "最大的模块(111文件, ~39K LOC)，涵盖 6 个子领域：固件分析(UEFI/安全启动/OTA/飞地)、"
        "内核安全(eBPF字节码分析/内核利用生成/系统调用模糊测试)、"
        "硬件安全(侧信道CPA/ttest/ Spectre V1-V4/Meltdown/微架构验证/GPU RowHammer)、"
        "恶意软件分析(DBSCAN聚类/勒索软件评分/配置提取/壳检测/反分析检测)、"
        "移动安全(Android ART/OAT/iOS ARM64E/WebAssembly WASI)、"
        "智能合约安全(CrossInspector跨合约SDG分析)。"
    ),
    "key_files": [
        "firmware/firmware_analyzer.py", "kernel/ebpf_analyzer.py",
        "hardware/side_channel_evaluator.py", "hardware/spectre_detector.py",
        "malware/malware_clustering.py", "malware/ransomware_detector.py",
        "smart_contract/cross_inspector.py",
    ],
    "core_keywords": ["firmware", "kernel", "hardware security", "malware", "smart contract"],
    "innovation": {
        "title": "CrossInspector 增强跨合约漏洞检测 + Spectre V2+ 微架构感知模式匹配",
        "rationale": (
            "当前 CrossInspector 使用 SDG 检测跨合约漏洞(97%精度)，但仅覆盖 3 种漏洞类型。"
            "spectre_detector.py 支持 Spectre V1/V2/V4/Meltdown 但检测基于静态模式匹配。"
            "创新点：(1) CrossInspector 扩展：将 SDG 节点类型从 11 种扩展到包含"
            "代理模式，检测可升级合约漏洞和钻石代理漏洞；"
            "(2) Spectre V2+ 微架构感知检测：集成微架构验证器的缓存命中/未命中模拟，"
            "在 Spectre 小配件检测中考虑实际的缓存时序而非仅模式匹配；"
            "(3) NEUROSCOPE 启发的 DNN 二进制逆向：对固件中的闭源 DNN 模型进行架构推断"
            "和灰盒对抗攻击评估。"
            "差异点：CrossInspector 仅覆盖 3 种漏洞，Spectre 检测不考虑微架构具体参数。"
        ),
        "papers": [
            {"id": "", "title": "CrossInspector: Cross-Contract Vulnerability Detection via State Dependency Graph",
             "venue": "arXiv 2024", "key_idea": "SDG跨合约数据流分析，97%精度"},
            {"id": "NEUROSCOPE", "title": "NEUROSCOPE: Reverse Engineering Deep Neural Network Binaries",
             "venue": "USENIX Security 2025", "key_idea": "编译器无关+动态分析+灰盒对抗攻击"},
        ],
    },
}
