"""network 模块定义 — 网络流量分析。"""
NETWORK = {
    "name": "网络流量分析",
    "description": (
        "综合网络分析工具包：mmap 零拷贝 PCAP 处理(>500MB 文件)、BPF 过滤器表达式解析、"
        "协议逆向(熵边界检测+KL散度)、协议模糊测试编排(LibAFL风格能量调度)、"
        "Suricata 风格 IDS 规则引擎、多向量 DDoS 检测(EWMA自适应阈值)、"
        "加密流量分类(ECHO启发式+FG-SAT图特征)、TLS JA3/JA4 指纹、"
        "DNS/QUIC/NTP/SNMP/VoIP 分析、拓扑映射(LLDP/CDP/p0f被动OS检测)。"
    ),
    "key_files": [
        "pcap_processor.py", "protocol_reversing.py",
        "network_ids.py", "ddos_detector.py",
        "encrypted_traffic_classifier.py", "tls_analyzer.py",
    ],
    "core_keywords": ["network traffic", "protocol analysis", "encrypted traffic", "DDoS detection", "IDS"],
    "innovation": {
        "title": "ECHO 增强型加密流量分类 + JA4+ 指纹演化的自适应检测",
        "rationale": (
            "当前 encrypted_traffic_classifier.py 使用 ECHO 启发的 13 非均匀熵箱"
            "和 FG-SAT 流图特征，但原型分类器是静态的。创新点："
            "(1) JA4+ 指纹演化追踪：当 TLS 指纹变化时(如 Chrome 更新密码套件)，"
            "自动检测指纹漂移并使用增量学习更新分类器原型，而非重新训练；"
            "(2) 自适应熵箱边界：根据网络环境(数据中心 vs 家庭网络 vs 移动网络)的"
            "典型流量熵分布，动态调整 13 个熵箱的边界值；"
            "(3) 多分辨率流图：在 3 个时间尺度(前10包/前50包/全流)上构建 FG-SAT 图，"
            "使用早/中/晚期融合策略组合预测结果。"
            "差异点：当前分类器使用固定原型，无法适应 TLS 生态的持续演化。"
        ),
        "papers": [
            {"id": "GETA", "title": "GETA: Generalized Encrypted Traffic Analysis",
             "venue": "arXiv 2025 ", "key_idea": "元学习+自注意力+多变量时序 → 协议无关加密流量分析，9个数据集SOTA"},
            {"id": "FG-MCRF", "title": "FG-MCRF: Fine-Grained Message Clustering for Protocol Reverse Engineering",
             "venue": "Computers & Security 2025", "key_idea": "深度消息表示+标识符指纹 → 0.9961聚类纯度，3-10%超越SOTA"},
            {"id": "PathSig-LSTM", "title": "Path Signature + LSTM for Encrypted Traffic Classification",
             "venue": "Electronics 2024", "key_idea": "24包路径签名+LSTM → 0.03M参数，4ms推理，94.74% VPN准确率"},
        ],
    },
}
