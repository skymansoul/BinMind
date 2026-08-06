"""utils 模块定义 — 工具库。"""
UTILS = {
    "name": "工具库",
    "description": (
        "跨模块基础设施原语：端序无关二进制 I/O(含ULEB128)、密码学/LSH哈希(SimHash/MinHash/"
        "滚动哈希CDC)、Boyer-Moore-Horspool + Aho-Corasick 模式匹配、"
        "熵分析(Shannon/Renyi/卡方/压缩率)、分段树(区间刺入查询 O(log N+K))、"
        "多级缓存(LRU/TTL/LFU)、Myers 差异算法、并发工具、安全文件操作、"
        "序列化/压缩(JSON/MessagePack/zlib/LZMA)、结构化日志。"
    ),
    "key_files": [
        "binary_io.py", "hash_utils.py", "pattern_scan.py",
        "entropy_utils.py", "segment_tree.py", "diff_utils.py",
    ],
    "core_keywords": ["binary I/O", "hashing", "pattern matching", "data structures", "utilities"],
    "innovation": {
        "title": "分段树增强的多维范围查询 + 自适应哈希策略选择器",
        "rationale": (
            "当前 SegmentTree 支持区间刺入查询但仅存储单一类型。创新点："
            "(1) 多维分段树：扩展为支持多维区间查询(地址空间 + 权限位 + 类型标记)，"
            "用于二进制分析中的内存区域快速查找；"
            "(2) 自适应哈希选择器：根据数据特征(大小/熵/重复率)自动选择最优哈希策略"
            "(SHA-256/SimHash/MinHash/FNV-1a)，避免手动选择的开销；"
            "(3) 增量模式匹配缓存：Aho-Corasick 自动机支持增量模式添加(无需重建)"
            "和序列化到磁盘(避免每次启动重新编译)。"
            "差异点：当前数据结构是单一的，自适应选择可显著提升大规模二进制分析的效率。"
        ),
        "papers": [
            {"id": "LSHBloom", "title": "LSHBloom: Memory-efficient, Extreme-scale Document Deduplication",
             "venue": "arXiv 2024", "key_idea": "MinHashLSH+Bloom过滤器 → 0.6%磁盘空间, 270%速度提升, 54x空间优势"},
            {"id": "Learned-Index", "title": "Learned Index Structures for Efficient Data Access",
             "venue": "数据库最佳实践 2024", "key_idea": "学习型索引(RMI/FITing-Tree) → 替代B+树，最高3x查询加速"},
        ],
    },
}
