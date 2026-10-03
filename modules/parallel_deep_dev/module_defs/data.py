"""data 模块定义 — 二进制签名数据库与 ETL。"""
DATA = {
    "name": "二进制签名数据库与 ETL",
    "description": (
        "中央数据管理层：SQLite 签名数据库(SHA256)、内容定义分块(FastCDC)、"
        "多算法去重(SimHash/MinHash/OPH)、压缩(zstd/gzip/lzma/snappy)、"
        "多级缓存(L1 LRU + L2 mmap + TinyLFU准入)、学习型分区布隆过滤器、"
        "向量索引(随机投影LSH)、冷热分层存储、增量编码(bsdiff风格)。"
    ),
    "key_files": [
        "db.py", "dedup.py", "compression.py", "cache.py",
        "delta.py", "learned_filter.py", "vector_search.py",
        "pipeline.py", "cold_storage.py",
    ],
    "core_keywords": ["deduplication", "bloom filter", "signature database", "ETL", "compression"],
    "innovation": {
        "title": "学习型自适应过滤器 + 流式近似去重 (Learned Adaptive Filter with SplineSketch)",
        "rationale": (
            "当前 data 模块已实现 PLBF (Sato & Matsui 2024) 和 SplineSketch，"
            "但过滤器和去重管道各自独立。创新点：(1) 自适应频率估计：将 SplineSketch"
            "的频率估计反馈回 PLBF 的分组策略，实现运行时自适应分组优化；"
            "(2) 双通道去重：第一通道使用学习型过滤器快速排除 >99% 的非重复项，"
            "第二通道使用精确哈希验证，将去重吞吐量提升 3-5x；"
            "(3) 动态掩码调整：FastCDC 的 gear mask 根据数据熵自动调整。"
            "差异点：当前 PLBF 的分组是静态的，动态反馈可实现自优化。"
        ),
        "papers": [
            {"id": "PLBF", "title": "Partitioned Learned Bloom Filter",
             "venue": "Sato & Matsui 2024", "key_idea": "频率分组 + 指数衰减Bloom分配"},
            {"id": "LSHBloom", "title": "LSHBloom: Memory-efficient, Extreme-scale Document Deduplication",
             "venue": "arXiv 2024", "key_idea": "MinHashLSH + Bloom过滤器替换 → 0.6%磁盘空间, 270%速度提升"},
            {"id": "FastCDC", "title": "FastCDC: Content-Defined Chunking with Gear Hash",
             "venue": "Xia et al. 2016/2024", "key_idea": "动态mask归一化 + 齿轮哈希 → 流式分块"},
        ],
    },
}
