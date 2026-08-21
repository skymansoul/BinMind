"""
配置模块 — 所有可调参数集中于此，用户可直接修改。

使用方法:
  from parallel_deep_dev.config import CONFIG
  CONFIG.MAX_WORKERS = 3   # 运行时覆盖
"""

import os

# 数据目录 — bandit/evo/hyper 优化器的持久化数据存放位置
def _data_dir() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")



class CONFIG:
    """全局配置 — 修改此类的属性以适配你的环境。"""

# API 配置
    API_KEY: str = os.environ.get("ANTHROPIC_API_KEY", "")
    API_MODEL: str = "claude-sonnet-5-20251001"
    API_MAX_TOKENS: int = 16000
    API_TEMPERATURE: float = 0.3
    API_TIMEOUT: int = 600       # 单个 API 调用超时 (秒)

# 路径配置
    ROOT_DIR: str = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 执行配置
    MAX_WORKERS: int = min(5, os.cpu_count() or 4)
    MAX_RETRIES: int = 2
    DRY_RUN: bool = False        # True = 仅生成 prompt 文件，不调用 API

# 时间戳伪造配置
    FORGE_DAYS_SPAN: int = 14
    FORGE_HOUR_START: int = 9
    FORGE_HOUR_END: int = 23
    FORGE_MIN_GAP_MINUTES: int = 5
    FORGE_MAX_GAP_MINUTES: int = 180
    FORGE_IDLE_DAYS: int = 2     # 至少 N 整天无修改

# 排除列表 (不会被修改时间戳的文件/目录模式)
    EXCLUDE_PATTERNS: list[str] = [
        "__pycache__", ".git", ".claude", ".mypy_cache",
        ".pytest_cache", "*.pyc", "parallel_deep_dev",
        "forge_timestamps.py", "_forge_timestamps.py",
    ]

# CDC (Content-Defined Chunking) 分块参数
    # 对大于 CDC_MIN_FILE_SIZE 的文件启用 CDC 分块哈希，而非整文件 SHA-256。
    # CDC 允许检测文件内的部分变更（如 AI 仅新增函数到文件末尾），
    # 避免将整文件标记为"已修改"。
    CDC_ENABLED: bool = False               # 默认关闭，大目录时建议开启
    CDC_MIN_FILE_SIZE: int = 16384          # 16KB，小于此值的文件用整文件哈希
    CDC_CHUNK_MIN: int = 2048               # 最小块 2KB
    CDC_CHUNK_AVG: int = 8192               # 期望块大小 8KB
    CDC_CHUNK_MAX: int = 32768              # 最大块 32KB

# 韧性层配置（断路器 + 令牌预算 + 自适应并发）
    RESILIENCE_ENABLED: bool = True
    # 断路器
    CB_FAILURE_THRESHOLD: int = 5           # 连续失败 N 次跳闸
    CB_FAILURE_RATE_THRESHOLD: float = 0.6  # 窗口内 60%+ 失败率跳闸
    CB_COOLDOWN_SECONDS: float = 45.0       # 跳闸后冷却时间
    CB_WINDOW_SECONDS: float = 120.0        # 滑动窗口宽度
    # 令牌预算
    TB_TOKENS_PER_MINUTE: int = 200_000     # 每分钟令牌软上限
    TB_TOKENS_PER_SESSION: int = 2_000_000  # 每会话令牌硬上限
    # 自适应并发
    AC_MIN_WORKERS: int = 2                 # 最小并发数
    AC_MAX_WORKERS: int = 8                 # 最大并发数
    AC_INITIAL_WORKERS: int = 4             # 初始并发数（必须 <= MAX_WORKERS）

# Merkle 树配置
    MERKLE_ENABLED: bool = False            # 默认关闭，需配合 CDC 或大目录使用

# 黑板（跨 Worker 知识共享）配置
    BLACKBOARD_ENABLED: bool = True
    BB_DEFAULT_TTL_SECONDS: float = 1800.0  # 条目默认有效期 30 分钟
    BB_QUERY_MIN_SCORE: float = 0.15        # 检索最低 Dice 系数阈值

# 语义验证配置
    SEMANTIC_VALIDATION_ENABLED: bool = True
    SV_MAX_PROPERTY_TESTS: int = 5          # 每文件最多生成的属性测试函数数
    SV_DIFF_EXEC_TIMEOUT: float = 3.0       # 差异执行单次调用超时 (秒)


# 模块级单例
config = CONFIG()
