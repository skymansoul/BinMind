# data 模块运行时配置：读取 YAML + 环境变量覆写
# cve/src/config.py 模式实现，参数集合不完全一致

import os
import json
import yaml
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, List


def _env_or(key: str, default=None):
    """读取环境变量，缺失时返回默认值。"""
    val = os.environ.get(key)
    return val if val is not None else default


def _env_int(key: str, default: int) -> int:
    try:
        return int(os.environ.get(key, default))
    except (TypeError, ValueError):
        return default


def _env_float(key: str, default: float) -> float:
    try:
        return float(os.environ.get(key, default))
    except (TypeError, ValueError):
        return default


def _env_bool(key: str, default: bool) -> bool:
    v = os.environ.get(key)
    if v is None:
        return default
    return v.lower() in ("1", "true", "yes", "on")


@dataclass
class DBConfig:
    path: str = "data/signatures.db"
    wal: bool = True
    cache_size_mb: int = 64
    page_size: int = 4096
    timeout_ms: int = 5000
    fts_enabled: bool = True


@dataclass
class PipelineConfig:
    batch_size: int = 1000
    max_workers: int = 4
    queue_size: int = 10000
    retry_count: int = 3
    retry_delay: float = 0.5


@dataclass
class DedupConfig:
    algorithm: str = "sha256"      # 默认仅精确哈希去重 (模糊索引待实现)
    simhash_bits: int = 128
    # simhash_threshold 和 minhash_threshold 为指纹索引表预留。
    # 当前仅 sha256 精确哈希去重可用。
    chunk_size: int = 4096
    minhash_perms: int = 128


@dataclass
class IndexConfig:
    fts_tokenizer: str = "unicode61"
    fts_remove_diacritics: int = 2
    btree_cache_pages: int = 2000
    auto_vacuum: bool = False


@dataclass
class LifecycleStageCfg:
    name: str = ""
    ttl_days: int = 0
    compress_after_days: int = 0


@dataclass
class LifecycleConfig:
    stages: list = field(default_factory=lambda: [
        LifecycleStageCfg(name="raw", ttl_days=90, compress_after_days=7),
        LifecycleStageCfg(name="analysis", ttl_days=180, compress_after_days=30),
        LifecycleStageCfg(name="report", ttl_days=365, compress_after_days=60),
        LifecycleStageCfg(name="archive", ttl_days=0, compress_after_days=0),
    ])


@dataclass
class StreamingConfig:
    chunk_size: int = 65536
    max_memory_mb: int = 512
    backpressure_threshold: float = 0.8
    flush_interval_ms: int = 1000


@dataclass
class CompressionConfig:
    algorithm: str = "zstd"
    zstd_level: int = 3
    lzma_preset: int = 6
    min_size_bytes: int = 1024


@dataclass
class CacheConfig:
    l1_max_mb: int = 64
    l2_enabled: bool = False
    l2_path: str = ""
    l2_slot_size: int = 4096
    l2_slots: int = 16384
    shards: int = 4
    default_ttl_sec: float = 300.0


@dataclass
class ExportConfig:
    default_format: str = "json"
    pretty_print: bool = True
    max_rows_per_file: int = 100000
    json_indent: int = 2


@dataclass
class DataConfig:
    """data 模块顶层配置聚合。"""
    db: DBConfig = field(default_factory=DBConfig)
    pipeline: PipelineConfig = field(default_factory=PipelineConfig)
    dedup: DedupConfig = field(default_factory=DedupConfig)
    index: IndexConfig = field(default_factory=IndexConfig)
    lifecycle: LifecycleConfig = field(default_factory=LifecycleConfig)
    streaming: StreamingConfig = field(default_factory=StreamingConfig)
    compression: CompressionConfig = field(default_factory=CompressionConfig)
    export: ExportConfig = field(default_factory=ExportConfig)
    cache: CacheConfig = field(default_factory=CacheConfig)
    source_file: str = ""

    @classmethod
    def from_file(cls, path: Optional[str] = None) -> "DataConfig":
        """从 YAML 文件加载配置，随后以环境变量覆写。

        path 为 None 时查找默认路径：当前目录下的 config/default.yaml。
        """
        if path is None:
            base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            path = os.path.join(base, "config", "default.yaml")

        cfg_dict: Dict[str, Any] = {}
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as fh:
                raw = yaml.safe_load(fh) or {}
            cfg_dict = raw.get("data", {})

        cfg = cls._from_dict_with_env(cfg_dict)
        cfg.source_file = path
        return cfg

    @classmethod
    def from_profile(cls, profile_name: str) -> "DataConfig":
        """从命名 profile 加载配置 — 在 config/ 下查找 <profile>.yaml。

        profile 间共享默认值，仅覆盖差异字段。
        适用于 quick-prod / quick-dev / ci 等场景快速切换。
        """
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        profile_path = os.path.join(base, "config", f"{profile_name}.yaml")
        if os.path.isfile(profile_path):
            return cls.from_file(profile_path)
        _log_fallback = __import__('logging').getLogger(__name__)
        _log_fallback.warning("Profile '%s' not found at %s, using defaults.", profile_name, profile_path)
        return cls.from_file()

    @classmethod
    def _from_dict_with_env(cls, d: dict) -> "DataConfig":
        defaults = DataConfig()

        db_d = d.get("db", {})
        db_cfg = DBConfig(
            path=_env_or("DATA_DB_PATH", db_d.get("path", defaults.db.path)),
            wal=_env_bool("DATA_DB_WAL", db_d.get("wal", defaults.db.wal)),
            cache_size_mb=_env_int("DATA_DB_CACHE_MB", db_d.get("cache_size_mb", defaults.db.cache_size_mb)),
            page_size=_env_int("DATA_DB_PAGE_SIZE", db_d.get("page_size", defaults.db.page_size)),
            timeout_ms=_env_int("DATA_DB_TIMEOUT_MS", db_d.get("timeout_ms", defaults.db.timeout_ms)),
            fts_enabled=_env_bool("DATA_DB_FTS", db_d.get("fts_enabled", defaults.db.fts_enabled)),
        )

        pl_d = d.get("pipeline", {})
        pl_cfg = PipelineConfig(
            batch_size=_env_int("DATA_PIPE_BATCH", pl_d.get("batch_size", defaults.pipeline.batch_size)),
            max_workers=_env_int("DATA_PIPE_WORKERS", pl_d.get("max_workers", defaults.pipeline.max_workers)),
            queue_size=_env_int("DATA_PIPE_QUEUE", pl_d.get("queue_size", defaults.pipeline.queue_size)),
            retry_count=_env_int("DATA_PIPE_RETRY", pl_d.get("retry_count", defaults.pipeline.retry_count)),
            retry_delay=_env_float("DATA_PIPE_RETRY_DELAY", pl_d.get("retry_delay", defaults.pipeline.retry_delay)),
        )

        dd_d = d.get("dedup", {})
        dd_cfg = DedupConfig(
            algorithm=_env_or("DATA_DEDUP_ALGO", dd_d.get("algorithm", defaults.dedup.algorithm)),
            simhash_bits=_env_int("DATA_DEDUP_SIMHASH_BITS", dd_d.get("simhash_bits", defaults.dedup.simhash_bits)),
            minhash_perms=_env_int("DATA_DEDUP_MINHASH_PERMS", dd_d.get("minhash_perms", defaults.dedup.minhash_perms)),
            chunk_size=_env_int("DATA_DEDUP_CHUNK_SIZE", dd_d.get("chunk_size", defaults.dedup.chunk_size)),
        )

        ix_d = d.get("index", {})
        ix_cfg = IndexConfig(
            fts_tokenizer=_env_or("DATA_IDX_TOKENIZER", ix_d.get("fts_tokenizer", defaults.index.fts_tokenizer)),
            fts_remove_diacritics=_env_int("DATA_IDX_DIACRITICS", ix_d.get("fts_remove_diacritics", defaults.index.fts_remove_diacritics)),
            btree_cache_pages=_env_int("DATA_IDX_BTREE_CACHE", ix_d.get("btree_cache_pages", defaults.index.btree_cache_pages)),
            auto_vacuum=_env_bool("DATA_IDX_AUTO_VACUUM", ix_d.get("auto_vacuum", defaults.index.auto_vacuum)),
        )

        lc_stages = []
        for s in d.get("lifecycle", {}).get("stages", []):
            lc_stages.append(LifecycleStageCfg(
                name=s.get("name", ""),
                ttl_days=int(s.get("ttl_days", 0)),
                compress_after_days=int(s.get("compress_after_days", 0)),
            ))
        lc_cfg = LifecycleConfig(stages=lc_stages if lc_stages else defaults.lifecycle.stages)

        st_d = d.get("streaming", {})
        st_cfg = StreamingConfig(
            chunk_size=_env_int("DATA_STREAM_CHUNK", st_d.get("chunk_size", defaults.streaming.chunk_size)),
            max_memory_mb=_env_int("DATA_STREAM_MEM_MB", st_d.get("max_memory_mb", defaults.streaming.max_memory_mb)),
            backpressure_threshold=_env_float("DATA_STREAM_BP_THRESH", st_d.get("backpressure_threshold", defaults.streaming.backpressure_threshold)),
            flush_interval_ms=_env_int("DATA_STREAM_FLUSH_MS", st_d.get("flush_interval_ms", defaults.streaming.flush_interval_ms)),
        )

        cp_d = d.get("compression", {})
        cp_cfg = CompressionConfig(
            algorithm=_env_or("DATA_COMP_ALGO", cp_d.get("algorithm", defaults.compression.algorithm)),
            zstd_level=_env_int("DATA_COMP_ZSTD_LEVEL", cp_d.get("zstd_level", defaults.compression.zstd_level)),
            lzma_preset=_env_int("DATA_COMP_LZMA_PRESET", cp_d.get("lzma_preset", defaults.compression.lzma_preset)),
            min_size_bytes=_env_int("DATA_COMP_MIN_SIZE", cp_d.get("min_size_bytes", defaults.compression.min_size_bytes)),
        )

        ex_d = d.get("export", {})
        ex_cfg = ExportConfig(
            default_format=_env_or("DATA_EXPORT_FMT", ex_d.get("default_format", defaults.export.default_format)),
            pretty_print=_env_bool("DATA_EXPORT_PRETTY", ex_d.get("pretty_print", defaults.export.pretty_print)),
            max_rows_per_file=_env_int("DATA_EXPORT_MAX_ROWS", ex_d.get("max_rows_per_file", defaults.export.max_rows_per_file)),
            json_indent=_env_int("DATA_EXPORT_JSON_INDENT", ex_d.get("json_indent", defaults.export.json_indent)),
        )

        ca_d = d.get("cache", {})
        ca_cfg = CacheConfig(
            l1_max_mb=_env_int("DATA_CACHE_L1_MB", ca_d.get("l1_max_mb", defaults.cache.l1_max_mb)),
            l2_enabled=_env_bool("DATA_CACHE_L2_ENABLED", ca_d.get("l2_enabled", defaults.cache.l2_enabled)),
            l2_path=_env_or("DATA_CACHE_L2_PATH", ca_d.get("l2_path", defaults.cache.l2_path)),
            l2_slot_size=_env_int("DATA_CACHE_L2_SLOT_SZ", ca_d.get("l2_slot_size", defaults.cache.l2_slot_size)),
            l2_slots=_env_int("DATA_CACHE_L2_SLOTS", ca_d.get("l2_slots", defaults.cache.l2_slots)),
            shards=_env_int("DATA_CACHE_SHARDS", ca_d.get("shards", defaults.cache.shards)),
            default_ttl_sec=_env_float("DATA_CACHE_TTL", ca_d.get("default_ttl_sec", defaults.cache.default_ttl_sec)),
        )

        return cls(
            db=db_cfg, pipeline=pl_cfg, dedup=dd_cfg, index=ix_cfg,
            lifecycle=lc_cfg, streaming=st_cfg, compression=cp_cfg, export=ex_cfg,
            cache=ca_cfg,
        )

    def validate(self) -> List[str]:
        """校验配置合法性，返回问题列表。空列表表示配置有效。"""
        issues = []
        if self.db.page_size not in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536):
            issues.append(f"db.page_size={self.db.page_size} 不是 SQLite 支持的页大小")
        if self.db.cache_size_mb < 1:
            issues.append("db.cache_size_mb 必须 >= 1")
        if self.pipeline.max_workers < 1:
            issues.append("pipeline.max_workers 必须 >= 1")
        if self.pipeline.batch_size < 1:
            issues.append("pipeline.batch_size 必须 >= 1")
        if self.dedup.algorithm not in ("sha256", "simhash", "minhash", "all"):
            issues.append(f"dedup.algorithm='{self.dedup.algorithm}' 无效")
        if self.streaming.backpressure_threshold <= 0 or self.streaming.backpressure_threshold > 1:
            issues.append("streaming.backpressure_threshold 必须在 (0, 1] 范围内")
        if self.compression.min_size_bytes < 0:
            issues.append("compression.min_size_bytes 不能为负")
        if self.export.max_rows_per_file < 1:
            issues.append("export.max_rows_per_file 必须 >= 1")
        return issues

    def dump(self) -> str:
        """将解析后的最终配置以 JSON 格式输出，便于调试。"""
        cfg_dict = asdict(self)
        cfg_dict.pop("source_file", None)
        return json.dumps(cfg_dict, indent=2, default=str)

    def to_dict(self) -> Dict:
        """返回配置的字典表示，用于序列化或跨模块传递。"""
        d = asdict(self)
        d.pop("source_file", None)
        return d

    def diff(self, other: "DataConfig") -> List[str]:
        """逐字段比较两份配置的差异，返回可读差异列表。

        用于排查环境间配置漂移 (dev vs prod) 或 CI 中验证一致性。
        递归遍历字段，输出形如 "db.cache_size_mb: 64 → 128"。
        """
        diffs = []
        a = self.to_dict()
        b = other.to_dict()

        def _walk(prefix, d1, d2):
            for k in d1:
                full = f"{prefix}.{k}" if prefix else k
                v1 = d1.get(k)
                v2 = d2.get(k)
                if isinstance(v1, dict) and isinstance(v2, dict):
                    _walk(full, v1, v2)
                elif v1 != v2:
                    diffs.append(f"{full}: {v1} → {v2}")

        _walk("", a, b)
        return diffs

    def freeze(self):
        """冻结配置 — __frozen=True 后禁止任何属性写入。

        多线程环境或插件系统中，冻结可防止初始化完成后非预期修改
        导致的竞态条件。DataConfig 及各子配置均为 frozen dataclass，
        freeze 后触发 __setattr__ 拦截。
        """
        object.__setattr__(self, '__frozen', True)
        for field_name in self.__dataclass_fields__:
            sub = getattr(self, field_name)
            if hasattr(sub, '__dataclass_fields__'):
                object.__setattr__(sub, '__frozen', True)

    def __setattr__(self, name, value):
        if getattr(self, '__frozen', False):
            raise AttributeError(f"DataConfig is frozen — cannot set '{name}'")
        super().__setattr__(name, value)


def lc_cfg_default():
    """Lifecycle 配置默认值工厂，规避 dataclass factory 可变默认值陷阱。"""
    return LifecycleConfig(stages=[
        LifecycleStageCfg(name="raw", ttl_days=90, compress_after_days=7),
        LifecycleStageCfg(name="analysis", ttl_days=180, compress_after_days=30),
        LifecycleStageCfg(name="report", ttl_days=365, compress_after_days=60),
        LifecycleStageCfg(name="archive", ttl_days=0, compress_after_days=0),
    ])


_GLOBAL_CONFIG: Optional[DataConfig] = None


def get_config(path: Optional[str] = None) -> DataConfig:
    global _GLOBAL_CONFIG
    if _GLOBAL_CONFIG is None:
        _GLOBAL_CONFIG = DataConfig.from_file(path)
    return _GLOBAL_CONFIG


def get_config_by_profile(profile: str) -> DataConfig:
    global _GLOBAL_CONFIG
    _GLOBAL_CONFIG = DataConfig.from_profile(profile)
    return _GLOBAL_CONFIG


def reset_config():
    """重置全局配置 — 用于测试及配置热加载场景。"""
    global _GLOBAL_CONFIG
    _GLOBAL_CONFIG = None
