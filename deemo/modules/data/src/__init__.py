# data module — binary signature db, ETL pipeline, dedup, compression, export
# 大部分工具类支持 lazy init，避免启动时全加载

from .config import DataConfig, DBConfig, PipelineConfig, DedupConfig, \
    IndexConfig, LifecycleConfig, StreamingConfig, CompressionConfig, \
    CacheConfig, ExportConfig, get_config, reset_config
from .db import DataDB, get_db
from .pipeline import Pipeline, ParallelPipeline, FanOutPipeline, \
    make_hash_stage, make_compress_stage, batch_iter
from .dedup import SimHashDedup, MinHashDedup, OPHMinHash, cdc_chunk, \
    BloomFilter, CuckooFilter, HyperLogLog, TDigest, dedup_from_config
from .compression import compress, decompress, detect_codec, Compressor, batch_compress
from .export import DataExporter, StreamingExporter, read_bin, import_bin_to_db
from .cache import LRUCache, S3LRUCache, MmapDiskCache, CacheRouter
from .metrics import MetricsRegistry, Counter, Gauge, Delta, Histogram, Summary, \
    Rate, Timer, get_registry
from .validate import RecordValidator, FieldValidator, CrossRecordValidator, \
    IntegrityChecker, signature_validator, cross_record_validator, time_range_validator
from .query import Query, Mutation, SignatureQuery
from .streaming import StreamProcessor, ChunkPool, MmapReader, FileBatchIngest
from .lifecycle import LifecycleManager
from .async_pipeline import AsyncPipeline, AsyncParallelPipeline
