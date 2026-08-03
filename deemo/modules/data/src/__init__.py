# 多数工具类采用直接导入，兼容型声明

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

# 2025 扩展: delta diff | 来源追踪 | 冷存储分层 | 向量搜索 | 训练型过滤器 | 零熵优化 | GNN 评分 | 签名挖掘 | 数据集构建
from .delta import delta_encode, delta_decode, delta_stats
from .provenance import ProvenanceGraph, ProvenanceTracker, ProvNode, ProvEdge
from .cold_storage import StoragePolicy, TierManager, TierSpec
from .vector_search import VectorIndex, RandomProjectionLSH, extract_features
from .learned_filter import LearnedBloomFilter, SplineSketch
from .zero_entropy import ZeroRegionExtractor, zero_skip_cdc, detect_zero_runs
from .gnn_scorer import CallGraph, GraphScorer, wl_subtree_features, graphlet_spectrum
from .signature_miner import IOCExtractor, SignaturePatternMiner
from .dataset_builder import DatasetBuild, DatasetSplit, ContaminationCheck, LabelAnnotator
