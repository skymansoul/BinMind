"""Fuzzing core submodules -- re-exports for convenience."""

from .core import Seed, FuzzConfig, FuzzResult, CorpusStats
from .coverage import CoverageBitmap, EdgeCoverage, CoverageTracker
from .scheduler import Scheduler, CorpusManager, pick_seed, cull_queue
# 新增时态新颖度调度器
from .decaying_novelty_scheduler import (
    DecayingNoveltyScheduler, NoveltyRecord,
)
# 种子关系图（已有实现）
from .seed_relation_graph import SeedRelationGraph, SeedNode
# 在线结构约束推断变异器
from .constraint_inference_mutator import (
    ConstraintInferenceMutator, ConstraintType, ByteConstraint,
)
# 差分跟踪制导变异器
from .trace_diff_mutator import (
    TraceDiffMutator, TraceDiffResult, BifurcationPoint, TraceEntry,
)
# 跨层模糊测试-分布式调度桥接
from .cross_layer_fuzz_bridge import (
    CrossLayerFuzzBridge, FuzzCampaignConfig, launch_distributed_campaign,
)

__all__ = [
    "Seed",
    "FuzzConfig",
    "FuzzResult",
    "CorpusStats",
    "CoverageBitmap",
    "EdgeCoverage",
    "CoverageTracker",
    "Scheduler",
    "CorpusManager",
    "pick_seed",
    "cull_queue",
    "DecayingNoveltyScheduler",
    "NoveltyRecord",
    "SeedRelationGraph",
    "SeedNode",
    "ConstraintInferenceMutator",
    "ConstraintType",
    "ByteConstraint",
    "TraceDiffMutator",
    "TraceDiffResult",
    "BifurcationPoint",
    "TraceEntry",
    # 2025-07/08 跨层桥接
    "CrossLayerFuzzBridge",
    "FuzzCampaignConfig",
    "launch_distributed_campaign",
]
