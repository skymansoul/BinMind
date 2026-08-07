"""PCFV — Path-Constrained Controllability Verification.

堆溢出静态检测的误报抑制引擎. 核心方法论:
  1. Guard-Dominance-Aware Safety Proof: 只采信支配访问点的分支守卫.
  2. Controllability-Verified Overflow Proof: 确认溢出必须携带
     常量偏移或用户可控污点链证据.
  3. Allocator-Rounding Padding Exclusion: 分配器舍入padding区访问过滤.

与基线 DP-TVRA (modules.vuln.src.heap.heap_fp_filter_v2) 的差异:
  - 基线在无数据流边注册时按 UNTAINTED 过滤 → 真阳性被误杀;
    PCFV 要求过滤必须携带常量/守卫/padding 证据.
  - 基线反向BFS收集守卫不验证支配性 → 兄弟分支守卫误过滤;
    PCFV 引入支配性验证.

创建: 2026-07-23
"""
from .types import (Verdict, ProofRule, Provenance, ValueInfo,
                    Evidence, FindingVerdict, GuardConstraint)
from .value_flow import ValueFlowTracer
from .value_ops import ValueOpsMixin
from .guard_dominance import GuardExtractor
from .alloc import AllocSizeResolver, ptmalloc2_usable
from .loop_bound import LoopBoundExtractor
from .access_extractor import AccessExtractor
from .extract_ops import AccessOpsMixin
from .proof import SafetyProver, OverflowProver
from .engine import PCFVEngine
from .pipeline import PCFVReport, analyze_heap_pcfv

__all__ = [
    "Verdict", "ProofRule", "Provenance", "ValueInfo", "Evidence",
    "FindingVerdict", "GuardConstraint",
    "ValueFlowTracer", "ValueOpsMixin", "GuardExtractor",
    "AllocSizeResolver", "ptmalloc2_usable", "LoopBoundExtractor",
    "AccessExtractor", "AccessOpsMixin",
    "SafetyProver", "OverflowProver", "PCFVEngine",
    "PCFVReport", "analyze_heap_pcfv",
]
