"""UAF 深度检测模块 — 使用链追踪 + 生命周期 + 堆重用 + 利用性评分."""
from .uaf_use_chain_tracker import UAFUseChainTracker, UseChain
from .uaf_alloc_lifetime import UAFAllocationLifetime, AllocationLifetime
from .heap_reuse_estimator import HeapReuseEstimator, ReuseEstimate
from .uaf_exploitability import UAFExploitabilityScorer, UAFExploitScore
__all__ = ["UAFUseChainTracker","UseChain","UAFAllocationLifetime","AllocationLifetime","HeapReuseEstimator","ReuseEstimate","UAFExploitabilityScorer","UAFExploitScore"]
