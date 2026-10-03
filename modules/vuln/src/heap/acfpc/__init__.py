"""分配契约流保持 — Allocation-Contract Flow-Preserving Compression.

堆溢出检测误报压缩包. 三证据链: 双常量几何, 守卫支配, 写-分配耦合.
仅新增, 不改动既有检测器.
"""

from .def_chain import DefChainTracker, DefKind, DefNode
from .alloc_contract import AllocContract, AllocContractExtractor
from .allocator_geometry import usable_size, write_fits, overflow_bytes
from .write_coupling import WriteCouplingAnalyzer, Coupling
from .guard_dominance import GuardDominanceChecker
from .fp_compressor import ACFPCVerdict, ACFPCVerdictKind, VerdictSynthesizer
from .fp_compressor import FpCompressor, CompressResult, CompressStats

__all__ = [
    'DefChainTracker', 'DefKind', 'DefNode',
    'AllocContract', 'AllocContractExtractor',
    'usable_size', 'write_fits', 'overflow_bytes',
    'WriteCouplingAnalyzer', 'Coupling',
    'GuardDominanceChecker',
    'FpCompressor', 'CompressResult', 'CompressStats',
    'ACFPCVerdict', 'ACFPCVerdictKind', 'VerdictSynthesizer',
]
