"""UAF 检测模块导入 — 时序-别名-可达-路径验证 (Type-State Alias Reachability Verification)/Temporal/Dominator/对象身份图 (Object Identity Graph)/PTASM."""
from analysis.uaf_state_path_verifier import (
    UafTarpsVerifier, TarpsVerdict, TarpsResult,
)
try:
    from analysis.uaf_state_path_verifier import batch_verify_uaf
except ImportError:
    batch_verify_uaf = None  # type: ignore
from analysis.uaf_temporal_verifier import (
    TemporalVerdict, TemporalResult, UafTemporalVerifier,
    verify_uaf_temporal, verify_uaf_batch,
)
from analysis.uaf_dominator_verifier import (
    UAFDominatorVerifier, DominatorVerdict, DominatorResult,
    dominator_batch_verify,
)
try:
    from analysis.uaf_interproc_summary import (
        Lifetime, HeapPtrSummary, FuncSummary,
        InterProcLifetimeAnalyzer,
    )
except ImportError:
    Lifetime = None  # type: ignore
    HeapPtrSummary = None  # type: ignore
    FuncSummary = None  # type: ignore
    InterProcLifetimeAnalyzer = None  # type: ignore
try:
    from analysis.uaf_fp_cascade import (
        UafVerdict, EscapeLevel, UafCandidate, CascadeReport,
        extract_uaf_candidates, run_uaf_cascade,
        phase0_pattern_safety, phase1_alias_lifetime,
        phase2_path_dominance, phase3_escape_analysis,
    )
except ImportError:
    UafVerdict = None  # type: ignore
    EscapeLevel = None  # type: ignore
    UafCandidate = None  # type: ignore
    CascadeReport = None  # type: ignore
    extract_uaf_candidates = None  # type: ignore
    run_uaf_cascade = None  # type: ignore
    phase0_pattern_safety = None  # type: ignore
    phase1_alias_lifetime = None  # type: ignore
    phase2_path_dominance = None  # type: ignore
    phase3_escape_analysis = None  # type: ignore
from analysis.uaf_cfg_builder import (
    UafBasicBlock, UafCFGBuilder,
)
# 对象身份图 (Object Identity Graph)
from analysis.uaf_obj_graph_types import (
    ObjState, ObjectID, ObjStateAtPoint,
    IdentityEdge, FuncObjSummary, UafHoigVerdict,
)
from analysis.uaf_obj_graph_builder import HoigBuilder
try:
    from analysis.uaf_obj_graph_propagator import HoigPropagator
except ImportError:
    HoigPropagator = None  # type: ignore
try:
    from analysis.uaf_obj_graph_cross_func import HoigCrossFuncVerifier
except ImportError:
    HoigCrossFuncVerifier = None  # type: ignore
from analysis.uaf_obj_graph_verifier import HoigVerifier, HoigReallocTracker
# PTASM
from analysis.ptasm_engine import (
    PTASMEngine, PTASMStats, ptasm_analyze,
    ptasm_verify_candidates, ptasm_detect_uaf, ptasm_pipeline_detect,
    PTASM_PROTECTED, PTASM_CONFIRMED, PTASM_UNCERTAIN,
)
from analysis.ptasm_types import (
    PtrState, PtrTransition, PtrInfo, PTASMResult,
    parse_line_operations,
)
from analysis.ptasm_pipeline import (
    PTASM_PROTECTED, PTASM_CONFIRMED, PTASM_UNCERTAIN,
    ptasm_analyze, ptasm_verify_candidates,
    ptasm_detect_uaf, ptasm_pipeline_detect,
)
from analysis.ptasm_ctrl_flow import (
    normalize_single_line_ifs, find_branch_bodies, join_ptr_states,
)

__all__ = [
    'UafTarpsVerifier', 'TarpsVerdict', 'TarpsResult', 'batch_verify_uaf',
    'TemporalVerdict', 'TemporalResult', 'UafTemporalVerifier',
    'verify_uaf_temporal', 'verify_uaf_batch',
    'UAFDominatorVerifier', 'DominatorVerdict', 'DominatorResult',
    'dominator_batch_verify',
    'Lifetime', 'HeapPtrSummary', 'FuncSummary',
    'InterProcLifetimeAnalyzer',
    'UafVerdict', 'EscapeLevel', 'UafCandidate', 'CascadeReport',
    'extract_uaf_candidates', 'run_uaf_cascade',
    'phase0_pattern_safety', 'phase1_alias_lifetime',
    'phase2_path_dominance', 'phase3_escape_analysis',
    'UafBasicBlock', 'UafCFGBuilder',
    'ObjState', 'ObjectID', 'ObjStateAtPoint',
    'IdentityEdge', 'FuncObjSummary', 'UafHoigVerdict',
    'HoigBuilder', 'HoigPropagator', 'HoigCrossFuncVerifier',
    'HoigVerifier', 'HoigReallocTracker',
    'PTASMEngine', 'PTASMStats', 'ptasm_analyze',
    'ptasm_verify_candidates', 'ptasm_detect_uaf', 'ptasm_pipeline_detect',
    'PTASM_PROTECTED', 'PTASM_CONFIRMED', 'PTASM_UNCERTAIN',
    'PtrState', 'PtrTransition', 'PtrInfo', 'PTASMResult',
    'parse_line_operations',
    'normalize_single_line_ifs', 'find_branch_bodies', 'join_ptr_states',
]
