# 补丁存在性检测 + 差分执行器
# concolic 执行测试生成 + IR 等值缓存
# 符号状态引擎独立
# 多补丁交互图 + 时间衰减可靠性
# 环境漂移检测 + temporal reliability 集成
# patching/src — 二进制补丁基础设施
from .config import PatchConfig, load_config, save_config
from .exceptions import PatchError, PatchApplyError, PatchVerifyError, BackupError
from .exceptions import AnalysisError, BinaryLoadError, SandboxError, ConfigError
from .utils import find_pattern, detect_binary_format, hex_to_bytes, generate_nop_slide
from .utils import jaccard_similarity, entropy_of, lru_cache_with_ttl, safe_subprocess
from .utils import retry_on_failure, bubble_sort, parse_hex, short_hash
from .backup_manager import BackupManager
from .instr_manager import InstrumentationManager
from .patch_verifier import PatchVerifier, VerificationLevel
# 补丁存在性检测与差分执行
from .patch_presence_tester import (
    SemanticSignatureExtractor, PatchPresenceTester,
    SemanticSignature, SigKind, FunctionSignatureProfile,
    MatchResult, build_reference_profiles,
)
from .differential_executor import (
    DifferentialExecutor, DiffExecutionReport, DiffVerdict,
    DiffTestCase, SeedGenerator, InputMutator, diff_exec_verify,
)
# concolic 执行测试
from .symbolic_state import (
    SymExpr, ExprKind, SymbolicState, Constraint, ConstraintKind, PathCondition,
)
from .concolic_test_gen import ConcolicTestGenerator, ConcolicTestCase
# IR 级等值缓存
from .ir_equiv_cache import (
    IREquivalenceCache, SemanticFingerprint, EquivCacheEntry,
    normalize_function, compute_fingerprint, create_equiv_cache, LFUDACache,
)
# 多补丁交互图
from .patch_interaction_graph import (
    PatchInteractionGraph, PatchNode, InteractionEdge, EdgeType,
    InteractionReport, patch_node_from_spec, analyze_patch_set,
)
# 时间衰减可靠性
from .temporal_reliability import (
    TemporalReliabilityModel, TemporalReliabilityReport,
    EnvironmentFingerprint, EnvironmentDriftDetector, RefreshUrgency,
    capture_environment, predict_patch_longevity, estimate_decay_constant,
)
