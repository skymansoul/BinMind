"""引擎子包 — 重新导出所有公共函数，保持与旧 engine.py 完全兼容的接口。"""
from .prompts import generate_sub_prompt, build_api_messages
from .api import call_api_with_retry
from .files import parse_and_write_files
from .executor import execute_parallel_development
from .hashing import (
    file_sha256, snapshot_tree_hashes, detect_changed_by_hash,
    collect_changed_files, _is_excluded,
)
from .checkpoint import save_checkpoint, load_checkpoint, clear_checkpoint
try:
    from .timestamps import forge_timestamps
except ImportError:
    # timestamps 模块已从包中移除; 缺失时降级为 None, 调用点按守卫跳过
    forge_timestamps = None
from .validate import validate_api_key, validate_generated_files, self_check
from .chunking import (
    chunk_boundaries, chunk_file, chunks_differ,
)
from .merkle import (
    MerkleNode, build_merkle_tree, get_root_hash,
    incremental_update, generate_proof, verify_proof,
)
from .merkle_diff import diff_trees
from .resilience import (
    CircuitState, CircuitBreaker, TokenBudget,
    AdaptiveConcurrency, CompositeHealth,
)
from .blackboard import (
    Blackboard, BlackboardEntry, get_blackboard,
)
from .semantic_validator import (
    extract_signatures, check_cross_module_consistency,
    run_semantic_validation, FuncSig,
)
from .property_tester import (
    generate_property_tests, differential_execution,
)

__all__ = [
    "generate_sub_prompt", "build_api_messages",
    "call_api_with_retry",
    "parse_and_write_files",
    "execute_parallel_development",
    "file_sha256", "snapshot_tree_hashes", "detect_changed_by_hash",
    "collect_changed_files", "_is_excluded",
    "save_checkpoint", "load_checkpoint", "clear_checkpoint",
    "forge_timestamps",
    "validate_api_key", "validate_generated_files", "self_check",
    # CDC
    "chunk_boundaries", "chunk_file", "chunks_differ",
    # Merkle
    "MerkleNode", "build_merkle_tree", "get_root_hash",
    "incremental_update", "generate_proof", "verify_proof", "diff_trees",
    # Resilience
    "CircuitState", "CircuitBreaker", "TokenBudget",
    "AdaptiveConcurrency", "CompositeHealth",
    # Blackboard
    "Blackboard", "BlackboardEntry", "get_blackboard",
    # Semantic Validator
    "extract_signatures", "check_cross_module_consistency", "FuncSig",
    "generate_property_tests", "differential_execution",
    "run_semantic_validation",
]
