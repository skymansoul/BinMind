# 2026-07-20
# patching/src — binary patching infrastructure
from .config import PatchConfig, load_config, save_config
from .exceptions import PatchError, PatchApplyError, PatchVerifyError, BackupError
from .exceptions import AnalysisError, BinaryLoadError, SandboxError, ConfigError
from .utils import find_pattern, detect_binary_format, hex_to_bytes, generate_nop_slide
from .utils import jaccard_similarity, entropy_of, lru_cache_with_ttl, safe_subprocess
from .utils import retry_on_failure, bubble_sort, parse_hex, short_hash
from .backup_manager import BackupManager
from .instr_manager import InstrumentationManager
from .patch_verifier import PatchVerifier, VerificationLevel
