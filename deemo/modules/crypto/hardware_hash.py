# 硬件加速哈希 — 委托至 src 实现
from .src.hardware_hash import (
    HashAlgorithm, HashResult, HashConfig, FastHasher, HashManager,
    get_hash_manager, compute_file_hash, compute_data_hash,
    compute_fast_hash, verify_file_integrity,
)
