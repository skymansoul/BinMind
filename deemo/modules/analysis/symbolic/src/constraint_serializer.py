"""Constraint 序列化 反序列化 for persistent storage

转换 constraints -memory representations persistent
格式化: canonical normalized strings, JSON-safe dictionaries, SQLite
row tuples. Normalization rewrites SMT-LIB operators semantically
identical constraints share same 缓存key

Usage:
analysis.symbolic.src.constraint_serializer import (
normalize_constraint, compute_constraint_hash_bytes
entry_to_dict, entry_to_db_params, db_row_to_init_kwargs
)
"""

from __future__ import annotations

import hashlib
import logging
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SMT-LIB operator -> canonical symbol lookup for normalization
# Mapping fixed; operators listed pass unchanged
# ---------------------------------------------------------------------------
NORMALIZE_PATTERNS: List[Tuple[str, str]] = [
    ("bvadd", "+"),
    ("bvmul", "*"),
    ("bvsub", "-"),
    ("bvsdiv", "/"),
    ("bvand", "&"),
    ("bvor", "|"),
    ("bvxor", "^"),
    ("bvshl", "<<"),
    ("bvlshr", ">>"),
    ("bvult", "<"),
    ("bvule", "<="),
    ("bvugt", ">"),
    ("bvuge", ">="),
]

# Fast category 签名s: matched against lowercased canonical form
# First match wins; order matters (bitvector checked integer because
# 包含 overlapping tokens like "+")
CATEGORY_SIGNATURES: List[Tuple[str, List[str]]] = [
    ("bitvector", ["bvadd", "bvmul", "bvand", "bvor", "bvxor", "bvshl", "concat", "extract"]),
    ("integer",   ["Int", "int", "+", "*", "mod"]),
    ("string",    ["str.", "Str", "concat", "substring"]),
    ("boolean",   ["and", "or", "not", "=>", "ite"]),
]


def normalize_constraint(constraint: str) -> str:
    """Canonicalize a constraint string for consistent 哈希
    
    流水线: collapse whitespace -> lowercase -> 标准化 SMT-LIB
    operators -> clean parenthesis spacing. 返回 canonical form
    suitable for SHA256 哈希
    """
    normalized = " ".join(constraint.split())
    normalized = normalized.lower()

    for old, new in NORMALIZE_PATTERNS:
        normalized = normalized.replace(f"({old} ", f"({new} ")

    # Collapse residual double spaces multi-step replacements
    while "  " in normalized:
        normalized = normalized.replace("  ", " ")
    normalized = normalized.replace("( ", "(")
    normalized = normalized.replace(" )", ")")

    return normalized


def classify_constraint_category(normalized: str) -> str:
    """Infer constraint category operator 签名s canonical form
    
    返回 one: 'bitvector', 'integer', 'string', 'boolean', 'unknown'
    Used for statistics grouping eviction policy decisions
    """
    lower = normalized.lower()
    for cat, sigs in CATEGORY_SIGNATURES:
        if any(sig.lower() in lower for sig in sigs):
            return cat
    return "unknown"


def compute_constraint_hash_bytes(normalized: str) -> bytes:
    """SHA256 digest *normalized* raw bytes
    
    Raw bytes avoid hex-编码/解码 overhead hot paths shard
    indexing 使用 first two bytes directly
    """
    return hashlib.sha256(normalized.encode("utf-8")).digest()


def compute_constraint_hash(normalized: str) -> str:
    """SHA256 digest *normalized* hex string
    
    Convenience 封装; prefer:func:`compute_constraint_hash_bytes`
    性能-sensitive paths
    """
    return compute_constraint_hash_bytes(normalized).hex()


# ---------------------------------------------------------------------------
# Entry <-> dict conversion (JSON-compatible)
# *entry* duck-typed: object exposing the缓存dConstraint attribute
# interface works. avoids a circular import main module
# ---------------------------------------------------------------------------

def entry_to_dict(entry: Any) -> Dict[str, Any]:
    """序列化 a 缓存entry a JSON-safe dictionary
    
    *entry* expose: constraint_hash, original_constraint
    normalized_constraint, solution, solver_name, solve_time_ms, timestamp
    hit_count, constraint_category, ttl_seconds
    """
    return {
        "constraint_hash": entry.constraint_hash,
        "original_constraint": entry.original_constraint,
        "normalized_constraint": entry.normalized_constraint,
        "solution": str(entry.solution) if entry.solution is not None else None,
        "solver_name": entry.solver_name,
        "solve_time_ms": entry.solve_time_ms,
        "timestamp": entry.timestamp,
        "hit_count": entry.hit_count,
        "constraint_category": entry.constraint_category,
        "ttl_seconds": entry.ttl_seconds,
    }


def json_item_to_init_kwargs(item: Dict[str, Any]) -> Dict[str, Any]:
    """转换 a JSON-imported dict keyword arguments for缓存dConstraint()
    
    Missing keys 接收 sensible defaults. Timestamp defaults current
    time absent JSON payload
    """
    return {
        "constraint_hash": item.get("constraint_hash", ""),
        "original_constraint": item.get("original_constraint", ""),
        "normalized_constraint": item.get("normalized_constraint", ""),
        "solution": item.get("solution"),
        "solver_name": item.get("solver_name", "unknown"),
        "solve_time_ms": item.get("solve_time_ms", 0.0),
        "timestamp": item.get("timestamp", time.time()),
        "hit_count": item.get("hit_count", 0),
        "constraint_category": item.get("constraint_category", ""),
        "ttl_seconds": item.get("ttl_seconds", 0.0),
    }


# ---------------------------------------------------------------------------
# SQLite row conversion
# Column order (constraint_缓存table):
# constraint_hash, original_constraint, normalized_constraint
# solution, solver_name, solve_time_ms, timestamp, hit_count
#   constraint_category, ttl_seconds
# ---------------------------------------------------------------------------

def entry_to_db_params(entry: Any) -> tuple:
    """转换 a 缓存entry a 10-element parameter tuple for SQLite 插入
    
    Stringifies *solution* for storage; None maps NULL SQLite
    *entry* expose same attributes as缓存dConstraint
    """
    return (
        entry.constraint_hash,
        entry.original_constraint,
        entry.normalized_constraint,
        str(entry.solution) if entry.solution is not None else None,
        entry.solver_name,
        entry.solve_time_ms,
        entry.timestamp,
        entry.hit_count,
        entry.constraint_category,
        entry.ttl_seconds,
    )


def db_row_to_init_kwargs(row: tuple) -> Dict[str, Any]:
    """转换 a SQLite row tuple keyword arguments for缓存dConstraint()
    
    处理 variable column counts for forward 兼容性 -- older rows
    lack ``constraint_category`` (col 8) or ``ttl_seconds`` (col 9)
    """
    return {
        "constraint_hash": row[0],
        "original_constraint": row[1],
        "normalized_constraint": row[2],
        "solution": row[3],
        "solver_name": row[4],
        "solve_time_ms": row[5],
        "timestamp": row[6],
        "hit_count": row[7],
        "constraint_category": row[8] if len(row) > 8 else "",
        "ttl_seconds": row[9] if len(row) > 9 else 0.0,
    }


__all__ = [
    "NORMALIZE_PATTERNS",
    "CATEGORY_SIGNATURES",
    "normalize_constraint",
    "classify_constraint_category",
    "compute_constraint_hash_bytes",
    "compute_constraint_hash",
    "entry_to_dict",
    "json_item_to_init_kwargs",
    "entry_to_db_params",
    "db_row_to_init_kwargs",
]
