# 约束序列化/反序列化: 持久化存储
# 转换约束的内存表示为持久格式: 规范化字符串, JSON字典, SQLite行元组
# 规范化重写SMT-LIB算子, 语义相同的约束共享相同缓存key

from __future__ import annotations

import hashlib
import logging
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# SMT-LIB operator -> canonical symbol lookup for normalization
# Mapping fixed; operators listed pass unchanged
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

# 快速分类签名: 匹配规范化形式的小写
# 首个匹配生效; 顺序敏感(bitvector先于integer检查, 因包含"+"等重叠token)
CATEGORY_SIGNATURES: List[Tuple[str, List[str]]] = [
    ("bitvector", ["bvadd", "bvmul", "bvand", "bvor", "bvxor", "bvshl", "concat", "extract"]),
    ("integer",   ["Int", "int", "+", "*", "mod"]),
    ("string",    ["str.", "Str", "concat", "substring"]),
    ("boolean",   ["and", "or", "not", "=>", "ite"]),
]


def normalize_constraint(constraint: str) -> str:
    # 规范化约束字符串: 折叠空白->小写->替换SMT-LIB算子->清理括号间距
    # 返回适合SHA256哈希的规范形式
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
    # 根据规范化形式的算子签名推断约束类别
    # 返回: bitvector/integer/string/boolean/unknown
    lower = normalized.lower()
    for cat, sigs in CATEGORY_SIGNATURES:
        if any(sig.lower() in lower for sig in sigs):
            return cat
    return "unknown"


def compute_constraint_hash_bytes(normalized: str) -> bytes:
    # 对规范化字符串的原始字节做SHA256摘要
    # 使用原始字节避免hex编解码开销, 分片索引直接取前两字节
    return hashlib.sha256(normalized.encode("utf-8")).digest()


def compute_constraint_hash(normalized: str) -> str:
    # SHA256摘要的hex字符串封装, 性能敏感路径优先用compute_constraint_hash_bytes
    return compute_constraint_hash_bytes(normalized).hex()


# Entry <-> dict转换 (JSON兼容)
# entry为duck-typed对象, 暴露cachedConstraint属性接口即可, 避免循环导入

def entry_to_dict(entry: Any) -> Dict[str, Any]:
    # 序列化缓存entry为JSON安全字典
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
    # 转换JSON导入的字典为CachedConstraint()的关键字参数
    # 缺失键使用合理默认值, 时间戳缺省为当前时间
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


# SQLite行转换
# 列顺序(constraint缓存表):
# constraint_hash, original_constraint, normalized_constraint
# solution, solver_name, solve_time_ms, timestamp, hit_count
# constraint_category, ttl_seconds

def entry_to_db_params(entry: Any) -> tuple:
    # 转换缓存entry为10元素参数元组, 用于SQLite插入
    # solution字符串化存储; None映射为SQLite NULL
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
    # 转换SQLite行元组为CachedConstraint()的关键字参数
    # 处理变量列数的前向兼容: 旧行可能缺少constraint_category(col 8)或ttl_seconds(col 9)
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
