# 2026-07-26
# Crash deduplication — 基于 crash hash + stack trace 去重
# 策略：SHA-256(top-5 stack frames + signal) 为 crash hash，
# 同 hash 组内保留信息最丰富的文件（ASan > UBSan > raw crash）。
# 分类：解析 ASan/UBSan/TSan 输出特征码。
import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set, Tuple


@dataclass
class CrashInfo:
    signal: int
    stack_trace: List[int]  # addresses
    sanitizer_output: str = ""
    crash_hash: str = ""
    reproducer_path: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


# ================================================
def crash_hash(crash: CrashInfo) -> str:
    """SHA-256 (top 5 frames + signal)。"""
    _top = crash.stack_trace[:5] if crash.stack_trace else [0]
    _seed = json.dumps([_top, crash.signal], sort_keys=True).encode()
    return hashlib.sha256(_seed).hexdigest()[:16]


# ================================================
def deduplicate_crashes(crashes: List[CrashInfo]) -> List[CrashInfo]:
    """按 crash_hash 分组去重。每组保留 sanitizer 输出最丰富的。
    优先级：ASan > UBSan > MSan > raw stack trace。
    """
    _groups: Dict[str, List[CrashInfo]] = {}
    for _c in crashes:
        if not _c.crash_hash:
            _c.crash_hash = crash_hash(_c)
        _groups.setdefault(_c.crash_hash, []).append(_c)

    _deduped = []
    _score_map = {"asan": 5, "ubsan": 4, "msan": 3, "tsan": 2, "raw": 1}

    for _hash, _group in _groups.items():
        _best = _group[0]
        _best_score = _score_map.get(_get_sanitizer_type(_best), 0)
        for _c in _group[1:]:
            _score = _score_map.get(_get_sanitizer_type(_c), 0)
            if _score > _best_score:
                _best = _c
                _best_score = _score
            elif _score == _best_score and len(_c.sanitizer_output) > len(_best.sanitizer_output):
                _best = _c
        _deduped.append(_best)

    return _deduped


def _get_sanitizer_type(crash: CrashInfo) -> str:
    _o = crash.sanitizer_output.lower()
    if "addresssanitizer" in _o or "heap-buffer-overflow" in _o or "stack-buffer-overflow" in _o:
        return "asan"
    if "undefinedbehaviorsanitizer" in _o or "runtime error:" in _o:
        return "ubsan"
    if "memorysanitizer" in _o:
        return "msan"
    if "threadsanitizer" in _o or "data race" in _o:
        return "tsan"
    return "raw"


# ================================================
def categorize_crash(crash: CrashInfo) -> str:
    """将 crash 分类为已知类别。

    Returns one of: NULL_DEREF, USE_AFTER_FREE, HEAP_BUFFER_OVERFLOW,
    STACK_BUFFER_OVERFLOW, GLOBAL_BUFFER_OVERFLOW, INTEGER_OVERFLOW,
    DIVIDE_BY_ZERO, SEGFAULT, ASSERTION_FAIL, DOUBLE_FREE, UNKNOWN
    """
    _sig = crash.signal
    _out = crash.sanitizer_output.lower()

    # Sanitizer 输出分类
    if "heap-buffer-overflow" in _out:
        return "HEAP_BUFFER_OVERFLOW"
    if "stack-buffer-overflow" in _out:
        return "STACK_BUFFER_OVERFLOW"
    if "global-buffer-overflow" in _out:
        return "GLOBAL_BUFFER_OVERFLOW"
    if "heap-use-after-free" in _out:
        return "USE_AFTER_FREE"
    if "double-free" in _out:
        return "DOUBLE_FREE"
    if "signed integer overflow" in _out or "integer overflow" in _out:
        return "INTEGER_OVERFLOW"
    if "division by zero" in _out:
        return "DIVIDE_BY_ZERO"
    if "null pointer" in _out or "null-ptr" in _out:
        return "NULL_DEREF"
    if "memory leak" in _out:
        return "MEMORY_LEAK"

    # 信号分类
    if _sig == 11:  # SIGSEGV
        return "NULL_DEREF" if _is_low_addr(crash) else "SEGFAULT"
    if _sig == 6:   # SIGABRT
        return "ASSERTION_FAIL"
    if _sig == 8:   # SIGFPE
        return "DIVIDE_BY_ZERO"
    if _sig == 4:   # SIGILL
        return "SIGILL"

    return "UNKNOWN"


def _is_low_addr(crash: CrashInfo) -> bool:
    """检查 segfault 地址是否在低地址空间 (NULL pointer)"""
    if crash.stack_trace:
        _top = crash.stack_trace[0]
        return _top < 0x1000
    return False


# ================================================
def sanitizer_fingerprint(crash: CrashInfo) -> str:
    """从 ASan/UBSan 输出提取指纹（用于更精确的去重）。
    提取第一行错误描述 + 第一个有意义的 frame。
    """
    _fingerprint = ""
    _lines = crash.sanitizer_output.split("\n") if crash.sanitizer_output else []

    for _line in _lines:
        _line_stripped = _line.strip()
        # 匹配 ASan 错误行
        if "error:" in _line_stripped.lower() or "overflow" in _line_stripped.lower():
            _fingerprint = _line_stripped
            break

    # 取第一个 #0 frame
    for _line in _lines:
        if _line.strip().startswith("#0"):
            _fingerprint += "|" + _line.strip()
            break

    return hashlib.sha256(_fingerprint.encode(errors="replace")).hexdigest()[:12]


# ================================================
def group_crashes_by_category(crashes: List[CrashInfo]) -> Dict[str, List[CrashInfo]]:
    """按类别分组，返回各类别的 crash 列表。"""
    _groups: Dict[str, List[CrashInfo]] = {}
    for _c in crashes:
        _cat = categorize_crash(_c)
        _groups.setdefault(_cat, []).append(_c)
    return _groups
