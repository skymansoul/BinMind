"""崩溃去重——基于 crash hash + stack trace 分组，保留信息最丰富样本"""
import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set, Tuple


@dataclass
class CrashInfo:
    signal: int
    stack_trace: List[int]  # 地址序列
    sanitizer_output: str = ""
    crash_hash: str = ""
    reproducer_path: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


def crash_hash(crash: CrashInfo) -> str:
    """SHA-256(前5栈帧 + 信号号) -> 16字符 hex"""
    _top = crash.stack_trace[:5] if crash.stack_trace else [0]
    _seed = json.dumps([_top, crash.signal], sort_keys=True).encode()
    return hashlib.sha256(_seed).hexdigest()[:16]


def deduplicate_crashes(crashes: List[CrashInfo]) -> List[CrashInfo]:
    """按 crash_hash 分组去重——每組保留 sanitizer 输出最丰富的"""
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


def categorize_crash(crash: CrashInfo) -> str:
    """崩溃分类：sanitizer 输出 + 信号组合判定"""
    _sig = crash.signal
    _out = crash.sanitizer_output.lower()

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

    if _sig == 11:
        return "NULL_DEREF" if _is_low_addr(crash) else "SEGFAULT"
    if _sig == 6:
        return "ASSERTION_FAIL"
    if _sig == 8:
        return "DIVIDE_BY_ZERO"
    if _sig == 4:
        return "SIGILL"

    return "UNKNOWN"


def _is_low_addr(crash: CrashInfo) -> bool:
    """检查 segfault 地址是否在低地址空间（NULL 解引用）"""
    if crash.stack_trace:
        _top = crash.stack_trace[0]
        return _top < 0x1000
    return False


def sanitizer_fingerprint(crash: CrashInfo) -> str:
    """从 sanitizer 输出提取指纹——首行错误描述 + 首个 #0 帧"""
    _fingerprint = ""
    _lines = crash.sanitizer_output.split("\n") if crash.sanitizer_output else []

    for _line in _lines:
        _line_stripped = _line.strip()
        if "error:" in _line_stripped.lower() or "overflow" in _line_stripped.lower():
            _fingerprint = _line_stripped
            break

    for _line in _lines:
        if _line.strip().startswith("#0"):
            _fingerprint += "|" + _line.strip()
            break

    return hashlib.sha256(_fingerprint.encode(errors="replace")).hexdigest()[:12]


def group_crashes_by_category(crashes: List[CrashInfo]) -> Dict[str, List[CrashInfo]]:
    """按类别分组，返回各类的崩溃列表"""
    _groups: Dict[str, List[CrashInfo]] = {}
    for _c in crashes:
        _cat = categorize_crash(_c)
        _groups.setdefault(_cat, []).append(_c)
    return _groups
