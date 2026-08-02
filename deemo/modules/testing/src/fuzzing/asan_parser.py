# 2026-08-01
# Sanitizer output parser — ASan / UBSan / MSan / TSan
# 解析 sanitizer 输出到结构化格式 → 分类 → 去重
# 兼容 clang/gcc sanitizers (AddressSanitizer, UndefinedBehaviorSanitizer,
# MemorySanitizer, ThreadSanitizer)
import re
import os
import subprocess
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple


@dataclass
class SanitizerFinding:
    sanitizer_type: str  # ASAN | UBSAN | MSAN | TSAN
    error_type: str      # e.g. heap-buffer-overflow, signed-integer-overflow
    location: str = ""   # source file/line or module+offset
    address: str = ""    # hex address of error
    access_type: str = ""  # READ | WRITE
    stack_trace: List[str] = field(default_factory=list)
    allocation_trace: List[str] = field(default_factory=list)
    deallocation_trace: List[str] = field(default_factory=list)
    raw_output: str = ""
    reproducible: bool = False


# ================================================
# ASan parser
# ================================================

def parse_asan_output(output: str) -> Optional[SanitizerFinding]:
    """解析 AddressSanitizer 输出。"""
    _finding = SanitizerFinding(sanitizer_type="ASAN", raw_output=output)

    # 错误类型
    _type_map = {
        "heap-buffer-overflow": "HEAP_BUFFER_OVERFLOW",
        "stack-buffer-overflow": "STACK_BUFFER_OVERFLOW",
        "global-buffer-overflow": "GLOBAL_BUFFER_OVERFLOW",
        "heap-use-after-free": "USE_AFTER_FREE",
        "stack-use-after-return": "STACK_USE_AFTER_RETURN",
        "stack-use-after-scope": "STACK_USE_AFTER_SCOPE",
        "double-free": "DOUBLE_FREE",
        "alloc-dealloc-mismatch": "ALLOC_DEALLOC_MISMATCH",
        "memcpy-param-overlap": "MEMCPY_OVERLAP",
        "calloc-overflow": "CALLOC_OVERFLOW",
        "reallocarray-overflow": "REALLOCARRAY_OVERFLOW",
        "container-overflow": "CONTAINER_OVERFLOW",
    }

    for _key, _val in _type_map.items():
        if _key in output.lower():
            _finding.error_type = _val
            break
    else:
        _finding.error_type = "UNKNOWN"

    # 提取地址
    _addr_m = re.search(r'(0x[0-9a-fA-F]+)', output)
    if _addr_m:
        _finding.address = _addr_m.group(1)

    # 提取访问类型
    if "WRITE of size" in output or "WRITE of" in output:
        _finding.access_type = "WRITE"
    elif "READ of size" in output or "READ of" in output:
        _finding.access_type = "READ"

    # 提取 stack trace (#0, #1, ... 行)
    _finding.stack_trace = _extract_stack_trace(output)

    # 提取 allocation/deallocation traces
    _finding.allocation_trace = _extract_trace_section(output, "allocated by thread")
    _finding.deallocation_trace = _extract_trace_section(output, "freed by thread")

    # 提取 location
    if _finding.stack_trace:
        _finding.location = _finding.stack_trace[0]

    return _finding


# ================================================
# UBSan parser
# ================================================

def parse_ubsan_output(output: str) -> Optional[SanitizerFinding]:
    """解析 UndefinedBehaviorSanitizer 输出。"""
    _finding = SanitizerFinding(sanitizer_type="UBSAN", raw_output=output)

    _type_map = {
        "signed integer overflow": "SIGNED_INTEGER_OVERFLOW",
        "unsigned integer overflow": "UNSIGNED_INTEGER_OVERFLOW",
        "null pointer": "NULL_POINTER_DEREFERENCE",
        "load of misaligned address": "MISALIGNED_ACCESS",
        "division by zero": "DIVISION_BY_ZERO",
        "shift exponent": "INVALID_SHIFT",
        "float cast overflow": "FLOAT_CAST_OVERFLOW",
        "out-of-bounds": "OUT_OF_BOUNDS",
        "enum value outside range": "ENUM_RANGE_VIOLATION",
        "member call on null pointer": "NULL_POINTER_MEMBER_CALL",
        "null pointer passed": "NULL_POINTER_ARGUMENT",
        "implicit conversion": "IMPLICIT_CONVERSION",
        "type": "IMPLICIT_TYPE_CAST",
    }

    for _key, _val in _type_map.items():
        if _key in output.lower():
            _finding.error_type = _val
            break
    else:
        _finding.error_type = "UNDEFINED_BEHAVIOR"

    _finding.stack_trace = _extract_stack_trace(output)
    if _finding.stack_trace:
        _finding.location = _finding.stack_trace[0]

    return _finding


# ================================================
# MSan parser
# ================================================

def parse_msan_output(output: str) -> Optional[SanitizerFinding]:
    """解析 MemorySanitizer 输出（未初始化内存读取）。"""
    _finding = SanitizerFinding(sanitizer_type="MSAN", raw_output=output)

    if "use-of-uninitialized-value" in output or "Uninitialized" in output:
        _finding.error_type = "USE_OF_UNINITIALIZED_VALUE"
    else:
        _finding.error_type = "UNINITIALIZED_MEMORY"

    _finding.stack_trace = _extract_stack_trace(output)
    if _finding.stack_trace:
        _finding.location = _finding.stack_trace[0]

    return _finding


# ================================================
# TSan parser
# ================================================

def parse_tsan_output(output: str) -> Optional[SanitizerFinding]:
    """解析 ThreadSanitizer 输出（数据竞争）。"""
    _finding = SanitizerFinding(sanitizer_type="TSAN", raw_output=output)

    if "data race" in output.lower():
        _finding.error_type = "DATA_RACE"
    elif "deadlock" in output.lower():
        _finding.error_type = "DEADLOCK"
    elif "thread leak" in output.lower():
        _finding.error_type = "THREAD_LEAK"
    else:
        _finding.error_type = "CONCURRENCY_ERROR"

    _finding.stack_trace = _extract_stack_trace(output)
    if _finding.stack_trace:
        _finding.location = _finding.stack_trace[0]

    return _finding


# ================================================
# Helpers
# ================================================

def _extract_stack_trace(output: str) -> List[str]:
    """从 sanitizer 输出中提取 #0, #1, ... 帧。"""
    _frames = []
    for _line in output.split("\n"):
        _line_s = _line.strip()
        _m = re.match(r'#\d+\s+(0x[0-9a-fA-F]+)\s+.*in\s+(.+?)(?:\s+\(.+\))?$', _line_s)
        if _m:
            _frames.append(_line_s)
        elif re.match(r'#\d+\s+(0x[0-9a-fA-F]+)\s+\(', _line_s):
            _frames.append(_line_s)
    return _frames


def _extract_trace_section(output: str, marker: str) -> List[str]:
    """提取特定 section 的 stack trace（如 'allocated by'）。"""
    _lines = output.split("\n")
    _capture = False
    _frames = []
    for _line in _lines:
        if marker in _line.lower():
            _capture = True
            continue
        if _capture:
            _line_s = _line.strip()
            if _line_s.startswith("#"):
                _frames.append(_line_s)
            elif _frames and not _line_s.startswith("#"):
                break
    return _frames


# ================================================
# Reproducibility & categorization
# ================================================

def is_reproducible(crash_output: str, target_binary: str,
                    test_input: bytes, timeout: float = 5.0) -> bool:
    """重新运行目标验证 crash 可复现性。"""
    import tempfile
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".input") as _tf:
            _tf.write(test_input)
            _input_path = _tf.name

        _r = subprocess.run(
            [target_binary, _input_path],
            capture_output=True, timeout=timeout,
        )
        os.unlink(_input_path)

        return _r.returncode != 0 and _r.returncode != 1
    except (subprocess.TimeoutExpired, OSError):
        return False


def categorize_sanitizer_finding(finding: SanitizerFinding) -> str:
    """将 sanitizer finding 映射到漏洞类别。"""
    _map = {
        "HEAP_BUFFER_OVERFLOW": "buffer_overflow",
        "STACK_BUFFER_OVERFLOW": "buffer_overflow",
        "GLOBAL_BUFFER_OVERFLOW": "buffer_overflow",
        "USE_AFTER_FREE": "use_after_free",
        "DOUBLE_FREE": "double_free",
        "SIGNED_INTEGER_OVERFLOW": "integer_overflow",
        "UNSIGNED_INTEGER_OVERFLOW": "integer_overflow",
        "NULL_POINTER_DEREFERENCE": "null_deref",
        "USE_OF_UNINITIALIZED_VALUE": "uninitialized_memory",
        "DATA_RACE": "data_race",
        "DEADLOCK": "deadlock",
        "DIVISION_BY_ZERO": "division_by_zero",
        "MISALIGNED_ACCESS": "misaligned_access",
    }
    return _map.get(finding.error_type, "unknown")


def parse_any_sanitizer(output: str) -> Optional[SanitizerFinding]:
    """自动检测 sanitizer 类型并解析。"""
    _ol = output.lower()
    if "addresssanitizer" in _ol or "heap-buffer-overflow" in _ol or "stack-buffer-overflow" in _ol:
        return parse_asan_output(output)
    if "undefinedbehaviorsanitizer" in _ol or "runtime error:" in _ol:
        return parse_ubsan_output(output)
    if "memorysanitizer" in _ol or "use-of-uninitialized-value" in _ol:
        return parse_msan_output(output)
    if "threadsanitizer" in _ol or "data race" in _ol:
        return parse_tsan_output(output)
    return None
