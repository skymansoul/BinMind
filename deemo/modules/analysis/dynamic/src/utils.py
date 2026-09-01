from __future__ import annotations

import collections
import hashlib
import logging
import math
import os
import struct
import sys
from typing import Any, Dict, List, Optional, Tuple


# 错误层级

class DynamicError(Exception):
    pass


class SandboxError(DynamicError):
    pass


class InstrumentationError(DynamicError):
    pass


class VMIAccessError(DynamicError):
    pass


class EmulationError(DynamicError):
    pass


class TraceError(DynamicError):
    pass


# 熵计算

def compute_entropy(data: bytes, base: int = 2) -> float:
    if not data:
        raise ValueError("Cannot compute entropy of empty data")

    if base <= 0:
        raise ValueError(f"Logarithm base must be positive, got {base}")

    freq = [0] * 256
    for byte in data:
        freq[byte] += 1

    n = len(data)
    entropy = 0.0
    for count in freq:
        if count:
            p = count / n
            entropy -= p * math.log(p)
    return entropy / math.log(base)


def compute_region_entropy(
    data: bytes, window_size: int = 256
) -> List[float]:
    if not data:
        return []
    entropies: List[float] = []
    for i in range(0, len(data), window_size):
        chunk = data[i : i + window_size]
        try:
            entropies.append(compute_entropy(chunk))
        except ValueError:
            entropies.append(0.0)
    return entropies


def find_high_entropy_regions(
    data: bytes, threshold: float = 7.0, window_size: int = 256
) -> List[Tuple[int, int, float]]:
    regions: List[Tuple[int, int, float]] = []
    for i in range(0, len(data), window_size):
        chunk = data[i : i + window_size]
        try:
            ent = compute_entropy(chunk)
            if ent >= threshold:
                regions.append((i, len(chunk), ent))
        except ValueError:
            pass
    return regions


# 日志配置

def setup_logging(
    level: str = "INFO",
    log_format: Optional[str] = None,
    log_file: Optional[str] = None,
    max_bytes: int = 10 * 1024 * 1024,
    backup_count: int = 3,
) -> logging.Logger:
    if log_format is None:
        log_format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

    root_logger = logging.getLogger("modules.analysis.dynamic")
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # 按 handler 类型去重：同一 logger 可能已被 pytest 捕获器或
    # 先前调用附加 handler，直接早退会跳过文件 handler 创建。
    has_console = any(
        isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler)
        for h in root_logger.handlers
    )
    has_file = any(
        getattr(h, "baseFilename", None) is not None
        and os.path.abspath(getattr(h, "baseFilename")) == os.path.abspath(log_file)
        for h in root_logger.handlers
    ) if log_file else False

    # 控制台处理器
    if not has_console:
        console = logging.StreamHandler(sys.stderr)
        console.setFormatter(logging.Formatter(log_format))
        root_logger.addHandler(console)

    # 文件处理器轮转
    if log_file and not has_file:
        try:
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            from logging.handlers import RotatingFileHandler
            file_handler: logging.Handler = RotatingFileHandler(
                log_file, maxBytes=max_bytes, backupCount=backup_count
            )
            file_handler.setFormatter(logging.Formatter(log_format))
            root_logger.addHandler(file_handler)
        except OSError as e:
            root_logger.warning("Failed to create log file %s: %s", log_file, e)

    return root_logger  # type: ignore[return-value]


# YAML 配置加载

def load_yaml_config(config_path: str) -> Dict[str, Any]:
    if not os.path.isfile(config_path):
        raise DynamicError(f"Config file not found: {config_path}")

    try:
        import yaml
        with open(config_path, "r") as f:
            return yaml.safe_load(f) or {}
    except ImportError:
        pass
    # 回退: 最小内联 YAML 解析器
    try:
        with open(config_path, "r") as f:
            content = f.read()
        return _parse_simple_yaml(content)
    except OSError as e:
        raise DynamicError(f"Failed to read config {config_path}: {e}") from e


def _parse_simple_yaml(content: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    lines = content.split("\n")
    stack: List[Dict[str, Any]] = [result]
    prev_indent = 0

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(line) - len(line.lstrip())
        colon_idx = stripped.find(":")

        if colon_idx == -1:
            continue

        key = stripped[:colon_idx].strip()
        value_str = stripped[colon_idx + 1:].strip()

        # 按缩进调整栈
        if indent < prev_indent:
            while len(stack) > 1 and indent <= prev_indent:
                stack.pop()
                prev_indent = indent if len(stack) == 1 else indent

        current = stack[-1]

        if not value_str:
            # 子字典
            sub_dict: Dict[str, Any] = {}
            current[key] = sub_dict
            stack.append(sub_dict)
        else:
            # 解析值
            if value_str.isdigit():
                current[key] = int(value_str)
            elif value_str.replace(".", "", 1).isdigit():
                current[key] = float(value_str)
            elif value_str.lower() in ("true", "false"):
                current[key] = value_str.lower() == "true"
            elif value_str.startswith('"') and value_str.endswith('"'):
                current[key] = value_str[1:-1]
            else:
                current[key] = value_str

        prev_indent = indent

    return result


# API 调用轨迹格式化

def format_api_trace(
    api_name: str,
    arguments: Optional[Dict[str, Any]] = None,
    return_value: Any = None,
    indent: int = 2,
) -> str:
    lines = [f"{api_name}("]

    if arguments:
        for arg_name, arg_value in arguments.items():
            if isinstance(arg_value, int) and arg_value > 0xFFFF:
                arg_str = f"0x{arg_value:X}"
            elif isinstance(arg_value, bytes):
                arg_str = arg_value.hex()[:32] + ("..." if len(arg_value) > 16 else "")
            else:
                arg_str = repr(arg_value)
            lines.append(f"{' ' * indent}{arg_name} = {arg_str}")

    lines.append(")")

    if return_value is not None:
        if isinstance(return_value, int) and return_value > 0xFFFF:
            ret_str = f"0x{return_value:X}"
        else:
            ret_str = repr(return_value)
        lines[-1] += f" -> {ret_str}"

    return "\n".join(lines)


def format_api_trace_compact(
    api_name: str,
    arguments: Optional[Dict[str, Any]] = None,
) -> str:
    parts = [f"{api_name}("]
    if arguments:
        arg_strs = []
        for name, val in arguments.items():
            if isinstance(val, int) and val > 0xFFFF:
                arg_strs.append(f"{name}=0x{val:X}")
            else:
                arg_strs.append(f"{name}={val!r}")
        parts.append(", ".join(arg_strs))
    parts.append(")")
    return "".join(parts)


# 其他工具函数

def hash_file(filepath: str, algorithm: str = "sha256") -> str:
    h = getattr(hashlib, algorithm, hashlib.sha256)()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
    except OSError as e:
        raise DynamicError(f"Failed to hash file {filepath}: {e}") from e
    return h.hexdigest()


def is_pe_file(data: bytes) -> bool:
    if len(data) < 64:
        return False
    if data[:2] != b"MZ":
        return False
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 4 > len(data):
        return False
    return data[pe_offset : pe_offset + 4] == b"PE\x00\x00"


def is_elf_file(data: bytes) -> bool:
    return len(data) >= 4 and data[:4] == b"\x7fELF"


