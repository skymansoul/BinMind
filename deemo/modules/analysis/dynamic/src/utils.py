# 2026-08-01
"""
Shared 工具集 for 动态分析 module

提供: entropy computation, 日志 setup, YAML 配置 loading
API trace formatting, error hierarchy
"""

from __future__ import annotations

import collections
import hashlib
import logging
import math
import os
import struct
import sys
from typing import Any, Dict, List, Optional, Tuple


# Error hierarchy

class DynamicError(Exception):
    """Base error for 动态分析 failures"""
    pass


class SandboxError(DynamicError):
    """Raised 沙箱 execution fails (crash, timeout, detection)"""
    pass


class InstrumentationError(DynamicError):
    """Raised 插桩 (Frida, PIN, etc.) fails"""
    pass


class VMIAccessError(DynamicError):
    """Raised VMI memory access fails (permissions, connection loss)"""
    pass


class EmulationError(DynamicError):
    """Raised 仿真 (Unicorn, QEMU) encounters an unrecoverable fault"""
    pass


class TraceError(DynamicError):
    """Raised trace collection or 解码 fails"""
    pass


# Entropy computation

def compute_entropy(data: bytes, base: int = 2) -> float:
    """计算 Shannon entropy a byte sequence
    
    Args:
    data: Input byte sequence
    base: Logarithm base (default 2, gives bits per byte)
    使用 math.e for nats, 10 for dits
    
    返回:
    Entropy value range [0, log2(256)] = [0, 8.0]
    Higher values indicate randomness
    
    Raises:
    ValueError: data empty or base <= 0
    """
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
    """计算 per-window entropy across a data region
    
    Useful for detecting packed/encrypted sections a binary
    
    Args:
    data: Input data
    window_size: Size analysis window bytes
    
    返回:
    List entropy values, one per window
    """
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
    """查找 regions entropy above a threshold
    
    返回:
    List (offset, size, entropy) tuples
    """
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


# 日志 setup

def setup_logging(
    level: str = "INFO",
    log_format: Optional[str] = None,
    log_file: Optional[str] = None,
    max_bytes: int = 10 * 1024 * 1024,
    backup_count: int = 3,
) -> logging.Logger:
    """Set up 日志 for 动态分析 module
    
    配置ures console (stderr) optional file 日志
    rotation. 使用 standard 日志 module for maximum 兼容性
    
    Args:
    level: 记录 level name ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
    log_format: Custom 格式化字符串. Defaults timestamp+level+message
    log_file: Path 记录 file. None, console 日志
    max_bytes: Maximum 记录 file size rotation
    备份_count: Number rotated 备份s keep
    
    返回:
    root 日志器 for dynamic module
    """
    if log_format is None:
        log_format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

    root_logger = logging.getLogger("modules.analysis.dynamic")
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Avoid duplicate 处理器s
    if root_logger.handlers:
        return root_logger  # type: ignore[return-value]

    # Console 处理器
    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(logging.Formatter(log_format))
    root_logger.addHandler(console)

    # File 处理器 rotation
    if log_file:
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


# YAML 配置 loading

def load_yaml_config(config_path: str) -> Dict[str, Any]:
    """加载 a YAML 配置 file
    
    Tries PyYAML first, falls back a minimal inline 解析器 for
    subset YAML actually 使用 (flat key-value mappings)
    
    Args:
    配置_path: Path YAML file
    
    返回:
    Parsed 配置 dictionary
    
    Raises:
    DynamicError: file cannot 读取 or parsed
    """
    if not os.path.isfile(config_path):
        raise DynamicError(f"Config file not found: {config_path}")

    try:
        import yaml
        with open(config_path, "r") as f:
            return yaml.safe_load(f) or {}
    except ImportError:
        pass
    # 回退: minimal inline YAML 解析器
    try:
        with open(config_path, "r") as f:
            content = f.read()
        return _parse_simple_yaml(content)
    except OSError as e:
        raise DynamicError(f"Failed to read config {config_path}: {e}") from e


def _parse_simple_yaml(content: str) -> Dict[str, Any]:
    """Minimal YAML 解析器 for simple key-value mappings
    
    处理 nested dictionaries indentation. 支持
    lists, multi-line strings, anchors, or tags
    """
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

        # Adjust 栈 基于 indentation
        if indent < prev_indent:
            while len(stack) > 1 and indent <= prev_indent:
                stack.pop()
                prev_indent = indent if len(stack) == 1 else indent

        current = stack[-1]

        if not value_str:
            # Sub-dictionary
            sub_dict: Dict[str, Any] = {}
            current[key] = sub_dict
            stack.append(sub_dict)
        else:
            # 解析 value
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


# API trace formatting

def format_api_trace(
    api_name: str,
    arguments: Optional[Dict[str, Any]] = None,
    return_value: Any = None,
    indent: int = 2,
) -> str:
    """格式化 an API调用 trace a human-readable string
    
    Produces 输出 like:
    VirtualAllocEx(
    hProcess = 0x1234
    lpAddress = 0x0
    dwSize = 4096
    ) -> 0x7FFA00000000
    
    Args:
    api_name: Name API function
    arguments: Dictionary argument names values
    return_value: 返回 value call
    indent: Number spaces for indentation
    
    返回:
    Multi-line formatted string
    """
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
    """Compact single-line API调用 trace
    
    Produces: VirtualAllocEx(hProcess=0x1234, lpAddress=0x0, dwSize=4096)
    """
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


# Misc 工具集

def hash_file(filepath: str, algorithm: str = "sha256") -> str:
    """计算 hash a file"""
    h = getattr(hashlib, algorithm, hashlib.sha256)()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
    except OSError as e:
        raise DynamicError(f"Failed to hash file {filepath}: {e}") from e
    return h.hexdigest()


def is_pe_file(data: bytes) -> bool:
    """检查 data looks like a PE (Portable 可执行文件) file"""
    if len(data) < 64:
        return False
    if data[:2] != b"MZ":
        return False
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 4 > len(data):
        return False
    return data[pe_offset : pe_offset + 4] == b"PE\x00\x00"


def is_elf_file(data: bytes) -> bool:
    """检查 data looks like an ELF文件"""
    return len(data) >= 4 and data[:4] == b"\x7fELF"


