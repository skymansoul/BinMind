"""动态分析模块共享工具集。

提供: 熵计算, 日志配置, YAML 配置加载,
API 调用轨迹格式化, 错误层级。
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


# 错误层级

class DynamicError(Exception):
    """动态分析失败的基础错误"""
    pass


class SandboxError(DynamicError):
    """沙箱执行失败时抛出（崩溃、超时、检测）。"""
    pass


class InstrumentationError(DynamicError):
    """插桩 (Frida, PIN 等) 失败时抛出"""
    pass


class VMIAccessError(DynamicError):
    """VMI 内存访问失败时抛出（权限不足、连接中断）"""
    pass


class EmulationError(DynamicError):
    """仿真 (Unicorn, QEMU) 遇到不可恢复故障时抛出"""
    pass


class TraceError(DynamicError):
    """轨迹收集或解码失败时抛出"""
    pass


# 熵计算

def compute_entropy(data: bytes, base: int = 2) -> float:
    """计算字节序列的 Shannon 熵。

    data 输入字节序列, base 对数底 (默认 2, 每字节比特数);
    使用 math.e 为 nat, 10 为 dit。返回熵值, 范围
    [0, log2(256)] = [0, 8.0], 越高越随机。
    data 为空或 base <= 0 时抛 ValueError。
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
    """计算数据区域的分窗口熵。

    用于检测二进制中的加壳/加密段。data 输入数据,
    window_size 分析窗口字节数; 返回每个窗口的熵值列表。
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
    """查找熵高于阈值的区域, 返回 (offset, size, entropy) 元组列表。"""
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
    """配置动态分析模块的日志。

    配置控制台 (stderr) 和可选的文件日志轮转, 使用标准
    logging 模块以最大化兼容性。

    参数: level 日志级别名 ("DEBUG", "INFO", "WARNING",
    "ERROR", "CRITICAL"), log_format 自定义格式字符串, 默认
    timestamp+level+message, log_file 日志文件路径, None 则仅
    控制台, max_bytes 单文件最大字节数 (触发轮转),
    backup_count 保留的轮转备份数;
    返回 dynamic 模块的根日志器。
    """
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
    """加载 YAML 配置文件。

    先尝试 PyYAML, 失败后回退到最小内联解析器, 只覆盖实际
    用到的 YAML 子集 (扁平 key-value 映射)。

    参数: config_path YAML 文件路径; 返回解析后的配置字典。
    文件无法读取或解析失败时抛 DynamicError。
    """
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
    """简单 key-value 映射的最小 YAML 解析器。

    按缩进处理嵌套字典。不支持 lists, multi-line strings,
    anchors 或 tags。
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
    """将 API 调用轨迹格式化为人类可读字符串。

    输出形如:
    VirtualAllocEx(
    hProcess = 0x1234
    lpAddress = 0x0
    dwSize = 4096
    ) -> 0x7FFA00000000

    参数: api_name API 函数名, arguments 参数名到值的字典,
    return_value 调用的返回值, indent 缩进空格数;
    返回多行格式化字符串。
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
    """紧凑单行 API 调用轨迹。

    输出: VirtualAllocEx(hProcess=0x1234, lpAddress=0x0, dwSize=4096)
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


# 其他工具函数

def hash_file(filepath: str, algorithm: str = "sha256") -> str:
    """计算文件哈希。"""
    h = getattr(hashlib, algorithm, hashlib.sha256)()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
    except OSError as e:
        raise DynamicError(f"Failed to hash file {filepath}: {e}") from e
    return h.hexdigest()


def is_pe_file(data: bytes) -> bool:
    """检查 data 是否像 PE (Portable Executable) 文件。"""
    if len(data) < 64:
        return False
    if data[:2] != b"MZ":
        return False
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 4 > len(data):
        return False
    return data[pe_offset : pe_offset + 4] == b"PE\x00\x00"


def is_elf_file(data: bytes) -> bool:
    """检查 data 是否像 ELF 文件。"""
    return len(data) >= 4 and data[:4] == b"\x7fELF"


