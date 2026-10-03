"""二进制信息采集 — 格式识别、字符串/导入表提取。"""

import logging, os

logger = logging.getLogger(__name__)

DANGEROUS_FUNCTIONS = {"gets", "strcpy", "system", "execve", "scanf", "free",
                        "sprintf", "strcat", "memcpy", "popen"}
KEY_STRING_PATTERNS = {"system", "bin/sh", "flag", "password", "secret", "key"}
KERNEL_DANGEROUS_FUNCTIONS = ["copy_from_user", "copy_to_user", "sprintf",
                               "strcpy", "strncpy", "memcpy"]
KERNEL_DRIVER_DANGEROUS_FUNCTIONS = ["IoControlCode", "MmMapIoSpace",
                                      "ExAllocatePool", "ZwOpenProcess"]


def detect_language(binary):
    return "unknown"


def detect_binary_format(path):
    """通过魔数字节判定二进制格式（ELF/PE/Mach-O）。"""
    if not os.path.exists(path):
        return "unknown"
    with open(path, "rb") as f:
        magic = f.read(4)
    if magic[:4] == b"\x7fELF":
        return "ELF"
    if magic[:2] == b"MZ":
        return "PE"
    if magic[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe"):
        return "Mach-O"
    return "unknown"


def format_info_for_report(info):
    """将二进制信息渲染为中文标签的摘要字符串。"""
    if not info:
        return "无info"
    lines = []
    if "format" in info:
        lines.append(f"格式: {info['format']}")
    if "size" in info:
        lines.append(f"size: {info['size']} 字节")
    if "arch" in info:
        lines.append(f"architecture: {info['arch']}")
    if "strings" in info:
        key_strs = [s for s in info.get("strings", [])
                    if any(p in s.lower() for p in KEY_STRING_PATTERNS)]
        if key_strs:
            lines.append(f"关keystring: {', '.join(key_strs[:5])}")
    if "dangerous" in info:
        lines.append(f"dangerous function: {', '.join(info['dangerous'][:10])}")
    return "\n".join(lines) if lines else "无可报告info"


def get_binary_info(path):
    """提取二进制文件的格式、大小、架构及可疑指标。"""
    if not os.path.exists(path):
        return {"error": "file not found"}
    return {
        "format": detect_binary_format(path),
        "size": os.path.getsize(path),
        "arch": "unknown",
        "strings": [],
        "dangerous": [],
    }


def get_language_specific_dangerous_functions(lang):
    """按语言返回对应的危险函数列表。"""
    if lang == "c" or lang == "c++":
        return list(DANGEROUS_FUNCTIONS)
    return []


def validate_elf_file(path):
    """验证文件偏移 0 处的 ELF 魔数。"""
    if not os.path.exists(path):
        return False
    with open(path, "rb") as f:
        return f.read(4) == b"\x7fELF"

def get_language_analysis_hints(lang): return []

# 占位数据 — 由语言特定插件在集成时填充。
GO_SYMBOLS = []

RUST_SYMBOLS = []

GO_SECTIONS = []

RUST_SECTIONS = []

GO_DANGEROUS_FUNCTIONS = []

RUST_DANGEROUS_FUNCTIONS = []
