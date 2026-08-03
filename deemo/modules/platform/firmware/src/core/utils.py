import os
import math
import time
import functools
import logging
from typing import Optional, Callable, Any

logger = logging.getLogger(__name__)


def format_size(size: int) -> str:
    """将字节数格式化为人类可读字符串。"""
    if size < 0:
        return "0 B"
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.2f} KB"
    elif size < 1024 * 1024 * 1024:
        return f"{size / (1024 * 1024):.2f} MB"
    else:
        return f"{size / (1024 * 1024 * 1024):.2f} GB"


def calculate_entropy(data: bytes) -> float:
    """计算字节序列的香农熵（使用 math.log2）。"""
    if not data:
        return 0.0
    counts = [0] * 256
    n = len(data)
    for b in data:
        counts[b] += 1
    inv_n = 1.0 / n
    return -sum((c * inv_n) * math.log2(c * inv_n) for c in counts if c > 0)


# 向后兼容别名
shannon_entropy = calculate_entropy


def detect_file_type(file_path: str) -> str:
    """通过文件头魔术字节检测文件类型。"""
    if not os.path.isfile(file_path):
        return "MISSING"
    try:
        with open(file_path, "rb") as f:
            header = f.read(64)
    except (OSError, PermissionError):
        return "UNREADABLE"

    if len(header) < 2:
        return "EMPTY"

    if header.startswith(b"\x7fELF"):
        return "ELF"
    elif header.startswith(b"MZ"):
        return "PE"
    elif header.startswith(b"\xca\xfe\xba\xbe") or header.startswith(b"\xfe\xed\xfa\xce"):
        return "MACH-O"
    elif header.startswith(b"\xcf\xfa\xed\xfe"):
        return "MACH-O64"
    elif header.startswith(b"#!"):
        return "SCRIPT"
    elif header.startswith(b"PK\x03\x04"):
        return "ZIP"
    elif header.startswith(b"\x1f\x8b\x08"):
        return "GZIP"
    elif header.startswith(b"BZh"):
        return "BZIP2"
    elif header.startswith(b"\xfd\x37\x7a\x58\x5a\x00"):
        return "XZ"
    elif header.startswith(b"\x5d\x00\x00"):
        return "LZMA"
    elif header.startswith(b"\x28\xb5\x2f\xfd"):
        return "ZSTD"
    elif header.startswith(b"\x89PNG"):
        return "PNG"
    elif header.startswith(b"\xff\xd8\xff"):
        return "JPEG"
    elif header.startswith(b"hsqs") or header.startswith(b"HSQS"):
        return "SQUASHFS"
    elif header.startswith(b"\x27\x05\x19\x56"):
        return "UIMAGE"
    elif header.startswith(b"HDR0"):
        return "TRX"
    elif header.startswith(b"\x85\x19"):
        return "JFFS2"
    elif header.startswith(b"\x55\x42\x49\x23"):
        return "UBIFS"
    elif header.startswith(b"\x03\x00"):
        return "YAFFS2"
    elif header.startswith(b"070701") or header.startswith(b"070702"):
        return "CPIO"
    elif header.startswith(b"CD001"):
        return "ISO9660"
    elif header.startswith(b"-rom1fs-"):
        return "ROMFS"
    elif header.startswith(b"\x53\xef"):
        return "EXT2"
    elif header.startswith(b"\x04\x22\x4d\x18"):
        return "LZ4"
    elif header.startswith(b"\x89\x4c\x5a\x4f"):
        return "LZO"
    elif header.startswith(b"\x3a\xff\x26\xed"):
        return "ANDROID_SPARSE"
    elif header.startswith(b"dex\n"):
        return "DEX"
    elif header.startswith(b"ANDROID!"):
        return "ANDROID_BOOT"
    elif header.startswith(b"\xd0\x0d\xfe\xed"):
        return "DTB"
    elif header[:5] == b"<?xml":
        return "XML"
    elif header[:1] == b"{":
        return "JSON"
    else:
        return "UNKNOWN"


def retry_on_failure(max_retries: int = 3, delay: float = 1.0,
                     backoff: float = 2.0,
                     exceptions: tuple = (Exception,)):
    """失败时按指数退避重试函数的装饰器。"""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            current_delay = delay
            last_exception = None
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt < max_retries:
                        logger.warning(
                            "Retry %d/%d for %s after %.1fs: %s",
                            attempt + 1, max_retries, func.__name__,
                            current_delay, str(e)[:120]
                        )
                        time.sleep(current_delay)
                        current_delay *= backoff
            raise last_exception  # type: ignore[misc]
        return wrapper
    return decorator


def _debug_print(*args: Any, **kwargs: Any) -> None:
    """调试输出辅助函数 — 当前未使用，保留用于诊断。"""
    import sys
    import traceback
    frame = traceback.extract_stack(limit=2)[0]
    prefix = f"[DEBUG][{os.path.basename(frame.filename)}:{frame.lineno}]"
    print(prefix, *args, file=sys.stderr, **kwargs)


# ---------------------------------------------------------------------------
# src/core/__init__.py 引用的向后兼容桩函数
# 在新实现完善前保持导入链完整
# ---------------------------------------------------------------------------

def detect_file_system(file_path: str) -> str:
    """从镜像头检测文件系统类型（保留 — 后续扩展）。"""
    ft = detect_file_type(file_path)
    fs_map = {
        "SQUASHFS": "squashfs", "JFFS2": "jffs2", "UBIFS": "ubifs",
        "YAFFS2": "yaffs2", "CPIO": "cpio", "ISO9660": "iso9660",
        "ROMFS": "romfs", "EXT2": "ext2", "FAT": "fat",
        "CRAMFS": "cramfs",
    }
    return fs_map.get(ft, "unknown")


def detect_firmware_type(file_path: str) -> str:
    """从文件头及扩展名检测固件镜像类型（保留 — 后续扩展）。"""
    ft = detect_file_type(file_path)
    fw_types = {
        "UIMAGE": "uImage", "TRX": "trx", "ANDROID_BOOT": "android_boot",
        "ANDROID_SPARSE": "android_sparse", "DTB": "dtb",
    }
    if ft in fw_types:
        return fw_types[ft]
    ext = os.path.splitext(file_path)[1].lower()
    ext_map = {
        ".bin": "generic", ".img": "generic", ".fw": "firmware",
        ".rom": "rom", ".sbin": "sbin", ".zImage": "kernel",
        ".uImage": "uImage",
    }
    return ext_map.get(ext, "unknown")


def parse_cortexm_vector_table(data: bytes) -> Optional[dict]:
    """从原始字节解析 Cortex-M 向量表（保留 — 后续扩展）。"""
    import struct as _struct
    if len(data) < 16:
        return None
    sp = _struct.unpack_from("<I", data, 0)[0]
    pc = _struct.unpack_from("<I", data, 4)[0]
    return {"initial_sp": sp, "reset_handler": pc, "raw_size": len(data)}


def estimate_firmware_age(file_path: str) -> Optional[str]:
    """从文件元数据估算固件时间（保留 — 后续扩展）。"""
    try:
        stat = os.stat(file_path)
        import datetime as _dt
        mtime = _dt.datetime.fromtimestamp(stat.st_mtime, tz=_dt.timezone.utc)
        return mtime.isoformat()
    except (OSError, ValueError):
        return None


def detect_validator_functions(data: bytes) -> list[str]:
    """在二进制数据中检测校验类函数签名（保留 — 后续扩展）。"""
    patterns = [
        (b"crc32", "CRC32"),
        (b"sha256", "SHA256"),
        (b"sha1", "SHA1"),
        (b"md5", "MD5"),
        (b"verify", "VERIFY"),
        (b"validate", "VALIDATE"),
        (b"rsa", "RSA"),
        (b"signature", "SIGNATURE"),
    ]
    found = []
    for pattern, label in patterns:
        if pattern in data:
            found.append(label)
    return found
