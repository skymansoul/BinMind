"""文件格式魔数字节数据库与检测"""
# 覆盖常见可执行格式 (PE/ELF/Mach-O)、压缩格式、固件镜像、文档格式、多媒体。
# ReCopilot] 调用图分析的前置步骤需要识别二进制格式（PE vs ELF
# 影响导入表解析路径）—— 此处提供无外部依赖的轻量格式检测。
from typing import Optional, List, Tuple
import os


# 魔数定义: (offset, magic_bytes, label, category)

_MAGIC_DB: List[Tuple[int, bytes, str, str]] = [
# 可执行文件
    (0, b'MZ', "PE (Windows 可执行/DLL)", "executable"),
    (0, b'\x7FELF', "ELF (Linux 可执行/共享库)", "executable"),
    (0, b'\xFE\xED\xFA\xCE', "Mach-O 32-bit", "executable"),
    (0, b'\xFE\xED\xFA\xCF', "Mach-O 64-bit", "executable"),
    (0, b'\xCE\xFA\xED\xFE', "Mach-O 32-bit (reverse)", "executable"),
    (0, b'\xCF\xFA\xED\xFE', "Mach-O 64-bit (reverse)", "executable"),
    (0, b'\xCA\xFE\xBA\xBE', "Mach-O Universal Binary", "executable"),
    (0, b'\x00asm', "WebAssembly (WASM)", "executable"),
# 脚本
    (0, b'#!/', "Shebang 脚本", "script"),
# 压缩/归档
    (0, b'\x1F\x8B', "GZIP 压缩", "compressed"),
    (0, b'PK\x03\x04', "ZIP 归档", "archive"),
    (0, b'BZh', "BZip2 压缩", "compressed"),
    (0, b'\xFD7zXZ\x00', "XZ/LZMA 压缩", "compressed"),
    (0, b'Rar!\x1A\x07', "RAR 归档", "archive"),
    (0, b'7z\xBC\xAF\x27\x1C', "7-Zip 归档", "archive"),
    (0, b'\x89LZO\x00\x0D\x0A\x1A\x0A', "LZO 压缩", "compressed"),
# 固件/磁盘镜像
    (0, b'\xD0\x0D\xFE\xED', "U-Boot 固件镜像", "firmware"),
    (0, b'\x27\x05\x19\x56', "U-Boot (旧版)", "firmware"),
    (0, b'AVB0', "Android Verified Boot", "firmware"),
# 文档
    (0, b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1', "OLE2 (MS Office 97-2003)", "document"),
    (0, b'PK\x03\x04', "Office Open XML (docx/xlsx/pptx)", "document"),
    (0, b'%PDF', "PDF 文档", "document"),
# 多媒体
    (0, b'\xFF\xD8\xFF', "JPEG 图像", "image"),
    (0, b'\x89PNG\x0D\x0A\x1A\x0A', "PNG 图像", "image"),
    (0, b'GIF87a', "GIF 图像 (1987)", "image"),
    (0, b'GIF89a', "GIF 图像 (1989)", "image"),
    (0, b'RIFF', "RIFF 容器 (AVI/WAV/...)", "multimedia"),
    (0, b'\x1A\x45\xDF\xA3', "Matroska/WebM", "multimedia"),
# 数据库
    (0, b'SQLite format 3\x00', "SQLite 3 数据库", "database"),
# 密钥/证书
    (0, b'-----BEGIN ', "PEM 证书/密钥", "crypto"),
    (0, b'\x30\x82', "DER 证书 (X.509)", "crypto"),
]

# 扩展名映射表（优先于魔数判断的快速路径）
_EXT_MAP = {
    ".exe": ("PE (Windows 可执行/DLL)", "executable"),
    ".dll": ("PE (Windows 可执行/DLL)", "executable"),
    ".sys": ("PE (Windows 驱动)", "executable"),
    ".so": ("ELF (Linux 共享库)", "executable"),
    ".elf": ("ELF (Linux 可执行/共享库)", "executable"),
    ".o": ("ELF 目标文件", "executable"),
    ".dylib": ("Mach-O 64-bit", "executable"),
    ".wasm": ("WebAssembly (WASM)", "executable"),
    ".pyc": ("Python 字节码", "executable"),
    ".class": ("Java 类文件", "executable"),
    ".gz": ("GZIP 压缩", "compressed"),
    ".zip": ("ZIP 归档", "archive"),
    ".tar": ("TAR 归档", "archive"),
    ".pdf": ("PDF 文档", "document"),
    ".jpg": ("JPEG 图像", "image"),
    ".jpeg": ("JPEG 图像", "image"),
    ".png": ("PNG 图像", "image"),
    ".gif": ("GIF 图像", "image"),
}

# 检测函数

def detect_by_magic(data: bytes) -> List[Tuple[str, str]]:
    """通过魔数字节检测文件类型。
    返回 [(label, category), ...] —— 可能匹配多个（如 ZIP 既匹配 ZIP 归档也匹配 Office Open XML）。"""
    matches = []
    for offset, magic, label, cat in _MAGIC_DB:
        if len(data) >= offset + len(magic):
            if data[offset:offset + len(magic)] == magic:
                matches.append((label, cat))
    return matches

def detect_file_type(filepath: str, *, read_size: int = 4096) -> List[Tuple[str, str]]:
    """综合检测文件类型。
    先查扩展名快速路径，再读文件头部做魔数匹配。
    read_size: 读取文件头部字节数。
    返回 [(label, category), ...]。"""
    # 扩展名快速路径
    ext = os.path.splitext(filepath)[1].lower()
    if ext in _EXT_MAP:
        return [_EXT_MAP[ext]]

    # 魔数检测
    try:
        with open(filepath, "rb") as fh:
            header = fh.read(read_size)
        return detect_by_magic(header)
    except (IOError, OSError):
        # 无法读取文件时返回空列表而非抛出异常
        return []

def is_executable(filepath: str) -> bool:
    """快速判断文件是否为可执行格式。"""
    results = detect_file_type(filepath)
    return any(cat == "executable" for _, cat in results)

def is_archive(filepath: str) -> bool:
    """快速判断文件是否为归档/压缩格式。"""
    results = detect_file_type(filepath)
    return any(cat in ("archive", "compressed") for _, cat in results)

# 补充性魔数搜索

def find_magic_offset(data: bytes, magic: bytes) -> int:
    """在数据中搜索魔数字节序列。返回偏移，未找到为 -1。"""
    return data.find(magic)

def add_custom_magic(offset: int, magic: bytes, label: str, category: str):
    """注册自定义魔数到全局数据库。"""
    _MAGIC_DB.append((offset, magic, label, category))
    # 保持按 offset 排序以加速匹配（不需要但便于调试）
    _MAGIC_DB.sort(key=lambda x: x[0])

