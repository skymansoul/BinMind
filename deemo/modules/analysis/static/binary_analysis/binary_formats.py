# INTJ策略: 单一真相源。所有格式检测逻辑集中于此，避免各处散落 magic byte 比对
# 算法复杂度: detect() 为 O(1) — 仅检查前 4 字节 magic number

from __future__ import annotations

import struct
import math
import hashlib
from typing import Any, Optional

from modules.analysis.static.binary_analysis.src.utils.constants import BinaryFormat, Arch
from modules.analysis.static.binary_analysis.src.utils.errors import BinaryParseError


class BinaryFormatParser:
    """二进制文件格式检测与头部解析器
    
    INTJ策略: 采用分层解析——先 detect 格式，再 parse 头部。分离的好处是调用方
    可以先做粗略的格式筛选，不需要完整解析就能判断文件类型
    
    复杂度:
    - 检测(): O(1) magic byte lookup
    - parse_header(): O(1) 固定长度头部读取，~64-128 bytes
    """

    def __init__(self):
        self._last_result: Optional[dict] = None

    def detect(self, data: bytes) -> Optional[str]:
        """检测二进制格式。返回 'elf', 'pe', 'mach_o', 'unknown', 或 None

        数据不足 2 字节时返回 None 表明无法判断；
        无法识别的数据统一归为 'unknown'，不返回 'raw'。
        """
        if not data or len(data) < 2:
            return None
        fmt = BinaryFormat.from_magic(data[:4])
        if fmt in (BinaryFormat.UNKNOWN, BinaryFormat.RAW):
            return "unknown"
        return fmt.value

# ELF 解析

    def _parse_elf_header(self, data: bytes) -> dict:
        """解析 ELF 头部 (64/32 bit autodetect)"""
        ei_class = data[4]  # 1=32bit, 2=64bit
        if ei_class == 1:
            return self._parse_elf32_header(data)
        elif ei_class == 2:
            return self._parse_elf64_header(data)
        else:
            raise BinaryParseError(f"unknown ELF class: {ei_class}")

    def _parse_elf32_header(self, data: bytes) -> dict:
        if len(data) < 52:
            raise BinaryParseError("truncated ELF32 header")
        hdr = struct.unpack_from("<HHIIIIIHHHHHH", data, 16)
        return {
            "format": "elf",
            "bits": 32,
            "endian": "little" if data[5] == 1 else "big",
            "type": hdr[0],
            "machine": hdr[1],
            "version": hdr[2],
            "entry": hdr[3],
            "phoff": hdr[4],
            "shoff": hdr[5],
            "flags": hdr[6],
            "ehsize": hdr[7],
            "phentsize": hdr[8],
            "phnum": hdr[9],
            "shentsize": hdr[10],
            "shnum": hdr[11],
        }

    def _parse_elf64_header(self, data: bytes) -> dict:
        if len(data) < 64:
            raise BinaryParseError("truncated ELF64 header")
        hdr = struct.unpack_from("<HHIQQQIHHHHH", data, 16)
        return {
            "format": "elf",
            "bits": 64,
            "endian": "little" if data[5] == 1 else "big",
            "type": hdr[0],
            "machine": hdr[1],
            "version": hdr[2],
            "entry": hdr[3],
            "phoff": hdr[4],
            "shoff": hdr[5],
            "flags": hdr[6],
            "ehsize": hdr[7],
            "phentsize": hdr[8],
            "phnum": hdr[9],
            "shentsize": hdr[10],
            "shnum": hdr[11],
        }

# PE 解析

    def _parse_pe_header(self, data: bytes) -> dict:
        """解析 PE 头部 (PE32/PE32+ autodetect)"""
        if len(data) < 64 or data[:2] != b"MZ":
            raise BinaryParseError("not a valid PE file (missing MZ signature)")

        # 定位 PE 签名
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 4 > len(data):
            raise BinaryParseError("PE signature offset out of range")

        sig = data[e_lfanew:e_lfanew + 4]
        if sig != b"PE\x00\x00":
            raise BinaryParseError("invalid PE signature")

        # COFF header e_lfanew + 4
        coff_off = e_lfanew + 4
        if coff_off + 20 > len(data):
            raise BinaryParseError("truncated COFF header")

        machine, num_sections = struct.unpack_from("<HH", data, coff_off)
        # optional header
        opt_off = coff_off + 20
        if opt_off + 2 > len(data):
            raise BinaryParseError("truncated optional header")
        magic = struct.unpack_from("<H", data, opt_off)[0]
        pe32_plus = (magic == 0x20B)

        entry_point = 0
        if opt_off + 20 <= len(data):
            entry_point = struct.unpack_from("<I", data, opt_off + 16)[0]

        return {
            "format": "pe",
            "bits": 64 if pe32_plus else 32,
            "machine": machine,
            "num_sections": num_sections,
            "entry": entry_point,
            "pe_signature_offset": e_lfanew,
        }

    # //// Mach-O 解析

    def _parse_macho_header(self, data: bytes) -> dict:
        if len(data) < 28:
            raise BinaryParseError("truncated Mach-O header")
        magic = struct.unpack_from("<I", data, 0)[0]
        if magic in (0xCAFEBABE, 0xBEBAFECA):
            return {"format": "mach_o", "type": "fat", "bits": "multi"}
        cputype = struct.unpack_from("<I", data, 4)[0]
        bits = 64 if (magic == 0xFEEDFACF or magic == 0xCFFAEDFE) else 32
        return {
            "format": "mach_o",
            "bits": bits,
            "cputype": cputype,
            "magic": f"0x{magic:08X}",
        }

# 主入口

    def parse_header(self, data: bytes) -> dict:
        """根据 detect 结果自动选择解析器，返回结构化头部信息"""
        fmt = self.detect(data)
        # 对于无法识别的格式，返回基本信息而非报错
        # INTJ策略: 文件识别失败不应阻断后续分析流程
        if fmt == "elf":
            result = self._parse_elf_header(data)
        elif fmt == "pe":
            result = self._parse_pe_header(data)
        elif fmt == "mach_o":
            result = self._parse_macho_header(data)
        else:
            # unknown/raw — 保留原始熵信息，不阻断后续分析
            result = {
                "format": fmt or "unknown",
                "size": len(data),
                "entropy": _shannon_entropy(data[:4096]),
            }
            result = {"format": "unknown", "size": len(data)}
        self._last_result = result
        return result

# 便捷方法

    def arch_from_header(self, data: bytes) -> Arch:
        """从二进制头部推断目标架构"""
        hdr = self.parse_header(data)
        machine = hdr.get("machine", 0)
        return Arch.from_elf_machine(machine)

    def is_library(self, data: bytes) -> bool:
        """判断是否为动态库/共享对象"""
        hdr = self.parse_header(data)
        return hdr.get("type") == 3  # ET_DYN for ELF

    @property
    def last_result(self) -> Optional[dict]:
        return self._last_result


# 辅助函数
# 留着备用，后面分析 raw binary 时可能需要更细粒度的熵分块

def _shannon_entropy(data: bytes) -> float:
    """计算字节级香农熵。0.0 ~ 8.0"""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    entropy = 0.0
    for c in freq:
        if c == 0:
            continue
        p = c / n
        entropy -= p * math.log2(p)
    return entropy


def _compute_section_hashes(data: bytes, chunk_size: int = 4096) -> list[str]:
    """分块哈希，用于快速差异化比较。2025-11-03 FIXME: 大文件时 chunk_size 应该可配"""
    return [hashlib.sha256(data[i:i + chunk_size]).hexdigest()[:16]
            for i in range(0, min(len(data), chunk_size * 16), chunk_size)]


# from typing import OrderedDict  # python3.7+自带dict有序，不需要了
