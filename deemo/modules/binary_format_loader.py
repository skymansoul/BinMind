"""
插件化二进制文件格式解析器

注册机制支持 ELF/PE/Mach-O/OMF/COFF/Flat binary，自动识别并加载。

核心功能：
1. 格式识别：自动检测二进制文件格式
2. 插件注册：支持动态注册新的格式解析器
3. 统一接口：提供一致的二进制加载和解析接口
4. 格式转换：支持不同格式之间的转换
5. 元数据提取：提取二进制文件的关键元数据
"""

import os
import logging
from typing import Dict, Any, List, Optional, Type, Callable
from pathlib import Path
from enum import Enum
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from modules.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

logger = logging.getLogger(__name__)


class BinaryFormat(Enum):
    """二进制格式枚举"""
    ELF = "elf"
    PE = "pe"
    MACHO = "macho"
    OMF = "omf"
    COFF = "coff"
    FLAT = "flat"
    RAW = "raw"
    UNKNOWN = "unknown"


class Architecture(Enum):
    """架构枚举"""
    X86 = "x86"
    X86_64 = "x86_64"
    ARM = "arm"
    ARM64 = "arm64"
    MIPS = "mips"
    POWERPC = "powerpc"
    SPARC = "sparc"
    RISCV = "riscv"
    UNKNOWN = "unknown"


class Endianness(Enum):
    """字节序枚举"""
    LITTLE_ENDIAN = "little_endian"
    BIG_ENDIAN = "big_endian"
    UNKNOWN = "unknown"


@dataclass
class BinaryInfo:
    """二进制文件信息"""
    file_path: str
    format: BinaryFormat
    architecture: Architecture
    endianness: Endianness
    bits: int
    entry_point: int
    base_address: int
    sections: List[Dict[str, Any]]
    symbols: List[Dict[str, Any]]
    imports: List[str]
    exports: List[str]
    headers: Dict[str, Any]
    metadata: Dict[str, Any]


class BinaryFormatParser(ABC):
    """
    二进制格式解析器基类
    
    所有格式解析器必须继承此类并实现抽象方法。
    """
    
    @abstractmethod
    def detect(self, data: bytes) -> bool:
        """
        检测数据是否为该格式
        
        Args:
            data: 文件数据
        
        Returns:
            是否匹配该格式
        """
        pass
    
    @abstractmethod
    def parse(self, file_path: str) -> BinaryInfo:
        """
        解析二进制文件
        
        Args:
            file_path: 文件路径
        
        Returns:
            BinaryInfo 对象
        """
        pass
    
    @abstractmethod
    def get_format(self) -> BinaryFormat:
        """
        获取格式类型
        
        Returns:
            BinaryFormat 枚举值
        """
        pass
    
    @abstractmethod
    def get_supported_architectures(self) -> List[Architecture]:
        """
        获取支持的架构列表
        
        Returns:
            架构列表
        """
        pass


class ELFParser(BinaryFormatParser):
    """ELF 格式解析器"""
    
    ELF_MAGIC = b'\x7fELF'
    
    def detect(self, data: bytes) -> bool:
        return len(data) >= 4 and data[:4] == self.ELF_MAGIC
    
    def parse(self, file_path: str) -> BinaryInfo:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        info = BinaryInfo(
            file_path=file_path,
            format=BinaryFormat.ELF,
            architecture=self._parse_architecture(data),
            endianness=self._parse_endianness(data),
            bits=self._parse_bits(data),
            entry_point=self._parse_entry_point(data),
            base_address=0,
            sections=self._parse_sections(data),
            symbols=[],
            imports=[],
            exports=[],
            headers=self._parse_headers(data),
            metadata={}
        )
        
        return info
    
    def _parse_architecture(self, data: bytes) -> Architecture:
        # ELF header e_machine field (byte 18)
        if len(data) > 18:
            e_machine = data[18]
            if e_machine == 3:  # EM_386
                return Architecture.X86
            elif e_machine == 62:  # EM_X86_64
                return Architecture.X86_64
            elif e_machine == 40:  # EM_ARM
                return Architecture.ARM
            elif e_machine == 183:  # EM_AARCH64
                return Architecture.ARM64
            elif e_machine == 8:  # EM_MIPS
                return Architecture.MIPS
        return Architecture.UNKNOWN
    
    def _parse_endianness(self, data: bytes) -> Endianness:
        if len(data) > 5:
            # ELF header EI_DATA (byte 5)
            ei_data = data[5]
            if ei_data == 1:
                return Endianness.LITTLE_ENDIAN
            elif ei_data == 2:
                return Endianness.BIG_ENDIAN
        return Endianness.UNKNOWN
    
    def _parse_bits(self, data: bytes) -> int:
        if len(data) > 4:
            # ELF header EI_CLASS (byte 4)
            ei_class = data[4]
            if ei_class == 1:
                return 32
            elif ei_class == 2:
                return 64
        return 32
    
    def _parse_entry_point(self, data: bytes) -> int:
        if len(data) >= 28:
            ei_class = data[4] if len(data) > 4 else 1
            if ei_class == 1:  # 32-bit
                return int.from_bytes(data[24:28], 'little')
            else:  # 64-bit
                return int.from_bytes(data[24:32], 'little')
        return 0
    
    def _parse_sections(self, data: bytes) -> List[Dict[str, Any]]:
        sections = []
        try:
            ei_class = data[4] if len(data) > 4 else 1
            ei_data = data[5] if len(data) > 5 else 1
            
            endian = 'little' if ei_data == 1 else 'big'
            if ei_class == 1:
                # 32-bit ELF 程序头字段偏移
                if len(data) < 52:
                    return sections
                phoff = int.from_bytes(data[0x1C:0x20], endian)      # e_phoff (4 bytes)
                phentsize = int.from_bytes(data[0x2A:0x2C], endian)  # e_phentsize (2 bytes)
                phnum = int.from_bytes(data[0x2C:0x2E], endian)      # e_phnum (2 bytes)
            else:
                # 64-bit ELF 程序头字段偏移
                if len(data) < 64:
                    return sections
                phoff = int.from_bytes(data[0x20:0x28], endian)      # e_phoff (8 bytes)
                phentsize = int.from_bytes(data[0x36:0x38], endian)  # e_phentsize (2 bytes)
                phnum = int.from_bytes(data[0x38:0x3A], endian)      # e_phnum (2 bytes)
            
            for i in range(min(phnum, 10)):
                offset = phoff + i * phentsize
                if offset + phentsize <= len(data):
                    p_type = int.from_bytes(data[offset:offset+4], endian)
                    sections.append({
                        'index': i,
                        'type': self._get_segment_type(p_type),
                        'offset': offset
                    })
        except Exception:
            pass
        
        return sections
    
    def _get_segment_type(self, p_type: int) -> str:
        types = {
            0: 'NULL',
            1: 'LOAD',
            2: 'DYNAMIC',
            3: 'INTERP',
            4: 'NOTE',
            5: 'SHLIB',
            6: 'PHDR'
        }
        return types.get(p_type, f'UNKNOWN_{p_type}')
    
    def _parse_headers(self, data: bytes) -> Dict[str, Any]:
        headers = {}
        try:
            headers['e_ident'] = list(data[:16]) if len(data) >= 16 else []
            headers['e_type'] = int.from_bytes(data[16:18], 'little') if len(data) >= 18 else 0
            headers['e_machine'] = int.from_bytes(data[18:20], 'little') if len(data) >= 20 else 0
            headers['e_version'] = int.from_bytes(data[20:24], 'little') if len(data) >= 24 else 0
        except Exception:
            pass
        return headers
    
    def get_format(self) -> BinaryFormat:
        return BinaryFormat.ELF
    
    def get_supported_architectures(self) -> List[Architecture]:
        return [Architecture.X86, Architecture.X86_64, Architecture.ARM, 
                Architecture.ARM64, Architecture.MIPS, Architecture.RISCV]


class PEParser(BinaryFormatParser):
    """PE 格式解析器"""
    
    PE_MAGIC = b'MZ'
    
    def detect(self, data: bytes) -> bool:
        return len(data) >= 2 and data[:2] == self.PE_MAGIC
    
    def parse(self, file_path: str) -> BinaryInfo:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        info = BinaryInfo(
            file_path=file_path,
            format=BinaryFormat.PE,
            architecture=self._parse_architecture(data),
            endianness=Endianness.LITTLE_ENDIAN,
            bits=self._parse_bits(data),
            entry_point=self._parse_entry_point(data),
            base_address=self._parse_image_base(data),
            sections=self._parse_sections(data),
            symbols=[],
            imports=[],
            exports=[],
            headers=self._parse_headers(data),
            metadata={}
        )
        
        return info
    
    def _parse_architecture(self, data: bytes) -> Architecture:
        try:
            pe_offset = int.from_bytes(data[0x3C:0x40], 'little')
            if pe_offset + 4 <= len(data):
                magic = data[pe_offset:pe_offset+4]
                if magic == b'PE\x00\x00':
                    machine = int.from_bytes(data[pe_offset+4:pe_offset+6], 'little')
                    if machine == 0x014C:  # IMAGE_FILE_MACHINE_I386
                        return Architecture.X86
                    elif machine == 0x8664:  # IMAGE_FILE_MACHINE_AMD64
                        return Architecture.X86_64
                    elif machine == 0x01C0:  # IMAGE_FILE_MACHINE_ARM
                        return Architecture.ARM
                    elif machine == 0xAA64:  # IMAGE_FILE_MACHINE_ARM64
                        return Architecture.ARM64
        except Exception:
            pass
        return Architecture.UNKNOWN
    
    def _parse_bits(self, data: bytes) -> int:
        arch = self._parse_architecture(data)
        if arch in [Architecture.X86_64, Architecture.ARM64]:
            return 64
        return 32
    
    def _parse_entry_point(self, data: bytes) -> int:
        try:
            pe_offset = int.from_bytes(data[0x3C:0x40], 'little')
            if pe_offset + 0x28 <= len(data):
                entry_rva = int.from_bytes(data[pe_offset+0x28:pe_offset+0x2C], 'little')
                return entry_rva
        except Exception:
            pass
        return 0
    
    def _parse_image_base(self, data: bytes) -> int:
        try:
            pe_offset = int.from_bytes(data[0x3C:0x40], 'little')
            # 读取可选头魔法值，位于 pe_offset+0x18 处
            magic = int.from_bytes(data[pe_offset+0x18:pe_offset+0x1A], 'little')
            if magic == 0x10B:  # PE32
                image_base = int.from_bytes(data[pe_offset+0x34:pe_offset+0x38], 'little')
            elif magic == 0x20B:  # PE32+
                image_base = int.from_bytes(data[pe_offset+0x30:pe_offset+0x38], 'little')
            else:
                # 回退尝试
                image_base = int.from_bytes(data[pe_offset+0x34:pe_offset+0x38], 'little')
            if image_base == 0:
                image_base = 0x00400000
            return image_base
        except Exception:
            pass
        return 0x00400000
    
    def _parse_sections(self, data: bytes) -> List[Dict[str, Any]]:
        sections = []
        try:
            pe_offset = int.from_bytes(data[0x3C:0x40], 'little')
            num_sections = int.from_bytes(data[pe_offset+0x6:pe_offset+0x8], 'little')
            optional_hdr_size = int.from_bytes(data[pe_offset+0x14:pe_offset+0x16], 'little')
            section_table_offset = pe_offset + 24 + optional_hdr_size
            
            for i in range(min(num_sections, 20)):
                offset = section_table_offset + i * 40
                if offset + 40 <= len(data):
                    name = data[offset:offset+8].decode('ascii', errors='ignore').strip('\x00')
                    sections.append({
                        'index': i,
                        'name': name,
                        'offset': offset
                    })
        except Exception:
            pass
        return sections
    
    def _parse_headers(self, data: bytes) -> Dict[str, Any]:
        headers = {}
        try:
            pe_offset = int.from_bytes(data[0x3C:0x40], 'little')
            headers['pe_offset'] = pe_offset
            headers['signature'] = data[pe_offset:pe_offset+4].hex() if pe_offset + 4 <= len(data) else ''
            headers['machine'] = int.from_bytes(data[pe_offset+4:pe_offset+6], 'little') if pe_offset + 6 <= len(data) else 0
            headers['number_of_sections'] = int.from_bytes(data[pe_offset+6:pe_offset+8], 'little') if pe_offset + 8 <= len(data) else 0
        except Exception:
            pass
        return headers
    
    def get_format(self) -> BinaryFormat:
        return BinaryFormat.PE
    
    def get_supported_architectures(self) -> List[Architecture]:
        return [Architecture.X86, Architecture.X86_64, Architecture.ARM, Architecture.ARM64]


class MachOParser(BinaryFormatParser):
    """Mach-O 格式解析器"""
    
    MACHO_MAGICS = [
        b'\xFE\xED\xFA\xCE',  # 32-bit big-endian
        b'\xCE\xFA\xED\xFE',  # 32-bit little-endian
        b'\xFE\xED\xFA\xCF',  # 64-bit big-endian
        b'\xCF\xFA\xED\xFE'   # 64-bit little-endian
    ]
    
    def detect(self, data: bytes) -> bool:
        return len(data) >= 4 and any(data[:4] == magic for magic in self.MACHO_MAGICS)
    
    def parse(self, file_path: str) -> BinaryInfo:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        info = BinaryInfo(
            file_path=file_path,
            format=BinaryFormat.MACHO,
            architecture=self._parse_architecture(data),
            endianness=self._parse_endianness(data),
            bits=self._parse_bits(data),
            entry_point=self._parse_entry_point(data),
            base_address=0,
            sections=self._parse_sections(data),
            symbols=[],
            imports=[],
            exports=[],
            headers=self._parse_headers(data),
            metadata={}
        )
        
        return info
    
    def _parse_architecture(self, data: bytes) -> Architecture:
        magic = data[:4]
        if magic in [b'\xFE\xED\xFA\xCE', b'\xCE\xFA\xED\xFE']:
            return Architecture.X86
        elif magic in [b'\xFE\xED\xFA\xCF', b'\xCF\xFA\xED\xFE']:
            return Architecture.X86_64
        return Architecture.UNKNOWN
    
    def _parse_endianness(self, data: bytes) -> Endianness:
        magic = data[:4]
        if magic in [b'\xCE\xFA\xED\xFE', b'\xCF\xFA\xED\xFE']:
            return Endianness.LITTLE_ENDIAN
        return Endianness.BIG_ENDIAN
    
    def _parse_bits(self, data: bytes) -> int:
        magic = data[:4]
        if magic in [b'\xFE\xED\xFA\xCF', b'\xCF\xFA\xED\xFE']:
            return 64
        return 32
    
    def _parse_entry_point(self, data: bytes) -> int:
        """
        从 LC_MAIN 或 LC_UNIXTHREAD 命令中提取入口点。
        若无有效信息则返回 0。
        """
        try:
            bits = self._parse_bits(data)
            endian = 'little' if self._parse_endianness(data) == Endianness.LITTLE_ENDIAN else 'big'
            
            # 读取 mach_header
            if bits == 64:
                if len(data) < 32:
                    return 0
                ncmds = int.from_bytes(data[16:20], endian)
                load_commands_offset = 32
            else:
                if len(data) < 28:
                    return 0
                ncmds = int.from_bytes(data[12:16], endian)
                load_commands_offset = 28
            
            offset = load_commands_offset
            for _ in range(min(ncmds, 20)):
                if offset + 8 > len(data):
                    break
                cmd = int.from_bytes(data[offset:offset+4], endian)
                cmdsize = int.from_bytes(data[offset+4:offset+8], endian)
                if cmdsize <= 0:
                    break
                # LC_MAIN (0x28 | 0x80000000) 或 LC_UNIXTHREAD (0x5)
                if cmd == 0x80000028:  # LC_MAIN
                    if offset + 16 <= len(data):
                        entry_offset = int.from_bytes(data[offset+8:offset+16], endian)
                        return entry_offset
                elif cmd == 0x5:  # LC_UNIXTHREAD
                    # 简单处理：通常入口偏移在命令开始后的某个位置，这里跳过
                    pass
                offset += cmdsize
        except Exception:
            pass
        return 0
    
    def _parse_sections(self, data: bytes) -> List[Dict[str, Any]]:
        sections = []
        try:
            bits = self._parse_bits(data)
            endian = 'little' if self._parse_endianness(data) == Endianness.LITTLE_ENDIAN else 'big'
            
            if bits == 64:
                ncmds = int.from_bytes(data[16:20], endian)
                load_commands_offset = 32
            else:
                ncmds = int.from_bytes(data[12:16], endian)
                load_commands_offset = 28
            
            offset = load_commands_offset
            for i in range(min(ncmds, 10)):
                if offset + 8 <= len(data):
                    cmd = int.from_bytes(data[offset:offset+4], endian)
                    cmdsize = int.from_bytes(data[offset+4:offset+8], endian)
                    if cmd == 0x19:  # LC_SEGMENT or LC_SEGMENT_64
                        sections.append({
                            'index': i,
                            'type': 'SEGMENT',
                            'offset': offset
                        })
                    offset += cmdsize
        except Exception:
            pass
        return sections
    
    def _parse_headers(self, data: bytes) -> Dict[str, Any]:
        headers = {}
        try:
            headers['magic'] = data[:4].hex()
            headers['cputype'] = int.from_bytes(data[4:8], 'big') if len(data) >= 8 else 0
            headers['cpusubtype'] = int.from_bytes(data[8:12], 'big') if len(data) >= 12 else 0
        except Exception:
            pass
        return headers
    
    def get_format(self) -> BinaryFormat:
        return BinaryFormat.MACHO
    
    def get_supported_architectures(self) -> List[Architecture]:
        return [Architecture.X86, Architecture.X86_64]


class COFFParser(BinaryFormatParser):
    """COFF (Common Object File Format) 格式解析器"""
    
    COFF_MAGIC = 0x014C
    
    def detect(self, data: bytes) -> bool:
        if len(data) < 2:
            return False
        magic = int.from_bytes(data[:2], 'little')
        return magic == self.COFF_MAGIC
    
    def parse(self, file_path: str) -> BinaryInfo:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        info = BinaryInfo(
            file_path=file_path,
            format=BinaryFormat.COFF,
            architecture=self._parse_architecture(data),
            endianness=Endianness.LITTLE_ENDIAN,
            bits=self._parse_bits(data),
            entry_point=self._parse_entry_point(data),
            base_address=0,
            sections=self._parse_sections(data),
            symbols=[],
            imports=[],
            exports=[],
            headers=self._parse_headers(data),
            metadata={}
        )
        
        return info
    
    def _parse_architecture(self, data: bytes) -> Architecture:
        try:
            # COFF header: machine type at offset 4 (2 bytes)
            if len(data) >= 6:
                machine = int.from_bytes(data[4:6], 'little')
                if machine == 0x014C:  # IMAGE_FILE_MACHINE_I386
                    return Architecture.X86
                elif machine == 0x8664:  # IMAGE_FILE_MACHINE_AMD64
                    return Architecture.X86_64
                elif machine == 0x01C0:  # IMAGE_FILE_MACHINE_ARM
                    return Architecture.ARM
                elif machine == 0xAA64:  # IMAGE_FILE_MACHINE_ARM64
                    return Architecture.ARM64
        except Exception:
            pass
        return Architecture.UNKNOWN
    
    def _parse_bits(self, data: bytes) -> int:
        arch = self._parse_architecture(data)
        if arch in [Architecture.X86_64, Architecture.ARM64]:
            return 64
        return 32
    
    def _parse_entry_point(self, data: bytes) -> int:
        return 0  # COFF doesn't have entry point in header
    
    def _parse_sections(self, data: bytes) -> List[Dict[str, Any]]:
        sections = []
        try:
            if len(data) < 24:
                return sections
            
            num_sections = int.from_bytes(data[2:4], 'little')
            optional_header_size = int.from_bytes(data[20:22], 'little')
            section_table_offset = 24 + optional_header_size
            
            for i in range(min(num_sections, 20)):
                offset = section_table_offset + i * 40
                if offset + 40 <= len(data):
                    name = data[offset:offset+8].decode('ascii', errors='ignore').strip('\x00')
                    sections.append({
                        'index': i,
                        'name': name,
                        'offset': offset
                    })
        except Exception:
            pass
        return sections
    
    def _parse_headers(self, data: bytes) -> Dict[str, Any]:
        headers = {}
        try:
            if len(data) >= 24:
                headers['machine'] = int.from_bytes(data[4:6], 'little')
                headers['number_of_sections'] = int.from_bytes(data[2:4], 'little')
                headers['time_date_stamp'] = int.from_bytes(data[8:12], 'little')
                headers['pointer_to_symbol_table'] = int.from_bytes(data[12:16], 'little')
                headers['number_of_symbols'] = int.from_bytes(data[16:20], 'little')
        except Exception:
            pass
        return headers
    
    def get_format(self) -> BinaryFormat:
        return BinaryFormat.COFF
    
    def get_supported_architectures(self) -> List[Architecture]:
        return [Architecture.X86, Architecture.X86_64, Architecture.ARM, Architecture.ARM64]


class OMFParser(BinaryFormatParser):
    """OMF (Object Module Format) 格式解析器"""
    
    OMF_MAGIC = b'\x80'
    
    def detect(self, data: bytes) -> bool:
        # OMF files start with 0x80 byte
        if len(data) < 1:
            return False
        return data[0] == 0x80
    
    def parse(self, file_path: str) -> BinaryInfo:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        info = BinaryInfo(
            file_path=file_path,
            format=BinaryFormat.OMF,
            architecture=self._parse_architecture(data),
            endianness=Endianness.LITTLE_ENDIAN,
            bits=16,  # OMF is typically 16-bit
            entry_point=self._parse_entry_point(data),
            base_address=0,
            sections=self._parse_sections(data),
            symbols=[],
            imports=[],
            exports=[],
            headers=self._parse_headers(data),
            metadata={}
        )
        
        return info
    
    def _parse_architecture(self, data: bytes) -> Architecture:
        # OMF is primarily used for 16-bit x86
        return Architecture.X86
    
    def _parse_entry_point(self, data: bytes) -> int:
        # Entry point in OMF is stored in FIXUPP records
        return 0
    
    def _parse_sections(self, data: bytes) -> List[Dict[str, Any]]:
        sections = []
        try:
            offset = 1  # Skip magic byte
            while offset < len(data):
                if offset + 3 > len(data):
                    break
                
                rec_type = data[offset]
                rec_len = int.from_bytes(data[offset+1:offset+3], 'little')
                
                if rec_type == 0x06:  # COMENT record (section info)
                    sections.append({
                        'index': len(sections),
                        'type': 'comment',
                        'offset': offset
                    })
                elif rec_type == 0x08:  # MODEND record
                    break
                
                offset += 3 + rec_len
        except Exception:
            pass
        return sections
    
    def _parse_headers(self, data: bytes) -> Dict[str, Any]:
        headers = {}
        try:
            headers['magic'] = hex(data[0]) if len(data) > 0 else ''
        except Exception:
            pass
        return headers
    
    def get_format(self) -> BinaryFormat:
        return BinaryFormat.OMF
    
    def get_supported_architectures(self) -> List[Architecture]:
        return [Architecture.X86]


class RawBinaryParser(BinaryFormatParser):
    """原始二进制/Flat格式解析器"""
    
    def detect(self, data: bytes) -> bool:
        return True
    
    def parse(self, file_path: str) -> BinaryInfo:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        info = BinaryInfo(
            file_path=file_path,
            format=BinaryFormat.RAW,
            architecture=Architecture.UNKNOWN,
            endianness=Endianness.LITTLE_ENDIAN,
            bits=32,
            entry_point=0,
            base_address=0,
            sections=[],
            symbols=[],
            imports=[],
            exports=[],
            headers={},
            metadata={
                'size': len(data),
                'entropy': self._calculate_entropy(data)
            }
        )
        
        return info
    
    def _calculate_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        
        import math
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                probability = count / len(data)
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def get_format(self) -> BinaryFormat:
        return BinaryFormat.RAW
    
    def get_supported_architectures(self) -> List[Architecture]:
        return [Architecture.UNKNOWN]


class BinaryFormatLoader(BaseAnalyzer):
    """
    二进制格式加载器
    
    负责注册和管理各种二进制格式解析器，自动检测并加载二进制文件。
    """
    
    def __init__(self):
        self.parsers: Dict[BinaryFormat, BinaryFormatParser] = {}
        self.detection_order: List[BinaryFormat] = []
        
        self._register_default_parsers()
    
    def _register_default_parsers(self):
        """注册默认格式解析器"""
        parsers = [
            ELFParser(),
            PEParser(),
            MachOParser(),
            COFFParser(),
            OMFParser(),
            RawBinaryParser()
        ]
        
        for parser in parsers:
            self.register_parser(parser)
    
    def register_parser(self, parser: BinaryFormatParser):
        """
        注册格式解析器
        
        Args:
            parser: BinaryFormatParser 实例
        """
        format_type = parser.get_format()
        self.parsers[format_type] = parser
        
        if format_type not in self.detection_order:
            self.detection_order.append(format_type)
        
        logger.info(f"[BinaryFormatLoader] 已注册格式解析器: {format_type.value}")
    
    def unregister_parser(self, format_type: BinaryFormat):
        """
        注销格式解析器
        
        Args:
            format_type: 格式类型
        """
        if format_type in self.parsers:
            del self.parsers[format_type]
            if format_type in self.detection_order:
                self.detection_order.remove(format_type)
            logger.info(f"[BinaryFormatLoader] 已注销格式解析器: {format_type.value}")
    
    def detect_format(self, file_path: str) -> BinaryFormat:
        """
        检测二进制文件的格式
        
        Args:
            file_path: 文件路径
        
        Returns:
            检测到的格式枚举值
        """
        try:
            with open(file_path, 'rb') as f:
                data = f.read(4096)  # 读取前4KB用于检测
        except Exception as e:
            logger.error(f"无法读取文件 {file_path}: {e}")
            return BinaryFormat.UNKNOWN
        
        for format_type in self.detection_order:
            parser = self.parsers.get(format_type)
            if parser and parser.detect(data):
                return format_type
        
        return BinaryFormat.UNKNOWN
    
    def load_binary(self, file_path: str) -> Optional[BinaryInfo]:
        """
        加载并解析二进制文件
        
        Args:
            file_path: 文件路径
        
        Returns:
            BinaryInfo 对象，解析失败返回 None
        """
        if not os.path.exists(file_path):
            logger.error(f"文件不存在: {file_path}")
            return None
        
        try:
            fmt = self.detect_format(file_path)
            if fmt == BinaryFormat.UNKNOWN:
                logger.warning(f"未能识别文件格式: {file_path}")
                return None
            
            parser = self.parsers.get(fmt)
            if parser is None:
                logger.error(f"未找到格式 {fmt.value} 的解析器")
                return None
            
            binary_info = parser.parse(file_path)
            logger.info(f"成功加载二进制文件: {file_path} (格式: {fmt.value}, 架构: {binary_info.architecture.value})")
            return binary_info
        
        except Exception as e:
            logger.error(f"加载二进制文件失败 {file_path}: {e}")
            return None
    
    def get_available_formats(self) -> List[str]:
        """获取所有可用的格式列表"""
        return [fmt.value for fmt in self.detection_order]
    
    def analyze(self, file_path: str) -> Dict[str, Any]:
        """
        实现 BaseAnalyzer 要求的分析方法（简单委托给 load_binary）
        """
        info = self.load_binary(file_path)
        if info is None:
            return {"error": "analysis failed"}
        return {
            "format": info.format.value,
            "architecture": info.architecture.value,
            "bits": info.bits,
            "entry_point": info.entry_point,
            "base_address": info.base_address,
            "sections": len(info.sections),
        }
    
    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            name="BinaryFormatLoader",
            type=AnalyzerType.OTHER,
            version="1.0.0",
            description="插件化二进制文件格式解析器，支持 ELF/PE/Mach-O/OMF/COFF/Flat binary",
            author="BinaryAnalysisPlatform",
            supported_platforms=["all"]
        )