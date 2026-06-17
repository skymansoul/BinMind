#!/usr/bin/env python3
"""
多平台二进制文件格式 Fuzzer 生成模块

功能：
- 自动生成 ELF/PE/Mach-O 解析器的 LibFuzzer harness
- 支持多种文件格式
- 生成结构化测试用例
- 提供变异策略
"""

import logging
import os
import struct
import json
import hashlib
import random
from typing import Dict, Any, List, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


class FileFormatType(Enum):
    """文件格式类型"""
    ELF = "elf"
    PE = "pe"
    MACH_O = "mach_o"
    ZIP = "zip"
    TAR = "tar"
    GZIP = "gzip"
    PDF = "pdf"
    PNG = "png"
    JPEG = "jpeg"
    BMP = "bmp"
    WAV = "wav"
    MP3 = "mp3"
    MP4 = "mp4"
    AVI = "avi"
    CUSTOM = "custom"
    UNKNOWN = "unknown"


class FuzzerType(Enum):
    """Fuzzer 类型"""
    LIBFUZZER = "libfuzzer"
    AFL = "afl"
    HONGGFUZZ = "honggfuzz"
    SYZKALLER = "syzkaller"
    CUSTOM = "custom"


class MutationStrategy(Enum):
    """变异策略"""
    RANDOM = "random"
    STRUCTURE_AWARE = "structure_aware"
    FIELD_TARGETED = "field_targeted"
    MAGIC_VALUES = "magic_values"
    BIT_FLIP = "bit_flip"
    BYTE_INSERT = "byte_insert"
    BYTE_DELETE = "byte_delete"
    BLOCK_SWAP = "block_swap"


@dataclass
class FormatField:
    """格式字段"""
    name: str
    offset: int
    size: int
    type: str  # uint8, uint16, uint32, uint64, string, bytes, etc.
    description: str = ""
    valid_values: List[Any] = field(default_factory=list)
    constraints: Dict[str, Any] = field(default_factory=dict)
    is_critical: bool = False


@dataclass
class FormatStructure:
    """格式结构"""
    format_type: FileFormatType
    magic_bytes: bytes
    fields: List[FormatField] = field(default_factory=list)
    sub_structures: List[Dict[str, Any]] = field(default_factory=list)
    validation_rules: List[Dict[str, Any]] = field(default_factory=list)
    description: str = ""


@dataclass
class FuzzerConfig:
    """Fuzzer 配置"""
    fuzzer_type: FuzzerType
    target_format: FileFormatType
    target_function: str = ""
    max_input_size: int = 4096
    mutation_strategies: List[MutationStrategy] = field(default_factory=list)
    seed_corpus: List[str] = field(default_factory=list)
    dictionary: List[str] = field(default_factory=list)
    custom_mutators: List[str] = field(default_factory=list)
    sanitizer_options: Dict[str, str] = field(default_factory=dict)
    timeout_ms: int = 1000
    runs: int = 1000000
    output_dir: str = "./fuzzer_output"


@dataclass
class FuzzerHarness:
    """Fuzzer Harness"""
    harness_code: str
    fuzzer_type: FuzzerType
    target_format: FileFormatType
    build_command: str = ""
    run_command: str = ""
    dependencies: List[str] = field(default_factory=list)
    seed_files: List[str] = field(default_factory=list)


@dataclass
class TestCase:
    """测试用例"""
    data: bytes
    description: str = ""
    mutation_applied: str = ""
    expected_behavior: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


# ELF 格式结构定义
ELF_STRUCTURE = FormatStructure()
    format_type=FileFormatType.ELF,
    magic_bytes=b'\x7fELF',
    fields=[
        # ELF Header
        FormatField('e_ident_magic', 0, 4, 'bytes', 'Magic number', valid_values=[b'\x7fELF'], is_critical=True),
        FormatField('e_ident_class', 4, 1, 'uint8', '32/64 bit', valid_values=[1, 2], is_critical=True),
        FormatField('e_ident_data', 5, 1, 'uint8', 'Endianness', valid_values=[1, 2], is_critical=True),
        FormatField('e_ident_version', 6, 1, 'uint8', 'ELF version', valid_values=[1]),
        FormatField('e_ident_osabi', 7, 1, 'uint8', 'OS/ABI', valid_values=[0, 1, 2, 3, 6, 7, 8, 9, 10, 11, 12, 13, 255]),
        FormatField('e_ident_abiversion', 8, 1, 'uint8', 'ABI version'),
        FormatField('e_ident_pad', 9, 7, 'bytes', 'Padding'),
        FormatField('e_type', 16, 2, 'uint16', 'Object file type', valid_values=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], is_critical=True),
        FormatField('e_machine', 18, 2, 'uint16', 'Machine type', valid_values=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 15, 20, 21, 22, 23, 24, 40, 41, 42, 43, 50, 62, 183, 188, 243, 247], is_critical=True),
        FormatField('e_version', 20, 4, 'uint32', 'Object file version', valid_values=[1]),
        FormatField('e_entry', 24, 8, 'uint64', 'Entry point address', is_critical=True),
        FormatField('e_phoff', 32, 8, 'uint64', 'Program header offset', is_critical=True),
        FormatField('e_shoff', 40, 8, 'uint64', 'Section header offset', is_critical=True),
        FormatField('e_flags', 48, 4, 'uint32', 'Processor-specific flags'),
        FormatField('e_ehsize', 52, 2, 'uint16', 'ELF header size', valid_values=[52, 64]),
        FormatField('e_phentsize', 54, 2, 'uint16', 'Program header entry size', valid_values=[32, 56]),
        FormatField('e_phnum', 56, 2, 'uint16', 'Number of program headers', constraints={'max': 65535}),
        FormatField('e_shentsize', 58, 2, 'uint16', 'Section header entry size', valid_values=[40, 64]),
        FormatField('e_shnum', 60, 2, 'uint16', 'Number of section headers', constraints={'max': 65535}),
        FormatField('e_shstrndx', 62, 2, 'uint16', 'Section name string table index'),
    ],
    sub_structures=[
        {
            'name': 'Program Header',
            'offset_field': 'e_phoff',
            'count_field': 'e_phnum',
            'entry_size_field': 'e_phentsize',
            'fields': [
                FormatField('p_type', 0, 4, 'uint32', 'Segment type', valid_values=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0x60000000, 0x70000000]),
                FormatField('p_flags', 4, 4, 'uint32', 'Segment flags', valid_values=[0, 1, 2, 4, 5, 6]),
                FormatField('p_offset', 8, 8, 'uint64', 'Segment file offset'),
                FormatField('p_vaddr', 16, 8, 'uint64', 'Segment virtual address'),
                FormatField('p_paddr', 24, 8, 'uint64', 'Segment physical address'),
                FormatField('p_filesz', 32, 8, 'uint64', 'Segment size in file'),
                FormatField('p_memsz', 40, 8, 'uint64', 'Segment size in memory'),
                FormatField('p_align', 48, 8, 'uint64', 'Segment alignment'),
            ]
        },
        {
            'name': 'Section Header',
            'offset_field': 'e_shoff',
            'count_field': 'e_shnum',
            'entry_size_field': 'e_shentsize',
            'fields': [
                FormatField('sh_name', 0, 4, 'uint32', 'Section name (string table index)'),
                FormatField('sh_type', 4, 4, 'uint32', 'Section type', valid_values=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0x60000000, 0x70000000, 0x80000000]),
                FormatField('sh_flags', 8, 8, 'uint64', 'Section flags'),
                FormatField('sh_addr', 16, 8, 'uint64', 'Section virtual address'),
                FormatField('sh_offset', 24, 8, 'uint64', 'Section file offset'),
                FormatField('sh_size', 32, 8, 'uint64', 'Section size'),
                FormatField('sh_link', 40, 4, 'uint32', 'Link to another section'),
                FormatField('sh_info', 44, 4, 'uint32', 'Additional section information'),
                FormatField('sh_addralign', 48, 8, 'uint64', 'Section alignment'),
                FormatField('sh_entsize', 56, 8, 'uint64', 'Entry size if section holds table'),
            ]
        }
    ],
    validation_rules=[
        {'rule': 'magic_check', 'description': 'Must start with \\x7fELF'},
        {'rule': 'class_check', 'description': 'Class must be 1 (32-bit) or 2 (64-bit)'},
        {'rule': 'data_check', 'description': 'Data encoding must be 1 (little endian) or 2 (big endian)'},
        {'rule': 'size_consistency', 'description': 'Header size must match class'},
        {'rule': 'offset_validity', 'description': 'Offsets must not exceed file size'},
    ],
    description="ELF (Executable and Linkable Format) - Linux/Unix executable format"


# PE 格式结构定义
PE_STRUCTURE = FormatStructure()
    format_type=FileFormatType.PE,
    magic_bytes=b'MZ',
    fields=[
        # DOS Header
        FormatField('e_magic', 0, 2, 'bytes', 'Magic number', valid_values=[b'MZ'], is_critical=True),
        FormatField('e_cblp', 2, 2, 'uint16', 'Bytes on last page of file'),
        FormatField('e_cp', 4, 2, 'uint16', 'Pages in file'),
        FormatField('e_crlc', 6, 2, 'uint16', 'Relocations'),
        FormatField('e_cparhdr', 8, 2, 'uint16', 'Size of header in paragraphs'),
        FormatField('e_minalloc', 10, 2, 'uint16', 'Minimum extra paragraphs needed'),
        FormatField('e_maxalloc', 12, 2, 'uint16', 'Maximum extra paragraphs needed'),
        FormatField('e_ss', 14, 2, 'uint16', 'Initial (relative) SS value'),
        FormatField('e_sp', 16, 2, 'uint16', 'Initial SP value'),
        FormatField('e_csum', 18, 2, 'uint16', 'Checksum'),
        FormatField('e_ip', 20, 2, 'uint16', 'Initial IP value'),
        FormatField('e_cs', 22, 2, 'uint16', 'Initial (relative) CS value'),
        FormatField('e_lfarlc', 24, 2, 'uint16', 'File address of relocation table'),
        FormatField('e_ovno', 26, 2, 'uint16', 'Overlay number'),
        FormatField('e_oemid', 36, 2, 'uint16', 'OEM identifier'),
        FormatField('e_oeminfo', 38, 2, 'uint16', 'OEM information'),
        FormatField('e_lfanew', 60, 4, 'uint32', 'File address of new exe header', is_critical=True),
    ],
    sub_structures=[
        {
            'name': 'PE Signature',
            'offset_field': 'e_lfanew',
            'size': 4,
            'magic': b'PE\x00\x00',
            'fields': [
                FormatField('Signature', 0, 4, 'bytes', 'PE signature', valid_values=[b'PE\x00\x00'], is_critical=True),
            ]
        },
        {
            'name': 'COFF Header',
            'offset': 4,  # Relative to PE signature
            'fields': [
                FormatField('Machine', 0, 2, 'uint16', 'Machine type', valid_values=[0x0000, 0x014c, 0x0166, 0x0169, 0x01a2, 0x01a6, 0x01c0, 0x01c2, 0x01c4, 0x01f0, 0x0200, 0x8664], is_critical=True),
                FormatField('NumberOfSections', 2, 2, 'uint16', 'Number of sections', constraints={'max': 96}),
                FormatField('TimeDateStamp', 4, 4, 'uint32', 'Time date stamp'),
                FormatField('PointerToSymbolTable', 8, 4, 'uint32', 'Pointer to symbol table'),
                FormatField('NumberOfSymbols', 12, 4, 'uint32', 'Number of symbols'),
                FormatField('SizeOfOptionalHeader', 16, 2, 'uint16', 'Size of optional header'),
                FormatField('Characteristics', 18, 2, 'uint16', 'Characteristics'),
            ]
        },
        {
            'name': 'Optional Header',
            'fields': [
                FormatField('Magic', 0, 2, 'uint16', 'PE32/PE32+', valid_values=[0x10b, 0x20b], is_critical=True),
                FormatField('MajorLinkerVersion', 2, 1, 'uint8', 'Major linker version'),
                FormatField('MinorLinkerVersion', 3, 1, 'uint8', 'Minor linker version'),
                FormatField('SizeOfCode', 4, 4, 'uint32', 'Size of code'),
                FormatField('SizeOfInitializedData', 8, 4, 'uint32', 'Size of initialized data'),
                FormatField('SizeOfUninitializedData', 12, 4, 'uint32', 'Size of uninitialized data'),
                FormatField('AddressOfEntryPoint', 16, 4, 'uint32', 'Address of entry point', is_critical=True),
                FormatField('BaseOfCode', 20, 4, 'uint32', 'Base of code'),
                FormatField('ImageBase', 24, 8, 'uint64', 'Image base (PE32+)', is_critical=True),
                FormatField('SectionAlignment', 32, 4, 'uint32', 'Section alignment'),
                FormatField('FileAlignment', 36, 4, 'uint32', 'File alignment'),
                FormatField('SizeOfImage', 56, 4, 'uint32', 'Size of image', is_critical=True),
                FormatField('SizeOfHeaders', 60, 4, 'uint32', 'Size of headers', is_critical=True),
            ]
        },
        {
            'name': 'Section Header',
            'fields': [
                FormatField('Name', 0, 8, 'string', 'Section name'),
                FormatField('VirtualSize', 8, 4, 'uint32', 'Virtual size'),
                FormatField('VirtualAddress', 12, 4, 'uint32', 'Virtual address'),
                FormatField('SizeOfRawData', 16, 4, 'uint32', 'Size of raw data'),
                FormatField('PointerToRawData', 20, 4, 'uint32', 'Pointer to raw data'),
                FormatField('Characteristics', 36, 4, 'uint32', 'Characteristics'),
            ]
        }
    ],
    validation_rules=[
        {'rule': 'dos_magic', 'description': 'Must start with MZ'},
        {'rule': 'pe_signature', 'description': 'PE signature must be PE\\x00\\x00'},
        {'rule': 'offset_valid', 'description': 'e_lfanew must point within file'},
        {'rule': 'section_count', 'description': 'Number of sections must be reasonable'},
    ],
    description="PE (Portable Executable) - Windows executable format"


# Mach-O 格式结构定义
MACH_O_STRUCTURE = FormatStructure()
    format_type=FileFormatType.MACH_O,
    magic_bytes=b'\xfe\xed\xfa\xce',  # 还有其他魔数
    fields=[
        FormatField('magic', 0, 4, 'uint32', 'Magic number')
                    valid_values=[0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE], is_critical=True),
        FormatField('cputype', 4, 4, 'uint32', 'CPU type')
                    valid_values=[1, 6, 7, 12, 18, 0x01000007, 0x0100000c], is_critical=True),
        FormatField('cpusubtype', 8, 4, 'uint32', 'CPU subtype'),
        FormatField('filetype', 12, 4, 'uint32', 'File type')
                    valid_values=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12], is_critical=True),
        FormatField('ncmds', 16, 4, 'uint32', 'Number of load commands', constraints={'max': 65535}),
        FormatField('sizeofcmds', 20, 4, 'uint32', 'Size of load commands'),
        FormatField('flags', 24, 4, 'uint32', 'Flags'),
        FormatField('reserved', 28, 4, 'uint32', 'Reserved (64-bit only)'),
    ],
    sub_structures=[
        {
            'name': 'Load Command',
            'fields': [
                FormatField('cmd', 0, 4, 'uint32', 'Command type')
                            valid_values=[0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x80000022, 0x80000023, 0x80000024, 0x80000025, 0x80000026, 0x80000027, 0x80000028, 0x80000029, 0x8000002a, 0x8000002b, 0x8000002c], is_critical=True),
                FormatField('cmdsize', 4, 4, 'uint32', 'Command size'),
            ]
        },
        {
            'name': 'Segment Command',
            'fields': [
                FormatField('segname', 8, 16, 'string', 'Segment name'),
                FormatField('vmaddr', 24, 8, 'uint64', 'Virtual memory address'),
                FormatField('vmsize', 32, 8, 'uint64', 'Virtual memory size'),
                FormatField('fileoff', 40, 8, 'uint64', 'File offset'),
                FormatField('filesize', 48, 8, 'uint64', 'File size'),
                FormatField('maxprot', 56, 4, 'uint32', 'Maximum protection'),
                FormatField('initprot', 60, 4, 'uint32', 'Initial protection'),
                FormatField('nsects', 64, 4, 'uint32', 'Number of sections'),
                FormatField('flags', 68, 4, 'uint32', 'Flags'),
            ]
        }
    ],
    validation_rules=[
        {'rule': 'magic_check', 'description': 'Magic must be valid Mach-O magic'},
        {'rule': 'cpu_type', 'description': 'CPU type must be valid'},
        {'rule': 'file_type', 'description': 'File type must be valid'},
        {'rule': 'cmd_size', 'description': 'Load command sizes must be consistent'},
    ],
    description="Mach-O - macOS/iOS executable format"


# 格式结构映射
FORMAT_STRUCTURES = {
    FileFormatType.ELF: ELF_STRUCTURE,
    FileFormatType.PE: PE_STRUCTURE,
    FileFormatType.MACH_O: MACH_O_STRUCTURE,
}


class FormatFuzzerGenerator:
    """文件格式 Fuzzer 生成器"""
    
    def __init__(self, config: FuzzerConfig = None):
        """
        初始化 Fuzzer 生成器
        
        Args:
            config: Fuzzer 配置
        """
        self.config = config or FuzzerConfig()
            fuzzer_type=FuzzerType.LIBFUZZER,
            target_format=FileFormatType.ELF
        
    
    def generate_harness(self) -> FuzzerHarness:
        """
        生成 Fuzzer Harness
        
        Returns:
            Fuzzer Harness
        """
        harness = FuzzerHarness()
            harness_code="",
            fuzzer_type=self.config.fuzzer_type,
            target_format=self.config.target_format
        
        
        if self.config.fuzzer_type == FuzzerType.LIBFUZZER:
            harness.harness_code = self._generate_libfuzzer_harness()
            harness.build_command = self._generate_libfuzzer_build_command()
            harness.run_command = self._generate_libfuzzer_run_command()
        
        elif self.config.fuzzer_type == FuzzerType.AFL:
            harness.harness_code = self._generate_afl_harness()
            harness.build_command = self._generate_afl_build_command()
            harness.run_command = self._generate_afl_run_command()
        
        # 生成种子文件
        harness.seed_files = self._generate_seed_files()
        
        return harness
    
    def _generate_libfuzzer_harness(self) -> str:
        """生成 LibFuzzer harness"""
        format_struct = FORMAT_STRUCTURES.get(self.config.target_format)
        
        if not format_struct:
            return self._generate_generic_harness()
        
        harness_code = '''// LibFuzzer harness for {format_name} format parsing
// Generated automatically

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>

// Include the parser library header
// #include "{format_lower}_parser.h"

// Mock parser function for demonstration
// Replace with actual parser implementation
int parse_{format_lower}(const uint8_t *data, size_t size) {
    // Basic validation
    if (size < {min_size}) {
        return 0;  // Too small, not interesting
    }
    
    // Check magic bytes
    if (memcmp(data, "{magic_hex}", {magic_len}) != 0) {,
        return 0;  // Invalid magic
    }
    
    // Parse header fields
    // Add actual parsing logic here
    
    // Trigger potential vulnerabilities:
    // - Out-of-bounds reads
    // - Integer overflow in size calculations
    // - Null pointer dereferences
    // - Use after free
    
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    parse_{format_lower}(data, size);
    return 0;
}

// Optional: Custom mutation function
extern "C" size_t LLVMFuzzerCustomMutator()
    uint8_t *data, size_t size, size_t max_size, unsigned int seed) {
    
    // Structure-aware mutation
    if (size < {min_size}) {
        // Generate minimal valid structure
        memcpy(data, "{magic_hex}", {magic_len});
        // Fill remaining with random data
        for (size_t i = {magic_len}; i < max_size && i < {min_size}; i++) {
            data[i] = rand() % 256;
        }
        return {min_size};
    }
    
    // Mutate specific fields
    random_seed = seed;
    
    // Choose mutation strategy
    int strategy = rand() % 5;
    
    switch (strategy) {
        case 0:  // Mutate header field
            {
                size_t field_offset = {header_field_offsets}[rand() % {num_header_fields}];
                size_t field_size = {header_field_sizes}[rand() % {num_header_fields}];,
                if (field_offset + field_size <= size) {,
                    for (size_t i = 0; i < field_size; i++) {
                        data[field_offset + i] = rand() % 256;
                    }
                }
            }
            break;
        
        case 1:  // Insert bytes
            {
                size_t insert_pos = rand() % size;
                size_t insert_len = rand() % 16 + 1;,
                if (size + insert_len <= max_size) {
                    memmove(data + insert_pos + insert_len, data + insert_pos, size - insert_pos);
                    for (size_t i = 0; i < insert_len; i++) {
                        data[insert_pos + i] = rand() % 256;
                    }
                    size += insert_len;
                }
            }
            break;
        
        case 2:  // Delete bytes
            {
                size_t delete_pos = rand() % size;
                size_t delete_len = rand() % 16 + 1;,
                if (delete_pos + delete_len <= size) {
                    memmove(data + delete_pos, data + delete_pos + delete_len, size - delete_pos - delete_len);
                    size -= delete_len;
                }
            }
            break;
        
        case 3:  // Bit flip
            {
                size_t flip_pos = rand() % size;
                data[flip_pos] ^= (1 << (rand() % 8));
            }
            break;
        
        case 4:  // Magic value replacement
            {
                size_t replace_pos = rand() % (size - 4);
                uint32_t magic_values[] = {0, 0xFFFFFFFF, 0x7FFFFFFF, 0x80000000, 
                                           0x41414141, 0xDEADBEEF, 0xCAFEBABE};
                uint32_t magic = magic_values[rand() % 7];
                memcpy(data + replace_pos, &magic, 4);
            }
            break;
    }
    
    return size;
}

// Optional: Initialize fuzzer
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    // Initialize parser
    // Load dictionaries
    // Set up environment
    return 0;
}
'''
        
        # 填充模板参数
        min_size = self._get_min_format_size()
        header_offsets, header_sizes = self._get_header_field_info()
        
        return harness_code.format()
            format_name=format_struct.format_type.value.upper(),
            format_lower=format_struct.format_type.value.lower(),
            min_size=min_size,
            magic_hex=format_struct.magic_bytes.hex(),
            magic_len=len(format_struct.magic_bytes),
            header_field_offsets="{" + ", ".join(str(f.offset) for f in format_struct.fields[:10]) + "}",
            header_field_sizes="{" + ", ".join(str(f.size) for f in format_struct.fields[:10]) + "}",
            num_header_fields=min(len(format_struct.fields), 10)
        

    
    def _generate_generic_harness(self) -> str:
        """生成通用 harness"""
        return '''// Generic LibFuzzer harness
#include <stdint.h>
#include <stddef.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Generic parsing - customize for your target
    if (size < 4) return 0;
    
    // Process data
    // Add your parsing logic here
    
    return 0;
}
'''
    
    def _generate_afl_harness(self) -> str:
        """生成 AFL harness"""
        format_struct = FORMAT_STRUCTURES.get(self.config.target_format)
        
        harness_code = '''// AFL harness for {format_name} format parsing
// Generated automatically

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

// Include parser header
// #include "{format_lower}_parser.h"

int parse_{format_lower}(const uint8_t *data, size_t size) {
    // Parsing implementation
    if (size < {min_size}) return 0;
    
    // Check magic
    if (memcmp(data, "{magic_hex}", {magic_len}) != 0) return 0;
    
    // Parse structure
    // ...
    
    return 0;
}

int main(int argc, char **argv) {
    // AFL persistent mode
    #ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
    #endif
    
    // Read from stdin or file
    uint8_t buffer[4096];
    size_t size;
    
    if (argc > 1) {
        // Read from file
        FILE *f = fopen(argv[1], "rb");,
        if (!f) return 1;
        size = fread(buffer, 1, sizeof(buffer), f);
        fclose(f);
    } else {
        // Read from stdin
        size = read(0, buffer, sizeof(buffer));
    }
    
    // Parse
    parse_{format_lower}(buffer, size);
    
    return 0;
}
'''
        
        if format_struct:
            return harness_code.format()
                format_name=format_struct.format_type.value.upper(),
                format_lower=format_struct.format_type.value.lower(),
                min_size=self._get_min_format_size(),
                magic_hex=format_struct.magic_bytes.hex(),
                magic_len=len(format_struct.magic_bytes)
            

        
        return harness_code.format()
            format_name="BINARY",
            format_lower="binary",
            min_size=4,
            magic_hex="",
            magic_len=0
        

    
    def _generate_libfuzzer_build_command(self) -> str:
        """生成 LibFuzzer 编译命令"""
        format_name = self.config.target_format.value.lower()
        
        sanitizer = self.config.sanitizer_options.get('type', 'address')
        
        return f'''# Build LibFuzzer harness
clang -fsanitize=fuzzer,{sanitizer} -g -O1 \
    {format_name}_fuzzer.cpp \
    -o {format_name}_fuzzer

# Or with additional flags:
clang -fsanitize=fuzzer,address,undefined \
    -fsanitize-coverage=trace-pc-guard \
    -g -O1 \
    {format_name}_fuzzer.cpp \
    -o {format_name}_fuzzer
'''
    
    def _generate_libfuzzer_run_command(self) -> str:
        """生成 LibFuzzer 运行命令"""
        format_name = self.config.target_format.value.lower()
        
        return f'''# Run LibFuzzer
./{format_name}_fuzzer \
    -max_len={self.config.max_input_size} \
    -timeout={self.config.timeout_ms} \
    -max_total_time=3600 \
    -artifact_prefix={self.config.output_dir}/ \
    {self.config.output_dir}/corpus/

# With dictionary:
./{format_name}_fuzzer -dict={format_name}.dict ...

# With specific options:
./{format_name}_fuzzer \
    -rss_limit_mb=2048 \
    -jobs=4 \
    -workers=4
'''
    
    def _generate_afl_build_command(self) -> str:
        """生成 AFL 编译命令"""
        format_name = self.config.target_format.value.lower()
        
        return f'''# Build with AFL compiler
afl-gcc -g -O2 {format_name}_fuzzer.c -o {format_name}_fuzzer

# Or with afl-clang-fast:
afl-clang-fast -g -O2 {format_name}_fuzzer.c -o {format_name}_fuzzer
'''
    
    def _generate_afl_run_command(self) -> str:
        """生成 AFL 运行命令"""
        format_name = self.config.target_format.value.lower()
        
        return f'''# Run AFL
afl-fuzz -i {self.config.output_dir}/seed/ \
    -o {self.config.output_dir}/findings/ \
    -m 2048 \
    -t {self.config.timeout_ms} \
    ./{format_name}_fuzzer
'''
    
    def _get_min_format_size(self) -> int:
        """获取最小格式大小"""
        format_struct = FORMAT_STRUCTURES.get(self.config.target_format)
        
        if format_struct:
            # 计算头部大小
            return sum(f.size for f in format_struct.fields)
        
        return 64  # 默认值
    
    def _get_header_field_info(self) -> Tuple[List[int], List[int]]:
        """获取头部字段信息"""
        format_struct = FORMAT_STRUCTURES.get(self.config.target_format)
        
        if format_struct:
            offsets = [f.offset for f in format_struct.fields]
            sizes = [f.size for f in format_struct.fields]
            return offsets, sizes
        
        return [], []
    
    def _generate_seed_files(self) -> List[str]:
        """生成种子文件"""
        seeds = []
        format_struct = FORMAT_STRUCTURES.get(self.config.target_format)
        
        if format_struct:
            # 生成最小有效文件
            min_seed = self._generate_minimal_valid_file(format_struct)
            seeds.append(f"seed_minimal.bin")
            
            # 生成变体
            for i in range(5):
                variant = self._generate_variant_file(format_struct, i)
                seeds.append(f"seed_variant_{i}.bin")
        
        return seeds
    
    def _generate_minimal_valid_file(self, format_struct: FormatStructure) -> bytes:
        """生成最小有效文件"""
        data = bytearray(self._get_min_format_size(

        
        # 写入魔数
        magic = format_struct.magic_bytes
        data[:len(magic)] = magic
        
        # 写入其他必要字段
        for field in format_struct.fields:
            if field.is_critical and field.valid_values:
                # 使用有效值
                valid_val = field.valid_values[0]
                self._write_field_value(data, field, valid_val)
        
        return bytes(data)
    
    def _generate_variant_file(self, format_struct: FormatStructure, variant_index: int) -> bytes:
        """生成变体文件"""
        base_data = bytearray(self._generate_minimal_valid_file(format_struct

        
        # 根据变体索引应用不同的修改
        if variant_index == 0:
            # 修改头部大小
            pass
        elif variant_index == 1:
            # 修改偏移值
            pass
        elif variant_index == 2:
            # 添加额外数据
            base_data.extend(bytes(256

        elif variant_index == 3:
            # 修改字段值
            pass
        elif variant_index == 4:
            # 创建嵌套结构
            pass
        
        return bytes(base_data)
    
    def _write_field_value(self, data: bytearray, field: FormatField, value: Any) -> None:
        """写入字段值"""
        if field.type == 'uint8':
            data[field.offset] = value
        elif field.type == 'uint16':
            struct.pack_into('<H', data, field.offset, value)
        elif field.type == 'uint32':
            struct.pack_into('<I', data, field.offset, value)
        elif field.type == 'uint64':
            struct.pack_into('<Q', data, field.offset, value)
        elif field.type == 'bytes':
            if isinstance(value, bytes):
                data[field.offset:field.offset + len(value)] = value
    
    def generate_dictionary(self) -> List[str]:
        """生成字典"""
        dictionary = []
        format_struct = FORMAT_STRUCTURES.get(self.config.target_format)
        
        if format_struct:
            # 魔数
            dictionary.append(format_struct.magic_bytes.hex(

            
            # 有效值
            for field in format_struct.fields:
                if field.valid_values:
                    for val in field.valid_values[:5]:
                        if isinstance(val, int):
                            # 不同编码
                            dictionary.append(hex(val

                            dictionary.append(str(val

                        elif isinstance(val, bytes):
                            dictionary.append(val.hex(

            
            # 特殊值
            dictionary.extend([)
                "0", "-1", "255", "65535", "0xffffffff",
                "0x7fffffff", "0x80000000",
                "AAAA", "BBBB", "CCCC",
                "deadbeef", "cafebabe"
            ]
        
        return dictionary
    
    def generate_test_cases(self, count: int = 100) -> List[TestCase]:
        """
        生成测试用例
        
        Args:
            count: 测试用例数量
            
        Returns:
            测试用例列表
        """
        test_cases = []
        format_struct = FORMAT_STRUCTURES.get(self.config.target_format)
        
        if not format_struct:
            # 生成随机测试用例
            for i in range(count):
                size = random.randint(64, 4096)
                data = bytes([random.randint(0, 255) for _ in range(size)])
                test_cases.append(TestCase(
                    data=data,
                    description=f"Random test case {i}",
                    mutation_applied="random"
                

            return test_cases
        
        # 结构感知测试用例
        base_file = self._generate_minimal_valid_file(format_struct)
        
        for i in range(count):
            mutation_type = random.choice(list(MutationStrategy

            mutated_data = self._apply_mutation(base_file, format_struct, mutation_type)
            
            test_cases.append(TestCase(
                data=mutated_data,
                description=f"Mutated test case {i}",
                mutation_applied=mutation_type.value,
                metadata={'base_size': len(base_file)}
            

        
        return test_cases
    
    def _apply_mutation(self, data: bytes, format_struct: FormatStructure, strategy: MutationStrategy) -> bytes:
        """应用变异"""
        mutated = bytearray(data)
        
        if strategy == MutationStrategy.RANDOM:
            # 随机字节修改
            for _ in range(random.randint(1, 10)):
                pos = random.randint(0, len(mutated) - 1)
                mutated[pos] = random.randint(0, 255)
        
        elif strategy == MutationStrategy.BIT_FLIP:
            # 位翻转
            for _ in range(random.randint(1, 20)):
                pos = random.randint(0, len(mutated) - 1)
                bit = random.randint(0, 7)
                mutated[pos] ^= (1 << bit)
        
        elif strategy == MutationStrategy.MAGIC_VALUES:
            # 魔数替换
            magic_values = [0, 0xFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                           0x7F, 0x7FFF, 0x7FFFFFFF, 0x80000000,
                           0xDEADBEEF, 0xCAFEBABE, 0x41414141]
            
            pos = random.randint(0, len(mutated) - 8)
            magic = random.choice(magic_values)
            size = min(8, len(mutated) - pos)
            
            for i in range(size):
                mutated[pos + i] = (magic >> (i * 8)) & 0xFF
        
        elif strategy == MutationStrategy.FIELD_TARGETED:
            # 针对特定字段
            if format_struct.fields:
                field = random.choice(format_struct.fields)
                if field.offset + field.size <= len(mutated):
                    for i in range(field.size):
                        mutated[field.offset + i] = random.randint(0, 255)
        
        elif strategy == MutationStrategy.BYTE_INSERT:
            # 字节插入
            pos = random.randint(0, len(mutated

            insert_len = random.randint(1, 16)
            insert_data = bytes([random.randint(0, 255) for _ in range(insert_len)])
            mutated = bytearray(mutated[:pos] + insert_data + mutated[pos:])
        
        elif strategy == MutationStrategy.BYTE_DELETE:
            # 字节删除
            if len(mutated) > 10:
                pos = random.randint(0, len(mutated) - 1)
                delete_len = random.randint(1, min(16, len(mutated) - pos

                mutated = bytearray(mutated[:pos] + mutated[pos + delete_len:])
        
        elif strategy == MutationStrategy.BLOCK_SWAP:
            # 块交换
            if len(mutated) > 32:
                block_size = random.randint(4, min(32, len(mutated) // 2

                pos1 = random.randint(0, len(mutated) - block_size * 2)
                pos2 = pos1 + block_size
                
                block1 = mutated[pos1:pos1 + block_size]
                block2 = mutated[pos2:pos2 + block_size]
                
                mutated[pos1:pos1 + block_size] = block2
                mutated[pos2:pos2 + block_size] = block1
        
        return bytes(mutated)
    
    def save_harness(self, harness: FuzzerHarness, output_dir: str) -> Dict[str, str]:
        """
        保存 Harness 到文件
        
        Args:
            harness: Fuzzer Harness
            output_dir: 输出目录
            
        Returns:
            保存的文件路径
        """
        saved_files = {}
        
        os.makedirs(output_dir, exist_ok=True)
        
        # 保存 harness 代码
        format_name = self.config.target_format.value.lower()
        harness_file = os.path.join(output_dir, f"{format_name}_fuzzer.cpp")
        with open(harness_file, 'w') as f:
            f.write(harness.harness_code)
        saved_files['harness'] = harness_file
        
        # 保存构建脚本
        build_file = os.path.join(output_dir, "build.sh")
        with open(build_file, 'w') as f:
            f.write(harness.build_command)
        saved_files['build_script'] = build_file
        
        # 保存运行脚本
        run_file = os.path.join(output_dir, "run.sh")
        with open(run_file, 'w') as f:
            f.write(harness.run_command)
        saved_files['run_script'] = run_file
        
        # 保存字典
        dict_file = os.path.join(output_dir, f"{format_name}.dict")
        dictionary = self.generate_dictionary()
        with open(dict_file, 'w') as f:
            for entry in dictionary:
                f.write(f"{entry}\n")
        saved_files['dictionary'] = dict_file
        
        # 保存种子文件
        seed_dir = os.path.join(output_dir, "seed")
        os.makedirs(seed_dir, exist_ok=True)
        
        test_cases = self.generate_test_cases(10)
        for i, tc in enumerate(test_cases):
            seed_file = os.path.join(seed_dir, f"seed_{i}.bin")
            with open(seed_file, 'wb') as f:
                f.write(tc.data)
        
        saved_files['seed_dir'] = seed_dir
        
        return saved_files


def generate_format_fuzzer(format_type: str, fuzzer_type: str = 'libfuzzer', output_dir: str = './fuzzer_output', config: Dict[str, Any] = None) -> FuzzerHarness:
    """
    生成文件格式 Fuzzer 便捷函数
    
    Args:
        format_type: 文件格式类型
        fuzzer_type: Fuzzer 类型
        output_dir: 输出目录
        config: 配置参数
        
    Returns:
        Fuzzer Harness
    """
    ft = FileFormatType(format_type.lower(

    fz = FuzzerType(fuzzer_type.lower(

    
    fuzzer_config = FuzzerConfig()
        fuzzer_type=fz,
        target_format=ft,
        output_dir=output_dir
    
    
    if config:
        for key, value in config.items():
            if hasattr(fuzzer_config, key):
                setattr(fuzzer_config, key, value)
    
    generator = FormatFuzzerGenerator(fuzzer_config)
    harness = generator.generate_harness()
    
    # 保存文件
    generator.save_harness(harness, output_dir)
    
    return harness


def generate_test_corpus(format_type: str, count: int = 100, output_dir: str = './corpus') -> List[str]:
    """
    生成测试语料库
    
    Args:
        format_type: 文件格式类型
        count: 测试用例数量
        output_dir: 输出目录
        
    Returns:
        生成的文件路径列表
    """
    ft = FileFormatType(format_type.lower(

    
    config = FuzzerConfig(fuzzer_type=FuzzerType.LIBFUZZER, target_format=ft)
    generator = FormatFuzzerGenerator(config)
    
    test_cases = generator.generate_test_cases(count)
    
    os.makedirs(output_dir, exist_ok=True)
    
    files = []
    for i, tc in enumerate(test_cases):
        file_path = os.path.join(output_dir, f"test_{i:04d}.bin")
        with open(file_path, 'wb') as f:
            f.write(tc.data)
        files.append(file_path)
    
    return files


# 导出主要类和函数
__all__ = [
    'FormatFuzzerGenerator',
    'FuzzerConfig',
    'FuzzerHarness',
    'TestCase',
    'FormatStructure',
    'FormatField',
    'FileFormatType',
    'FuzzerType',
    'MutationStrategy',
    'FORMAT_STRUCTURES',
    'ELF_STRUCTURE',
    'PE_STRUCTURE',
    'MACH_O_STRUCTURE',
    'generate_format_fuzzer',
    'generate_test_corpus'
]))))))))))))))))))))))