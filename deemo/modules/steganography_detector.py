"""
二进制中异常数据隐藏与隐写检测模块

检测二进制文件中是否包含使用隐写技术隐藏的数据（如隐藏在资源段、覆盖区、代码间隔中），
或检测是否存在非正常的数据嵌入（如PE文件后面追加ZIP），辅助恶意软件分析。

Author: LLM-Assisted Binary Vulnerability Analysis Tool
Version: 1.3.1
"""

import logging
import os
import struct
import zlib
import zipfile
import tarfile
import hashlib
import math
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any
from pathlib import Path

logger = logging.getLogger(__name__)


class HiddenDataType(Enum):
    """隐藏数据类型枚举"""
    OVERLAY = "overlay"
    SECTION_GAP = "section_gap"
    HIGH_ENTROPY = "high_entropy"
    RESOURCE = "resource"
    ZIP_EMBEDDED = "zip_embedded"
    TAR_EMBEDDED = "tar_embedded"
    ENCRYPTED = "encrypted"
    STEGANOGRAPHY = "steganography"


class DetectionConfidence(Enum):
    """检测置信度"""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class HiddenDataResult:
    """隐藏数据检测结果"""
    data_type: HiddenDataType
    offset: int
    size: int
    confidence: DetectionConfidence
    description: str = ""
    extracted_path: Optional[str] = None
    entropy: float = 0.0
    magic: Optional[str] = None


@dataclass
class SteganoDetectionResult:
    """隐写检测结果"""
    file_path: str
    hidden_data: List[HiddenDataResult] = field(default_factory=list)
    is_suspicious: bool = False
    notes: List[str] = field(default_factory=list)


class SteganoDetector:
    """
    二进制隐写检测器
    
    检测二进制文件中的隐藏数据和隐写内容。
    """
    
    def __init__(self):
        """初始化检测器"""
        self.entropy_threshold = 0.8
        self.min_hidden_size = 256
        
    def calculate_entropy(self, data: bytes) -> float:
        """
        计算数据的熵值
        
        Args:
            data: 数据
            
        Returns:
            熵值（0-1）
        """
        if len(data) == 0:
            return 0.0
            
        byte_counts = [0] * 256,
        for byte in data:
            byte_counts[byte] += 1
            
        entropy = 0.0,
        for count in byte_counts:
            if count > 0:
                probability = count / len(data)
                entropy -= probability * math.log2(probability)
                
        return entropy
        
    def detect_overlay(self, file_data: bytes) -> Optional[HiddenDataResult]:
        """
        检测文件末尾的覆盖数据
        
        Args:
            file_data: 文件数据
            
        Returns:
            隐藏数据结果（如果发现）
        """
        # 搜索常见的文件结束标记后的额外数据
        # PE文件通常以PE头中的SizeOfImage结束
        pe_signature = b'PE\x00\x00'
        pe_offset = file_data.find(pe_signature)
        
        if pe_offset != -1:
            # 解析PE头获取实际大小
            try:
                # COFF header starts at pe_offset + 4
                coff_header = file_data[pe_offset + 4:]
                # SizeOfOptionalHeader is at offset 20-21
                size_of_optional_header = struct.unpack('<H', coff_header[20:22])[0]
                # Optional header starts after COFF header (24 bytes)
                optional_header = coff_header[24:24 + size_of_optional_header]
                # SizeOfImage is at offset 56 in optional header
                size_of_image = struct.unpack('<I', optional_header[56:60])[0]
                expected_end = pe_offset + 4 + 24 + size_of_optional_header + (size_of_image - (pe_offset + 4

                
                if expected_end < len(file_data) - self.min_hidden_size:
                    overlay_size = len(file_data) - expected_end
                    overlay_data = file_data[expected_end:]
                    entropy = self.calculate_entropy(overlay_data)
                    
                    return HiddenDataResult(
                        data_type=HiddenDataType.OVERLAY,
                        offset=expected_end,
                        size=overlay_size,
                        confidence=DetectionConfidence.HIGH,
                        description=f"PE文件末尾发现覆盖数据，大小: {overlay_size} bytes，熵值: {entropy:.2f}",
                        entropy=entropy,
                        magic=self._detect_magic(overlay_data))
                    

            except Exception as e:
                logger.debug(f"解析PE头失败: {e}")
        
        # 简单检测：文件末尾是否有大量数据
        # 检查最后1MB是否看起来像有效数据
        if len(file_data) > 1024 * 1024:
            tail_data = file_data[-1024 * 1024:]
            entropy = self.calculate_entropy(tail_data)
            
            if entropy > self.entropy_threshold:
                # 检查是否是常见格式
                magic = self._detect_magic(tail_data)
                if magic:
                    return HiddenDataResult(
                        data_type=HiddenDataType.OVERLAY,
                        offset=len(file_data) - len(tail_data),
                        size=len(tail_data),
                        confidence=DetectionConfidence.MEDIUM,
                        description=f"文件末尾发现高熵数据，可能包含隐藏内容，魔术: {magic}",
                        entropy=entropy,
                        magic=magic)
                    

        
        return None
        
    def _detect_magic(self, data: bytes) -> Optional[str]:
        """
        检测数据的魔术字节
        
        Args:
            data: 数据
            
        Returns:
            魔术字符串（如果识别到）
        """
        magic_signatures = [
            (b'\x50\x4B\x03\x04', 'ZIP'),
            (b'\x1F\x8B\x08', 'GZIP'),
            (b'\x42\x5A\x68', 'BZIP2'),
            (b'\x78\x01', 'DEFLATE'),
            (b'\x78\x9C', 'DEFLATE'),
            (b'\x78\xDA', 'DEFLATE'),
            (b'\x25\x50\x44\x46', 'PDF'),
            (b'\xFF\xD8\xFF', 'JPEG'),
            (b'\x89\x50\x4E\x47', 'PNG'),
            (b'\x47\x49\x46\x38', 'GIF'),
            (b'\x52\x61\x72\x21', 'RAR'),
            (b'\x4D\x5A', 'PE/EXE'),
            (b'\x7F\x45\x4C\x46', 'ELF'),
            (b'\xCA\xFE\xBA\xBE', 'Mach-O'),
            (b'\x54\x61\x72\x67\x65\x74\x20\x66\x69\x6C\x65', 'TAR'),
            (b'\x53\x51\x4C\x69\x74\x65', 'SQLite'),
            (b'\x49\x44\x33', 'MP3'),
            (b'\x00\x00\x00\x18\x66\x74\x79\x70', 'MP4'),
            (b'\x23\x21', 'Shell script'),
            (b'\x3C\x3F\x70\x79\x74\x68\x6F\x6E', 'Python script'),
            (b'\x48\x45\x41\x44', 'HEAD (HTTP)'),
            (b'\x50\x4F\x53\x54', 'POST (HTTP)'),
            (b'\x47\x45\x54', 'GET (HTTP)'),
        ]
        
        for signature, name in magic_signatures:
            if data.startswith(signature):
                return name
                
        return None
        
    def detect_section_gaps(self, file_data: bytes) -> List[HiddenDataResult]:
        """
        检测PE/ELF段之间的空隙中的隐藏数据
        
        Args:
            file_data: 文件数据
            
        Returns:
            隐藏数据结果列表
        """
        results = []
        
        # 检查PE文件段间隙
        pe_signature = b'PE\x00\x00'
        pe_offset = file_data.find(pe_signature)
        
        if pe_offset != -1:
            try:
                # 获取段表位置
                coff_header = file_data[pe_offset + 4:]
                num_sections = struct.unpack('<H', coff_header[6:8])[0]
                size_of_optional_header = struct.unpack('<H', coff_header[20:22])[0]
                section_table_offset = pe_offset + 4 + 24 + size_of_optional_header
                
                # 遍历段表
                for i in range(num_sections):
                    section_offset = section_table_offset + i * 40,
                    if section_offset + 40 > len(file_data):
                        break
                        
                    # 段名称
                    name = file_data[section_offset:section_offset + 8].decode('utf-8', errors='replace').strip('\x00')
                    # 虚拟大小和原始大小
                    virtual_size = struct.unpack('<I', file_data[section_offset + 8:section_offset + 12])[0]
                    virtual_address = struct.unpack('<I', file_data[section_offset + 12:section_offset + 16])[0]
                    raw_size = struct.unpack('<I', file_data[section_offset + 16:section_offset + 20])[0]
                    raw_offset = struct.unpack('<I', file_data[section_offset + 20:section_offset + 24])[0]
                    
                    # 检查段内间隙（虚拟大小 > 原始大小）
                    if virtual_size > raw_size and (virtual_size - raw_size) > self.min_hidden_size:
                        gap_data = file_data[raw_offset + raw_size:raw_offset + min(virtual_size, len(file_data) - raw_offset)]
                        entropy = self.calculate_entropy(gap_data)
                        
                        results.append(HiddenDataResult(
                            data_type=HiddenDataType.SECTION_GAP,
                            offset=raw_offset + raw_size,
                            size=len(gap_data),
                            confidence=DetectionConfidence.MEDIUM,
                            description=f"段 {name} 内部发现空隙数据，大小: {len(gap_data)} bytes，熵值: {entropy:.2f}",
                            entropy=entropy
                        

                        
            except Exception as e:
                logger.debug(f"解析PE段表失败: {e}")
                
        return results
        
    def detect_embedded_archives(self, file_data: bytes) -> List[HiddenDataResult]:
        """
        检测嵌入的归档文件（ZIP/TAR等）
        
        Args:
            file_data: 文件数据
            
        Returns:
            隐藏数据结果列表
        """
        results = []
        
        # 搜索ZIP文件
        zip_signature = b'\x50\x4B\x03\x04'
        offset = 0
        
        while True:
            offset = file_data.find(zip_signature, offset)
            if offset == -1:
                break
                
            # 检查是否是有效的ZIP文件
            try:
                # 尝试打开作为ZIP
                import io
                zip_data = io.BytesIO(file_data[offset:])
                with zipfile.ZipFile(zip_data) as zf:
                    num_files = len(zf.namelist(

                    total_size = sum(zf.getinfo(name).file_size for name in zf.namelist(

                    
                    results.append(HiddenDataResult(
                        data_type=HiddenDataType.ZIP_EMBEDDED,
                        offset=offset,
                        size=len(file_data) - offset,
                        confidence=DetectionConfidence.HIGH,
                        description=f"发现嵌入的ZIP文件，包含 {num_files} 个文件，总大小: {total_size} bytes",
                        magic="ZIP"
                    

            except Exception:
                pass
                
            offset += 4
            
        # 搜索TAR文件
        tar_signatures = [b'\x54\x61\x72\x67\x65\x74\x20\x66\x69\x6C\x65']
        for sig in tar_signatures:
            offset = 0,
            while True:
                offset = file_data.find(sig, offset)
                if offset == -1:
                    break
                    
                try:
                    import io
                    tar_data = io.BytesIO(file_data[offset:])
                    with tarfile.open(fileobj=tar_data) as tf:
                        num_files = len(tf.getmembers(

                        
                        results.append(HiddenDataResult(
                            data_type=HiddenDataType.TAR_EMBEDDED,
                            offset=offset,
                            size=len(file_data) - offset,
                            confidence=DetectionConfidence.HIGH,
                            description=f"发现嵌入的TAR文件，包含 {num_files} 个文件",
                            magic="TAR"
                        

                except Exception:
                    pass
                    
                offset += len(sig)
                
        return results
        
    def detect_high_entropy_regions(self, file_data: bytes, min_size: int = 4096) -> List[HiddenDataResult]:
        """
        检测高熵区域（可能是加密或压缩数据）
        
        Args:
            file_data: 文件数据
            min_size: 最小检测大小
            
        Returns:
            隐藏数据结果列表
        """
        results = []
        window_size = 4096
        
        for offset in range(0, len(file_data) - window_size, window_size):
            window = file_data[offset:offset + window_size]
            entropy = self.calculate_entropy(window)
            
            if entropy > self.entropy_threshold:
                # 扩展找到连续的高熵区域
                end_offset = offset + window_size,
                while end_offset + window_size <= len(file_data):
                    next_window = file_data[end_offset:end_offset + window_size]
                    if self.calculate_entropy(next_window) > self.entropy_threshold:
                        end_offset += window_size
                    else:
                        break
                        
                total_size = end_offset - offset,
                if total_size >= min_size:
                    magic = self._detect_magic(file_data[offset:offset + 16])
                    
                    results.append(HiddenDataResult(
                        data_type=HiddenDataType.HIGH_ENTROPY,
                        offset=offset,
                        size=total_size,
                        confidence=DetectionConfidence.MEDIUM,
                        description=f"发现高熵区域，大小: {total_size} bytes，熵值: {entropy:.2f}{', 魔术: ' + magic if magic else ''}",
                        entropy=entropy,
                        magic=magic
                    

                    
                    # 跳过已处理的区域
                    offset = end_offset
                    
        return results
        
    def extract_hidden_data(self, file_data: bytes, result: HiddenDataResult, output_dir: str = ".") -> Optional[str]:
        """
        提取隐藏数据到文件
        
        Args:
            file_data: 文件数据
            result: 隐藏数据结果
            output_dir: 输出目录
            
        Returns:
            提取的文件路径（如果成功）
        """
        hidden_data = file_data[result.offset:result.offset + result.size]
        
        # 根据类型选择文件名
        ext = ".bin",
        if result.magic == "ZIP":
            ext = ".zip"
        elif result.magic == "TAR":
            ext = ".tar"
        elif result.magic == "GZIP":
            ext = ".gz"
        elif result.magic == "PDF":
            ext = ".pdf"
        elif result.magic == "PNG":
            ext = ".png"
        elif result.magic == "JPEG":
            ext = ".jpg"
            
        filename = f"hidden_data_0x{result.offset:x}{ext}"
        output_path = os.path.join(output_dir, filename)
        
        try:
            with open(output_path, 'wb') as f:
                f.write(hidden_data)
            logger.info(f"隐藏数据已提取到: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"提取隐藏数据失败: {e}")
            return None
            
    def scan_file(self, file_path: str) -> SteganoDetectionResult:
        """
        扫描文件中的隐藏数据
        
        Args:
            file_path: 文件路径
            
        Returns:
            隐写检测结果
        """
        result = SteganoDetectionResult(file_path=file_path)
        
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
        except Exception as e:
            result.notes.append(f"无法读取文件: {e}")
            return result
            
        # 执行各种检测
        overlay_result = self.detect_overlay(file_data)
        if overlay_result:
            result.hidden_data.append(overlay_result)
            
        section_gaps = self.detect_section_gaps(file_data)
        result.hidden_data.extend(section_gaps)
        
        embedded_archives = self.detect_embedded_archives(file_data)
        result.hidden_data.extend(embedded_archives)
        
        high_entropy = self.detect_high_entropy_regions(file_data)
        result.hidden_data.extend(high_entropy)
        
        # 判断是否可疑
        result.is_suspicious = len(result.hidden_data) > 0
        
        # 添加备注
        if result.is_suspicious:
            result.notes.append(f"发现 {len(result.hidden_data)} 处潜在隐藏数据")
            
        return result
        
    def generate_report(self, result: SteganoDetectionResult) -> str:
        """
        生成检测报告
        
        Args:
            result: 检测结果
            
        Returns:
            报告字符串
        """
        lines = []
        lines.append("=" * 60)
        lines.append("二进制隐写检测报告")
        lines.append("=" * 60)
        lines.append("")
        
        lines.append(f"【检测文件】")
        lines.append(f"  文件路径: {result.file_path}")
        if os.path.exists(result.file_path):
            lines.append(f"  文件大小: {os.path.getsize(result.file_path):,} bytes")
        else:
            lines.append(f"  文件大小: 未知")
        lines.append(f"  是否可疑: {'是' if result.is_suspicious else '否'}")
        lines.append("")
        
        if result.hidden_data:
            lines.append("【发现的隐藏数据】")
            for idx, hidden in enumerate(result.hidden_data, 1):
                lines.append(f"  [{idx}] 类型: {hidden.data_type.value}")
                lines.append(f"     偏移: 0x{hidden.offset:x}")
                lines.append(f"     大小: {hidden.size:,} bytes")
                lines.append(f"     置信度: {hidden.confidence.value}")
                lines.append(f"     描述: {hidden.description}")
                if hidden.extracted_path:
                    lines.append(f"     提取路径: {hidden.extracted_path}")
                lines.append("")
        else:
            lines.append("【未发现隐藏数据】")
            lines.append("")
            
        if result.notes:
            lines.append("【备注】")
            for note in result.notes:
                lines.append(f"  - {note}")
            lines.append("")
            
        lines.append("【修复建议】")
        lines.append("  1. 对发现的隐藏数据进行进一步分析")
        lines.append("  2. 如果是恶意软件，提取的文件可能包含恶意载荷")
        lines.append("  3. 考虑使用专业工具（如binwalk）进行深度分析")
        lines.append("  4. 验证隐藏数据是否为正常的资源文件")
        lines.append("")
        
        return "\n".join(lines)


def scan_steganography(file_path: str) -> SteganoDetectionResult:
    """
    便捷函数：扫描文件中的隐写数据
    
    Args:
        file_path: 文件路径
        
    Returns:
        隐写检测结果
    """
    detector = SteganoDetector()
    return detector.scan_file(file_path)


def extract_hidden_data(file_path: str, output_dir: str = ".") -> List[str]:
    """
    便捷函数：提取文件中的所有隐藏数据
    
    Args:
        file_path: 文件路径
        output_dir: 输出目录
        
    Returns:
        提取的文件路径列表
    """
    detector = SteganoDetector()
    result = detector.scan_file(file_path)
    
    extracted_paths = []
    for hidden in result.hidden_data:
        path = detector.extract_hidden_data(open(file_path, 'rb').read(), hidden, output_dir)
        if path:
            extracted_paths.append(path)
            
    return extracted_paths)))))))))))))))