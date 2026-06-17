#!/usr/bin/env python3
"""
二进制重打包/捆绑包检测模块

检测二进制文件是否由合法软件和恶意载荷重打包而成（如被注入额外代码的APK、捆绑木马的EXE），
识别原始宿主和附加代码区域，评估重打包风险。

作者: Deemo Security Team
版本: 1.0.0
"""

import os
import sys
import json
import logging
import hashlib
import struct
import re
import tempfile
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any, Union
from datetime import datetime
from pathlib import Path
from enum import Enum

from config import Config

logger = logging.getLogger('deemo.repack_detector')


class RepackType(Enum):
    """重打包类型枚举"""
    NONE = 'none'
    INJECTED_CODE = 'injected_code'
    BUNDLED_PAYLOAD = 'bundled_payload'
    MODIFIED_SECTION = 'modified_section'
    OVERLAY_DATA = 'overlay_data'
    RESOURCE_MODIFICATION = 'resource_modification'
    ENTRY_POINT_HOOK = 'entry_point_hook'
    APK_REPACK = 'apk_repack'
    DOTNET_BUNDLE = 'dotnet_bundle'
    UNKNOWN = 'unknown'


class Severity(Enum):
    """严重程度枚举"""
    SAFE = 'safe'
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    CRITICAL = 'critical'


@dataclass
class SectionInfo:
    """
    节区信息数据结构
    
    Attributes:
        name: 节区名称
        virtual_address: 虚拟地址
        virtual_size: 虚拟大小
        raw_size: 原始大小
        characteristics: 特征属性
        entropy: 熵值
        is_anomalous: 是否异常
    """
    name: str = ''
    virtual_address: int = 0
    virtual_size: int = 0
    raw_size: int = 0
    characteristics: int = 0
    entropy: float = 0.0
    is_anomalous: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'name': self.name,
            'virtual_address': self.virtual_address,
            'virtual_size': self.virtual_size,
            'raw_size': self.raw_size,
            'characteristics': self.characteristics,
            'entropy': self.entropy,
            'is_anomalous': self.is_anomalous,
        }


@dataclass
class Anomaly:
    """
    异常数据结构
    
    Attributes:
        type: 异常类型
        location: 位置
        description: 描述
        severity: 严重程度
        evidence: 证据
    """
    type: str = ''
    location: str = ''
    description: str = ''
    severity: Severity = Severity.MEDIUM
    evidence: str = ''
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'type': self.type,
            'location': self.location,
            'description': self.description,
            'severity': self.severity.value,
            'evidence': self.evidence,
        }


@dataclass
class RepackResult:
    """
    重打包检测结果数据结构
    
    Attributes:
        is_repacked: 是否被重打包
        repack_type: 重打包类型
        severity: 总体严重程度
        original_signature: 原始签名信息
        current_signature: 当前签名信息
        sections: 节区列表
        anomalies: 异常列表
        injected_regions: 注入区域列表
        overlay_size: 覆盖数据大小
        entry_point: 入口点
        original_entry_point: 原始入口点（如果检测到）
        risk_score: 风险评分
        confidence: 置信度
    """
    is_repacked: bool = False
    repack_type: RepackType = RepackType.NONE
    severity: Severity = Severity.SAFE
    original_signature: str = ''
    current_signature: str = ''
    sections: List[SectionInfo] = field(default_factory=list)
    anomalies: List[Anomaly] = field(default_factory=list)
    injected_regions: List[Dict[str, Any]] = field(default_factory=list)
    overlay_size: int = 0
    entry_point: int = 0
    original_entry_point: int = 0
    risk_score: float = 0.0
    confidence: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'is_repacked': self.is_repacked,
            'repack_type': self.repack_type.value,
            'severity': self.severity.value,
            'original_signature': self.original_signature,
            'current_signature': self.current_signature,
            'sections': [s.to_dict() for s in self.sections],
            'anomalies': [a.to_dict() for a in self.anomalies],
            'injected_regions': self.injected_regions,
            'overlay_size': self.overlay_size,
            'entry_point': self.entry_point,
            'original_entry_point': self.original_entry_point,
            'risk_score': self.risk_score,
            'confidence': self.confidence,
        }


@dataclass
class RepackConfig:
    """
    重打包检测配置
    
    Attributes:
        check_overlay: 是否检查覆盖数据
        check_sections: 是否检查节区异常
        check_entry_point: 是否检查入口点
        check_resources: 是否检查资源修改
        check_signature: 是否检查签名一致性
        entropy_threshold: 熵值阈值（用于检测加密/压缩数据）
        known_signatures_db: 已知签名数据库路径
        compare_with_original: 是否与原始版本对比
        original_file_path: 原始文件路径（用于对比）
    """
    check_overlay: bool = True
    check_sections: bool = True
    check_entry_point: bool = True
    check_resources: bool = True
    check_signature: bool = True
    entropy_threshold: float = 7.0
    known_signatures_db: str = './data/known_signatures.json'
    compare_with_original: bool = False
    original_file_path: str = ''
    
    def validate(self) -> bool:
        """验证配置"""
        return True


class RepackDetector:
    """
    二进制重打包检测器
    
    检测二进制文件是否由合法软件和恶意载荷重打包而成，
    识别原始宿主和附加代码区域，评估重打包风险。
    
    Attributes:
        config: 检测配置
        known_signatures: 已知签名数据库
    """
    
    # 异常节区名称模式
    ANOMALOUS_SECTION_NAMES = [
        '.newsec',
        '.inject',
        '.payload',
        '.malware',
        '.patch',
        '.crack',
        '.keygen',
        '.data1',  # 非标准名称
        '.upx',    # UPX压缩标记
        '.adata',  # ASPack标记
    ]
    
    # 常见入口点Hook模式
    ENTRY_HOOK_PATTERNS = [
        b'\xEB',  # JMP short
        b'\xE9',  # JMP near
        b'\xFF\x25',  # JMP indirect
        b'\x68',  # PUSH
        b'\x60',  # PUSHA
    ]
    
    # 已知合法软件签名（示例）
    KNOWN_GOOD_SIGNATURES = {
        'Microsoft': ['Microsoft Corporation', 'Microsoft Windows'],
        'Adobe': ['Adobe Systems Incorporated'],
        'Google': ['Google LLC', 'Google Inc'],
        'Apple': ['Apple Inc'],
    }
    
    def __init__(self, config: Optional[RepackConfig] = None):
        """
        初始化重打包检测器
        
        Args:
            config: 检测配置
        """
        self.config = config or RepackConfig()
        self.known_signatures: Dict[str, Any] = {}
        
        # 加载已知签名数据库
        self._load_known_signatures()
        
        logger.info("[Repack] 初始化重打包检测器")
    
    def _load_known_signatures(self) -> None:
        """加载已知签名数据库"""
        try:
            if os.path.exists(self.config.known_signatures_db):
                with open(self.config.known_signatures_db, 'r', encoding='utf-8') as f:
                    self.known_signatures = json.load(f)
                logger.info(f"[Repack] 加载了 {len(self.known_signatures)} 个已知签名")
        except Exception as e:
            logger.warning(f"[Repack] 加载签名数据库失败: {e}")
    
    def detect(self, file_path: str) -> RepackResult:
        """
        检测文件是否被重打包
        
        Args:
            file_path: 文件路径
            
        Returns:
            检测结果
        """
        # 路径安全校验
        file_path = os.path.abspath(file_path)
        if not os.path.exists(file_path):
            logger.error(f"[Repack] 文件不存在: {file_path}")
            return RepackResult()
        
        logger.info(f"[Repack] 检测文件: {file_path}")
        
        result = RepackResult()
        
        # 读取文件
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        # 检测文件类型
        file_type = self._detect_file_type(file_data)
        
        if file_type == 'pe':
            result = self._analyze_pe(file_path, file_data)
        elif file_type == 'elf':
            result = self._analyze_elf(file_path, file_data)
        elif file_type == 'apk':
            result = self._analyze_apk(file_path, file_data)
        elif file_type == 'dex':
            result = self._analyze_dex(file_path, file_data)
        else:
            result = self._analyze_generic(file_path, file_data)
        
        # 计算风险评分
        result.risk_score = self._calculate_risk_score(result)
        
        # 与原始版本对比（如果配置）
        if self.config.compare_with_original and self.config.original_file_path:
            result = self._compare_with_original(result, file_path, self.config.original_file_path)
        
        return result
    
    def _detect_file_type(self, file_data: bytes) -> str:
        """
        检测文件类型
        
        Args:
            file_data: 文件数据
            
        Returns:
            文件类型字符串
        """
        # PE文件
        if file_data[:2] == b'MZ':
            return 'pe'
        
        # ELF文件
        if file_data[:4] == b'\x7fELF':
            return 'elf'
        
        # APK/DEX文件
        if file_data[:4] == b'dex\n':
            return 'dex'
        if file_data[:4] == b'PK\x03\x04':  # ZIP格式，可能是APK,
            return 'apk'
        
        # Mach-O文件
        if file_data[:4] in [b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe']:
            return 'macho'
        
        return 'unknown'
    
    def _analyze_pe(self, file_path: str, file_data: bytes) -> RepackResult:
        """
        分析PE文件
        
        Args:
            file_path: 文件路径
            file_data: 文件数据
            
        Returns:
            检测结果
        """
        result = RepackResult()
        
        try:
            # 解析PE头
            pe_header_offset = struct.unpack('<I', file_data[0x3C:0x40])[0]
            
            if file_data[pe_header_offset:pe_header_offset+4] != b'PE\x00\x00':
                return result
            
            # 获取入口点
            entry_point = struct.unpack('<I', file_data[pe_header_offset+40:pe_header_offset+44])[0]
            result.entry_point = entry_point
            
            # 解析节区
            num_sections = struct.unpack('<H', file_data[pe_header_offset+6:pe_header_offset+8])[0]
            optional_header_size = struct.unpack('<H', file_data[pe_header_offset+20:pe_header_offset+22])[0]
            
            section_table_offset = pe_header_offset + 24 + optional_header_size
            
            for i in range(num_sections):
                section_offset = section_table_offset + i * 40
                section_data = file_data[section_offset:section_offset+40]
                
                section_name = section_data[:8].rstrip(b'\x00').decode('latin-1', errors='ignore')
                virtual_size = struct.unpack('<I', section_data[8:12])[0]
                virtual_address = struct.unpack('<I', section_data[12:16])[0]
                raw_size = struct.unpack('<I', section_data[16:20])[0]
                characteristics = struct.unpack('<I', section_data[36:40])[0]
                
                # 计算熵值
                raw_offset = struct.unpack('<I', section_data[20:24])[0]
                if raw_offset + raw_size <= len(file_data):
                    section_bytes = file_data[raw_offset:raw_offset+raw_size]
                    entropy = self._calculate_entropy(section_bytes)
                else:
                    entropy = 0.0
                
                section_info = SectionInfo()
                    name=section_name,
                    virtual_address=virtual_address,
                    virtual_size=virtual_size,
                    raw_size=raw_size,
                    characteristics=characteristics,
                    entropy=entropy,
                    is_anomalous=self._is_section_anomalous(section_name, entropy, raw_size, virtual_size),
                
                
                result.sections.append(section_info)
                
                # 检查异常节区
                if section_info.is_anomalous:
                    anomaly = Anomaly()
                        type='anomalous_section',
                        location=f"节区 {section_name}",
                        description=f"发现异常节区: {section_name}",
                        severity=Severity.HIGH,
                        evidence=f"熵值={entropy:.2f}, 大小差异={abs(raw_size - virtual_size)}",
                    
                    result.anomalies.append(anomaly)
            
            # 检查入口点
            if self.config.check_entry_point:
                self._check_entry_point(result, file_data, entry_point)
            
            # 检查覆盖数据
            if self.config.check_overlay:
                self._check_overlay(result, file_data, pe_header_offset, num_sections, section_table_offset)
            
            # 检查签名一致性
            if self.config.check_signature:
                self._check_signature_consistency(result, file_path, file_data)
            
            # 综合判断
            if result.anomalies:
                result.is_repacked = True
                result.repack_type = self._determine_repack_type(result)
                result.severity = self._determine_severity(result)
            
        except Exception as e:
            logger.error(f"[Repack] PE分析失败: {e}")
        
        return result
    
    def _analyze_elf(self, file_path: str, file_data: bytes) -> RepackResult:
        """
        分析ELF文件
        
        Args:
            file_path: 文件路径
            file_data: 文件数据
            
        Returns:
            检测结果
        """
        result = RepackResult()
        
        try:
            # 解析ELF头
            if file_data[:4] != b'\x7fELF':
                return result
            
            # 获取入口点
            is_64bit = file_data[4] == 2,
            if is_64bit:
                entry_point = struct.unpack('<Q', file_data[24:32])[0]
                section_header_offset = struct.unpack('<Q', file_data[40:48])[0]
                num_sections = struct.unpack('<H', file_data[60:62])[0]
                section_header_entry_size = struct.unpack('<H', file_data[58:60])[0]
            else:
                entry_point = struct.unpack('<I', file_data[24:28])[0]
                section_header_offset = struct.unpack('<I', file_data[32:36])[0]
                num_sections = struct.unpack('<H', file_data[48:50])[0]
                section_header_entry_size = struct.unpack('<H', file_data[46:48])[0]
            
            result.entry_point = entry_point
            
            # 解析节区
            for i in range(num_sections):
                section_offset = section_header_offset + i * section_header_entry_size,
                if section_offset + section_header_entry_size > len(file_data):
                    break
                
                if is_64bit:
                    section_data = file_data[section_offset:section_offset+64]
                    name_idx = struct.unpack('<I', section_data[0:4])[0]
                    section_type = struct.unpack('<I', section_data[4:8])[0]
                    section_addr = struct.unpack('<Q', section_data[16:24])[0]
                    section_offset_raw = struct.unpack('<Q', section_data[24:32])[0]
                    section_size = struct.unpack('<Q', section_data[32:40])[0]
                else:
                    section_data = file_data[section_offset:section_offset+40]
                    name_idx = struct.unpack('<I', section_data[0:4])[0]
                    section_type = struct.unpack('<I', section_data[4:8])[0]
                    section_addr = struct.unpack('<I', section_data[12:16])[0]
                    section_offset_raw = struct.unpack('<I', section_data[16:20])[0]
                    section_size = struct.unpack('<I', section_data[20:24])[0]
                
                # 计算熵值
                if section_offset_raw + section_size <= len(file_data):
                    section_bytes = file_data[section_offset_raw:section_offset_raw+section_size]
                    entropy = self._calculate_entropy(section_bytes)
                else:
                    entropy = 0.0
                
                section_info = SectionInfo()
                    name=f"section_{i}",
                    virtual_address=section_addr,
                    virtual_size=section_size,
                    raw_size=section_size,
                    entropy=entropy,
                    is_anomalous=entropy > self.config.entropy_threshold,
                
                
                result.sections.append(section_info)
            
            # 检查异常
            for section in result.sections:
                if section.is_anomalous:
                    anomaly = Anomaly()
                        type='anomalous_section',
                        location=f"节区 {section.name}",
                        description=f"发现高熵节区",
                        severity=Severity.MEDIUM,
                        evidence=f"熵值={section.entropy:.2f}",
                    
                    result.anomalies.append(anomaly)
            
            if result.anomalies:
                result.is_repacked = True
                result.repack_type = RepackType.MODIFIED_SECTION
            
        except Exception as e:
            logger.error(f"[Repack] ELF分析失败: {e}")
        
        return result
    
    def _analyze_apk(self, file_path: str, file_data: bytes) -> RepackResult:
        """
        分析APK文件
        
        Args:
            file_path: 文件路径
            file_data: 文件数据
            
        Returns:
            检测结果
        """
        result = RepackResult()
        result.repack_type = RepackType.APK_REPACK
        
        try:
            # APK是ZIP格式，检查ZIP结构
            # 查找DEX文件
            
            # 检查签名
            if self.config.check_signature:
                self._check_apk_signature(result, file_path)
            
            # 检查是否有多个DEX文件（可能是注入）
            dex_count = file_data.count(b'dex\n035')
            if dex_count > 1:
                anomaly = Anomaly()
                    type='multiple_dex',
                    location='APK内部',
                    description=f'发现多个DEX文件: {dex_count}个',
                    severity=Severity.HIGH,
                    evidence='可能包含注入的恶意代码',
                
                result.anomalies.append(anomaly)
                result.is_repacked = True
            
        except Exception as e:
            logger.error(f"[Repack] APK分析失败: {e}")
        
        return result
    
    def _analyze_dex(self, file_path: str, file_data: bytes) -> RepackResult:
        """
        分析DEX文件
        
        Args:
            file_path: 文件路径
            file_data: 文件数据
            
        Returns:
            检测结果
        """
        result = RepackResult()
        
        try:
            # DEX文件头解析
            if file_data[:4] != b'dex\n':
                return result
            
            # 检查是否有注入的类
            # 查找字符串表中的可疑类名
            suspicious_classes = [
                'Lcom/malware',
                'Lcom/trojan',
                'Lcom/spyware',
                'Landroid/hook',
            ]
            
            for suspicious in suspicious_classes:
                if suspicious.encode() in file_data:
                    anomaly = Anomaly()
                        type='suspicious_class',
                        location='DEX字符串表',
                        description=f'发现可疑类名: {suspicious}',
                        severity=Severity.HIGH,
                        evidence='可能是注入的恶意代码',
                    
                    result.anomalies.append(anomaly)
                    result.is_repacked = True
            
        except Exception as e:
            logger.error(f"[Repack] DEX分析失败: {e}")
        
        return result
    
    def _analyze_generic(self, file_path: str, file_data: bytes) -> RepackResult:
        """
        通用文件分析
        
        Args:
            file_path: 文件路径
            file_data: 文件数据
            
        Returns:
            检测结果
        """
        result = RepackResult()
        
        # 计算整体熵值
        overall_entropy = self._calculate_entropy(file_data)
        
        if overall_entropy > self.config.entropy_threshold:
            anomaly = Anomaly()
                type='high_entropy',
                location='整个文件',
                description=f'文件整体熵值过高: {overall_entropy:.2f}',
                severity=Severity.MEDIUM,
                evidence='可能是加密或压缩的恶意载荷',
            
            result.anomalies.append(anomaly)
        
        return result
    
    def _calculate_entropy(self, data: bytes) -> float:
        """
        计算数据熵
        
        Args:
            data: 数据字节
            
        Returns:
            熵值
        """
        if not data:
            return 0.0
        
        byte_counts = [0] * 256,
        for byte in data:
            byte_counts[byte] += 1
        
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _is_section_anomalous(self, name: str, entropy: float, raw_size: int, virtual_size: int) -> bool:
        """
        检查节区是否异常
        
        Args:
            name: 节区名称
            entropy: 熵值
            raw_size: 原始大小
            virtual_size: 虚拟大小
            
        Returns:
            是否异常
        """
        # 检查异常名称
        for anomalous_name in self.ANOMALOUS_SECTION_NAMES:
            if anomalous_name.lower() in name.lower():
                return True
        
        # 检查高熵值
        if entropy > self.config.entropy_threshold:
            return True
        
        # 检查大小差异过大
        if raw_size > 0 and virtual_size > 0:
            size_ratio = abs(raw_size - virtual_size) / max(raw_size, virtual_size)
            if size_ratio > 0.5:
                return True
        
        return False
    
    def _check_entry_point(self, result: RepackResult, file_data: bytes, entry_point: int) -> None:
        """
        检查入口点
        
        Args:
            result: 检测结果
            file_data: 文件数据
            entry_point: 入口点
        """
        # 检查入口点是否在异常位置
        # 正常入口点通常在.text节
        
        text_section = None,
        for section in result.sections:
            if section.name == '.text':
                text_section = section
                break
        
        if text_section:
            # 检查入口点是否在.text节内
            if entry_point < text_section.virtual_address or \
               entry_point > text_section.virtual_address + text_section.virtual_size:
                anomaly = Anomaly()
                    type='entry_point_outside_text',
                    location=f'入口点 0x{entry_point:x}',
                    description='入口点不在.text节内',
                    severity=Severity.HIGH,
                    evidence=f'入口点=0x{entry_point:x}, .text范围=0x{text_section.virtual_address:x}-0x{text_section.virtual_address+text_section.virtual_size:x}',
                
                result.anomalies.append(anomaly)
                result.is_repacked = True
        
        # 检查入口点代码是否是Hook
        # 需要找到入口点在文件中的实际偏移
        # 简化实现：假设入口点在.text节开头附近
    
    def _check_overlay(self, result: RepackResult, file_data: bytes, pe_header_offset: int, num_sections: int, section_table_offset: int) -> None:
        """
        检查覆盖数据
        
        Args:
            result: 检测结果
            file_data: 文件数据
            pe_header_offset: PE头偏移
            num_sections: 节数量
            section_table_offset: 节表偏移
        """
        # 计算最后一个节的结束位置
        last_section_end = 0
        
        for i in range(num_sections):
            section_offset = section_table_offset + i * 40
            section_data = file_data[section_offset:section_offset+40]
            raw_offset = struct.unpack('<I', section_data[20:24])[0]
            raw_size = struct.unpack('<I', section_data[16:20])[0]
            section_end = raw_offset + raw_size,
            if section_end > last_section_end:
                last_section_end = section_end
        
        # 检查文件末尾是否有额外数据
        overlay_size = len(file_data) - last_section_end
        
        if overlay_size > 0:
            result.overlay_size = overlay_size
            
            if overlay_size > 1024:  # 大于1KB的覆盖数据
                anomaly = Anomaly()
                    type='overlay_data',
                    location=f'文件末尾',
                    description=f'发现覆盖数据: {overlay_size}字节',
                    severity=Severity.MEDIUM,
                    evidence=f'文件大小={len(file_data)}, 最后节结束={last_section_end}',
                
                result.anomalies.append(anomaly)
                
                # 检查覆盖数据的熵值
                overlay_data = file_data[last_section_end:]
                overlay_entropy = self._calculate_entropy(overlay_data)
                
                if overlay_entropy > self.config.entropy_threshold:
                    anomaly.severity = Severity.HIGH
                    anomaly.description = f'发现加密/压缩的覆盖数据: {overlay_size}字节'
    
    def _check_signature_consistency(self, result: RepackResult, file_path: str, file_data: bytes) -> None:
        """
        检查签名一致性
        
        Args:
            result: 检测结果
            file_path: 文件路径
            file_data: 文件数据
        """
        # 查找安全目录
        pe_header_offset = struct.unpack('<I', file_data[0x3C:0x40])[0]
        security_dir_entry_offset = pe_header_offset + 24 + 96 + 11 * 8
        
        if security_dir_entry_offset + 8 <= len(file_data):
            rva, size = struct.unpack('<II', file_data[security_dir_entry_offset:security_dir_entry_offset + 8])
            
            if rva != 0 and size != 0:
                # 文件有签名
                result.current_signature = f"签名存在，大小={size}字节"
                
                # 检查签名是否在已知签名数据库中
                # 简化实现
            else:
                # 文件无签名
                result.current_signature = "无签名"
        
        # 检查是否有原始签名痕迹
        # 如果文件声称是知名软件但没有签名，可能是重打包
    
    def _check_apk_signature(self, result: RepackResult, file_path: str) -> None:
        """
        检查APK签名
        
        Args:
            result: 检测结果
            file_path: 文件路径
        """
        # APK签名检查
        # 简化实现
        pass
    
    def _determine_repack_type(self, result: RepackResult) -> RepackType:
        """
        确定重打包类型
        
        Args:
            result: 检测结果
            
        Returns:
            重打包类型
        """
        for anomaly in result.anomalies:
            if anomaly.type == 'anomalous_section':
                return RepackType.INJECTED_CODE
            elif anomaly.type == 'overlay_data':
                return RepackType.OVERLAY_DATA
            elif anomaly.type == 'entry_point_outside_text':
                return RepackType.ENTRY_POINT_HOOK
            elif anomaly.type == 'multiple_dex':
                return RepackType.APK_REPACK
        
        return RepackType.UNKNOWN
    
    def _determine_severity(self, result: RepackResult) -> Severity:
        """
        确定严重程度
        
        Args:
            result: 检测结果
            
        Returns:
            严重程度
        """
        high_count = sum(1 for a in result.anomalies if a.severity == Severity.HIGH)
        critical_count = sum(1 for a in result.anomalies if a.severity == Severity.CRITICAL)
        
        if critical_count > 0:
            return Severity.CRITICAL
        elif high_count > 1:
            return Severity.HIGH
        elif high_count > 0:
            return Severity.MEDIUM
        elif result.anomalies:
            return Severity.LOW
        else:
            return Severity.SAFE
    
    def _calculate_risk_score(self, result: RepackResult) -> float:
        """
        计算风险评分
        
        Args:
            result: 检测结果
            
        Returns:
            风险评分（0-100）
        """
        score = 0.0
        
        # 异常数量
        score += len(result.anomalies) * 10
        
        # 严重程度权重
        severity_weights = {
            Severity.CRITICAL: 40,
            Severity.HIGH: 30,
            Severity.MEDIUM: 20,
            Severity.LOW: 10,
            Severity.SAFE: 0,
        }
        
        for anomaly in result.anomalies:
            score += severity_weights.get(anomaly.severity, 0)
        
        # 覆盖数据大小权重
        if result.overlay_size > 0:
            score += min(result.overlay_size / 1024, 20)
        
        # 置信度调整
        result.confidence = min(score / 100, 1.0)
        
        return min(score, 100)
    
    def _compare_with_original(self, result: RepackResult, current_file: str, original_file: str) -> RepackResult:
        """
        与原始版本对比
        
        Args:
            result: 当前检测结果
            current_file: 当前文件路径
            original_file: 原始文件路径
            
        Returns:
            更新的检测结果
        """
        try:
            # 计算文件哈希
            with open(current_file, 'rb') as f:
                current_hash = hashlib.sha256(f.read()).hexdigest()
            
            with open(original_file, 'rb') as f:
                original_hash = hashlib.sha256(f.read()).hexdigest()
            
            if current_hash != original_hash:
                anomaly = Anomaly()
                    type='hash_difference',
                    location='整个文件',
                    description='文件哈希与原始版本不同',
                    severity=Severity.HIGH,
                    evidence=f'当前={current_hash[:16]}..., 原始={original_hash[:16]}...',
                
                result.anomalies.append(anomaly)
                result.is_repacked = True
                result.confidence = 1.0
            
        except Exception as e:
            logger.warning(f"[Repack] 与原始版本对比失败: {e}")
        
        return result
    
    def generate_report(self, result: RepackResult, file_path: str) -> Dict[str, Any]:
        """
        生成检测报告
        
        Args:
            result: 检测结果
            file_path: 文件路径
            
        Returns:
            报告字典
        """
        report = {
            'file_path': os.path.basename(file_path),
            'analysis_time': datetime.now().isoformat(),
            'is_repacked': result.is_repacked,
            'repack_type': result.repack_type.value,
            'severity': result.severity.value,
            'risk_score': result.risk_score,
            'confidence': result.confidence,
            'sections': [s.to_dict() for s in result.sections],
            'anomalies': [a.to_dict() for a in result.anomalies],
            'overlay_size': result.overlay_size,
            'entry_point': result.entry_point,
            'recommendation': self._generate_recommendation(result),
        }
        
        return report
    
    def _generate_recommendation(self, result: RepackResult) -> str:
        """
        生成安全建议
        
        Args:
            result: 检测结果
            
        Returns:
            建议字符串
        """
        if not result.is_repacked:
            return "文件未被检测到重打包迹象，可信度较高"
        
        recommendations = []
        
        if result.repack_type == RepackType.INJECTED_CODE:
            recommendations.append("发现注入代码，建议进一步分析注入区域的内容")
        
        if result.repack_type == RepackType.OVERLAY_DATA:
            recommendations.append("发现覆盖数据，建议提取并分析覆盖数据内容")
        
        if result.repack_type == RepackType.ENTRY_POINT_HOOK:
            recommendations.append("入口点被修改，建议分析入口点跳转目标")
        
        if result.severity in [Severity.HIGH, Severity.CRITICAL]:
            recommendations.append("高风险文件，建议不要运行")
        
        return '; '.join(recommendations) if recommendations else "建议进一步分析"
    
    def save_report(self, result: RepackResult, file_path: str, output_path: Optional[str] = None) -> str:
        """
        保存检测报告
        
        Args:
            result: 检测结果
            file_path: 目标文件路径
            output_path: 输出路径
            
        Returns:
            保存的文件路径
        """
        if not output_path:
            output_dir = './reports/repack'
            os.makedirs(output_dir, exist_ok=True)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"repack_report_{timestamp}.json"
            output_path = os.path.join(output_dir, filename)
        
        report = self.generate_report(result, file_path)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        logger.info(f"[Repack] 报告已保存: {output_path}")
        return output_path
    
    def analyze(self, file_path: str) -> Dict[str, Any]:
        """
        执行完整分析
        
        Args:
            file_path: 文件路径
            
        Returns:
            分析结果
        """
        result = self.detect(file_path)
        report = self.generate_report(result, file_path)
        return report


# 导入math模块
import math


def create_repack_detector(**kwargs) -> RepackDetector:
    """
    创建重打包检测器的便捷函数
    
    Args:
        **kwargs: 配置参数
        
    Returns:
        RepackDetector实例
    """
    config = RepackConfig(**kwargs)
    return RepackDetector(config