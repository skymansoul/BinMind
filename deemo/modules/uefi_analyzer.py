#!/usr/bin/env python3
"""
UEFI 固件深度分析与 SMM 漏洞检测模块

功能：
1. 解析 UEFI BIOS 映像（.rom/.fd 格式）
2. 提取 Firmware Volume、DXE/SMM 模块（PE/COFF）
3. SMM 特定漏洞检测（CommBuffer 验证、SMRAM 泄露、SMI 处理函数安全）
4. 模块上下文分析（GUID、依赖关系）
5. 与现有 PE 分析流水线集成

依赖：uefi_firmware（可选）、pefile
"""

import os
import re
import struct
import logging
import hashlib
import tempfile
import shutil
import json
from typing import Dict, Any, List, Optional, Tuple, BinaryIO
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from collections import defaultdict

logger = logging.getLogger(__name__)

# UEFI 固件解析器可用性检查
UEFI_FIRMWARE_AVAILABLE = False
try:
    import uefi_firmware
    UEFI_FIRMWARE_AVAILABLE = True
    logger.info("uefi_firmware 包已加载，UEFI 解析功能可用")
except ImportError:
    logger.warning("uefi_firmware 未安装，将使用内置解析器。安装: pip install uefi_firmware")

# PE 文件解析
PEFILE_AVAILABLE = False
try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    logger.warning("pefile 未安装，PE 模块分析受限。安装: pip install pefile")


# ==================== UEFI 常量定义 ====================

# UEFI 文件类型
UEFI_FILE_TYPES = {
    0x01: 'EFI_FV_FILETYPE_RAW',
    0x02: 'EFI_FV_FILETYPE_FREEFORM',
    0x03: 'EFI_FV_FILETYPE_SECURITY_CORE',
    0x04: 'EFI_FV_FILETYPE_PEI_CORE',
    0x05: 'EFI_FV_FILETYPE_DXE_CORE',
    0x06: 'EFI_FV_FILETYPE_PEIM',
    0x07: 'EFI_FV_FILETYPE_DRIVER',
    0x08: 'EFI_FV_FILETYPE_COMBINED_PEIM_DRIVER',
    0x09: 'EFI_FV_FILETYPE_APPLICATION',
    0x0A: 'EFI_FV_FILETYPE_MM',
    0x0B: 'EFI_FV_FILETYPE_MM_CORE',
    0x0C: 'EFI_FV_FILETYPE_MM_STANDALONE',
    0x0D: 'EFI_FV_FILETYPE_MM_CORE_STANDALONE',
    0xE0: 'EFI_FV_FILETYPE_FFS_PAD',
}

# SMM 相关危险函数
SMM_DANGEROUS_FUNCTIONS = [
    # CommBuffer 相关
    'SmmCommunicate',
    'SmmIsCommunicateBufferValid',
    'SmramIsValid',
    
    # 内存操作
    'SmmCopyMem',
    'SmmSetMem',
    'SmmAllocatePool',
    'SmmFreePool',
    
    # SMI 处理
    'SmmRegisterHandler',
    'SmmUnregisterHandler',
    'SmiHandler',
    
    # 外部调用
    'SmmCallFunction',
    'SmmEntryPoint',
    
    # SMRAM 配置
    'SmmOpenSmram',
    'SmmCloseSmram',
    'SmmLockSmram',
    
    # DMA 相关
    'DmaMap',
    'DmaUnmap',
    'DmaAllocateBuffer',
]

# SMM 漏洞类型
SMM_VULN_TYPES = {
    'COMMBUFFER_VALIDATION_MISSING': {
        'name': 'CommBuffer 验证缺失',
        'severity': 'Critical',
        'description': 'SMM 驱动未正确验证通信缓冲区的来源和大小',
        'cwe': 'CWE-20'
    },
    'SMRAM_LEAK': {
        'name': 'SMRAM 泄露',
        'severity': 'Critical',
        'description': 'SMRAM 内容可能被 DMA 或其他方式访问',
        'cwe': 'CWE-200'
    },
    'UNSAFE_EXTERNAL_CALL': {
        'name': '不安全的外部调用',
        'severity': 'High',
        'description': 'SMI 处理函数中的外部调用可能被利用',
        'cwe': 'CWE-822'
    },
    'TOCTOU_IN_SMI': {
        'name': 'SMI 中的 TOCTOU',
        'severity': 'High',
        'description': 'SMI 处理函数存在时间检查/时间使用漏洞',
        'cwe': 'CWE-367'
    },
    'PRIVILEGE_ESCALATION': {
        'name': 'SMM 权限提升',
        'severity': 'Critical',
        'description': '攻击者可利用 SMM 驱动漏洞获取 SMM 权限',
        'cwe': 'CWE-269'
    },
    'INSUFFICIENT_INPUT_VALIDATION': {
        'name': '输入验证不足',
        'severity': 'High',
        'description': 'SMM 驱动未充分验证来自外部的输入',
        'cwe': 'CWE-20'
    },
}


@dataclass
class UEFIModuleInfo:
    """UEFI 模块信息数据类"""
    name: str = ''
    guid: str = ''
    file_type: str = ''
    file_type_id: int = 0
    is_smm: bool = False
    is_dxe: bool = False
    is_pei: bool = False
    pe_path: Optional[str] = None
    size: int = 0
    offset: int = 0
    dependencies: List[str] = field(default_factory=list)
    protocols_used: List[str] = field(default_factory=list)
    protocols_produced: List[str] = field(default_factory=list)
    smi_handlers: List[str] = field(default_factory=list)
    dangerous_functions: List[str] = field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FirmwareVolumeInfo:
    """Firmware Volume 信息数据类"""
    name: str = ''
    guid: str = ''
    size: int = 0
    offset: int = 0
    file_count: int = 0
    modules: List[UEFIModuleInfo] = field(default_factory=list)
    fv_type: str = ''


class UEFIFirmwareAnalyzer:
    """
    UEFI 固件分析器
    
    功能：
    - 解析 UEFI BIOS 映像
    - 提取 Firmware Volume 和模块
    - SMM 漏洞检测
    - 生成分析报告
    
    Attributes:
        firmware_path: 固件文件路径
        output_dir: 输出目录
        modules: 提取的模块列表
        firmware_volumes: Firmware Volume 列表
    """
    
    # UEFI GUID 格式
    GUID_FORMAT = re.compile(
        r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    )
    
    # UEFI 签名
    UEFI_SIGNATURES = {
        'FV': b'_FVH',
        'FFS': b'\x00\x00\x00\x00',  # FFS 文件头前4字节为0
        'PE': b'MZ',
        'TE': b'VZ',  # Terse Executable
    }
    
    def __init__(
        self,
        firmware_path: str,
        output_dir: Optional[str] = None,
        extract_modules: bool = True,
        analyze_smm: bool = True
    ):
        """
        初始化 UEFI 固件分析器
        
        Args:
            firmware_path: UEFI 固件文件路径 (.rom, .fd, .bin)
            output_dir: 模块提取输出目录（可选）
            extract_modules: 是否提取 PE/TE 模块到文件
            analyze_smm: 是否执行 SMM 漏洞检测
        """
        self.firmware_path = firmware_path
        self.output_dir = output_dir or tempfile.mkdtemp(prefix='uefi_extract_')
        self.extract_modules = extract_modules
        self.analyze_smm = analyze_smm
        
        self.modules: List[UEFIModuleInfo] = []
        self.firmware_volumes: List[FirmwareVolumeInfo] = []
        self.smm_modules: List[UEFIModuleInfo] = []
        self.dxe_modules: List[UEFIModuleInfo] = []
        self.pei_modules: List[UEFIModuleInfo] = []
        
        self.total_vulnerabilities: List[Dict[str, Any]] = []
        self.analysis_stats: Dict[str, Any] = {}
        
        # 验证路径
        self._validate_path()
        
        logger.info(f"[UEFI] 初始化分析器: {firmware_path}")
        logger.info(f"[UEFI] 输出目录: {self.output_dir}")
    
    def _validate_path(self) -> None:
        """
        验证固件文件路径
        
        Raises:
            ValueError: 路径无效或文件不存在
        """
        if not self.firmware_path:
            raise ValueError("固件文件路径不能为空")
        
        # 路径规范化
        path = os.path.abspath(self.firmware_path)
        
        # 检查路径注入
        if '..' in self.firmware_path or not os.path.exists(path):
            raise ValueError(f"无效的固件文件路径: {self.firmware_path}")
        
        # 检查文件大小
        size = os.path.getsize(path)
        if size < 1024:
            raise ValueError(f"文件太小，可能不是有效的 UEFI 固件: {size} bytes")
        
        if size > 100 * 1024 * 1024:  # 100MB
            logger.warning(f"[UEFI] 固件文件较大 ({size / 1024 / 1024:.2f} MB)，解析可能耗时")
        
        self.firmware_path = path
    
    def analyze(self) -> Dict[str, Any]:
        """
        执行完整的 UEFI 固件分析
        
        Returns:
            包含分析结果的字典
        """
        logger.info("[UEFI] 开始分析 UEFI 固件...")
        
        start_time = datetime.now()
        
        try:
            # 1. 解析固件结构
            self._parse_firmware()
            
            # 2. 提取模块
            if self.extract_modules:
                self._extract_all_modules()
            
            # 3. 分析模块
            self._analyze_modules()
            
            # 4. SMM 漏洞检测
            if self.analyze_smm:
                self._detect_smm_vulnerabilities()
            
            # 5. 生成报告
            report = self._generate_report()
            
            elapsed = (datetime.now() - start_time).total_seconds()
            logger.info(f"[UEFI] 分析完成，耗时 {elapsed:.2f} 秒")
            
            return report
            
        except Exception as e:
            logger.error(f"[UEFI] 分析失败: {e}")
            return {
                'success': False,
                'error': str(e),
                'firmware_path': self.firmware_path
            }
    
    def _parse_firmware(self) -> None:
        """
        解析 UEFI 固件结构
        
        优先使用 uefi_firmware 包，否则使用内置解析器
        """
        logger.info("[UEFI] 解析固件结构...")
        
        if UEFI_FIRMWARE_AVAILABLE:
            self._parse_with_uefi_firmware()
        else:
            self._parse_with_builtin()
        
        # 分类模块
        self._classify_modules()
        
        logger.info(f"[UEFI] 发现 {len(self.firmware_volumes)} 个 Firmware Volume")
        logger.info(f"[UEFI] 发现 {len(self.modules)} 个模块")
        logger.info(f"[UEFI] SMM 模块: {len(self.smm_modules)}")
        logger.info(f"[UEFI] DXE 模块: {len(self.dxe_modules)}")
    
    def _parse_with_uefi_firmware(self) -> None:
        """
        使用 uefi_firmware 包解析固件
        """
        try:
            firmware = uefi_firmware.FirmwareFile(self.firmware_path)
            firmware.process()
            
            # 遍历 Firmware Volumes
            for fv in firmware.objects:
                if hasattr(fv, 'name') and 'FV' in str(type(fv)):
                    fv_info = self._process_firmware_volume_uefi(fv)
                    self.firmware_volumes.append(fv_info)
                    
        except Exception as e:
            logger.warning(f"[UEFI] uefi_firmware 解析失败: {e}，回退到内置解析器")
            self._parse_with_builtin()
    
    def _process_firmware_volume_uefi(self, fv_obj: Any) -> FirmwareVolumeInfo:
        """
        处理 uefi_firmware 返回的 Firmware Volume 对象
        
        Args:
            fv_obj: uefi_firmware 的 FV 对象
            
        Returns:
            FirmwareVolumeInfo 数据结构
        """
        fv_info = FirmwareVolumeInfo()
        
        try:
            fv_info.guid = getattr(fv_obj, 'guid', '')
            fv_info.name = getattr(fv_obj, 'name', f'FV_{fv_info.guid[:8]}')
            fv_info.size = getattr(fv_obj, 'size', 0)
            fv_info.offset = getattr(fv_obj, 'offset', 0)
            fv_info.fv_type = getattr(fv_obj, 'type', 'Unknown')
            
            # 处理 FV 内的文件
            if hasattr(fv_obj, 'objects'):
                for file_obj in fv_obj.objects:
                    module = self._process_uefi_file(file_obj, fv_info)
                    if module:
                        fv_info.modules.append(module)
                        self.modules.append(module)
            
            fv_info.file_count = len(fv_info.modules)
            
        except Exception as e:
            logger.warning(f"[UEFI] 处理 FV 失败: {e}")
        
        return fv_info
    
    def _process_uefi_file(self, file_obj: Any, fv_info: FirmwareVolumeInfo) -> Optional[UEFIModuleInfo]:
        """
        处理单个 UEFI 文件对象
        
        Args:
            file_obj: uefi_firmware 的文件对象
            fv_info: 所属的 Firmware Volume 信息
            
        Returns:
            UEFIModuleInfo 或 None
        """
        module = UEFIModuleInfo()
        
        try:
            module.guid = getattr(file_obj, 'guid', '')
            module.name = getattr(file_obj, 'name', f'Module_{module.guid[:8]}')
            module.file_type_id = getattr(file_obj, 'type', 0)
            module.file_type = UEFI_FILE_TYPES.get(module.file_type_id, 'Unknown')
            module.size = getattr(file_obj, 'size', 0)
            module.offset = getattr(file_obj, 'offset', 0) + fv_info.offset
            
            # 判断模块类型
            module.is_smm = module.file_type_id in [0x0A, 0x0B, 0x0C, 0x0D]
            module.is_dxe = module.file_type_id in [0x05, 0x07]
            module.is_pei = module.file_type_id in [0x04, 0x06]
            
            # 检查是否包含 PE/TE
            if hasattr(file_obj, 'objects'):
                for section in file_obj.objects:
                    if hasattr(section, 'data'):
                        # 检查 PE 签名
                        data = section.data
                        if len(data) >= 2:
                            if data[:2] == b'MZ':
                                module.pe_path = self._save_pe_file(module, data)
                            elif data[:2] == b'VZ':
                                # TE 文件，转换为 PE
                                module.pe_path = self._convert_te_to_pe(module, data)
            
        except Exception as e:
            logger.warning(f"[UEFI] 处理文件失败: {e}")
            return None
        
        return module
    
    def _parse_with_builtin(self) -> None:
        """
        使用内置解析器解析固件
        
        通过搜索签名来识别结构
        """
        logger.info("[UEFI] 使用内置解析器...")
        
        try:
            with open(self.firmware_path, 'rb') as f:
                data = f.read()
            
            # 搜索 Firmware Volume 头
            fv_offsets = self._find_firmware_volumes(data)
            
            for offset in fv_offsets:
                fv_info = self._parse_firmware_volume(data, offset)
                if fv_info:
                    self.firmware_volumes.append(fv_info)
            
            # 如果没有找到 FV，尝试直接搜索 PE 文件
            if not self.firmware_volumes:
                logger.warning("[UEFI] 未找到标准 FV 结构，尝试直接提取 PE 文件")
                self._extract_pe_files_directly(data)
                
        except Exception as e:
            logger.error(f"[UEFI] 内置解析失败: {e}")
    
    def _find_firmware_volumes(self, data: bytes) -> List[int]:
        """
        在固件数据中搜索 Firmware Volume 头
        
        Args:
            data: 固件二进制数据
            
        Returns:
            FV 偏移量列表
        """
        offsets = []
        signature = self.UEFI_SIGNATURES['FV']
        
        pos = 0
        while pos < len(data) - 16:
            if data[pos:pos+4] == signature:
                # 验证 FV 头结构
                try:
                    fv_size = struct.unpack('<Q', data[pos+16:pos+24])[0]
                    if fv_size > 0 and fv_size < len(data) - pos:
                        offsets.append(pos)
                        logger.debug(f"[UEFI] 发现 FV at offset {hex(offset)}, size {hex(fv_size)}")
                except:
                    pass
            pos += 1
        
        return offsets
    
    def _parse_firmware_volume(self, data: bytes, offset: int) -> Optional[FirmwareVolumeInfo]:
        """
        解析单个 Firmware Volume
        
        Args:
            data: 固件数据
            offset: FV 偏移量
            
        Returns:
            FirmwareVolumeInfo 或 None
        """
        fv_info = FirmwareVolumeInfo()
        
        try:
            # 解析 FV 头
            # FV 头结构：签名(4) + 属性(4) + GUID(16) + 大小(8) + ...
            fv_header = data[offset:offset+64]
            
            fv_info.offset = offset
            fv_info.size = struct.unpack('<Q', fv_header[16:24])[0]
            
            # GUID
            guid_bytes = fv_header[8:24]
            fv_info.guid = self._bytes_to_guid(guid_bytes)
            fv_info.name = f'FV_{fv_info.guid[:8]}'
            
            # 搜索 FV 内的文件
            file_start = offset + 64  # FV 头后
            file_end = offset + fv_info.size
            
            pos = file_start
            while pos < file_end - 24:
                # FFS 文件头：GUID(16) + 类型(1) + 属性(1) + 大小(3) + 状态(1)
                file_header = data[pos:pos+24]
                
                file_guid = self._bytes_to_guid(file_header[:16])
                file_type = file_header[16]
                file_size = struct.unpack('<I', file_header[18:21] + b'\x00')[0]
                
                if file_size == 0 or file_size > fv_info.size:
                    pos += 8
                    continue
                
                module = UEFIModuleInfo()
                module.guid = file_guid
                module.name = f'Module_{file_guid[:8]}'
                module.file_type_id = file_type
                module.file_type = UEFI_FILE_TYPES.get(file_type, 'Unknown')
                module.size = file_size
                module.offset = pos
                
                module.is_smm = file_type in [0x0A, 0x0B, 0x0C, 0x0D]
                module.is_dxe = file_type in [0x05, 0x07]
                module.is_pei = file_type in [0x04, 0x06]
                
                # 搜索 PE/TE
                file_data = data[pos+24:pos+file_size]
                pe_offset = self._find_pe_in_section(file_data)
                if pe_offset >= 0:
                    pe_data = file_data[pe_offset:]
                    if pe_data[:2] == b'MZ':
                        module.pe_path = self._save_pe_file(module, pe_data)
                    elif pe_data[:2] == b'VZ':
                        module.pe_path = self._convert_te_to_pe(module, pe_data)
                
                fv_info.modules.append(module)
                self.modules.append(module)
                
                # 对齐到 8 字节
                pos += ((file_size + 7) // 8) * 8
            
            fv_info.file_count = len(fv_info.modules)
            
        except Exception as e:
            logger.warning(f"[UEFI] 解析 FV 失败 at {hex(offset)}: {e}")
            return None
        
        return fv_info
    
    def _find_pe_in_section(self, data: bytes) -> int:
        """
        在数据中搜索 PE/TE 文件
        
        Args:
            data: 数据
            
        Returns:
            PE/TE 偏移量，-1 表示未找到
        """
        # 搜索 PE 签名
        pos = 0
        while pos < len(data) - 2:
            if data[pos:pos+2] == b'MZ':
                return pos
            if data[pos:pos+2] == b'VZ':
                return pos
            pos += 1
        return -1
    
    def _extract_pe_files_directly(self, data: bytes) -> None:
        """
        直接从固件数据中提取 PE 文件
        
        Args:
            data: 固件数据
        """
        pos = 0
        while pos < len(data) - 2:
            if data[pos:pos+2] == b'MZ':
                # 尝试确定 PE 大小
                try:
                    pe = pefile.PE(data=data[pos:], fast_load=True)
                    pe_size = len(pe.__data__)
                    pe.close()
                    
                    module = UEFIModuleInfo()
                    module.name = f'PE_{hex(pos)}'
                    module.offset = pos
                    module.size = pe_size
                    module.file_type = 'Extracted PE'
                    module.pe_path = self._save_pe_file(module, data[pos:pos+pe_size])
                    
                    self.modules.append(module)
                    
                    pos += pe_size
                except:
                    pos += 1
            else:
                pos += 1
    
    def _bytes_to_guid(self, guid_bytes: bytes) -> str:
        """
        将 GUID 字节转换为字符串格式
        
        Args:
            guid_bytes: 16 字节的 GUID
            
        Returns:
            GUID 字符串 (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
        """
        if len(guid_bytes) != 16:
            return '00000000-0000-0000-0000-000000000000'
        
        # UEFI GUID 格式：前3部分需要字节序转换
        part1 = struct.unpack('<I', guid_bytes[0:4])[0]
        part2 = struct.unpack('<H', guid_bytes[4:6])[0]
        part3 = struct.unpack('<H', guid_bytes[6:8])[0]
        part4 = struct.unpack('>H', guid_bytes[8:10])[0]
        part5 = struct.unpack('>Q', b'\x00\x00' + guid_bytes[10:16])[0]
        
        return f'{part1:08x}-{part2:04x}-{part3:04x}-{part4:04x}-{part5:012x}'
    
    def _save_pe_file(self, module: UEFIModuleInfo, pe_data: bytes) -> str:
        """
        保存 PE 文件到输出目录
        
        Args:
            module: 模块信息
            pe_data: PE 二进制数据
            
        Returns:
            保存的文件路径
        """
        # 创建安全的文件名
        safe_name = re.sub(r'[^\w\-]', '_', module.name or module.guid[:8])
        filename = f'{safe_name}.pe'
        filepath = os.path.join(self.output_dir, filename)
        
        try:
            with open(filepath, 'wb') as f:
                f.write(pe_data)
            logger.debug(f"[UEFI] 保存 PE: {filepath}")
            return filepath
        except Exception as e:
            logger.warning(f"[UEFI] 保存 PE 失败: {e}")
            return ''
    
    def _convert_te_to_pe(self, module: UEFIModuleInfo, te_data: bytes) -> str:
        """
        将 TE (Terse Executable) 转换为 PE
        
        TE 是 UEFI 的精简 PE 格式
        
        Args:
            module: 模块信息
            te_data: TE 二进制数据
            
        Returns:
            转换后的 PE 文件路径
        """
        try:
            # TE 头结构：签名(2) + 机器(2) + 节数(1) + 子系统(1) + ...
            if len(te_data) < 40:
                return ''
            
            machine = struct.unpack('<H', te_data[2:4])[0]
            sections = te_data[4]
            subsystem = te_data[5]
            
            # 构建简化的 PE 头
            pe_header = bytearray()
            pe_header.extend(b'MZ')  # DOS 签名
            pe_header.extend(b'\x00' * 58)  # DOS 头填充
            pe_header.extend(b'PE\x00\x00')  # PE 签名
            pe_header.extend(struct.pack('<H', machine))  # 机器类型
            pe_header.extend(struct.pack('<H', sections))  # 节数
            pe_header.extend(b'\x00' * 12)  # 时间戳等
            pe_header.extend(struct.pack('<H', subsystem))  # 子系统
            
            # 合成 PE
            pe_data = bytes(pe_header) + te_data[40:]
            
            return self._save_pe_file(module, pe_data)
            
        except Exception as e:
            logger.warning(f"[UEFI] TE 转换失败: {e}")
            return ''
    
    def _classify_modules(self) -> None:
        """
        分类模块到 SMM、DXE、PEI 列表
        """
        self.smm_modules = [m for m in self.modules if m.is_smm]
        self.dxe_modules = [m for m in self.modules if m.is_dxe]
        self.pei_modules = [m for m in self.modules if m.is_pei]
    
    def _extract_all_modules(self) -> None:
        """
        提取所有模块到输出目录
        
        已在解析过程中完成，此方法用于补充处理
        """
        logger.info(f"[UEFI] 已提取 {len([m for m in self.modules if m.pe_path])} 个 PE/TE 模块")
        
        # 创建模块索引文件
        index_path = os.path.join(self.output_dir, 'modules_index.json')
        try:
            index_data = {
                'firmware_path': self.firmware_path,
                'total_modules': len(self.modules),
                'smm_modules': len(self.smm_modules),
                'dxe_modules': len(self.dxe_modules),
                'pei_modules': len(self.pei_modules),
                'modules': [
                    {
                        'name': m.name,
                        'guid': m.guid,
                        'type': m.file_type,
                        'is_smm': m.is_smm,
                        'pe_path': m.pe_path,
                        'size': m.size,
                        'offset': hex(m.offset)
                    }
                    for m in self.modules
                ]
            }
            
            with open(index_path, 'w', encoding='utf-8') as f:
                json.dump(index_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"[UEFI] 模块索引已保存: {index_path}")
        except Exception as e:
            logger.warning(f"[UEFI] 保存索引失败: {e}")
    
    def _analyze_modules(self) -> None:
        """
        分析提取的 PE 模块
        
        使用 PEFILE 分析导入函数、危险函数等
        """
        logger.info("[UEFI] 分析 PE 模块...")
        
        for module in self.modules:
            if module.pe_path and os.path.exists(module.pe_path):
                self._analyze_pe_module(module)
    
    def _analyze_pe_module(self, module: UEFIModuleInfo) -> None:
        """
        分析单个 PE 模块
        
        Args:
            module: 模块信息
        """
        if not PEFILE_AVAILABLE:
            return
        
        try:
            pe = pefile.PE(module.pe_path, fast_load=True)
            
            # 解析导入函数
            imports = []
            dangerous = []
            
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode('utf-8', errors='ignore')
                            imports.append(f'{dll_name}:{func_name}')
                            
                            # 检查危险函数
                            if func_name in SMM_DANGEROUS_FUNCTIONS:
                                dangerous.append(func_name)
            
            module.dangerous_functions = dangerous
            module.metadata['imports'] = imports
            module.metadata['dll_count'] = len(imports)
            
            # 解析导出函数
            exports = []
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        exports.append(exp.name.decode('utf-8', errors='ignore'))
            
            module.metadata['exports'] = exports
            
            # 解析节区
            sections = []
            for section in pe.sections:
                sec_name = section.Name.decode('utf-8', errors='ignore').strip()
                sections.append({
                    'name': sec_name,
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData,
                    'characteristics': hex(section.Characteristics)
                })
            
            module.metadata['sections'] = sections
            
            pe.close()
            
            if dangerous:
                logger.warning(f"[UEFI] 模块 {module.name} 发现危险函数: {dangerous}")
            
        except Exception as e:
            logger.warning(f"[UEFI] PE 分析失败 ({module.name}): {e}")
    
    def _detect_smm_vulnerabilities(self) -> None:
        """
        SMM 漏洞检测
        
        检测：
        1. CommBuffer 验证缺失
        2. SMRAM 泄露风险
        3. 不安全的外部调用
        4. TOCTOU 漏洞
        """
        logger.info("[UEFI] 执行 SMM 漏洞检测...")
        
        for module in self.smm_modules:
            vulns = self._detect_smm_module_vulnerabilities(module)
            module.vulnerabilities = vulns
            self.total_vulnerabilities.extend(vulns)
        
        logger.info(f"[UEFI] 发现 {len(self.total_vulnerabilities)} 个潜在 SMM 漏洞")
    
    def _detect_smm_module_vulnerabilities(self, module: UEFIModuleInfo) -> List[Dict[str, Any]]:
        """
        检测单个 SMM 模块的漏洞
        
        Args:
            module: SMM 模块信息
            
        Returns:
            漏洞列表
        """
        vulns = []
        
        # 1. CommBuffer 验证检测
        vulns.extend(self._check_commbuffer_validation(module))
        
        # 2. SMRAM 泄露检测
        vulns.extend(self._check_smram_leak(module))
        
        # 3. 不安全外部调用检测
        vulns.extend(self._check_unsafe_external_calls(module))
        
        # 4. TOCTOU 检测
        vulns.extend(self._check_toctou(module))
        
        # 5. 输入验证检测
        vulns.extend(self._check_input_validation(module))
        
        return vulns
    
    def _check_commbuffer_validation(self, module: UEFIModuleInfo) -> List[Dict[str, Any]]:
        """
        检查 CommBuffer 验证
        
        Args:
            module: 模块信息
            
        Returns:
            检测到的漏洞列表
        """
        vulns = []
        
        # 检查是否使用了 SmmCommunicate 但未使用验证函数
        has_communicate = any('SmmCommunicate' in f for f in module.dangerous_functions)
        has_validation = any('SmramIsValid' in f or 'SmmIsCommunicateBufferValid' in f 
                            for f in module.metadata.get('imports', []))
        
        if has_communicate and not has_validation:
            vulns.append({
                'type': 'COMMBUFFER_VALIDATION_MISSING',
                'module': module.name,
                'guid': module.guid,
                'severity': 'Critical',
                'description': 'SMM 驱动使用 SmmCommunicate 但未验证通信缓冲区',
                'recommendation': '添加 SmramIsValid 或 SmmIsCommunicateBufferValid 验证',
                'evidence': f'发现 SmmCommunicate，缺少验证函数'
            })
        
        return vulns
    
    def _check_smram_leak(self, module: UEFIModuleInfo) -> List[Dict[str, Any]]:
        """
        检查 SMRAM 泄露风险
        
        Args:
            module: 模块信息
            
        Returns:
            检测到的漏洞列表
        """
        vulns = []
        
        # 检查 DMA 相关函数
        dma_funcs = ['DmaMap', 'DmaAllocateBuffer']
        has_dma = any(f in module.dangerous_functions for f in dma_funcs)
        
        if has_dma:
            vulns.append({
                'type': 'SMRAM_LEAK',
                'module': module.name,
                'guid': module.guid,
                'severity': 'High',
                'description': 'SMM 驱动使用 DMA 函数，可能导致 SMRAM 泄露',
                'recommendation': '确保 DMA 操作不涉及 SMRAM 区域',
                'evidence': f'发现 DMA 函数: {module.dangerous_functions}'
            })
        
        # 检查内存拷贝函数
        copy_funcs = ['SmmCopyMem', 'memcpy', 'CopyMem']
        has_copy = any(f in module.dangerous_functions or 
                      any(f in imp for imp in module.metadata.get('imports', [])) 
                      for f in copy_funcs)
        
        if has_copy and module.is_smm:
            # 检查是否有边界检查函数
            has_safe_copy = any('SafeCopy' in imp for imp in module.metadata.get('imports', []))
            if not has_safe_copy:
                vulns.append({
                    'type': 'INSUFFICIENT_INPUT_VALIDATION',
                    'module': module.name,
                    'guid': module.guid,
                    'severity': 'Medium',
                    'description': 'SMM 驱动使用内存拷贝函数，需确保边界检查',
                    'recommendation': '使用 SafeCopyMem 或添加长度验证',
                    'evidence': '发现内存拷贝函数，缺少安全版本'
                })
        
        return vulns
    
    def _check_unsafe_external_calls(self, module: UEFIModuleInfo) -> List[Dict[str, Any]]:
        """
        检查不安全的外部调用
        
        Args:
            module: 模块信息
            
        Returns:
            检测到的漏洞列表
        """
        vulns = []
        
        # 检查 SMI 处理函数
        smi_funcs = ['SmiHandler', 'SmmRegisterHandler']
        has_smi = any(f in module.dangerous_functions for f in smi_funcs)
        
        if has_smi:
            # 检查是否有外部调用保护
            imports = module.metadata.get('imports', [])
            external_calls = [imp for imp in imports if 
                            any(x in imp for x in ['Call', 'Invoke', 'Dispatch'])]
            
            if external_calls:
                vulns.append({
                    'type': 'UNSAFE_EXTERNAL_CALL',
                    'module': module.name,
                    'guid': module.guid,
                    'severity': 'High',
                    'description': 'SMI 处理函数中存在外部调用',
                    'recommendation': '验证外部调用的目标和参数',
                    'evidence': f'外部调用: {external_calls[:5]}'
                })
        
        return vulns
    
    def _check_toctou(self, module: UEFIModuleInfo) -> List[Dict[str, Any]]:
        """
        检查 TOCTOU 漏洞
        
        Args:
            module: 模块信息
            
        Returns:
            检测到的漏洞列表
        """
        vulns = []
        
        # 基于启发式检测
        imports = module.metadata.get('imports', [])
        
        # 检查多次访问模式
        check_funcs = [imp for imp in imports if 'Check' in imp or 'Verify' in imp or 'Validate' in imp]
        access_funcs = [imp for imp in imports if 'Access' in imp or 'Read' in imp or 'Get' in imp]
        
        if check_funcs and access_funcs:
            vulns.append({
                'type': 'TOCTOU_IN_SMI',
                'module': module.name,
                'guid': module.guid,
                'severity': 'Medium',
                'description': '可能存在检查-使用时间差漏洞',
                'recommendation': '使用原子操作或锁定机制',
                'evidence': f'检查函数: {check_funcs[:3]}, 访问函数: {access_funcs[:3]}'
            })
        
        return vulns
    
    def _check_input_validation(self, module: UEFIModuleInfo) -> List[Dict[str, Any]]:
        """
        检查输入验证
        
        Args:
            module: 模块信息
            
        Returns:
            检测到的漏洞列表
        """
        vulns = []
        
        imports = module.metadata.get('imports', [])
        
        # 检查是否有输入处理但缺少验证
        input_funcs = [imp for imp in imports if 
                      any(x in imp.lower() for x in ['input', 'param', 'arg', 'buffer', 'data'])]
        
        validate_funcs = [imp for imp in imports if 
                         any(x in imp.lower() for x in ['validate', 'check', 'verify', 'sanitize'])]
        
        if input_funcs and not validate_funcs and module.is_smm:
            vulns.append({
                'type': 'INSUFFICIENT_INPUT_VALIDATION',
                'module': module.name,
                'guid': module.guid,
                'severity': 'High',
                'description': 'SMM 驜动处理输入但缺少验证函数',
                'recommendation': '添加输入验证和边界检查',
                'evidence': f'输入处理函数: {input_funcs[:5]}'
            })
        
        return vulns
    
    def _generate_report(self) -> Dict[str, Any]:
        """
        生成分析报告
        
        Returns:
            包含完整分析结果的字典
        """
        report = {
            'success': True,
            'firmware_path': self.firmware_path,
            'output_dir': self.output_dir,
            'analysis_time': datetime.now().isoformat(),
            
            'statistics': {
                'total_modules': len(self.modules),
                'smm_modules': len(self.smm_modules),
                'dxe_modules': len(self.dxe_modules),
                'pei_modules': len(self.pei_modules),
                'firmware_volumes': len(self.firmware_volumes),
                'pe_files_extracted': len([m for m in self.modules if m.pe_path]),
                'total_vulnerabilities': len(self.total_vulnerabilities),
                'critical_vulns': len([v for v in self.total_vulnerabilities if v.get('severity') == 'Critical']),
                'high_vulns': len([v for v in self.total_vulnerabilities if v.get('severity') == 'High']),
            },
            
            'firmware_volumes': [
                {
                    'name': fv.name,
                    'guid': fv.guid,
                    'size': fv.size,
                    'offset': hex(fv.offset),
                    'file_count': fv.file_count,
                    'type': fv.fv_type
                }
                for fv in self.firmware_volumes
            ],
            
            'smm_modules': [
                {
                    'name': m.name,
                    'guid': m.guid,
                    'type': m.file_type,
                    'size': m.size,
                    'pe_path': m.pe_path,
                    'dangerous_functions': m.dangerous_functions,
                    'vulnerabilities': m.vulnerabilities
                }
                for m in self.smm_modules
            ],
            
            'dxe_modules': [
                {
                    'name': m.name,
                    'guid': m.guid,
                    'type': m.file_type,
                    'size': m.size,
                    'pe_path': m.pe_path,
                    'dangerous_functions': m.dangerous_functions
                }
                for m in self.dxe_modules
            ],
            
            'vulnerabilities': self.total_vulnerabilities,
            
            'vulnerability_summary': self._summarize_vulnerabilities(),
            
            'recommendations': self._generate_recommendations()
        }
        
        return report
    
    def _summarize_vulnerabilities(self) -> Dict[str, Any]:
        """
        漏洞摘要
        
        Returns:
            漏洞统计字典
        """
        summary = defaultdict(int)
        
        for vuln in self.total_vulnerabilities:
            vuln_type = vuln.get('type', 'Unknown')
            summary[vuln_type] += 1
        
        return dict(summary)
    
    def _generate_recommendations(self) -> List[str]:
        """
        生成修复建议
        
        Returns:
            建议列表
        """
        recommendations = []
        
        # 基于漏洞类型生成建议
        vuln_types = set(v.get('type') for v in self.total_vulnerabilities)
        
        if 'COMMBUFFER_VALIDATION_MISSING' in vuln_types:
            recommendations.append('为所有 SMM 驱动添加 CommBuffer 验证（使用 SmramIsValid 或 SmmIsCommunicateBufferValid）')
        
        if 'SMRAM_LEAK' in vuln_types:
            recommendations.append('审查 DMA 操作，确保不涉及 SMRAM 区域')
        
        if 'UNSAFE_EXTERNAL_CALL' in vuln_types:
            recommendations.append('验证 SMI 处理函数中的所有外部调用')
        
        if 'TOCTOU_IN_SMI' in vuln_types:
            recommendations.append('使用原子操作或锁定机制防止 TOCTOU 漏洞')
        
        if 'INSUFFICIENT_INPUT_VALIDATION' in vuln_types:
            recommendations.append('为所有外部输入添加边界检查和类型验证')
        
        # 通用建议
        if self.smm_modules:
            recommendations.append('定期更新 UEFI 固件以修复已知漏洞')
            recommendations.append('启用 UEFI Secure Boot 和 BIOS Guard')
        
        return recommendations
    
    def cleanup(self) -> None:
        """
        清理临时文件
        """
        if self.output_dir and self.output_dir.startswith(tempfile.gettempdir()):
            try:
                shutil.rmtree(self.output_dir)
                logger.info(f"[UEFI] 已清理临时目录: {self.output_dir}")
            except Exception as e:
                logger.warning(f"[UEFI] 清理失败: {e}")


def analyze_uefi_firmware(
    firmware_path: str,
    output_dir: Optional[str] = None,
    extract_modules: bool = True,
    analyze_smm: bool = True
) -> Dict[str, Any]:
    """
    分析 UEFI 固件的便捷函数
    
    Args:
        firmware_path: 固件文件路径
        output_dir: 输出目录（可选）
        extract_modules: 是否提取模块
        analyze_smm: 是否分析 SMM 漏洞
        
    Returns:
        分析结果字典
    """
    analyzer = UEFIFirmwareAnalyzer(
        firmware_path=firmware_path,
        output_dir=output_dir,
        extract_modules=extract_modules,
        analyze_smm=analyze_smm
    )
    
    result = analyzer.analyze()
    
    return result


# ==================== 导出 ====================

__all__ = [
    'UEFIFirmwareAnalyzer',
    'UEFIModuleInfo',
    'FirmwareVolumeInfo',
    'SMM_DANGEROUS_FUNCTIONS',
    'SMM_VULN_TYPES',
    'analyze_uefi_firmware',
    'UEFI_FIRMWARE_AVAILABLE',
    'PEFILE_AVAILABLE'
]