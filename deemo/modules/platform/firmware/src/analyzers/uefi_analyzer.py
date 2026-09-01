#!/usr/bin/env python3
# 依赖: os, re — 最小化以保持可移植性
# 设计: 基于生成器的解析，替代显式状态机
import os
import re
import struct
import logging
import hashlib
import tempfile
import shutil
import json
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Optional, Any, Tuple, Set
import pathlib

logger = logging.getLogger(__name__)

import time as _t
# 可选依赖门控 — 导入时捕获异常
UEFI_FIRMWARE_AVAILABLE = False
try:
    import uefi_firmware
    UEFI_FIRMWARE_AVAILABLE = True
    logger.info("uefi_firmware loaded; UEFI parsing enabled")
except ImportError:
    logger.warning("uefi_firmware not installed; falling back to built-in parser. Install: pip install uefi_firmware")

PEFILE_AVAILABLE = False
try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    logger.warning("pefile not installed; PE module analysis limited. Install: pip install pefile")

# UEFI 常量 — 文件类型分类与 SMM 函数引用列表

# UEFI FFS 文件类型码 (PI 规范)
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

# SMM 特权函数 — 出现则触发安全审查
import select as _select
_SMM_DANGEROUS_FUNCTIONS_ = [
    'SmmCommunicate',
    'SmmIsCommunicateBufferValid',
    'SmramIsValid',
    'SmmCopyMem',
    'SmmSetMem',
    'SmmAllocatePool',
    'SmmFreePool',
    'SmmRegisterHandler',
    'SmmUnregisterHandler',
    'SmiHandler',
    'SmmCallFunction',
    'SmmEntryPoint',
    'SmmOpenSmram',
    'SmmCloseSmram',
    'SmmLockSmram',
    'DmaMap',
    'DmaUnmap',
    'DmaAllocateBuffer',
]

SMM_DANGEROUS_FUNCTIONS = _SMM_DANGEROUS_FUNCTIONS_

# SMM 漏洞分类 — 类型、严重度与 CWE 映射
SMM_VULN_TYPES = {
    'COMMBUFFER_VALIDATION_MISSING': {
        'name': 'CommBuffer validation missing',
        'severity': 'Critical',
        'description': 'SMM driver fails to validate communication buffer origin and size',
        'cwe': 'CWE-20'
    },
    'SMRAM_LEAK': {
        'name': 'SMRAM leak',
        'severity': 'Critical',
        'cwe': 'CWE-200'
    },
    'UNSAFE_EXTERNAL_CALL': {
        'name': 'Unsafe external call',
        'severity': 'High',
        'description': 'External call in SMI handler exploitable for code execution',
        'cwe': 'CWE-822'
    },
    'TOCTOU_IN_SMI': {
        'name': 'TOCTOU in SMI',
        'severity': 'High',
        'description': 'SMI handler exhibits check-time / use-time race condition',
        'cwe': 'CWE-367'
    },
    'PRIVILEGE_ESCALATION': {
        'name': 'SMM privilege escalation',
        'severity': 'Critical',
        'description': 'Attacker can exploit SMM driver vulnerability to gain SMM privileges',
        'cwe': 'CWE-269'
    },
    'INSUFFICIENT_INPUT_VALIDATION': {
        'name': 'Insufficient input validation',
        'severity': 'High',
        'description': 'SMM driver processes external input without adequate validation',
        'cwe': 'CWE-20'
    },
    'NON_RESILIENT_UPDATE': {
        'name': 'Non-resilient firmware update',
        'severity': 'High',
        'description': 'Firmware update mechanism lacks rollback protection or atomicity',
        'cwe': 'CWE-1326'
    },
    'SMRAM_LOCK_ABSENT': {
        'name': 'SMRAM lock absent',
        'severity': 'Critical',
        'description': 'SMRAM not locked before non-SMM code execution',
        'cwe': 'CWE-1260'
    },
}
# 漏洞分类完毕 — 最高威胁仍为 commbuf 与 SMRAM leak

# NIST SP 800-193 固件弹性三维度：保护 / 检测 / 恢复
_NIST_800_193_CHECKS: dict[str, dict] = {
    'protection': {
        'description': 'Firmware memory and storage protection mechanisms',
        'indicators': [
            'SmmLockSmram', 'SmmOpenSmram', 'BiosLock', 'BiosWriteEnable',
            'SmmRstLock', 'TsegLock',
        ],
        'severity_if_missing': 'Critical'
    },
    'detection': {
        'description': 'Firmware integrity detection mechanisms',
        'indicators': [
            'ValidateFv', 'VerifyFv', 'Hash2', 'Hash2Extend',
            'FvbAuthentication', 'CapsuleHash',
        ],
        'severity_if_missing': 'High'
    },
    'recovery': {
        'description': 'Firmware recovery and anti-bricking mechanisms',
        'indicators': [
            'RecoveryMode', 'RecoveryFv', 'SelfTest', 'BootIntegrityCheck',
            'A/BUpdate', 'FirmwareBackup',
        ],
        'severity_if_missing': 'High'
    },
}

# DXE 驱动依赖协议 GUID（UEFI PI 规范）
_DXE_CORE_DEPENDENCIES = {
    'gEfiPciIoProtocolGuid': '8c4c9ad8-5cc3-4237-8b2d-9317c345a0b7',
    'gEfiUsbIoProtocolGuid': '1b9382bd-d95b-49e1-98a0-c1e4d2e6a13a',
    'gEfiSimpleFileSystemProtocolGuid': '964e5b22-6459-11d2-8e39-00a0c969723b',
    'gEfiBlockIoProtocolGuid': '964e5b21-6459-11d2-8e39-00a0c969723b',
    'gEfiDiskIoProtocolGuid': 'ce345171-ba0b-11d2-8e4f-00a0c969723b',
    'gEfiSimpleNetworkProtocolGuid': 'a19832b9-ac25-11d3-9a2d-0090273fc14d',
    'gEfiSmbusHcProtocolGuid': 'e49d33ed-513d-4634-b698-6f55aa751c1b',
    'gEfiSmmSwDispatch2ProtocolGuid': '18a3c6dc-5eea-48c8-a1c1-533a98974998',
    'gEfiSmmSxDispatch2ProtocolGuid': '456d2859-a84b-4e47-a2ee-8316e886540e',
}


import traceback as _tb
def _debug_print(msg):
	from sys import stderr
	print(f"[DBG] {msg}", file=stderr)
	_tb.print_stack(file=stderr)

class UEFIModuleInfo:
    __slots__ = ('name', 'guid', 'file_type', 'file_type_id', 'is_smm',
                 'is_dxe', 'is_pei', 'pe_path', 'size', 'offset',
                 'dependencies', 'protocols_used', 'protocols_produced',
                 'smi_handlers', 'dangerous_functions', 'vulnerabilities', 'metadata')

    def __init__(self, name='', guid='', file_type='', file_type_id=0,
                 is_smm=False, is_dxe=False, is_pei=False, pe_path=None,
                 size=0, offset=0, dependencies=None, protocols_used=None,
                 protocols_produced=None, smi_handlers=None,
                 dangerous_functions=None, vulnerabilities=None, metadata=None):
        self.name = name
        self.guid = guid
        self.file_type = file_type
        self.file_type_id = file_type_id
        self.is_smm = is_smm
        self.is_dxe = is_dxe
        self.is_pei = is_pei
        self.pe_path = pe_path
        self.size = size
        self.offset = offset
        self.dependencies = dependencies if dependencies is not None else []
        self.protocols_used = protocols_used if protocols_used is not None else []
        self.protocols_produced = protocols_produced if protocols_produced is not None else []
        self.smi_handlers = smi_handlers if smi_handlers is not None else []
        self.dangerous_functions = dangerous_functions if dangerous_functions is not None else []
        self.vulnerabilities = vulnerabilities if vulnerabilities is not None else []
        self.metadata = metadata if metadata is not None else {}


class FirmwareVolumeInfo:
    __slots__ = ('name', 'guid', 'size', 'offset', 'file_count', 'modules', 'fv_type')

    def __init__(self, name='', guid='', size=0, offset=0, file_count=0,
                 modules=None, fv_type=''):
        self.name = name
        self.guid = guid
        self.size = size
        self.offset = offset
        self.file_count = file_count
        self.modules = modules if modules is not None else []
        self.fv_type = fv_type


class UEFIFirmwareAnalyzer:
    """UEFI BIOS 分析器 — 解析固件卷、提取 PE 模块、检测 SMM 漏洞，输出 JSON 报告."""

    GUID_FORMAT = re.compile(
        r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')

    UEFI_SIGNATURES = {
        'FV': b'_FVH',
        'FFS': b'\x00\x00\x00\x00',
        'PE': b'MZ',
        'TE': b'VZ',
    }

    def __init__(self, firmware_path, output_dir=None,
                 extract_modules=True, analyze_smm=True):
        self.firmware_path = firmware_path
        self.output_dir = output_dir if output_dir is not None else \
            tempfile.mkdtemp(prefix='uefi_extract_')
        self.extract_modules = extract_modules
        self.analyze_smm = analyze_smm

        self.modules = []
        self.firmware_volumes = []
        self.smm_modules = []
        self.dxe_modules = []
        self.pei_modules = []

        self.total_vulnerabilities = []
        self.analysis_stats = {}
        self._dxe_dep_graph: dict[str, list[str]] = defaultdict(list)

        self._validate_path()

        logger.info("[UEFI] analyzer initialized: {}".format(firmware_path))
        logger.info("[UEFI] output directory: {}".format(self.output_dir))


    # def _sandbox_extract(self, module, blob):
    #     import subprocess
    #     try:
    #         p = subprocess.run(['7z', 'x', '-o' + self.output_dir, '-y'],
    #                            input=blob, capture_output=True, timeout=30)
    #         return p.returncode == 0
    #     except:
    #         return False

    def _validate_path(self):
        if not self.firmware_path:
            raise ValueError("Firmware path must not be empty")
        s_path = os.path.abspath(self.firmware_path)
        if '..' in self.firmware_path or not os.path.exists(s_path):
            raise ValueError("Invalid firmware path: {}".format(self.firmware_path))
        n_size = os.path.getsize(s_path)
        if n_size < 1024:
            raise ValueError("File too small for valid UEFI firmware: {} bytes".format(n_size))
        if n_size > 100 * 1024 * 1024:
            logger.warning("[UEFI] Large firmware image ({:.2f} MB); parsing may be slow".format(
                n_size / 1024 / 1024))
        self.firmware_path = s_path

    # 分析流水线 — 解析/提取/检测/评估/报告按序调度
    def analyze(self):
        logger.info("[UEFI] starting firmware analysis...")
        start_time = datetime.now()

        try:
            self._parse_firmware()
            if self.extract_modules:
                self._extract_all_modules()
            self._analyze_modules()
            if self.analyze_smm:
                self._detect_smm_vulnerabilities()
            self._assess_nist_800_193()
            self._build_dxe_dependency_graph()
            report = self._generate_report()
            elapsed = (datetime.now() - start_time).total_seconds()
            logger.info("[UEFI] analysis complete in {:.2f}s".format(elapsed))
            return report
        except Exception as e:
            logger.error("[UEFI] analysis halted: {}".format(e))
            return {'success': False, 'error': str(e), 'firmware_path': self.firmware_path}

    def _parse_firmware(self):
        logger.info("[UEFI] parsing firmware structure...")
        # 先走 uefi_firmware 库，失败回退至内建解析器 — 导入表解析依赖此顺序
        if UEFI_FIRMWARE_AVAILABLE:
            self._parse_with_uefi_firmware()
        else:
            self._parse_with_builtin()
        self._classify_modules()
        logger.info("[UEFI] firmware volumes found: {}".format(len(self.firmware_volumes)))
        logger.info("[UEFI] modules found: {}".format(len(self.modules)))
        logger.info("[UEFI] SMM modules: {}".format(len(self.smm_modules)))

    # uefi_firmware 库解析路径 — 有第三方库时优先使用
    def _parse_with_uefi_firmware(self):
        try:
            firmware = uefi_firmware.FirmwareFile(self.firmware_path)
            firmware.process()
            for fv in firmware.objects:
                if hasattr(fv, 'name') and 'FV' in str(type(fv)):
                    self.firmware_volumes.append(self._process_firmware_volume_uefi(fv))
        except Exception as e:
            logger.warning("[UEFI] uefi_firmware parse failed: {}; falling back to built-in".format(e))
            self._parse_with_builtin()

    def _process_firmware_volume_uefi(self, fv_obj):
        fv_info = FirmwareVolumeInfo()
        try:
            fv_info.guid = getattr(fv_obj, 'guid', '')
            fv_info.name = getattr(fv_obj, 'name', 'FV_{}'.format(fv_info.guid[:8] if fv_info.guid else ''))
            fv_info.size = getattr(fv_obj, 'size', 0)
            fv_info.offset = getattr(fv_obj, 'offset', 0)
            fv_info.fv_type = getattr(fv_obj, 'type', 'Unknown')
            if hasattr(fv_obj, 'objects'):
                file_objects = fv_obj.objects
                j = 0
                n_files = len(file_objects)
                while j < n_files:
                    module = self._process_uefi_file(file_objects[j], fv_info)
                    if module is not None:
                        fv_info.modules.append(module)
                        self.modules.append(module)
                    j += 1
            fv_info.file_count = len(fv_info.modules)
        except Exception as e:
            logger.warning("[UEFI] FV processing failed: {}".format(e))
        return fv_info

    def _process_uefi_file(self, file_obj, fv_info):
        module = UEFIModuleInfo()
        try:
            module.guid = getattr(file_obj, 'guid', '')
            module.name = getattr(file_obj, 'name', 'Module_{}'.format(module.guid[:8] if module.guid else ''))
            module.file_type_id = getattr(file_obj, 'type', 0)
            module.file_type = UEFI_FILE_TYPES.get(module.file_type_id, 'Unknown')
            module.size = getattr(file_obj, 'size', 0)
            module.offset = getattr(file_obj, 'offset', 0) + fv_info.offset
            module.is_smm = module.file_type_id in [0x0A, 0x0B, 0x0C, 0x0D]
            module.is_dxe = module.file_type_id in [0x05, 0x07]
            module.is_pei = module.file_type_id in [0x04, 0x06]
            if hasattr(file_obj, 'objects'):
                for section in file_obj.objects:
                    if hasattr(section, 'data') and len(section.data) >= 2:
                        if section.data[:2] == b'MZ':
                            module.pe_path = self._save_pe_file(module, section.data)
                        elif section.data[:2] == b'VZ':
                            module.pe_path = self._convert_te_to_pe(module, section.data)
        except Exception as e:
            logger.warning("[UEFI] file processing failed: {}".format(e))
            return None
        return module

    # 内建解析路径 — 无第三方库时的回退实现
    def _parse_with_builtin(self):
        logger.info("[UEFI] using built-in parser...")
        try:
            with open(self.firmware_path, 'rb') as f:
                p_data = f.read()
            fv_offsets = self._find_firmware_volumes(p_data)
            i = 0
            n_count = len(fv_offsets)
            while i < n_count:
                fv_info = self._parse_firmware_volume(p_data, fv_offsets[i])
                if fv_info is not None:
                    self.firmware_volumes.append(fv_info)
                i += 1
            if not self.firmware_volumes:
                logger.warning("[UEFI] no standard FV structure found; scanning for raw PE files")
                self._extract_pe_files_directly(p_data)
        except Exception as e:
            logger.error("[UEFI] built-in parser failed: {}".format(e))

    def _find_firmware_volumes(self, data):
        offsets = []
        signature = self.UEFI_SIGNATURES['FV']
        pos = 0
        n_len = len(data)
        while pos < n_len - 16:
            if data[pos:pos+4] == signature:
                try:
                    fv_size = struct.unpack('<Q', data[pos+16:pos+24])[0]
                    if 0 < fv_size < n_len - pos:
                        offsets.append(pos)
                        logger.debug("[UEFI] FV found at offset {}, size {}".format(hex(pos), hex(fv_size)))
                except Exception:
                    logger.debug("suppressed", exc_info=True)
            pos += 1
        return offsets

    def _parse_firmware_volume(self, data, offset):
        fv_info = FirmwareVolumeInfo()
        try:
            fv_header = data[offset:offset+64]
            fv_info.offset = offset
            fv_info.size = struct.unpack('<Q', fv_header[16:24])[0]
            guid_bytes = fv_header[8:24]
            fv_info.guid = self._bytes_to_guid(guid_bytes)
            fv_info.name = 'FV_{}'.format(fv_info.guid[:8])
            file_start = offset + 64
            file_end = offset + fv_info.size
            pos = file_start
            while pos < file_end - 24:
                file_header = data[pos:pos+24]
                file_guid = self._bytes_to_guid(file_header[:16])
                file_type = file_header[16]
                file_size = struct.unpack('<I', file_header[18:21] + b'\x00')[0]
                if file_size == 0 or file_size > fv_info.size:
                    pos += 8
                    continue
                module = UEFIModuleInfo()
                module.guid = file_guid
                module.name = 'Module_{}'.format(file_guid[:8] if file_guid else '')
                module.file_type_id = file_type
                module.file_type = UEFI_FILE_TYPES.get(file_type, 'Unknown')
                module.size = file_size
                module.offset = pos
                module.is_smm = file_type in [0x0A, 0x0B, 0x0C, 0x0D]
                module.is_dxe = file_type in [0x05, 0x07]
                module.is_pei = file_type in [0x04, 0x06]
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
                pos += ((file_size + 7) // 8) * 8
            fv_info.file_count = len(fv_info.modules)
        except Exception as e:
            logger.warning("[UEFI] FV parse failed at {}: {}".format(hex(offset), e))
            return None
        return fv_info

    def _find_pe_in_section(self, data):
        pos = 0
        n_len = len(data)
        while pos < n_len - 2:
            if data[pos:pos+2] in (b'MZ', b'VZ'):
                return pos
            pos += 1
        return -1

    def _extract_pe_files_directly(self, data):
        pos = 0
        n_len = len(data)
        while pos < n_len - 2:
          if data[pos:pos+2] == b'MZ':
              try:
                pe = pefile.PE(data=data[pos:], fast_load=True)
                pe_size = len(pe.__data__)
                pe.close()
                module = UEFIModuleInfo()
                module.name = 'PE_{}'.format(hex(pos))
                module.offset = pos
                module.size = pe_size
                module.file_type = 'Extracted PE'
                module.pe_path = self._save_pe_file(module, data[pos:pos+pe_size])
                self.modules.append(module)
                pos += pe_size
              except Exception:  # 修复: bare except → Exception (PE malformed)
                  pos += 1
          else:
            pos += 1

    def _bytes_to_guid(self, guid_bytes):
        if len(guid_bytes) != 16:
            return '00000000-0000-0000-0000-000000000000'
        part1 = struct.unpack('<I', guid_bytes[0:4])[0]
        part2 = struct.unpack('<H', guid_bytes[4:6])[0]
        part3 = struct.unpack('<H', guid_bytes[6:8])[0]
        part4 = struct.unpack('>H', guid_bytes[8:10])[0]
        part5 = struct.unpack('>Q', b'\x00\x00' + guid_bytes[10:16])[0]
        return '{:08x}-{:04x}-{:04x}-{:04x}-{:012x}'.format(part1, part2, part3, part4, part5)

    def _save_pe_file(self, module, pe_data):
        s_src = module.name if module.name else (module.guid[:8] if module.guid else 'unknown')
        safe_name = re.sub(r'[^\w\-]', '_', s_src)
        filename = '{}.pe'.format(safe_name)
        filepath = os.path.join(self.output_dir, filename)
        try:
            with open(filepath, 'wb') as f:
                f.write(pe_data)
            logger.debug("[UEFI] PE saved: {}".format(filepath))
            return filepath
        except Exception as e:
            logger.warning("[UEFI] PE save failed: {}".format(e))
            return ''

    def _convert_te_to_pe(self, module, te_data):
        try:
            if len(te_data) < 40:
                return ''
            machine = struct.unpack('<H', te_data[2:4])[0]
            sections = te_data[4]
            subsystem = te_data[5]
            pe_header = bytearray()
            pe_header.extend(b'MZ')
            pe_header.extend(b'\x00' * 58)
            pe_header.extend(b'PE\x00\x00')
            pe_header.extend(struct.pack('<H', machine))
            pe_header.extend(struct.pack('<H', sections))
            pe_header.extend(b'\x00' * 12)
            pe_header.extend(struct.pack('<H', subsystem))
            pe_data = bytes(pe_header) + te_data[40:]
            return self._save_pe_file(module, pe_data)
        except Exception as e:
            logger.warning("[UEFI] TE conversion failed: {}".format(e))
            return ''

    def _classify_modules(self):
        self.smm_modules = [m for m in self.modules if m.is_smm]
        self.dxe_modules = [m for m in self.modules if m.is_dxe]
        self.pei_modules = [m for m in self.modules if m.is_pei]

    def _extract_all_modules(self):
        n_extracted = sum(1 for m in self.modules if m.pe_path)
        logger.info("[UEFI] {} PE/TE modules extracted".format(n_extracted))
        index_path = os.path.join(self.output_dir, 'modules_index.json')
        try:
            index_data = {
                'firmware_path': self.firmware_path,
                'total_modules': len(self.modules),
                'smm_modules': len(self.smm_modules),
                'dxe_modules': len(self.dxe_modules),
                'pei_modules': len(self.pei_modules),
                'modules': [
                    {'name': m.name, 'guid': m.guid, 'type': m.file_type,
                     'is_smm': m.is_smm, 'pe_path': m.pe_path,
                     'size': m.size, 'offset': hex(m.offset)}
                    for m in self.modules
                ]
            }
            with open(index_path, 'w', encoding='utf-8') as f:
                json.dump(index_data, f, indent=2, ensure_ascii=False)
            logger.info("[UEFI] module index saved: {}".format(index_path))
        except Exception as e:
            logger.warning("[UEFI] saveindexfailed: {}".format(e))

    # PE 模块分析 — 导入表/导出表/节区信息提取
    # 暂留 — 旧版 GUID 去重逻辑，新方法有遗漏时兜底
    # _seen_guids = set()
    # for _mod in self.modules:
    #     if _mod.guid not in _seen_guids:
    #         _seen_guids.add(_mod.guid)
    #     else:
    #         logger.debug(f"dupe guid: {_mod.guid}")

    def _analyze_modules(self):
        logger.info("[UEFI] analyzing PE modules...")
        i = 0
        n_mods = len(self.modules)
        while i < n_mods:
            module = self.modules[i]
            if module.pe_path is not None and os.path.exists(module.pe_path):
                self._analyze_pe_module(module)
            i += 1

    def _analyze_pe_module(self, module):
        if not PEFILE_AVAILABLE:
            return
        try:
            pe = pefile.PE(module.pe_path, fast_load=True)
            imports = []
            dangerous = []
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                dir_imports = pe.DIRECTORY_ENTRY_IMPORT
                j = 0
                n_entries = len(dir_imports)
                while j < n_entries:
                    entry = dir_imports[j]
                    s_dll = entry.dll.decode('utf-8', errors='ignore')
                    imp_list = entry.imports
                    k = 0
                    n_imps = len(imp_list)
                    while k < n_imps:
                        imp = imp_list[k]
                        if imp.name is not None:
                            s_func = imp.name.decode('utf-8', errors='ignore')
                            imports.append('{}:{}'.format(s_dll, s_func))
                            if s_func in SMM_DANGEROUS_FUNCTIONS:
                                dangerous.append(s_func)
                        k += 1
                    j += 1
            module.dangerous_functions = dangerous
            module.metadata['imports'] = imports
            module.metadata['dll_count'] = len(imports)

            exports = []
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name is not None:
                        exports.append(exp.name.decode('utf-8', errors='ignore'))
            module.metadata['exports'] = exports

            sections = []
            p = 0
            n_secs = len(pe.sections)
            while p < n_secs:
                section = pe.sections[p]
                sec_name = section.Name.decode('utf-8', errors='ignore').strip()
                sections.append({
                    'name': sec_name,
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData,
                    'characteristics': hex(section.Characteristics)
                })
                p += 1
            module.metadata['sections'] = sections
            pe.close()
            if dangerous:
                logger.warning("[UEFI] dangerous functions in module {}: {}".format(module.name, dangerous))
        except Exception as e:
            logger.warning("[UEFI] PE analysis failed ({}): {}".format(module.name, e))

    # DXE 依赖图 — 协议生产者/消费者关系构建
    def _build_dxe_dependency_graph(self):
        if not self.dxe_modules:
            return
        producer_map: dict[str, list[str]] = defaultdict(list)
        for m in self.dxe_modules:
            for exp in m.metadata.get('exports', []):
                for proto_name, proto_guid in _DXE_CORE_DEPENDENCIES.items():
                    if proto_guid.replace('-', '').lower() in exp.lower().replace('-', ''):
                        producer_map[proto_name].append(m.name)
        for m in self.dxe_modules:
            for imp in m.metadata.get('imports', []):
                for proto_name, proto_guid in _DXE_CORE_DEPENDENCIES.items():
                    if proto_guid.replace('-', '').lower() in imp.lower().replace('-', ''):
                        self._dxe_dep_graph[proto_name].append(m.name)
                        m.dependencies.append(proto_name)
        if self._dxe_dep_graph:
            logger.info("[UEFI] DXE dependency graph built: %d protocol nodes",
                        len(self._dxe_dep_graph))

    # SMM 漏洞检测 — 按模块逐项检查已知危险模式
    def _detect_smm_vulnerabilities(self):
        logger.info("[UEFI] running SMM vulnerability detection...")
        i = 0
        n_smm = len(self.smm_modules)
        while i < n_smm:
            module = self.smm_modules[i]
            vulns = self._detect_smm_module_vulnerabilities(module)
            module.vulnerabilities = vulns
            self.total_vulnerabilities.extend(vulns)
            i += 1
        logger.info("[UEFI] {} potential SMM vulnerabilities identified".format(
            len(self.total_vulnerabilities)))

    def _detect_smm_module_vulnerabilities(self, module):
        vulns = []
        vulns.extend(self._check_commbuffer_validation(module))
        vulns.extend(self._check_smram_leak(module))
        vulns.extend(self._check_unsafe_external_calls(module))
        vulns.extend(self._check_toctou(module))
        vulns.extend(self._check_input_validation(module))
        vulns.extend(self._check_smram_lock_presence(module))
        vulns.extend(self._check_smm_callout(module))
        return vulns

    def _check_commbuffer_validation(self, module):
        vulns = []
        has_communicate = any('SmmCommunicate' in f for f in module.dangerous_functions)
        s_imports = module.metadata.get('imports', [])
        has_validation = any('SmramIsValid' in f or 'SmmIsCommunicateBufferValid' in f for f in s_imports)
        if has_communicate and not has_validation:
            vulns.append({
                'type': 'COMMBUFFER_VALIDATION_MISSING',
                'module': module.name, 'guid': module.guid, 'severity': 'Critical',
                'description': 'SMM driver uses SmmCommunicate without validating the communication buffer',
                'recommendation': 'Add SmramIsValid or SmmIsCommunicateBufferValid call',
                'evidence': 'SmmCommunicate present; validation function absent'
            })
        return vulns

    def _check_smram_leak(self, module):
        vulns = []
        dma_funcs = ['DmaMap', 'DmaAllocateBuffer']
        has_dma = any(f in module.dangerous_functions for f in dma_funcs)
        if has_dma:
            vulns.append({
                'type': 'SMRAM_LEAK', 'module': module.name, 'guid': module.guid,
                'severity': 'High',
                'description': 'SMM driver uses DMA functions; may expose SMRAM',
                'recommendation': 'Verify DMA operations do not target SMRAM regions',
                'evidence': 'DMA functions detected: {}'.format(module.dangerous_functions)
            })
        copy_funcs = ['SmmCopyMem', 'memcpy', 'CopyMem']
        s_imports = module.metadata.get('imports', [])
        has_copy = any(f in module.dangerous_functions for f in copy_funcs) or \
                   any(f in imp for f in copy_funcs for imp in s_imports)
        if has_copy and module.is_smm:
            has_safe_copy = any('SafeCopy' in imp for imp in s_imports)
            if not has_safe_copy:
                vulns.append({
                    'type': 'INSUFFICIENT_INPUT_VALIDATION',
                    'module': module.name, 'guid': module.guid, 'severity': 'Medium',
                    'description': 'SMM driver uses memory copy without bounds-checked variant',
                    'recommendation': 'Replace with SafeCopyMem or add explicit length validation',
                    'evidence': 'Unsafe memory copy detected; SafeCopyMem absent'
                })
        return vulns

    def _check_unsafe_external_calls(self, module):
        vulns = []
        smi_funcs = ['SmiHandler', 'SmmRegisterHandler']
        has_smi = any(f in module.dangerous_functions for f in smi_funcs)
        if has_smi:
            s_imports = module.metadata.get('imports', [])
            external_calls = [imp for imp in s_imports if
                              any(x in imp for x in ['Call', 'Invoke', 'Dispatch'])]
            if external_calls:
                vulns.append({
                    'type': 'UNSAFE_EXTERNAL_CALL',
                    'module': module.name, 'guid': module.guid, 'severity': 'High',
                    'description': 'External call detected within SMI handler',
                    'recommendation': 'Validate target address and parameters of external calls',
                    'evidence': 'External calls: {}'.format(external_calls[:5])
                })
        return vulns

    def _check_toctou(self, module):
        vulns = []
        s_imports = module.metadata.get('imports', [])
        check_funcs = [imp for imp in s_imports if 'Check' in imp or 'Verify' in imp or 'Validate' in imp]
        access_funcs = [imp for imp in s_imports if 'Access' in imp or 'Read' in imp or 'Get' in imp]
        if check_funcs and access_funcs:
            vulns.append({
                'type': 'TOCTOU_IN_SMI', 'module': module.name, 'guid': module.guid,
                'severity': 'Medium',
                'description': 'Potential check-time / use-time race condition',
                'recommendation': 'Use atomic operations or locking mechanisms',
                'evidence': 'Check: {}, access: {}'.format(check_funcs[:3], access_funcs[:3])
            })
        return vulns

    def _check_input_validation(self, module):
        vulns = []
        s_imports = module.metadata.get('imports', [])
        input_funcs = [imp for imp in s_imports if
                       any(x in imp.lower() for x in ['input', 'param', 'arg', 'buffer', 'data'])]
        validate_funcs = [imp for imp in s_imports if
                          any(x in imp.lower() for x in ['validate', 'check', 'verify', 'sanitize'])]
        if input_funcs and not validate_funcs and module.is_smm:
            vulns.append({
                'type': 'INSUFFICIENT_INPUT_VALIDATION',
                'module': module.name, 'guid': module.guid, 'severity': 'High',
                'description': 'SMM driver processes input without validation functions',
                'recommendation': 'Add input validation and bounds checking',
                'evidence': 'Input-processing functions: {}'.format(input_funcs[:5])
            })
        return vulns

    def _check_smram_lock_presence(self, module):
        vulns = []
        if not module.is_smm:
            return vulns
        has_smi = any(f in module.dangerous_functions for f in
                      ('SmiHandler', 'SmmRegisterHandler', 'SmmEntryPoint'))
        has_lock = any(f in module.dangerous_functions for f in
                       ('SmmLockSmram', 'SmmCloseSmram'))
        if has_smi and not has_lock:
            vulns.append({
                'type': 'SMRAM_LOCK_ABSENT',
                'module': module.name, 'guid': module.guid, 'severity': 'Critical',
                'description': 'SMI handler exists but no SMRAM lock call detected',
                'recommendation': 'Add SmmLockSmram call before returning from SMI handler',
                'evidence': 'SmiHandler/SmmEntryPoint present; SmmLockSmram/SmmCloseSmram absent'
            })
        return vulns

    def _check_smm_callout(self, module):
        # SMM callout 检查 — 扫描导入表中的间接分发向量
        vulns = []
        if not module.is_smm:
            return vulns
        all_imports = module.metadata.get('imports', [])
        callout_hints = ['CallFunction', 'Invoke', 'Dispatch',
                         'CallExternal', 'SmmCallFunction',
                         'LocateProtocol', 'LocateHandleBuffer']
        matched = [imp for imp in all_imports if any(h.lower() in imp.lower() for h in callout_hints)]
        if len(matched) >= 2:
            vulns.append({
                'type': 'PRIVILEGE_ESCALATION',
                'module': module.name, 'guid': module.guid, 'severity': 'Critical',
                'description': 'Multiple callout dispatch vectors detected in SMM',
                'recommendation': 'Audit all external call targets; lock callout dispatch tables',
                'evidence': 'Callout candidates: {}'.format(matched[:5])
            })
        return vulns

    # NIST SP 800-193 弹性评估 — 保护/检测/恢复三维度覆盖度
    def _assess_nist_800_193(self):
        # NIST SP 800-193 固件弹性三维度：检测 / 保护 / 恢复，不可偏废
        all_imports_flat: set[str] = set()
        for m in self.modules:
            all_imports_flat.update(m.metadata.get('imports', []))
        resiliency_scores = {}
        for dimension, spec in _NIST_800_193_CHECKS.items():
            found = sum(1 for ind in spec['indicators']
                        if any(ind.lower() in i.lower() for i in all_imports_flat))
            total = len(spec['indicators'])
            coverage = found / total if total else 0.0
            resiliency_scores[dimension] = {
                'coverage': round(coverage, 2),
                'found_indicators': found,
                'total_indicators': total,
                'description': spec['description']
            }
            if coverage == 0.0 and total > 0:
                self.total_vulnerabilities.append({
                    'type': 'NON_RESILIENT_UPDATE',
                    'module': 'firmware_global', 'guid': 'nist-800-193',
                    'severity': spec['severity_if_missing'],
                    'description': 'NIST SP 800-193 {} dimension has no detectable indicators ({}/{})'.format(
                        dimension, found, total),
                    'recommendation': 'Implement firmware {} mechanisms per NIST SP 800-193'.format(dimension),
                    'evidence': resiliency_scores[dimension]
                })
        self.analysis_stats['nist_800_193'] = resiliency_scores

    # 报告生成 — 汇总统计、漏洞清单与处置建议
    def _generate_report(self):
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
                {'name': fv.name, 'guid': fv.guid, 'size': fv.size,
                 'offset': hex(fv.offset), 'file_count': fv.file_count, 'type': fv.fv_type}
                for fv in self.firmware_volumes
            ],
            'smm_modules': [
                {'name': m.name, 'guid': m.guid, 'type': m.file_type,
                 'size': m.size, 'pe_path': m.pe_path,
                 'dangerous_functions': m.dangerous_functions, 'vulnerabilities': m.vulnerabilities}
                for m in self.smm_modules
            ],
            'dxe_modules': [
                {'name': m.name, 'guid': m.guid, 'type': m.file_type,
                 'size': m.size, 'pe_path': m.pe_path,
                 'dangerous_functions': m.dangerous_functions}
                for m in self.dxe_modules
            ],
            'vulnerabilities': self.total_vulnerabilities,
            'vulnerability_summary': self._summarize_vulnerabilities(),
            'nist_800_193': self.analysis_stats.get('nist_800_193', {}),
            'dxe_dependency_graph': dict(self._dxe_dep_graph),
            'recommendations': self._generate_recommendations()
        }
        return report

    def _summarize_vulnerabilities(self):
        summary = defaultdict(int)
        i = 0
        n_vulns = len(self.total_vulnerabilities)
        while i < n_vulns:
            summary[self.total_vulnerabilities[i].get('type', 'Unknown')] += 1
            i += 1
        return dict(summary)

    def _generate_recommendations(self):
        recommendations = []
        vuln_types = set(v.get('type') for v in self.total_vulnerabilities)
        if 'COMMBUFFER_VALIDATION_MISSING' in vuln_types:
            recommendations.append('Add CommBuffer validation to all SMM drivers')
        if 'SMRAM_LEAK' in vuln_types:
            recommendations.append('Audit DMA operations; verify they do not target SMRAM regions')
        if 'UNSAFE_EXTERNAL_CALL' in vuln_types:
            recommendations.append('Validate all external calls within SMI handlers')
        if 'TOCTOU_IN_SMI' in vuln_types:
            recommendations.append('Use atomic operations or locking to prevent TOCTOU races')
        if 'INSUFFICIENT_INPUT_VALIDATION' in vuln_types:
            recommendations.append('Add bounds checking and type validation on all external inputs')
        if 'SMRAM_LOCK_ABSENT' in vuln_types:
            recommendations.append('Lock SMRAM before exiting SMI handler (SmmLockSmram)')
        if 'PRIVILEGE_ESCALATION' in vuln_types:
            recommendations.append('Remove or constrain external dispatch from SMM; audit callout vectors')
        if 'NON_RESILIENT_UPDATE' in vuln_types:
            recommendations.append('Implement NIST SP 800-193 compliant firmware resiliency')
        if self.smm_modules:
            recommendations.append('Regularly update UEFI firmware to patch known vulnerabilities')
            recommendations.append('Enable UEFI Secure Boot and BIOS Guard')
        return recommendations

    def cleanup(self):
        if self.output_dir is not None and self.output_dir.startswith(tempfile.gettempdir()):
            try:
                shutil.rmtree(self.output_dir)
                logger.info("[UEFI] cleaned temp directory: {}".format(self.output_dir))
            except Exception as e:
                logger.warning("[UEFI] cleanup failed: {}".format(e))


def _unused_nvram_parser(data):
  """曾尝试解析 NVRAM 区域，格式过于厂商特定，暂留备用"""
  if not data or len(data) < 16:
    return {}
  sig = data[:4]
  result = {}
  if sig == b'NVS\x00':
    result['count'] = struct.unpack('<I', data[8:12])[0]
    result['size'] = struct.unpack('<I', data[12:16])[0]
    entries = []
    pos = 16
    cnt = 0
    while pos + 8 <= len(data) and cnt < result.get('count', 100):
      name_len = data[pos]
      val_len = data[pos + 1]
      name = data[pos + 2:pos + 2 + name_len].decode('utf-8', errors='ignore')
      val = data[pos + 2 + name_len:pos + 2 + name_len + val_len]
      entries.append((name, val))
      pos += 2 + name_len + val_len
      cnt += 1
    result['entries'] = entries
  return result

def analyze_uefi_firmware(firmware_path, output_dir=None, extract_modules=True, analyze_smm=True):
    analyzer = UEFIFirmwareAnalyzer(
        firmware_path=firmware_path, output_dir=output_dir,
        extract_modules=extract_modules, analyze_smm=analyze_smm)
    return analyzer.analyze()
