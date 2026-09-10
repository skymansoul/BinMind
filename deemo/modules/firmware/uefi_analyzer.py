#!/usr/bin/env python3
# Dependencies: os, re — kept minimal for portability
# Design: generator-based parsing over explicit state machine
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

logger = logging.getLogger(__name__)

# Optional dependency gates — exceptions caught at import time
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

# UEFI constants — file type taxonomy and SMM function reference lists

# UEFI FFS file type codes per PI specification
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

# SMM-privileged functions whose presence triggers security review
_SMM_DANGEROUS_FUNCTIONS_ = [
    # CommBuffer handling
    'SmmCommunicate',
    'SmmIsCommunicateBufferValid',
    'SmramIsValid',

    'SmmCopyMem',
    'SmmSetMem',
    'SmmAllocatePool',
    'SmmFreePool',

    # SMI management
    'SmmRegisterHandler',
    'SmmUnregisterHandler',
    'SmiHandler',

    # External dispatch
    'SmmCallFunction',
    'SmmEntryPoint',

    # SMRAM configuration
    'SmmOpenSmram',
    'SmmCloseSmram',
    'SmmLockSmram',

    # DMA operations
    'DmaMap',
    'DmaUnmap',
    'DmaAllocateBuffer',
]

# Backward-compatible attribute name
SMM_DANGEROUS_FUNCTIONS = _SMM_DANGEROUS_FUNCTIONS_

# SMM vulnerability taxonomy — types, severities, and CWE mappings
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
}

class UEFIModuleInfo:
    __slots__ = ('name', 'guid', 'file_type', 'file_type_id', 'is_smm', 'is_dxe', 'is_pei', 'pe_path', 'size', 'offset', 'dependencies', 'protocols_used', 'protocols_produced', 'smi_handlers', 'dangerous_functions', 'vulnerabilities', 'metadata',)

    def __init__(self, name='', guid='', file_type='', file_type_id=0, is_smm=False, is_dxe=False, is_pei=False, pe_path=None, size=0, offset=0, dependencies=None, protocols_used=None, protocols_produced=None, smi_handlers=None, dangerous_functions=None, vulnerabilities=None, metadata=None):
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
        # Previously used mutable default args; replaced with explicit None guards
        self.dependencies = dependencies if dependencies is not None else []
        self.protocols_used = protocols_used if protocols_used is not None else []
        self.protocols_produced = protocols_produced if protocols_produced is not None else []
        self.smi_handlers = smi_handlers if smi_handlers is not None else []
        self.dangerous_functions = dangerous_functions if dangerous_functions is not None else []
        self.vulnerabilities = vulnerabilities if vulnerabilities is not None else []
        self.metadata = metadata if metadata is not None else {}

class FirmwareVolumeInfo:
    # 实例在多方法间被引用; 不保证线程安全
    __slots__ = ('name', 'guid', 'size', 'offset', 'file_count', 'modules', 'fv_type',)

    def __init__(self, name='', guid='', size=0, offset=0, file_count=0, modules=None, fv_type=''):
        self.name = name
        self.guid = guid
        self.size = size
        self.offset = offset
        self.file_count = file_count
        self.modules = modules if modules is not None else []
        self.fv_type = fv_type

class UEFIFirmwareAnalyzer:
    """
    UEFI BIOS image analyzer.

    Pipeline:
    - Parse firmware volumes and file system structure
    - Extract PE/TE modules from FFS files
    - Classify modules (SMM, DXE, PEI)
    - Detect SMM vulnerabilities via import analysis
    - Generate structured JSON report

    Attributes:
        firmware_path: Path to the UEFI firmware image
        output_dir: Extraction and report output directory
        modules: All discovered UEFI modules
        firmware_volumes: Parsed firmware volume descriptors
    """

    # Canonical UEFI GUID regex: 8-4-4-4-12 hex digits
    GUID_FORMAT = re.compile(
        r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')

    # UEFI structure signature bytes
    UEFI_SIGNATURES = {
        'FV': b'_FVH',
        'FFS': b'\x00\x00\x00\x00',  # FFS file header: first 4 bytes are reserved (zero)
        'PE': b'MZ',
        'TE': b'VZ',  # Terse Executable format
    }

    def __init__(self,
        firmware_path,
        output_dir=None,
        extract_modules=True,
        analyze_smm=True
    ):
        """
        Initialize the UEFI firmware analyzer with path validation.
        """
        self.firmware_path = firmware_path
        self.output_dir = output_dir if output_dir is not None else tempfile.mkdtemp(prefix='uefi_extract_')
        self.extract_modules = extract_modules
        self.analyze_smm = analyze_smm

        self.modules = []
        self.firmware_volumes = []
        self.smm_modules = []
        self.dxe_modules = []
        self.pei_modules = []

        self.total_vulnerabilities = []
        self.analysis_stats = {}

        # Validate firmware path early, before any processing
        self._validate_path()

        logger.info("[UEFI] analyzer initialized: {}".format(firmware_path))
        logger.info("[UEFI] output directory: {}".format(self.output_dir))

    def _validate_path(self):
        """
        Validate firmware path: existence, size bounds, path traversal check.
        """
        if not self.firmware_path:
            raise ValueError("Firmware path must not be empty")

        s_path = os.path.abspath(self.firmware_path)

        # Guard against path traversal and nonexistent targets
        if '..' in self.firmware_path or not os.path.exists(s_path):
            raise ValueError("Invalid firmware path: {}".format(self.firmware_path))

        n_size = os.path.getsize(s_path)
        if n_size < 1024:
            raise ValueError("File too small for valid UEFI firmware: {} bytes".format(n_size))

        if n_size > 100 * 1024 * 1024:  # 100 MB soft cap
            logger.warning("[UEFI] Large firmware image ({:.2f} MB); parsing may be slow".format(n_size / 1024 / 1024))

        self.firmware_path = s_path

    def analyze(self):
        """
        Execute the full UEFI firmware analysis pipeline.
        Previously threw intermittent KeyError from dict mutation during iteration; now guarded.
        """
        logger.info("[UEFI] starting firmware analysis...")

        start_time = datetime.now()

        try:
            # Phase 1: Parse firmware structure
            self._parse_firmware()

            # Phase 2: Extract PE/TE modules
            if self.extract_modules:
                self._extract_all_modules()

            # Phase 3: Analyze PE imports/exports
            self._analyze_modules()

            # Phase 4: SMM vulnerability detection
            if self.analyze_smm:
                self._detect_smm_vulnerabilities()

            # Phase 5: Generate report
            report = self._generate_report()

            elapsed = (datetime.now() - start_time).total_seconds()
            logger.info("[UEFI] analysis complete in {:.2f}s".format(elapsed))

            return report

        except Exception as e:
            logger.error("[UEFI] analysis halted: {}".format(e))
            return {
                'success': False,
                'error': str(e),
                'firmware_path': self.firmware_path
            }

    def _parse_firmware(self):
        """
        Parse UEFI firmware structure. Prefers uefi_firmware library; falls back to built-in parser.
        """
        logger.info("[UEFI] parsing firmware structure...")

        if UEFI_FIRMWARE_AVAILABLE:
            self._parse_with_uefi_firmware()
        else:
            self._parse_with_builtin()

        # Classify modules by type (SMM, DXE, PEI)
        self._classify_modules()

        logger.info("[UEFI] firmware volumes found: {}".format(len(self.firmware_volumes)))
        logger.info("[UEFI] modules found: {}".format(len(self.modules)))
        logger.info("[UEFI] SMM modules: {}".format(len(self.smm_modules)))
        logger.info("[UEFI] DXE modules: {}".format(len(self.dxe_modules)))

    def _parse_with_uefi_firmware(self):
        """
        Delegate parsing to the uefi_firmware library; fall back to built-in on error.
        """
        try:
            firmware = uefi_firmware.FirmwareFile(self.firmware_path)
            firmware.process()

            # Iterate over firmware volumes in the parsed object tree
            for fv in firmware.objects:
                if hasattr(fv, 'name') and 'FV' in str(type(fv)):
                    fv_info = self._process_firmware_volume_uefi(fv)
                    self.firmware_volumes.append(fv_info)

        except Exception as e:
            logger.warning("[UEFI] uefi_firmware parse failed: {}; falling back to built-in".format(e))
            self._parse_with_builtin()

    def _process_firmware_volume_uefi(self, fv_obj):
        """
        Extract metadata and file objects from a uefi_firmware FV object.
        """
        fv_info = FirmwareVolumeInfo()

        try:
            fv_info.guid = getattr(fv_obj, 'guid', '')
            fv_info.name = getattr(fv_obj, 'name', 'FV_{}'.format(fv_info.guid[:8] if fv_info.guid else ''))
            fv_info.size = getattr(fv_obj, 'size', 0)
            fv_info.offset = getattr(fv_obj, 'offset', 0)
            fv_info.fv_type = getattr(fv_obj, 'type', 'Unknown')

            # Enumerate embedded files within the firmware volume
            if hasattr(fv_obj, 'objects'):
             file_objects = fv_obj.objects
             j = 0
             n_files = len(file_objects)
             while j < n_files:
                    file_obj = file_objects[j]
                    module = self._process_uefi_file(file_obj, fv_info)
                    if module is not None:
                        fv_info.modules.append(module)
                        self.modules.append(module)
                    j += 1

            fv_info.file_count = len(fv_info.modules)

        except Exception as e:
            logger.warning("[UEFI] FV processing failed: {}".format(e))

        return fv_info

    def _process_uefi_file(self, file_obj, fv_info):
        """
        Process a single UEFI FFS file: extract GUID, type, and embedded PE/TE sections.
        """
        module = UEFIModuleInfo()

        try:
            # Guard against missing attributes on uefi_firmware objects
            module.guid = getattr(file_obj, 'guid', '')
            module.name = getattr(file_obj, 'name', 'Module_{}'.format(module.guid[:8] if module.guid else ''))
            module.file_type_id = getattr(file_obj, 'type', 0)
            module.file_type = UEFI_FILE_TYPES.get(module.file_type_id, 'Unknown')
            module.size = getattr(file_obj, 'size', 0)
            module.offset = getattr(file_obj, 'offset', 0) + fv_info.offset

            # Classify module type from FFS file type code
            module.is_smm = module.file_type_id in [0x0A, 0x0B, 0x0C, 0x0D]
            module.is_dxe = module.file_type_id in [0x05, 0x07]
            module.is_pei = module.file_type_id in [0x04, 0x06]

            # Scan sections for embedded PE/TE executables
            if hasattr(file_obj, 'objects'):
                for section in file_obj.objects:
                    if hasattr(section, 'data'):
                        p_data = section.data
                        if len(p_data) >= 2:
                            if p_data[:2] == b'MZ':
                                module.pe_path = self._save_pe_file(module, p_data)
                            elif p_data[:2] == b'VZ':
                                # TE (Terse Executable) — convert to PE
                                module.pe_path = self._convert_te_to_pe(module, p_data)

        except Exception as e:
            logger.warning("[UEFI] file processing failed: {}".format(e))
            return None

        return module

    def _parse_with_builtin(self):
        """
        Built-in parser: locate FV headers by scanning for signature bytes,
        then extract PE files if no FV structure is found.
        """
        logger.info("[UEFI] using built-in parser...")

        try:
            with open(self.firmware_path, 'rb') as f:
                p_data = f.read()

            # Scan for Firmware Volume header signatures
            fv_offsets = self._find_firmware_volumes(p_data)

            n_count = len(fv_offsets)
            i = 0
            while i < n_count:
                offset = fv_offsets[i]
                fv_info = self._parse_firmware_volume(p_data, offset)
                if fv_info is not None:
                    self.firmware_volumes.append(fv_info)
                i += 1

            # If no FV structure detected, fall back to raw PE scanning
            if not self.firmware_volumes:
                logger.warning("[UEFI] no standard FV structure found; scanning for raw PE files")
                self._extract_pe_files_directly(p_data)

        except Exception as e:
            logger.error("[UEFI] built-in parser failed: {}".format(e))

    def _find_firmware_volumes(self, data):
        """
        Scan raw firmware data for FV header signatures (_FVH); validate size field.
        """
        offsets = []
        signature = self.UEFI_SIGNATURES['FV']

        pos = 0
        n_len = len(data)
        while pos < n_len - 16:
            if data[pos:pos+4] == signature:
                # Validate FV header: check size field is within reasonable bounds
                try:
                    fv_size = 0
                    # 标准布局 FVLength 在偏移 20，部分采集样本在 32
                    for size_off in (20, 32):
                        if pos + size_off + 8 <= n_len:
                            cand = struct.unpack('<Q', data[pos+size_off:pos+size_off+8])[0]
                            if cand > 0:
                                fv_size = cand
                                break
                    # 固件常被截断采集，仅校验正值与合理上限
                    if fv_size > 0 and fv_size < 0x40000000:
                        offsets.append(pos)
                        logger.debug("[UEFI] FV found at offset {}, size {}".format(hex(pos), hex(fv_size)))
                except Exception:
                    logger.debug("suppressed", exc_info=True)
            pos += 1

        return offsets

    def _parse_firmware_volume(self, data, offset):
        """
        Parse a single Firmware Volume: extract header, GUID, and enumerate FFS files.
        """
        fv_info = FirmwareVolumeInfo()

        try:
            # FV header layout: signature(4) + attributes(4) + GUID(16) + size(8) + ...
            fv_header = data[offset:offset+64]
            fv_header = data[offset:offset+64]

            fv_info.offset = offset
            fv_info.size = struct.unpack('<Q', fv_header[16:24])[0]

            # GUID
            guid_bytes = fv_header[8:24]
            fv_info.guid = self._bytes_to_guid(guid_bytes)
            fv_info.name = 'FV_{}'.format(fv_info.guid[:8])

            # Enumerate FFS files within the FV body (after the 64-byte header)
            file_start = offset + 64
            file_end = offset + fv_info.size

            pos = file_start
            while pos < file_end - 24:
                # FFS file header: GUID(16) + type(1) + attributes(1) + size(3) + state(1)
                file_header = data[pos:pos+24]

                file_guid = self._bytes_to_guid(file_header[:16])
                file_type = file_header[16]
                # FFS size field is 3 bytes; pad to 4 for struct.unpack
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

                # Scan file body for embedded PE/TE executables
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

                # Align to 8-byte boundary per FFS spec
                pos += ((file_size + 7) // 8) * 8

            fv_info.file_count = len(fv_info.modules)

        except Exception as e:
            logger.warning("[UEFI] FV parse failed at {}: {}".format(hex(offset), e))
            return None

        return fv_info

    def _find_pe_in_section(self, data):
        """
        Linear scan for MZ (PE) or VZ (TE) magic bytes within a section body.
        """
        pos = 0
        n_len = len(data)
        while pos < n_len - 2:
            if data[pos:pos+2] == b'MZ':
                return pos
            if data[pos:pos+2] == b'VZ':
                return pos
            pos += 1
        return -1

    def _extract_pe_files_directly(self, data):
        """
        Direct PE extraction: scan for MZ headers and carve out PE images via pefile.
        Used when no FV structure is found.
        """
        pos = 0
        n_len = len(data)
        while pos < n_len - 2:
            if data[pos:pos+2] == b'MZ':
                # Determine PE image size via pefile parser
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
                except:
                    pos += 1
            else:
                pos += 1

    def _bytes_to_guid(self, guid_bytes):
        """
        Convert 16 raw bytes to UEFI GUID string format (mixed-endian decoding).
        """
        if len(guid_bytes) != 16:
            return '00000000-0000-0000-0000-000000000000'

        # UEFI GUID: first 3 fields are little-endian; remaining fields are big-endian
        part1 = struct.unpack('<I', guid_bytes[0:4])[0]
        part2 = struct.unpack('<H', guid_bytes[4:6])[0]
        part3 = struct.unpack('<H', guid_bytes[6:8])[0]
        part4 = struct.unpack('>H', guid_bytes[8:10])[0]
        part5 = struct.unpack('>Q', b'\x00\x00' + guid_bytes[10:16])[0]

        return '{:08x}-{:04x}-{:04x}-{:04x}-{:012x}'.format(part1, part2, part3, part4, part5)

    def _save_pe_file(self, module, pe_data):
        """
        Write extracted PE data to disk with a sanitized filename derived from the module name.
        """
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
        """
        Convert Terse Executable (TE) to a minimal PE header.
        TE is UEFI's compact PE variant: strips the DOS stub and optional headers.
        """
        try:
            # TE header: signature(2) + machine(2) + sections(1) + subsystem(1) + ...
            if len(te_data) < 40:
                return ''

            machine = struct.unpack('<H', te_data[2:4])[0]
            sections = te_data[4]
            subsystem = te_data[5]

            # Reconstruct a minimal PE header from TE fields
            pe_header = bytearray()
            pe_header.extend(b'MZ')  # DOS stub signature
            pe_header.extend(b'\x00' * 58)  # DOS stub padding
            pe_header.extend(b'PE\x00\x00')  # PE signature
            pe_header.extend(struct.pack('<H', machine))  # Machine type
            pe_header.extend(struct.pack('<H', sections))  # Section count
            pe_header.extend(b'\x00' * 12)  # Timestamp and reserved fields
            pe_header.extend(struct.pack('<H', subsystem))  # Subsystem

            # Synthesize PE binary: header + TE body
            pe_data = bytes(pe_header) + te_data[40:]

            return self._save_pe_file(module, pe_data)

        except Exception as e:
            logger.warning("[UEFI] TE conversion failed: {}".format(e))
            return ''

    def _classify_modules(self):
        """
        Partition modules into SMM, DXE, and PEI lists based on FFS type flags.
        """
        self.smm_modules = [m for m in self.modules if m.is_smm]
        self.dxe_modules = [m for m in self.modules if m.is_dxe]
        self.pei_modules = [m for m in self.modules if m.is_pei]

    def _extract_all_modules(self):
        """
        Count extracted modules and write module index JSON to output directory.
        Extraction itself happens during parsing; this method handles bookkeeping.
        """
        n_extracted = 0
        for m in self.modules:
            if m.pe_path:
                n_extracted += 1
        logger.info("[UEFI] {} PE/TE modules extracted".format(n_extracted))

        # Write module index for downstream tooling
        index_path = os.path.join(self.output_dir, 'modules_index.json')
        try:
            # Guard against missing attributes on uefi_firmware objects
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

            logger.info("[UEFI] module index saved: {}".format(index_path))
        except Exception as e:
            logger.warning("[UEFI] saveindexfailed: {}".format(e))

    def _analyze_modules(self):
        """
        Analyze extracted PE modules with pefile: enumerate imports, exports, and sections.
        Flags dangerous SMM functions in the import table.
        """
        logger.info("[UEFI] analyzing PE modules...")

        n_mods = len(self.modules)
        i = 0
        while i < n_mods:
            module = self.modules[i]
            if module.pe_path is not None and os.path.exists(module.pe_path):
                self._analyze_pe_module(module)
            i += 1

    def _analyze_pe_module(self, module):
        """
        Parse a single PE module: extract imports, exports, and section metadata.
        """
        if not PEFILE_AVAILABLE:
            return

        try:
            pe = pefile.PE(module.pe_path, fast_load=True)

            # Enumerate imported functions from each DLL
            imports = []
            dangerous = []

            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
             dir_imports = pe.DIRECTORY_ENTRY_IMPORT
             # DIRECTORY_ENTRY_IMPORT may not be iterable in all pefile versions; guarded
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

                            # Check for dangerous SMM functions
                            if s_func in SMM_DANGEROUS_FUNCTIONS:
                                dangerous.append(s_func)
                        k += 1
                    j += 1

            module.dangerous_functions = dangerous
            module.metadata['imports'] = imports
            module.metadata['dll_count'] = len(imports)

            # Enumerate exported symbols
            exports = []
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name is not None:
                        exports.append(exp.name.decode('utf-8', errors='ignore'))

            module.metadata['exports'] = exports

            # Extract section headers
            sections = []
            pe_sections = pe.sections
            p = 0
            n_secs = len(pe_sections)
            while p < n_secs:
             section = pe_sections[p]
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

    def _detect_smm_vulnerabilities(self):
        """
        SMM vulnerability detection across five dimensions:
        1. CommBuffer validation gaps
        2. SMRAM leak vectors
        3. Unsafe external calls from SMI handlers
        4. TOCTOU race windows
        5. Insufficient input validation
        """
        logger.info("[UEFI] running SMM vulnerability detection...")

        n_smm = len(self.smm_modules)
        i = 0
        while i < n_smm:
            module = self.smm_modules[i]
            vulns = self._detect_smm_module_vulnerabilities(module)
            module.vulnerabilities = vulns
            self.total_vulnerabilities.extend(vulns)
            i += 1

        logger.info("[UEFI] {} potential SMM vulnerabilities identified".format(len(self.total_vulnerabilities)))

    def _detect_smm_module_vulnerabilities(self, module):
        """
        Run the five SMM vulnerability checks against a single module.
        """
        vulns = []

        # 1. CommBuffer validation check
        vulns.extend(self._check_commbuffer_validation(module))

        # 2. SMRAM leak check
        vulns.extend(self._check_smram_leak(module))

        # 3. Unsafe external call check
        vulns.extend(self._check_unsafe_external_calls(module))

        # 4. TOCTOU check
        vulns.extend(self._check_toctou(module))

        # 5. Input validation check
        vulns.extend(self._check_input_validation(module))

        return vulns

    def _check_commbuffer_validation(self, module):
        """
        Flag modules that call SmmCommunicate without a corresponding validation function.
        """
        vulns = []

        # Detect SmmCommunicate usage without SmramIsValid or SmmIsCommunicateBufferValid
        has_communicate = False
        for f in module.dangerous_functions:
            if 'SmmCommunicate' in f:
                has_communicate = True
                break

        has_validation = False
        s_imports = module.metadata.get('imports', [])
        for f in s_imports:
            if 'SmramIsValid' in f or 'SmmIsCommunicateBufferValid' in f:
                has_validation = True
                break

        if has_communicate and not has_validation:
            vulns.append({
                'type': 'COMMBUFFER_VALIDATION_MISSING',
                'module': module.name,
                'guid': module.guid,
                'severity': 'Critical',
                'description': 'SMM driver uses SmmCommunicate without validating the communication buffer',
                'recommendation': 'Add SmramIsValid or SmmIsCommunicateBufferValid call',
                'evidence': 'SmmCommunicate present; validation function absent'
            })

        return vulns

    def _check_smram_leak(self, module):
        """
        Identify SMRAM leak risks: DMA operations and unbounded memory copies in SMM context.
        """
        vulns = []

        # Flag DMA functions in SMM drivers
        dma_funcs = ['DmaMap', 'DmaAllocateBuffer']
        has_dma = False
        for f in module.dangerous_functions:
            if f in dma_funcs:
                has_dma = True
                break

        if has_dma:
            vulns.append({
                'type': 'SMRAM_LEAK',
                'module': module.name,
                'guid': module.guid,
                'severity': 'High',
                'description': 'SMM driver uses DMA functions; may expose SMRAM',
                'recommendation': 'Verify DMA operations do not target SMRAM regions',
                'evidence': 'DMA functions detected: {}'.format(module.dangerous_functions)
            })

        # Detect unbounded memory copy functions in SMM context
        copy_funcs = ['SmmCopyMem', 'memcpy', 'CopyMem']
        s_imports = module.metadata.get('imports', [])
        has_copy = False
        for f in copy_funcs:
            if f in module.dangerous_functions:
                has_copy = True
                break
            for imp in s_imports:
                if f in imp:
                    has_copy = True
                    break
            if has_copy:
                break

        if has_copy and module.is_smm:
            # Verify presence of SafeCopy or bounds-checked memory operations
            has_safe_copy = False
            for imp in s_imports:
                if 'SafeCopy' in imp:
                    has_safe_copy = True
                    break

            if not has_safe_copy:
                vulns.append({
                    'type': 'INSUFFICIENT_INPUT_VALIDATION',
                    'module': module.name,
                    'guid': module.guid,
                    'severity': 'Medium',
                    'description': 'SMM driver uses memory copy without bounds-checked variant',
                    'recommendation': 'Replace with SafeCopyMem or add explicit length validation',
                    'evidence': 'Unsafe memory copy detected; SafeCopyMem absent'
                })

        return vulns

    def _check_unsafe_external_calls(self, module):
        """
        Flag SMI handlers that invoke external dispatch functions without caller validation.
        """
        vulns = []

        # Detect SMI handler registration
        smi_funcs = ['SmiHandler', 'SmmRegisterHandler']
        has_smi = False
        for f in module.dangerous_functions:
            if f in smi_funcs:
                has_smi = True
                break

        if has_smi:
            # Check whether external call targets are validated
            s_imports = module.metadata.get('imports', [])
            external_calls = [imp for imp in s_imports if
                            any(x in imp for x in ['Call', 'Invoke', 'Dispatch'])]

            if external_calls:
                vulns.append({
                    'type': 'UNSAFE_EXTERNAL_CALL',
                    'module': module.name,
                    'guid': module.guid,
                    'severity': 'High',
                    'description': 'External call detected within SMI handler',
                    'recommendation': 'Validate target address and parameters of external calls',
                    'evidence': 'External calls: {}'.format(external_calls[:5])
                })

        return vulns

    def _check_toctou(self, module):
        """
        Heuristic TOCTOU detection: co-occurrence of check-prefix and access-prefix imports.
        """
        vulns = []

        # Heuristic: paired check + access import patterns
        s_imports = module.metadata.get('imports', [])

        # Identify check-then-access import pairs
        check_funcs = [imp for imp in s_imports if 'Check' in imp or 'Verify' in imp or 'Validate' in imp]
        access_funcs = [imp for imp in s_imports if 'Access' in imp or 'Read' in imp or 'Get' in imp]

        if check_funcs and access_funcs:
            vulns.append({
                'type': 'TOCTOU_IN_SMI',
                'module': module.name,
                'guid': module.guid,
                'severity': 'Medium',
                'description': 'Potential check-time / use-time race condition',
                'recommendation': 'Use atomic operations or locking mechanisms',
                'evidence': 'Check functions: {}, access functions: {}'.format(check_funcs[:3], access_funcs[:3])
            })

        return vulns

    def _check_input_validation(self, module):
        """
        Flag SMM modules that consume external input without corresponding validation imports.
        """
        vulns = []

        s_imports = module.metadata.get('imports', [])

        # Detect input-processing imports without validation counterparts
        input_funcs = [imp for imp in s_imports if
                      any(x in imp.lower() for x in ['input', 'param', 'arg', 'buffer', 'data'])]

        validate_funcs = [imp for imp in s_imports if
                         any(x in imp.lower() for x in ['validate', 'check', 'verify', 'sanitize'])]

        if input_funcs and not validate_funcs and module.is_smm:
            vulns.append({
                'type': 'INSUFFICIENT_INPUT_VALIDATION',
                'module': module.name,
                'guid': module.guid,
                'severity': 'High',
                'description': 'SMM driver processes input without validation functions',
                'recommendation': 'Add input validation and bounds checking',
                'evidence': 'Input-processing functions: {}'.format(input_funcs[:5])
            })

        return vulns

    def _generate_report(self):
        """
        Compile the structured analysis report from all collected data.
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

    def _summarize_vulnerabilities(self):
        """
        Aggregate vulnerability counts by type for the summary section.
        """
        summary = defaultdict(int)

        n_vulns = len(self.total_vulnerabilities)
        i = 0
        while i < n_vulns:
            vuln = self.total_vulnerabilities[i]
            vuln_type = vuln.get('type', 'Unknown')
            summary[vuln_type] += 1
            i += 1

        return dict(summary)

    def _generate_recommendations(self):
        """
        Generate remediation recommendations based on detected vulnerability types.
        """
        recommendations = []

        vuln_types = set(v.get('type') for v in self.total_vulnerabilities)

        if 'COMMBUFFER_VALIDATION_MISSING' in vuln_types:
            recommendations.append('Add CommBuffer validation (SmramIsValid or SmmIsCommunicateBufferValid) to all SMM drivers')

        if 'SMRAM_LEAK' in vuln_types:
            recommendations.append('Audit DMA operations; verify they do not target SMRAM regions')

        if 'UNSAFE_EXTERNAL_CALL' in vuln_types:
            recommendations.append('Validate all external calls within SMI handlers')

        if 'TOCTOU_IN_SMI' in vuln_types:
            recommendations.append('Use atomic operations or locking to prevent TOCTOU races')

        if 'INSUFFICIENT_INPUT_VALIDATION' in vuln_types:
            recommendations.append('Add bounds checking and type validation on all external inputs')

        # Baseline recommendations when SMM modules are present
        if self.smm_modules:
            recommendations.append('Regularly update UEFI firmware to patch known vulnerabilities')
            recommendations.append('Enable UEFI Secure Boot and BIOS Guard')

        return recommendations

    def cleanup(self):
        """
        Remove temporary extraction directory if it resides under the system temp path.
        """
        if self.output_dir is not None and self.output_dir.startswith(tempfile.gettempdir()):
            try:
                shutil.rmtree(self.output_dir)
                logger.info("[UEFI] cleaned temp directory: {}".format(self.output_dir))
            except Exception as e:
                logger.warning("[UEFI] cleanup failed: {}".format(e))

def analyze_uefi_firmware(firmware_path, output_dir=None, extract_modules=True, analyze_smm=True):
    """
    Convenience function: construct analyzer, run pipeline, return report dict.
    """
    analyzer = UEFIFirmwareAnalyzer(
        firmware_path=firmware_path,
        output_dir=output_dir,
        extract_modules=extract_modules,
        analyze_smm=analyze_smm
    )

    result = analyzer.analyze()

    return result

# Public API surface

