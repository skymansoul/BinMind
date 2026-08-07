# 2026-07-31
import re
import struct
import hashlib
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class IOCTLHandler:
    code: int
    handler_addr: int
    method: str  # METHOD_缓冲区ED, METHOD_IN_DIRECT, METHOD_OUT_DIRECT, METHOD_NEITHER
    access: str  # FILE_ANY_ACCESS, FILE_READ_ACCESS, etc
    device_type: int
    is_dangerous: bool = False


class KernelModuleAnalyzer:
    """Linux LKM + Windows 驱动 + macOS kext analysis: IOCTL, dangerous API, tainted kernel"""

# 初始化: 三平台特征

    def __init__(self):
        # Windows 驱动危险API
        self._win_dangerous_apis = {
            'memory': [
                'MmMapIoSpace', 'MmMapLockedPages', 'MmAllocateContiguousMemory',
                'MmGetPhysicalAddress', 'MmAllocatePagesForMdl',
                'MmProbeAndLockPages', 'MmUnlockPages',
                'ExAllocatePoolWithTag', 'ExFreePoolWithTag',
            ],
            'ioctl': [
                'METHOD_NEITHER', 'IoCompleteRequest', 'IofCompleteRequest',
                'ProbeForRead', 'ProbeForWrite',
            ],
            'registry': [
                'ZwCreateKey', 'ZwSetValueKey', 'ZwDeleteKey',
                'ZwOpenKey', 'ZwQueryValueKey',
            ],
            'process': [
                'PsCreateSystemThread', 'PsSetCreateProcessNotifyRoutine',
                'PsSetLoadImageNotifyRoutine', 'ZwCreateProcess',
                'ZwOpenProcess', 'ZwTerminateProcess',
            ],
            'file': [
                'ZwCreateFile', 'ZwReadFile', 'ZwWriteFile',
                'ZwDeleteFile', 'ZwSetInformationFile',
            ],
            'ssdt': [
                'KeServiceDescriptorTable', 'KeServiceDescriptorTableShadow',
                'KeAddSystemServiceTable',
            ],
            'obfuscation': [
                'MmIsAddressValid', 'ObReferenceObjectByName',
                'PsGetCurrentProcess', 'PsGetCurrentThread',
                'KeGetCurrentIrql', 'KdDebuggerEnabled',
            ],
        }

        # Linux LKM危险API
        self._linux_dangerous_apis = {
            'memory': [
                'ioremap', 'iounmap', 'kmap', 'kunmap',
                '__get_free_pages', 'get_free_pages', 'vmalloc', 'vfree',
                'kmalloc', 'kfree', 'kzalloc', 'kcalloc',
                'copy_from_user', 'copy_to_user', 'get_user', 'put_user',
            ],
            'syscall': [
                'sys_call_table', 'sysenter_table',
                'set_fs', 'get_fs', 'segment_eq',
            ],
            'process': [
                'call_usermodehelper', 'kthread_run', 'kthread_create',
                'kernel_thread', 'kernel_execve',
            ],
            'file': [
                'filp_open', 'kernel_read', 'kernel_write',
                'vfs_read', 'vfs_write', 'set_fs_pwd',
            ],
            'hook': [
                'ftrace_set_filter', 'register_kprobe',
                'register_kretprobe', 'text_poke', 'text_poke_early',
                'stop_machine',
            ],
            'net': [
                'nf_register_net_hook', 'nf_unregister_net_hook',
                'nf_hookfn', 'dev_add_pack',
            ],
            'hide': [
                'list_del', 'kobject_del', 'kobj_map',
            ],
        }

        # macOS kext危险API
        self._macos_dangerous_apis = {
            'memory': [
                'IOMalloc', 'IOFree', 'IOMallocAligned',
                'ml_static_malloc', 'OSMalloc', 'OSFree',
            ],
            'io': [
                'IOConnectCallMethod', 'IOConnectCallScalarMethod',
                'IOConnectCallStructMethod',
            ],
            'mach': [
                'mach_vm_allocate', 'mach_vm_deallocate',
                'mach_vm_protect', 'mach_vm_read', 'mach_vm_write',
                'vm_map_wire', 'vm_map_unwire',
            ],
        }

        # IOCTL method types (bits 0-1 IOCTL code)
        self._ioctl_methods = {
            0: 'METHOD_BUFFERED',
            1: 'METHOD_IN_DIRECT',
            2: 'METHOD_OUT_DIRECT',
            3: 'METHOD_NEITHER',
        }

        self._ioctl_access = {
            0: 'FILE_ANY_ACCESS',
            1: 'FILE_READ_ACCESS',
            2: 'FILE_WRITE_ACCESS',
            3: 'FILE_READ_ACCESS | FILE_WRITE_ACCESS',
        }

# 平台检测

    def detect_platform(self, data: bytes, strings: List[str]) -> str:
        _strs_text = ' '.join(strings)

        # Windows 驱动
        if b'DriverEntry' in data or b'DRIVER_OBJECT' in data:
            return 'windows'
        if 'DriverEntry' in _strs_text or 'DriverObject' in _strs_text:
            return 'windows'
        if b'IOCTL' in data or b'IRP_MJ_' in data:
            return 'windows'
        if data[:2] == b'MZ':
            return 'windows'

        # Linux LKM
        if b'module_init' in data or b'module_exit' in data:
            return 'linux'
        if b'MODULE_LICENSE' in data or b'__this_module' in data:
            return 'linux'
        if 'module_init' in _strs_text or 'MODULE_LICENSE' in _strs_text:
            return 'linux'

        # macOS kext
        if b'IOKit' in data or b'OSDeclareDefaultStructors' in data:
            return 'macos'
        if b'com.apple' in data or b'IOUserClient' in data:
            return 'macos'
        if 'IOKit' in _strs_text or 'OSDefineMetaClass' in _strs_text:
            return 'macos'

        return 'unknown'

    # //// IOCTL 处理器枚举 (仅Windows) ////

    def enumerate_ioctl_handlers(self, data: bytes,
                                  strings: List[str]) -> List[IOCTLHandler]:
        _handlers = []
        _strs_text = ' '.join(strings)

        # CTL_CODE宏: CTL_CODE(DeviceType, Function, Method, Access)
        # = ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method)
        _ioctl_patterns = [
            # Literal numbers switch/ statements
            re.compile(rb'(?:case|0x)([0-9A-Fa-f]{8})\s*:', re.I),
            # CTL_CODE macro
            re.compile(rb'CTL_CODE\s*\([^,]+,\s*0x(\w+)', re.I),
        ]

        _found_codes = set()
        for _pat in _ioctl_patterns:
            for _m in _pat.finditer(data):
                try:
                    _code = int(_m.group(1), 16)
                    if 0x00000000 < _code < 0xFFFFFFFF:
                        _found_codes.add(_code)
                except (ValueError, IndexError):
                    pass

        for _code in _found_codes:
            _dev_type = (_code >> 16) & 0xFFFF
            _access = (_code >> 14) & 0x3
            _func = (_code >> 2) & 0xFFF
            _method = _code & 0x3

            # METHOD_NEITHER dangerous
            _is_dangerous = _method == 3

            _handlers.append(IOCTLHandler(
                code=_code,
                handler_addr=0,  # needs disasm 解析
                method=self._ioctl_methods.get(_method, f'UNKNOWN({_method})'),
                access=self._ioctl_access.get(_access, f'UNKNOWN({_access})'),
                device_type=_dev_type,
                is_dangerous=_is_dangerous,
            ))

        return _handlers

# 危险API扫描

    def scan_dangerous_apis(self, imports: Dict[str, List[str]],
                            strings: List[str],
                            platform: str = 'unknown') -> List[Dict]:
        _findings = []
        _strs_text = ' '.join(strings)
        _imp_flat = set()
        for _mod, _funcs in imports.items():
            for _f in _funcs:
                _imp_flat.add(_f.lower())

        # 根据平台选择API库
        if platform == 'windows':
            _apis = self._win_dangerous_apis
        elif platform == 'linux':
            _apis = self._linux_dangerous_apis
        elif platform == 'macos':
            _apis = self._macos_dangerous_apis
        else:
            # 检查 platforms
            _apis = {}
            for _d in [self._win_dangerous_apis, self._linux_dangerous_apis,
                        self._macos_dangerous_apis]:
                for _k, _v in _d.items():
                    _apis.setdefault(_k, []).extend(_v)

        for _cat, _api_list in _apis.items():
            _found = []
            for _api in _api_list:
                _al = _api.lower()
                if _al in _strs_text.lower():
                    _found.append(_api)
                elif any(_al in _imp for _imp in _imp_flat):
                    _found.append(_api)

            if _found:
                _sev = 'MEDIUM'
                if _cat in ('ssdt', 'syscall', 'hook', 'hide'):
                    _sev = 'HIGH'
                elif _cat == 'memory' and len(_found) >= 3:
                    _sev = 'HIGH'

                _findings.append({
                    'category': _cat,
                    'apis': _found,
                    'severity': _sev,
                    'description': f'{len(_found)} dangerous {_cat} API(s) found',
                })

        return _findings

# Tainted/Unsigned module检测

    def detect_tainted_module(self, data: bytes, strings: List[str],
                               filepath: str = None) -> Dict:
        _indicators = []
        _strs_text = ' '.join(strings).lower()

        # 1. 无签名/自签名检测 (PE)
        if data[:2] == b'MZ':
            # 检查 security directory empty
            _pe_off = struct.unpack('<I', data[0x3C:0x40])[0] if len(data) > 0x40 else 0
            if _pe_off + 160 < len(data):
                _sec_dir_rva = struct.unpack('<I', data[_pe_off + 24 + 128:
                                                       _pe_off + 24 + 132])[0]
                _sec_dir_size = struct.unpack('<I', data[_pe_off + 24 + 132:
                                                         _pe_off + 24 + 136])[0]
                if _sec_dir_size == 0:
                    _indicators.append('unsigned_pe (empty security directory)')

        # 2. 内核版本信息缺失/伪造
        if platform := self.detect_platform(data, strings):
            if platform == 'linux':
                if 'MODULE_LICENSE' not in _strs_text:
                    _indicators.append('missing_MODULE_LICENSE')
                if 'GPL' not in _strs_text:
                    _indicators.append('non-GPL_license (tainted kernel)')

        # 3. 隐藏/混淆行为
        _hide_indicators = [
            'kobject_del', 'list_del', 'unregister',
            'hide', 'stealth', 'rootkit',
            'DKOM', 'FuTo', 'Heavens',
        ]
        for _ind in _hide_indicators:
            if _ind.lower() in _strs_text:
                _indicators.append(f'hiding_behavior_{_ind}')
                break

        # 4. 直接内存操作 (LKM)
        _mem_indicators = [
            'sys_call_table', 'sysenter_table', 'idt_table',
            'MmMapIoSpace', 'MmGetPhysicalAddress',
            'MmIsAddressValid',
        ]
        for _ind in _mem_indicators:
            if _ind.lower() in _strs_text:
                _indicators.append(f'direct_memory_access_{_ind}')
                break

        # 5. 无符号驱动 (自我生成/注入)
        _injection_indicators = [
            'ZwLoadDriver', 'NtLoadDriver', 'SCManager',
            'CreateServiceA', 'StartServiceA',
            'SeLoadDriverPrivilege',
        ]
        _injection_count = 0
        for _ind in _injection_indicators:
            if _ind.lower() in _strs_text:
                _injection_count += 1
        if _injection_count >= 2:
            _indicators.append('driver_injection_capability')

        _is_tainted = len(_indicators) >= 2
        _score = min(len(_indicators) * 25, 100)

        return {
            'is_tainted': _is_tainted,
            'taint_score': _score,
            'risk_level': 'HIGH' if _score >= 50 else ('MEDIUM' if _score >= 25 else 'LOW'),
            'indicators': _indicators,
        }

    # //// 综合分析入口 ////

    def analyze(self, data: bytes = None, filepath: str = None,
                strings: List[str] = None, imports: Dict[str, List[str]] = None) -> Dict:
        if data is None and filepath:
            with open(filepath, 'rb') as _f:
                data = _f.read()

        if data is None:
            return {'error': 'no data or filepath provided'}

        if strings is None:
            strings = self._extract_strings(data)
        if imports is None:
            imports = {}

        _platform = self.detect_platform(data, strings)
        _ioctls = self.enumerate_ioctl_handlers(data, strings) if _platform == 'windows' else []
        _apis = self.scan_dangerous_apis(imports, strings, _platform)
        _taint = self.detect_tainted_module(data, strings, filepath)

        # Adjust IOCTL danger assessment
        _danger_ioctls = [i for i in _ioctls if i.is_dangerous]

        return {
            'platform': _platform,
            'ioctl_handlers': _ioctls,
            'dangerous_ioctls': _danger_ioctls,
            'dangerous_api_categories': _apis,
            'tainted_module': _taint,
            'summary': {
                'platform': _platform,
                'total_ioctls': len(_ioctls),
                'dangerous_ioctl_count': len(_danger_ioctls),
                'dangerous_api_categories': len(_apis),
                'total_dangerous_apis': sum(len(a['apis']) for a in _apis),
                'is_tainted': _taint['is_tainted'],
                'risk_level': _taint['risk_level'],
            },
        }

# 辅助

    def _extract_strings(self, data: bytes, min_len=4) -> List[str]:
        _strings = []
        _pat = re.compile(rb'[\x20-\x7e]{%d,}' % min_len)
        for _m in _pat.finditer(data):
            _strings.append(_m.group().decode('ascii', errors='ignore'))
        _i = 0
        while _i < len(data) - 1:
            if 0x20 <= data[_i] <= 0x7e and data[_i + 1] == 0:
                _buf = bytearray()
                _j = _i
                while _j < len(data) - 1 and 0x20 <= data[_j] <= 0x7e and data[_j + 1] == 0:
                    _buf.append(data[_j])
                    _j += 2
                if len(_buf) >= min_len:
                    _strings.append(_buf.decode('ascii', errors='ignore'))
                _i = _j
            else:
                _i += 1
        return _strings
