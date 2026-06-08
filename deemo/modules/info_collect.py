import logging
import os
import struct
import re
import shlex
from typing import Dict, List, Optional, Tuple, Any

logger = logging.getLogger(__name__)

DANGEROUS_FUNCTIONS = [
    'gets', 'strcpy', 'strcat', 'sprintf', 'vsprintf',
    'scanf', 'sscanf', 'fscanf', 'vscanf',
    'system', 'execve', 'execl', 'execle', 'execlp', 'execv', 'execvp',
    'popen', 'unlink', 'remove',
    'malloc', 'free', 'realloc', 'calloc',
    'memcpy', 'memmove', 'memset'
]

KERNEL_DANGEROUS_FUNCTIONS = [
    'copy_from_user', 'copy_to_user',
    'kmalloc', 'kzalloc', 'kfree', 'vmalloc', 'vfree',
    'ioremap', 'ioremap_nocache', 'request_mem_region', 'release_mem_region',
    'ioremap', 'iounmap',
    'request_region', 'release_region',
    'kstrtol', 'kstrtoul', 'kstrtoint',
    'get_user', 'put_user',
    '__get_user', '__put_user',
    'access_ok',
    'strncpy_from_user', 'strnlen_user',
    'copy_in_user',
    'smp_mb', 'smp_rmb', 'smp_wmb',
    'spin_lock', 'spin_unlock',
    'mutex_lock', 'mutex_unlock',
    'down', 'up',
    'printk',
    'alloc_netdev', 'free_netdev',
    'skb_copy', 'skb_clone',
    'submit_bio', 'generic_make_request',
    'blk_rq_map_kern',
    'dma_alloc_coherent', 'dma_free_coherent',
    'vmemmap',
    'kallsyms_lookup_name',
    'module_layout',
    'init_module', 'cleanup_module',
    'sprintf', 'vsprintf',
    'sscanf', 'vsscanf'
]

KERNEL_DRIVER_DANGEROUS_FUNCTIONS = [
    'MmCopyVirtualMemory',
    'ZwMapViewOfSection', 'ZwUnmapViewOfSection',
    'MmMapIoSpace', 'MmUnmapIoSpace',
    'MmAllocateContiguousMemory', 'MmFreeContiguousMemory',
    'ExAllocatePool', 'ExAllocatePoolWithTag',
    'ExFreePool', 'ExFreePoolWithTag',
    'IoCreateDevice', 'IoDeleteDevice',
    'IoCreateSymbolicLink', 'IoDeleteSymbolicLink',
    'IoGetCurrentIrpStackLocation',
    'IofCallDriver', 'IoCompleteRequest',
    'KeBugCheck', 'KeBugCheckEx',
    'KeInitializeSpinLock', 'KeAcquireSpinLock', 'KeReleaseSpinLock',
    'KfRaiseIrql', 'KfLowerIrql',
    'ObReferenceObjectByHandle', 'ObDereferenceObject',
    'SeAccessCheck',
    'PsGetCurrentProcess', 'PsGetCurrentThread',
    'PsLookupProcessByProcessId',
    'RtlCopyMemory', 'RtlMoveMemory', 'RtlFillMemory',
    'RtlCompareMemory',
    'RtlUnicodeStringToAnsiString',
    'RtlInitUnicodeString',
    'NtOpenProcess', 'NtOpenThread',
    'NtReadVirtualMemory', 'NtWriteVirtualMemory',
    'NtAllocateVirtualMemory', 'NtFreeVirtualMemory',
    'NtCreateThreadEx',
    'NtQueryInformationProcess',
    'ZwQueryInformationProcess',
    'ZwSetInformationThread',
    'ZwTerminateProcess',
    'IoGetDeviceObjectPointer',
    'IoGetCurrentProcess',
    'IoIs32bitProcess',
    'MmGetSystemRoutineAddress',
    'MmGetPhysicalAddress',
    'MmGetVirtualForPhysical',
    'HalGetInterruptVector',
    'KeInitializeDpc',
    'KeInsertQueueDpc',
    'IoAllocateIrp', 'IoFreeIrp',
    'IoBuildAsynchronousFsdRequest',
    'IoBuildSynchronousFsdRequest',
    'PoSetPowerState',
    'PoCallDriver',
    'WdfDeviceCreate', 'WdfDriverCreate',
    'WdfObjectReference', 'WdfObjectDereference'
]


def validate_binary_path(binary_path: str) -> str:
    """
    验证并规范化二进制文件路径，防止路径遍历和命令注入攻击
    
    Args:
        binary_path: 原始二进制文件路径
        
    Returns:
        规范化后的绝对路径
        
    Raises:
        ValueError: 如果路径包含危险字符或格式无效
    """
    if not binary_path or not isinstance(binary_path, str):
        raise ValueError("二进制文件路径不能为空")
    
    dangerous_patterns = [
        r'\.\.',
        r'\$\(',
        r'`',
        r'\|\|',
        r'&&',
        r';',
        r'\n',
        r'\r',
        r'\$',
        r'\|',
        r'&',
        r'<',
        r'>',
        r'\?',
        r'\*',
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, binary_path):
            logger.warning(f"检测到危险路径模式: {repr(binary_path)}")
            raise ValueError(f"路径包含危险字符: {binary_path}")
    
    try:
        abs_path = os.path.abspath(os.path.expanduser(binary_path))
    except Exception as e:
        raise ValueError(f"无法解析路径: {e}")
    
    if not os.path.isabs(abs_path):
        raise ValueError(f"路径必须是绝对路径: {abs_path}")
    
    return abs_path

KEY_STRING_PATTERNS = [
    'system', 'bin/sh', 'cat', '/etc/passwd', 'flag',
    'password', 'secret', 'admin', 'root',
    'sudo', 'chmod', 'chown', 'setuid', 'setgid',
    'cmd.exe', 'powershell', 'CreateProcess', 'WinExec',
    'ShellExecute'
]


def detect_binary_format(binary_path: str) -> str:
    """
    检测二进制文件格式
    
    Args:
        binary_path: 文件路径
        
    Returns:
        'ELF', 'PE', 'MACH-O', 'KO' (Linux内核模块), 'SYS' (Windows驱动), 或 'UNKNOWN'
    """
    try:
        with open(binary_path, 'rb') as f:
            header = f.read(16)
            
        if len(header) < 4:
            return 'UNKNOWN'
            
        if header[:4] == b'\x7fELF':
            base_name = os.path.basename(binary_path).lower()
            if base_name.endswith('.ko') or _is_linux_kernel_module(binary_path):
                return 'KO'
            return 'ELF'
        elif header[:2] == b'MZ':
            base_name = os.path.basename(binary_path).lower()
            if base_name.endswith('.sys') or _is_windows_driver(binary_path):
                return 'SYS'
            return 'PE'
        elif header[:4] in [b'\xca\xfe\xba\xbe', b'\xfe\xed\xfa\xce', 
                            b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe']:
            return 'MACH-O'
        else:
            return 'UNKNOWN'
    except Exception as e:
        logger.error(f"检测文件格式失败: {e}")
        return 'UNKNOWN'


def _is_linux_kernel_module(binary_path: str) -> bool:
    """
    检查 ELF 文件是否为 Linux 内核模块
    
    判断依据:
    1. 文件名以 .ko 结尾
    2. 包含内核模块特有的符号 (init_module, cleanup_module, module_layout)
    3. 包含 .modinfo 段
    """
    try:
        try:
            from pwn import ELF
            elf = ELF(binary_path, checksec=False)
            
            kernel_symbols = ['init_module', 'cleanup_module', 'module_layout', 
                            '__this_module', 'pcpu_hot']
            for sym in kernel_symbols:
                if sym in elf.symbols:
                    logger.info(f"检测到内核模块符号: {sym}")
                    elf.close()
                    return True
            
            elf.close()
        except Exception:
            pass
        
        try:
            import subprocess
            from config import Config
            
            result = subprocess.run(
                ['readelf', '-S', binary_path],
                capture_output=True,
                text=True,
                timeout=Config.SUBPROCESS_TIMEOUT
            )
            if result.returncode == 0 and '.modinfo' in result.stdout:
                logger.info("检测到 .modinfo 段，确认为内核模块")
                return True
        except Exception:
            pass
        
        return False
    except Exception as e:
        logger.debug(f"内核模块检测失败: {e}")
        return False


def _is_windows_driver(binary_path: str) -> bool:
    """
    检查 PE 文件是否为 Windows 驱动
    
    判断依据:
    1. 文件名以 .sys 结尾
    2. PE 头中的子系统为 NATIVE (IMAGE_SUBSYSTEM_NATIVE = 1)
    3. 包含驱动特有的导出函数 (DriverEntry, Unload, AddDevice)
    """
    try:
        try:
            import pefile
            pe = pefile.PE(binary_path)
            
            if hasattr(pe, 'OPTIONAL_HEADER'):
                subsystem = pe.OPTIONAL_HEADER.Subsystem
                if subsystem == 1:
                    logger.info("检测到 SUBSYSTEM=NATIVE，确认为 Windows 驱动")
                    pe.close()
                    return True
            
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                driver_exports = ['DriverEntry', 'DriverUnload', 'AddDevice', 
                                'EvtDriverDeviceAdd', 'EvtDriverUnload']
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        try:
                            name = exp.name.decode('utf-8', errors='ignore')
                            for driver_sym in driver_exports:
                                if driver_sym.lower() in name.lower():
                                    logger.info(f"检测到驱动导出函数: {name}")
                                    pe.close()
                                    return True
                        except Exception:
                            pass
            
            pe.close()
        except Exception:
            pass
        
        return False
    except Exception as e:
        logger.debug(f"Windows 驱动检测失败: {e}")
        return False


def validate_file(binary_path: str) -> Tuple[bool, str]:
    """
    验证文件是否存在并可读取
    
    Returns:
        (is_valid, error_message)
    """
    if not os.path.exists(binary_path):
        return False, f"文件不存在: {binary_path}"
    
    if not os.path.isfile(binary_path):
        return False, f"路径不是文件: {binary_path}"
        
    try:
        with open(binary_path, 'rb') as f:
            f.read(4)
        return True, None
    except PermissionError:
        return False, f"没有权限读取文件: {binary_path}"
    except Exception as e:
        return False, f"读取文件失败: {e}"


def validate_elf_file(binary_path: str) -> bool:
    """
    验证文件是否为有效的 ELF 文件
    """
    is_valid, error = validate_file(binary_path)
    if not is_valid:
        logger.error(error)
        return False
    
    try:
        with open(binary_path, 'rb') as f:
            header = f.read(4)
            
        if header != b'\x7fELF':
            logger.error(f"文件不是 ELF 格式: {binary_path}")
            return False
        
        return True
    except Exception as e:
        logger.error(f"验证 ELF 文件时出错: {e}")
        return False


def validate_pe_file(binary_path: str) -> bool:
    """
    验证文件是否为有效的 PE 文件
    """
    is_valid, error = validate_file(binary_path)
    if not is_valid:
        logger.error(error)
        return False
    
    try:
        with open(binary_path, 'rb') as f:
            header = f.read(2)
            if header != b'MZ':
                logger.error(f"文件不是 PE 格式: {binary_path}")
                return False
        return True
    except Exception as e:
        logger.error(f"验证 PE 文件时出错: {e}")
        return False


def validate_macho_file(binary_path: str) -> bool:
    """
    验证文件是否为有效的 Mach-O 文件
    """
    is_valid, error = validate_file(binary_path)
    if not is_valid:
        logger.error(error)
        return False
    
    macho_magic = [b'\xca\xfe\xba\xbe', b'\xfe\xed\xfa\xce', 
                   b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe']
    
    try:
        with open(binary_path, 'rb') as f:
            header = f.read(4)
            if header not in macho_magic:
                logger.error(f"文件不是 Mach-O 格式: {binary_path}")
                return False
        return True
    except Exception as e:
        logger.error(f"验证 Mach-O 文件时出错: {e}")
        return False


def load_elf(binary_path: str) -> Optional[object]:
    """
    加载 ELF 文件
    """
    try:
        from pwn import ELF
        
        if not validate_elf_file(binary_path):
            return None
        
        logger.info(f"正在加载 ELF 文件: {binary_path}")
        elf = ELF(binary_path, checksec=False)
        logger.info(f"成功加载 ELF 文件: {binary_path}")
        return elf
        
    except ImportError:
        logger.error("pwntools 库未安装，无法加载 ELF 文件")
        return None
    except Exception as e:
        logger.error(f"加载 ELF 文件失败: {type(e).__name__}: {e}")
        return None


def load_pe(binary_path: str) -> Optional[object]:
    """
    加载 PE 文件，利用 pwntools 的 PE 类
    """
    try:
        from pwnlib.elf.pe import PE
        
        if not validate_pe_file(binary_path):
            return None
        
        logger.info(f"正在加载 PE 文件: {binary_path}")
        pe = PE(binary_path)
        logger.info(f"成功加载 PE 文件: {binary_path}")
        return pe
        
    except ImportError:
        logger.warning("pwntools PE 支持不可用，尝试使用 pefile")
        try:
            import pefile
            if not validate_pe_file(binary_path):
                return None
            logger.info(f"正在加载 PE 文件 (pefile): {binary_path}")
            pe = pefile.PE(binary_path)
            logger.info(f"成功加载 PE 文件 (pefile): {binary_path}")
            return pe
        except ImportError:
            logger.error("未安装 pwntools PE 支持或 pefile 库")
            return None
    except Exception as e:
        logger.error(f"加载 PE 文件失败: {type(e).__name__}: {e}")
        return None


def load_macho(binary_path: str) -> Optional[object]:
    """
    加载 Mach-O 文件
    """
    try:
        from pwnlib.elf.macho import MachO
        
        if not validate_macho_file(binary_path):
            return None
        
        logger.info(f"正在加载 Mach-O 文件: {binary_path}")
        macho = MachO(binary_path)
        logger.info(f"成功加载 Mach-O 文件: {binary_path}")
        return macho
        
    except ImportError:
        logger.warning("pwntools Mach-O 支持不可用，尝试使用 macholib")
        try:
            import macholib.MachO
            if not validate_macho_file(binary_path):
                return None
            logger.info(f"正在加载 Mach-O 文件 (macholib): {binary_path}")
            macho = macholib.MachO.MachO(binary_path)
            logger.info(f"成功加载 Mach-O 文件 (macholib): {binary_path}")
            return macho
        except ImportError:
            logger.error("未安装 pwntools Mach-O 支持或 macholib 库")
            return None
    except Exception as e:
        logger.error(f"加载 Mach-O 文件失败: {type(e).__name__}: {e}")
        return None


def load_binary(binary_path: str) -> Tuple[Optional[object], str]:
    """
    自动检测并加载二进制文件
    
    Returns:
        (binary_object, format_type)
    """
    binary_format = detect_binary_format(binary_path)
    logger.info(f"检测到文件格式: {binary_format}")
    
    if binary_format == 'ELF':
        return load_elf(binary_path), 'ELF'
    elif binary_format == 'PE':
        return load_pe(binary_path), 'PE'
    elif binary_format == 'MACH-O':
        return load_macho(binary_path), 'MACH-O'
    else:
        logger.error(f"不支持的文件格式: {binary_path}")
        return None, 'UNKNOWN'


def get_checksec_elf(elf: object) -> Dict[str, Any]:
    """
    获取 ELF 的保护机制信息
    """
    try:
        checksec = {
            'nx': getattr(elf, 'nx', None),
            'pie': getattr(elf, 'pie', None),
            'relro': getattr(elf, 'relro', None),
            'canary': getattr(elf, 'canary', None),
            'aslr': None,
            'format': 'ELF'
        }
        
        logger.info(f"ELF 保护机制: NX={checksec['nx']}, PIE={checksec['pie']}, "
                   f"RELRO={checksec['relro']}, Canary={checksec['canary']}")
        return checksec
    except AttributeError as e:
        logger.warning(f"获取部分保护机制字段失败: {e}")
        return {'format': 'ELF'}
    except Exception as e:
        logger.error(f"获取保护机制失败: {e}")
        return {'format': 'ELF'}


def get_checksec_pe(pe: object, binary_path: str) -> Dict[str, Any]:
    """
    获取 PE 文件的保护机制信息
    """
    checksec = {
        'nx': False,
        'pie': False,
        'aslr': False,
        'safeseh': False,
        'dep': False,
        'cfg': False,
        'gs': False,
        'format': 'PE'
    }
    
    try:
        module_name = type(pe).__module__
        
        if 'pefile' in module_name:
            opt_header = getattr(pe, 'OPTIONAL_HEADER', None)
            if opt_header:
                dll_characteristics = getattr(opt_header, 'DllCharacteristics', 0)
                
                IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
                IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
                IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400
                IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000
                
                checksec['pie'] = (dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0
                checksec['nx'] = (dll_characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0
                checksec['dep'] = checksec['nx']
                checksec['aslr'] = checksec['pie']
                checksec['cfg'] = (dll_characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0
                
                no_seh = (dll_characteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH) != 0
                
                if hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG'):
                    for entry in pe.DIRECTORY_ENTRY_LOAD_CONFIG:
                        if hasattr(entry, 'SecurityCookie') and entry.SecurityCookie:
                            checksec['gs'] = True
                            checksec['canary'] = True
                        if hasattr(entry, 'SEHandlerTable'):
                            checksec['safeseh'] = not no_seh
            else:
                logger.warning("PE 文件缺少 OPTIONAL_HEADER")
        elif 'pwnlib' in module_name:
            checksec['nx'] = getattr(pe, 'nx', False)
            checksec['pie'] = getattr(pe, 'pie', False)
            checksec['relro'] = getattr(pe, 'relro', None)
            checksec['canary'] = getattr(pe, 'canary', None)
        
        logger.info(f"PE 保护机制: NX/DEP={checksec['nx']}, ASLR={checksec['aslr']}, "
                   f"SafeSEH={checksec['safeseh']}, CFG={checksec['cfg']}, GS={checksec['gs']}")
        
        return checksec
    except Exception as e:
        logger.error(f"获取 PE 保护机制失败: {e}")
        return {'format': 'PE'}


def get_checksec_macho(macho: object, binary_path: str) -> Dict[str, Any]:
    """
    获取 Mach-O 文件的保护机制信息
    """
    checksec = {
        'nx': True,
        'pie': False,
        'canary': False,
        'arc': False,
        'fortify_source': False,
        'format': 'MACH-O'
    }
    
    try:
        module_name = type(macho).__module__
        
        if 'macholib' in module_name:
            for header in macho.headers:
                mach_header = header.header
                MH_PIE = 0x200000
                MH_NO_HEAP_EXECUTION = 0x01000000
                
                flags = getattr(mach_header, 'flags', 0)
                checksec['pie'] = (flags & MH_PIE) != 0
                
                if hasattr(header, 'load_commands'):
                    for cmd in header.load_commands:
                        cmd_type = getattr(cmd[0], 'cmd', 0)
                        LC_ENCRYPTION_INFO = 0x21
                        LC_ENCRYPTION_INFO_64 = 0x2C
                        if cmd_type in [LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64]:
                            checksec['encrypted'] = True
        elif 'pwnlib' in module_name:
            checksec['nx'] = getattr(macho, 'nx', True)
            checksec['pie'] = getattr(macho, 'pie', False)
        
        logger.info(f"Mach-O 保护机制: NX={checksec['nx']}, PIE={checksec['pie']}, "
                   f"Canary={checksec['canary']}, ARC={checksec['arc']}")
        
        return checksec
    except Exception as e:
        logger.error(f"获取 Mach-O 保护机制失败: {e}")
        return {'format': 'MACH-O'}


def get_checksec(binary_obj: object, binary_format: str = 'ELF', binary_path: str = '') -> Dict[str, Any]:
    """
    根据二进制格式获取保护机制信息
    """
    if binary_format == 'ELF':
        return get_checksec_elf(binary_obj)
    elif binary_format == 'PE':
        return get_checksec_pe(binary_obj, binary_path)
    elif binary_format == 'MACH-O':
        return get_checksec_macho(binary_obj, binary_path)
    else:
        logger.warning(f"未知格式，无法获取保护机制: {binary_format}")
        return {'format': binary_format}


def get_imported_functions(elf: object) -> Dict[str, List[str]]:
    """
    获取导入的函数，特别关注危险函数
    兼容 pwntools 4.x 不同版本的 API
    """
    try:
        imports = {}
        dangerous_found = []
        
        # 方式1：尝试 elf.imports (旧版)
        elf_imports = getattr(elf, 'imports', None)
        if elf_imports:
            for lib, funcs in elf_imports.items():
                imports[lib] = []
                func_names = list(funcs.keys()) if isinstance(funcs, dict) else list(funcs) if isinstance(funcs, (list, set)) else []
                for func_name in func_names:
                    imports[lib].append(func_name)
                    if func_name in DANGEROUS_FUNCTIONS:
                        dangerous_found.append(func_name)
        
        # 方式2：尝试 elf.plt (新版 pwntools 4.x)
        if not dangerous_found:
            plt = getattr(elf, 'plt', {})
            if plt:
                for func_name, addr in plt.items():
                    if func_name in DANGEROUS_FUNCTIONS:
                        dangerous_found.append(func_name)
                    if 'plt' not in imports:
                        imports['plt'] = []
                    imports['plt'].append(func_name)
        
        # 方式3：直接从 symbol 表找 PLT 条目
        if not dangerous_found:
            symbols = getattr(elf, 'symbols', {})
            for name in symbols:
                if name in DANGEROUS_FUNCTIONS or name.startswith('plt.'):
                    clean_name = name.replace('plt.', '')
                    if clean_name in DANGEROUS_FUNCTIONS:
                        dangerous_found.append(clean_name)
        
        # 方式4：解析 GOT 表查找外部函数
        if not dangerous_found:
            got = getattr(elf, 'got', {})
            for name in got:
                if name in DANGEROUS_FUNCTIONS:
                    dangerous_found.append(name)
        
        logger.info(f"发现危险函数: {dangerous_found}")
        return {
            'all_imports': imports,
            'dangerous_functions': list(set(dangerous_found))
        }
    except AttributeError as e:
        logger.warning(f"ELF 对象缺少属性: {e}")
        return {'all_imports': {}, 'dangerous_functions': []}
    except Exception as e:
        logger.error(f"获取导入函数失败: {e}")
        return {'all_imports': {}, 'dangerous_functions': []}

        
def get_key_strings(elf: object) -> List[str]:
    """

    获取关键字符串
    """
    try:
        key_strings = []
        
        elf_strings = getattr(elf, 'strings', [])
        for offset in elf_strings:
            try:
                raw_data = elf.read(offset, 100)
                if raw_data is None:
                    continue
                
                s = raw_data.decode('utf-8', errors='ignore')
                s = s.split('\x00')[0]
                
                if len(s) < 4:
                    continue
                
                for pattern in KEY_STRING_PATTERNS:
                    if pattern.lower() in s.lower() and s not in key_strings:
                        key_strings.append(s)
                        break
            except Exception:
                continue
        
        logger.info(f"发现关键字符串: {key_strings[:10]}")
        return key_strings
    except Exception as e:
        logger.error(f"获取关键字符串失败: {e}")
        return []


def get_symbols(elf: object) -> Dict[str, int]:
    """



    获取符号表中的函数和全局变量

    
    """
    try:
        symbols = {}
        
        elf_symbols = getattr(elf, 'symbols', {})
        for name, addr in elf_symbols.items():
            if addr != 0:
                symbols[name] = addr
        
        logger.info(f"获取到 {len(symbols)} 个符号")
        return symbols
    except AttributeError as e:
        logger.warning(f"ELF 对象缺少 symbols 属性: {e}")
        return {}
    except Exception as e:
        logger.error(f"获取符号表失败: {e}")
        return {}


def get_functions(elf: object) -> List[Dict[str, any]]:
    """
    获取所有函数信息

    
    """
    try:
        functions = []
        
        elf_functions = getattr(elf, 'functions', {})
        for name, addr in elf_functions.items():
            try:
                func_info = {
                    'name': name,
                    'address': getattr(addr, 'address', 0),
                    'size': getattr(addr, 'size', 0)
                }
                functions.append(func_info)
            except Exception:
                continue
        
        functions.sort(key=lambda x: x['size'], reverse=True)
        logger.info(f"获取到 {len(functions)} 个函数")
        return functions
    except AttributeError as e:
        logger.warning(f"ELF 对象缺少 functions 属性: {e}")
        return []
    except Exception as e:
        logger.error(f"获取函数列表失败: {e}")
        return []


def get_imported_functions_pe(pe: object) -> Dict[str, Any]:
    """
    获取 PE 文件的导入函数
    """
    result = {'all_imports': {}, 'dangerous_functions': []}
    
    try:
        module_name = type(pe).__module__
        
        if 'pefile' in module_name:
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = getattr(entry, 'dll', b'').decode('utf-8', errors='ignore')
                    funcs = []
                    
                    for imp in getattr(entry, 'imports', []):
                        func_name = getattr(imp, 'name', None)
                        if func_name:
                            try:
                                func_name = func_name.decode('utf-8', errors='ignore')
                            except:
                                func_name = str(func_name)
                            
                            funcs.append(func_name)
                            if func_name in DANGEROUS_FUNCTIONS:
                                result['dangerous_functions'].append(func_name)
                    
                    if funcs:
                        result['all_imports'][dll_name] = funcs
        
        result['dangerous_functions'] = list(set(result['dangerous_functions']))
        logger.info(f"PE 危险函数: {result['dangerous_functions']}")
        
    except Exception as e:
        logger.error(f"获取 PE 导入函数失败: {e}")
    
    return result


def get_symbols_pe(pe: object) -> Dict[str, int]:
    """
    获取 PE 文件的符号信息
    """
    symbols = {}
    
    try:
        module_name = type(pe).__module__
        
        if 'pefile' in module_name:
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    name = getattr(exp, 'name', None)
                    if name:
                        try:
                            name = name.decode('utf-8', errors='ignore')
                            addr = getattr(exp, 'address', 0)
                            if addr:
                                symbols[name] = addr
                        except:
                            pass
        
        logger.info(f"获取到 {len(symbols)} 个 PE 符号")
        
    except Exception as e:
        logger.error(f"获取 PE 符号失败: {e}")
    
    return symbols


def get_functions_pe(pe: object, binary_path: str) -> List[Dict[str, Any]]:
    """
    获取 PE 文件的函数信息
    """
    functions = []
    
    try:
        functions = get_functions_generic(binary_path)
        logger.info(f"获取到 {len(functions)} 个 PE 函数")
        
    except Exception as e:
        logger.error(f"获取 PE 函数失败: {e}")
    
    return functions


def get_functions_generic(binary_path: str) -> List[Dict[str, Any]]:
    """
    使用 radare2 获取函数列表（通用方法）
    """
    functions = []
    
    try:
        import subprocess
        from config import Config
        from modules.decomp_ai import strip_ansi_escape
        
        try:
            validated_path = validate_binary_path(binary_path)
        except ValueError as e:
            logger.error(f"路径验证失败: {e}")
            return []
        
        cmd = ['r2', '-q', '-e', 'io.color=false', '-c', 'afl', validated_path]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=Config.SUBPROCESS_TIMEOUT
        )
        
        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                line = strip_ansi_escape(line)
                parts = line.split()
                if len(parts) >= 3:
                    try:
                        addr = int(parts[0], 16)
                        size = int(parts[1], 16)
                        func_name = parts[-1]
                        
                        if func_name.startswith('sym.'):
                            func_name = func_name[4:]
                        
                        functions.append({
                            'name': func_name,
                            'address': addr,
                            'size': size
                        })
                    except (ValueError, IndexError):
                        continue
            
            functions.sort(key=lambda x: x['size'], reverse=True)
        
    except Exception as e:
        logger.debug(f"使用 radare2 获取函数失败: {e}")
    
    return functions


def get_binary_info(binary_path: str, force_kernel: bool = False) -> Dict[str, Any]:
    """
    获取完整的二进制文件信息，自动检测格式
    
    Args:
        binary_path: 二进制文件路径
        force_kernel: 是否强制使用内核模块分析模式
        
    Returns:
        包含二进制信息的字典
    """
    try:
        validated_path = validate_binary_path(binary_path)
    except ValueError as e:
        logger.error(f"路径验证失败: {e}")
        return {}
    
    logger.info(f"开始收集二进制信息: {validated_path}")
    
    is_valid, error_msg = validate_file(validated_path)
    if not is_valid:
        logger.error(error_msg)
        return {}
    
    binary_format = detect_binary_format(validated_path)
    logger.info(f"检测到文件格式: {binary_format}")
    
    if force_kernel:
        logger.info("[Kernel] 强制使用内核模块分析模式")
        if binary_format == 'SYS':
            return get_windows_driver_info(validated_path)
        elif binary_format in ['ELF', 'KO', 'UNKNOWN']:
            return get_kernel_module_info(validated_path)
    
    if binary_format == 'UNKNOWN':
        logger.error(f"不支持的文件格式")
        return {}
    
    if binary_format == 'KO':
        return get_kernel_module_info(validated_path)
    elif binary_format == 'SYS':
        return get_windows_driver_info(validated_path)
    
    binary_obj = None
    try:
        if binary_format == 'ELF':
            binary_obj = load_elf(validated_path)
            if not binary_obj:
                return {}
        elif binary_format == 'PE':
            binary_obj = load_pe(validated_path)
        elif binary_format == 'MACH-O':
            binary_obj = load_macho(validated_path)
        
        if binary_obj is None and binary_format != 'ELF':
            logger.warning(f"无法加载 {binary_format} 对象，尝试使用 radare2 收集基本信息")
            info = {
                'binary_path': validated_path,
                'format': binary_format,
                'arch': 'unknown',
                'bits': 0,
                'endian': 'unknown',
                'checksec': {'format': binary_format},
                'imports': {'all_imports': {}, 'dangerous_functions': []},
                'key_strings': [],
                'symbols': {},
                'functions': get_functions_generic(validated_path)
            }
            return info
        
        if binary_format == 'ELF':
            info = {
                'binary_path': validated_path,
                'format': 'ELF',
                'arch': getattr(binary_obj, 'arch', 'unknown'),
                'bits': getattr(binary_obj, 'bits', 0),
                'endian': getattr(binary_obj, 'endian', 'unknown'),
                'checksec': get_checksec_elf(binary_obj),
                'imports': get_imported_functions(binary_obj),
                'key_strings': get_key_strings(binary_obj),
                'symbols': get_symbols(binary_obj),
                'functions': get_functions(binary_obj)
            }
        elif binary_format == 'PE':
            info = {
                'binary_path': validated_path,
                'format': 'PE',
                'arch': _detect_pe_arch(binary_obj),
                'bits': _detect_pe_bits(binary_obj),
                'endian': 'little',
                'checksec': get_checksec_pe(binary_obj, validated_path),
                'imports': get_imported_functions_pe(binary_obj),
                'key_strings': get_key_strings_generic(validated_path),
                'symbols': get_symbols_pe(binary_obj),
                'functions': get_functions_pe(binary_obj, validated_path)
            }
        else:
            info = {
                'binary_path': validated_path,
                'format': 'MACH-O',
                'arch': 'unknown',
                'bits': 64,
                'endian': 'little',
                'checksec': get_checksec_macho(binary_obj, validated_path),
                'imports': {'all_imports': {}, 'dangerous_functions': []},
                'key_strings': get_key_strings_generic(validated_path),
                'symbols': {},
                'functions': get_functions_generic(validated_path)
            }
        
        logger.info("二进制信息收集完成")
        return info
        
    except Exception as e:
        logger.error(f"收集二进制信息时发生错误: {type(e).__name__}: {e}")
        return {}
    finally:
        try:
            if hasattr(binary_obj, 'close'):
                binary_obj.close()
        except Exception:
            pass


def get_kernel_module_info(binary_path: str) -> Dict[str, Any]:
    """
    收集 Linux 内核模块 (.ko) 的详细信息
    
    Args:
        binary_path: 内核模块文件路径
        
    Returns:
        包含内核模块信息的字典
    """
    try:
        logger.info(f"正在收集 Linux 内核模块信息: {binary_path}")
        
        base_info = {
            'binary_path': binary_path,
            'format': 'KO',
            'is_kernel_module': True,
            'module_name': os.path.basename(binary_path).replace('.ko', ''),
            'kernel_info': {}
        }
        
        modinfo = _extract_modinfo(binary_path)
        if modinfo:
            base_info['kernel_info']['modinfo'] = modinfo
            base_info['module_name'] = modinfo.get('name', base_info['module_name'])
        
        try:
            from pwn import ELF
            elf = ELF(binary_path, checksec=False)
            
            base_info['arch'] = getattr(elf, 'arch', 'unknown')
            base_info['bits'] = getattr(elf, 'bits', 64)
            base_info['endian'] = getattr(elf, 'endian', 'unknown')
            base_info['symbols'] = get_symbols(elf)
            base_info['functions'] = get_functions(elf)
            
            entry_points = _find_kernel_entry_points(elf)
            base_info['kernel_info']['entry_points'] = entry_points
            
            module_params = _extract_module_parameters(binary_path, elf)
            base_info['kernel_info']['parameters'] = module_params
            
            exported_symbols = _find_exported_symbols(elf)
            base_info['kernel_info']['exported_symbols'] = exported_symbols
            
            ioctl_handlers = _find_ioctl_handlers(elf)
            base_info['kernel_info']['ioctl_handlers'] = ioctl_handlers
            
            dangerous_found = _find_kernel_dangerous_functions(elf)
            base_info['kernel_info']['dangerous_functions'] = dangerous_found
            
            base_info['imports'] = {
                'all_imports': {},
                'dangerous_functions': dangerous_found
            }
            
            elf.close()
        except Exception as e:
            logger.warning(f"使用 ELF 解析内核模块失败: {e}")
            base_info['arch'] = 'unknown'
            base_info['bits'] = 64
            base_info['endian'] = 'unknown'
            base_info['symbols'] = {}
            base_info['functions'] = []
            base_info['imports'] = {'all_imports': {}, 'dangerous_functions': []}
        
        base_info['key_strings'] = get_key_strings_generic(binary_path)
        base_info['checksec'] = {'format': 'KO', 'note': '内核模块不适用常规用户态保护机制'}
        
        logger.info(f"Linux 内核模块信息收集完成: {base_info['module_name']}")
        return base_info
        
    except Exception as e:
        logger.error(f"收集内核模块信息失败: {e}")
        return {'error': str(e), 'format': 'KO'}


def get_windows_driver_info(binary_path: str) -> Dict[str, Any]:
    """
    收集 Windows 驱动程序 (.sys) 的详细信息
    
    Args:
        binary_path: 驱动文件路径
        
    Returns:
        包含驱动信息的字典
    """
    try:
        logger.info(f"正在收集 Windows 驱动信息: {binary_path}")
        
        base_info = {
            'binary_path': binary_path,
            'format': 'SYS',
            'is_windows_driver': True,
            'driver_name': os.path.basename(binary_path).replace('.sys', ''),
            'driver_info': {}
        }
        
        try:
            import pefile
            pe = pefile.PE(binary_path)
            
            base_info['arch'] = _detect_pe_arch(pe)
            base_info['bits'] = _detect_pe_bits(pe)
            base_info['endian'] = 'little'
            base_info['checksec'] = get_checksec_pe(pe, binary_path)
            base_info['symbols'] = get_symbols_pe(pe)
            base_info['functions'] = get_functions_pe(pe, binary_path)
            
            driver_entry = _find_driver_entry_points(pe)
            base_info['driver_info']['entry_points'] = driver_entry
            
            irp_handlers = _find_irp_handlers(pe)
            base_info['driver_info']['irp_handlers'] = irp_handlers
            
            ioctl_codes = _extract_ioctl_codes(binary_path)
            base_info['driver_info']['ioctl_codes'] = ioctl_codes
            
            device_operations = _extract_device_operations(pe)
            base_info['driver_info']['device_operations'] = device_operations
            
            dangerous_found = _find_driver_dangerous_functions(pe)
            base_info['driver_info']['dangerous_functions'] = dangerous_found
            
            imports_info = get_imported_functions_pe(pe)
            imports_info['dangerous_functions'].extend(dangerous_found)
            imports_info['dangerous_functions'] = list(set(imports_info['dangerous_functions']))
            base_info['imports'] = imports_info
            
            driver_type = _detect_driver_type(pe)
            base_info['driver_info']['driver_type'] = driver_type
            
            pe.close()
        except Exception as e:
            logger.warning(f"使用 pefile 解析驱动失败: {e}")
            base_info['arch'] = 'unknown'
            base_info['bits'] = 64
            base_info['endian'] = 'little'
            base_info['checksec'] = {'format': 'SYS'}
            base_info['symbols'] = {}
            base_info['functions'] = []
            base_info['imports'] = {'all_imports': {}, 'dangerous_functions': []}
        
        base_info['key_strings'] = get_key_strings_generic(binary_path)
        
        logger.info(f"Windows 驱动信息收集完成: {base_info['driver_name']}")
        return base_info
        
    except Exception as e:
        logger.error(f"收集 Windows 驱动信息失败: {e}")
        return {'error': str(e), 'format': 'SYS'}


def _extract_modinfo(binary_path: str) -> Dict[str, str]:
    """
    提取内核模块的 .modinfo 段信息
    
    Returns:
        包含 modinfo 键值对的字典
    """
    modinfo = {}
    
    try:
        try:
            import subprocess
            from config import Config
            
            result = subprocess.run(
                ['modinfo', binary_path],
                capture_output=True,
                text=True,
                timeout=Config.SUBPROCESS_TIMEOUT
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        modinfo[key.strip().lower()] = value.strip()
                
                logger.info(f"从 modinfo 获取到 {len(modinfo)} 个属性")
                return modinfo
        except Exception:
            pass
        
        try:
            from pwn import ELF
            elf = ELF(binary_path, checksec=False)
            
            modinfo_data = None
            for section in elf.iter_sections():
                if section.name == '.modinfo':
                    modinfo_data = section.data()
                    break
            
            if modinfo_data:
                import re
                modinfo_str = modinfo_data.decode('utf-8', errors='ignore')
                
                patterns = [
                    r'name=([^\x00]+)',
                    r'description=([^\x00]+)',
                    r'author=([^\x00]+)',
                    r'version=([^\x00]+)',
                    r'license=([^\x00]+)',
                    r'parm=([^\x00]+)',
                    r'depends=([^\x00]+)',
                ]
                
                for pattern in patterns:
                    matches = re.findall(pattern, modinfo_str)
                    if matches:
                        key = pattern.split('=')[0].strip('r()')
                        modinfo[key] = matches[0]
                
                elf.close()
        except Exception:
            pass
        
        return modinfo
    except Exception as e:
        logger.debug(f"提取 modinfo 失败: {e}")
        return modinfo


def _find_kernel_entry_points(elf: object) -> Dict[str, Any]:
    """
    查找内核模块的入口点 (module_init, module_exit)
    """
    entry_points = {
        'init_module': None,
        'cleanup_module': None,
        'module_init': None,
        'module_exit': None
    }
    
    try:
        symbols = getattr(elf, 'symbols', {})
        
        for sym_name, addr in symbols.items():
            if sym_name == 'init_module':
                entry_points['init_module'] = addr
            elif sym_name == 'cleanup_module':
                entry_points['cleanup_module'] = addr
            elif 'module_init' in sym_name.lower():
                entry_points['module_init'] = addr
            elif 'module_exit' in sym_name.lower():
                entry_points['module_exit'] = addr
        
        functions = getattr(elf, 'functions', {})
        for func_name in functions:
            if func_name == 'init_module':
                entry_points['init_module'] = getattr(functions[func_name], 'address', 0)
            elif func_name == 'cleanup_module':
                entry_points['cleanup_module'] = getattr(functions[func_name], 'address', 0)
        
        logger.info(f"找到内核入口点: {entry_points}")
        return entry_points
    except Exception as e:
        logger.debug(f"查找内核入口点失败: {e}")
        return entry_points


def _extract_module_parameters(binary_path: str, elf: object) -> List[Dict[str, Any]]:
    """
    提取内核模块参数
    """
    params = []
    
    try:
        import subprocess
        from config import Config
        
        result = subprocess.run(
            ['modinfo', '-p', binary_path],
            capture_output=True,
            text=True,
            timeout=Config.SUBPROCESS_TIMEOUT
        )
        
        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        params.append({
                            'name': parts[0].strip(),
                            'type': parts[1].strip()
                        })
        else:
            symbols = getattr(elf, 'symbols', {})
            for sym_name in symbols:
                if '__param_' in sym_name:
                    param_name = sym_name.replace('__param_', '')
                    params.append({
                        'name': param_name,
                        'address': symbols[sym_name],
                        'type': 'unknown'
                    })
        
        logger.info(f"找到 {len(params)} 个模块参数")
        return params
    except Exception as e:
        logger.debug(f"提取模块参数失败: {e}")
        return params


def _find_exported_symbols(elf: object) -> List[str]:
    """
    查找内核模块导出的符号
    """
    exported = []
    
    try:
        symbols = getattr(elf, 'symbols', {})
        for sym_name in symbols:
            if sym_name.startswith('__ksymtab_') or '__ksymtab' in sym_name:
                exported_name = sym_name.replace('__ksymtab_', '')
                if exported_name and exported_name not in exported:
                    exported.append(exported_name)
        
        functions = getattr(elf, 'functions', {})
        for func_name in functions:
            if '_exported' in func_name.lower():
                exported.append(func_name)
        
        logger.info(f"找到 {len(exported)} 个导出符号")
        return exported
    except Exception as e:
        logger.debug(f"查找导出符号失败: {e}")
        return exported


def _find_ioctl_handlers(elf: object) -> List[Dict[str, Any]]:
    """
    查找可能的 ioctl 处理函数
    """
    handlers = []
    
    try:
        ioctl_patterns = ['ioctl', 'unlocked_ioctl', 'compat_ioctl']
        symbols = getattr(elf, 'symbols', {})
        functions = getattr(elf, 'functions', {})
        
        all_funcs = list(functions.keys()) if functions else list(symbols.keys())
        
        for func_name in all_funcs:
            for pattern in ioctl_patterns:
                if pattern in func_name.lower():
                    addr = None
                    if func_name in symbols:
                        addr = symbols[func_name]
                    elif func_name in functions:
                        addr = getattr(functions[func_name], 'address', 0)
                    
                    handlers.append({
                        'name': func_name,
                        'address': addr,
                        'type': pattern
                    })
                    break
        
        logger.info(f"找到 {len(handlers)} 个 ioctl 处理函数")
        return handlers
    except Exception as e:
        logger.debug(f"查找 ioctl 处理函数失败: {e}")
        return handlers


def _find_kernel_dangerous_functions(elf: object) -> List[str]:
    """
    在内核模块中查找危险函数
    """
    found = []
    
    try:
        all_symbols = set()
        
        symbols = getattr(elf, 'symbols', {})
        all_symbols.update(symbols.keys())
        
        plt = getattr(elf, 'plt', {})
        all_symbols.update(plt.keys())
        
        for func in KERNEL_DANGEROUS_FUNCTIONS:
            for sym in all_symbols:
                if func in sym:
                    found.append(func)
                    break
        
        return list(set(found))
    except Exception as e:
        logger.debug(f"查找内核危险函数失败: {e}")
        return found


def _find_driver_entry_points(pe: object) -> Dict[str, Any]:
    """
    查找 Windows 驱动的入口点
    """
    entry_points = {
        'DriverEntry': None,
        'DriverUnload': None,
        'AddDevice': None,
        'EvtDriverDeviceAdd': None
    }
    
    try:
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    try:
                        name = exp.name.decode('utf-8', errors='ignore')
                        addr = exp.address
                        
                        if 'DriverEntry' in name:
                            entry_points['DriverEntry'] = addr
                        elif 'DriverUnload' in name:
                            entry_points['DriverUnload'] = addr
                        elif 'AddDevice' in name:
                            entry_points['AddDevice'] = addr
                        elif 'EvtDriverDeviceAdd' in name:
                            entry_points['EvtDriverDeviceAdd'] = addr
                    except Exception:
                        pass
        
        logger.info(f"找到驱动入口点: {entry_points}")
        return entry_points
    except Exception as e:
        logger.debug(f"查找驱动入口点失败: {e}")
        return entry_points


def _find_irp_handlers(pe: object) -> List[Dict[str, Any]]:
    """
    查找 IRP 处理函数
    """
    handlers = []
    
    try:
        irp_patterns = ['IRP_MJ', 'Dispatch', 'Irp', 'IoCompletion']
        
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    try:
                        name = exp.name.decode('utf-8', errors='ignore')
                        for pattern in irp_patterns:
                            if pattern in name:
                                handlers.append({
                                    'name': name,
                                    'address': exp.address,
                                    'type': 'IRP Handler'
                                })
                                break
                    except Exception:
                        pass
        
        logger.info(f"找到 {len(handlers)} 个 IRP 处理函数")
        return handlers
    except Exception as e:
        logger.debug(f"查找 IRP 处理函数失败: {e}")
        return handlers


def _extract_ioctl_codes(binary_path: str) -> List[Dict[str, Any]]:
    """
    从驱动中提取可能的 IOCTL 控制码
    """
    ioctl_codes = []
    
    try:
        with open(binary_path, 'rb') as f:
            content = f.read()
        
        import re
        
        ioctl_patterns = [
            rb'CTL_CODE\s*\(\s*0x[0-9a-fA-F]+\s*,\s*0x[0-9a-fA-F]+',
            rb'IOCTL_\w+',
            rb'0x[0-9a-fA-F]{8}',
        ]
        
        for pattern in ioctl_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                try:
                    code_str = match.group().decode('utf-8', errors='ignore')
                    ioctl_codes.append({
                        'code': code_str,
                        'offset': match.start(),
                        'type': 'potential_ioctl'
                    })
                except Exception:
                    pass
        
        ioctl_codes = ioctl_codes[:50]
        logger.info(f"找到 {len(ioctl_codes)} 个潜在 IOCTL 码")
        return ioctl_codes
    except Exception as e:
        logger.debug(f"提取 IOCTL 码失败: {e}")
        return ioctl_codes


def _extract_device_operations(pe: object) -> Dict[str, Any]:
    """
    提取设备操作相关信息
    """
    operations = {
        'create_close': [],
        'read_write': [],
        'ioctl': [],
        'power': [],
        'pn': []
    }
    
    try:
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    try:
                        name = exp.name.decode('utf-8', errors='ignore')
                        
                        if any(k in name for k in ['Create', 'Close', 'Open']):
                            operations['create_close'].append(name)
                        elif any(k in name for k in ['Read', 'Write']):
                            operations['read_write'].append(name)
                        elif 'ioctl' in name.lower():
                            operations['ioctl'].append(name)
                        elif any(k in name for k in ['Power', 'D0', 'D3']):
                            operations['power'].append(name)
                        elif any(k in name for k in ['PnP', 'AddDevice', 'StartDevice']):
                            operations['pn'].append(name)
                    except Exception:
                        pass
        
        return operations
    except Exception as e:
        logger.debug(f"提取设备操作失败: {e}")
        return operations


def _find_driver_dangerous_functions(pe: object) -> List[str]:
    """
    在 Windows 驱动中查找危险函数
    """
    found = []
    
    try:
        all_names = set()
        
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        try:
                            name = imp.name.decode('utf-8', errors='ignore')
                            all_names.add(name)
                        except Exception:
                            pass
        
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    try:
                        name = exp.name.decode('utf-8', errors='ignore')
                        all_names.add(name)
                    except Exception:
                        pass
        
        for func in KERNEL_DRIVER_DANGEROUS_FUNCTIONS:
            for name in all_names:
                if func.lower() in name.lower():
                    found.append(func)
                    break
        
        return list(set(found))
    except Exception as e:
        logger.debug(f"查找驱动危险函数失败: {e}")
        return found


def _detect_driver_type(pe: object) -> str:
    """
    检测 Windows 驱动类型
    """
    try:
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = getattr(entry, 'dll', b'').decode('utf-8', errors='ignore').lower()
                
                if 'wdf' in dll_name or 'wudf' in dll_name:
                    return 'KMDF/WDF'
                elif 'ntoskrnl' in dll_name:
                    return 'Native WDM'
                elif 'hal' in dll_name:
                    return 'HAL Extension'
        
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    try:
                        name = exp.name.decode('utf-8', errors='ignore').lower()
                        if 'evt' in name:
                            return 'WDF'
                        elif 'driverentry' in name:
                            return 'WDM'
                    except Exception:
                        pass
        
        return 'Unknown'
    except Exception as e:
        logger.debug(f"检测驱动类型失败: {e}")
        return 'Unknown'


def _detect_pe_arch(pe_obj: object) -> str:
    """
    检测 PE 文件架构
    """
    try:
        module_name = type(pe_obj).__module__
        
        if 'pefile' in module_name:
            machine = getattr(pe_obj, 'FILE_HEADER', None)
            if machine:
                machine_type = getattr(machine, 'Machine', 0)
                if machine_type == 0x014c:
                    return 'i386'
                elif machine_type == 0x8664:
                    return 'amd64'
    except Exception:
        pass
    
    return 'unknown'


def _detect_pe_bits(pe_obj: object) -> int:
    """
    检测 PE 文件位数
    """
    arch = _detect_pe_arch(pe_obj)
    if arch == 'amd64':
        return 64
    elif arch == 'i386':
        return 32
    return 0


def get_key_strings_generic(binary_path: str) -> List[str]:
    """
    通用方法获取关键字符串
    """
    key_strings = []
    
    try:
        import subprocess
        from config import Config
        from modules.decomp_ai import strip_ansi_escape
        
        try:
            validated_path = validate_binary_path(binary_path)
        except ValueError as e:
            logger.error(f"路径验证失败: {e}")
            return []
        
        cmd = ['r2', '-q', '-e', 'io.color=false', '-c', 'iz', validated_path]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=Config.SUBPROCESS_TIMEOUT
        )
        
        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                line = strip_ansi_escape(line)
                for pattern in KEY_STRING_PATTERNS:
                    if pattern.lower() in line.lower():
                        if line not in key_strings:
                            key_strings.append(line)
                            break
                        
                        if len(key_strings) >= 20:
                            return key_strings
                        
    except Exception as e:
        logger.debug(f"通用方法获取字符串失败: {e}")
    
    return key_strings


def format_info_for_report(info: Dict[str, Any]) -> str:
    """
    将信息格式化为 Markdown 格式（支持多格式）
    """
    if not info:
        return "无法获取二进制信息（文件格式不支持或已损坏）"
    
    binary_format = info.get('format', 'ELF')
    
    output = []
    output.append("## 二进制文件信息\n")
    
    output.append("### 基本信息")
    output.append(f"- 文件格式: **{binary_format}**")
    output.append(f"- 文件路径: {info.get('binary_path', 'N/A')}")
    output.append(f"- 架构: {info.get('arch', 'N/A')}")
    output.append(f"- 位数: {info.get('bits', 'N/A')}")
    output.append(f"- 字节序: {info.get('endian', 'N/A')}\n")
    
    checksec = info.get('checksec', {})
    output.append("### 保护机制")
    
    if binary_format == 'ELF':
        nx = checksec.get('nx')
        pie = checksec.get('pie')
        relro = checksec.get('relro')
        canary = checksec.get('canary')
        
        output.append(f"- NX (不可执行栈): {'启用' if nx else '禁用' if nx is not None else '未知'}")
        output.append(f"- PIE (位置无关可执行): {'启用' if pie else '禁用' if pie is not None else '未知'}")
        output.append(f"- RELRO: {relro if relro is not None else '未知'}")
        output.append(f"- Canary (栈溢出保护): {'启用' if canary else '禁用' if canary is not None else '未知'}")
    elif binary_format == 'PE':
        nx = checksec.get('nx')
        aslr = checksec.get('aslr')
        dep = checksec.get('dep')
        safeseh = checksec.get('safeseh')
        cfg = checksec.get('cfg')
        gs = checksec.get('gs')
        
        output.append(f"- NX/DEP (数据执行保护): {'启用' if nx or dep else '禁用' if (nx is not None) else '未知'}")
        output.append(f"- ASLR (地址空间随机化): {'启用' if aslr else '禁用' if aslr is not None else '未知'}")
        output.append(f"- SafeSEH: {'启用' if safeseh else '禁用' if safeseh is not None else '未知'}")
        output.append(f"- CFG (控制流防护): {'启用' if cfg else '禁用' if cfg is not None else '未知'}")
        output.append(f"- GS (栈保护): {'启用' if gs else '禁用' if gs is not None else '未知'}")
    elif binary_format == 'MACH-O':
        nx = checksec.get('nx')
        pie = checksec.get('pie')
        canary = checksec.get('canary')
        arc = checksec.get('arc')
        
        output.append(f"- NX: {'启用' if nx else '禁用' if nx is not None else '未知'}")
        output.append(f"- PIE: {'启用' if pie else '禁用' if pie is not None else '未知'}")
        output.append(f"- Canary: {'启用' if canary else '禁用' if canary is not None else '未知'}")
        output.append(f"- ARC (自动引用计数): {'启用' if arc else '禁用' if arc is not None else '未知'}")
    output.append("")
    
    imports = info.get('imports', {})
    dangerous = imports.get('dangerous_functions', [])
    if dangerous:
        output.append("### 危险函数")
        output.append("```")
        for func in dangerous:
            output.append(f"  - {func}")
        output.append("```\n")
    
    key_strings = info.get('key_strings', [])
    if key_strings:
        output.append("### 关键字符串")
        output.append("```")
        for s in key_strings[:20]:
            output.append(f"  - {s}")
        if len(key_strings) > 20:
            output.append(f"  ... 还有 {len(key_strings) - 20} 个")
        output.append("```\n")
    
    symbols = info.get('symbols', {})
    if symbols:
        output.append("### 重要符号 (前20个)")
        output.append("| 符号名 | 地址 |")
        output.append("|--------|------|")
        for name, addr in list(symbols.items())[:20]:
            try:
                output.append(f"| {name} | {hex(addr)} |")
            except TypeError:
                output.append(f"| {name} | {addr} |")
        output.append("")
    
    return '\n'.join(output)
