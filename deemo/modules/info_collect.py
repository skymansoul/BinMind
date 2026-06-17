import logging
import os
import struct
import re
import shlex
from typing import Dict, List, Optional, Tuple, Any, Union

logger = logging.getLogger(__name__)

MOBILE_DANGEROUS_FUNCTIONS = [
    '__android_log_print',
    '__android_log_write',
    'AAssetManager_open',
    'AAssetManager_read',
    'JNIEnv_::FindClass',
    'JNIEnv_::GetMethodID',
    'JNIEnv_::CallMethod',
    'JNIEnv_::GetFieldID',
    'JNIEnv_::SetField',
    'system',
    'popen',
    'strcpy',
    'strcat',
    'sprintf',
    'gets',
    'memcpy',
    'memmove',
]

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
    'copy_from_user',
    'copy_to_user',
    'copy_in_user',
    'copy_out_user',
    'get_user',
    'put_user',
    'kmalloc',
    'kzalloc',
    'kvmalloc',
    'kcalloc',
    'kfree',
    '__kmalloc',
    '__kzalloc',
    'ioremap',
    'ioremap_nocache',
    'ioremap_wc',
    'iounmap',
    'request_mem_region',
    'release_mem_region',
    'sprintf',
    'snprintf',
    'vsprintf',
    'strncpy_from_user',
    'strlen_user',
    'strnlen_user',
    'strcpy_from_user',
    'memcpy_fromiovec',
    'memcpy_toiovec',
    'ioctl',
    '__ioctl',
    'proc_create',
    'seq_open',
    'seq_read',
    'seq_write',
    'devm_kzalloc',
    'devm_kmalloc',
    'devm_kfree',
    'dma_alloc_coherent',
    'dma_alloc_noncoherent',
    'dma_free_coherent',
    'dma_free_noncoherent',
    'netdev_alloc_skb',
    'skb_copy',
    'skb_clone',
    'alloc_skb',
    'kmem_cache_alloc',
    'kmem_cache_free',
    '__get_free_pages',
    'free_pages',
    'vmalloc',
    'vfree',
    'slab_alloc',
    'slab_free',
    'down',
    'down_interruptible',
    'down_trylock',
    'up',
    'mutex_lock',
    'mutex_unlock',
    'spin_lock',
    'spin_unlock',
    'read_lock',
    'read_unlock',
    'write_lock',
    'write_unlock',
    'file_open',
    'file_close',
    'vfs_read',
    'vfs_write',
    'filp_open',
    'filp_close',
    'task_struct',
    'cred',
    'commit_creds',
    'prepare_kernel_cred',
    'cap_set_proc',
    'set_current_groups',
    'setgid',
    'setuid',
    'sys_setuid',
    'sys_setgid',
    'sys_setreuid',
    'sys_setregid',
    'sys_setresuid',
    'sys_setresgid',
    'allow_signal',
    'send_signal',
    'force_sig',
    'sig_send',
    'kernel_thread',
    'do_fork',
    'sys_clone',
    'sys_fork',
    'sys_vfork',
    'sys_execve',
    'sys_open',
    'sys_close',
    'sys_read',
    'sys_write',
    'sys_mmap',
    'sys_mprotect',
    'sys_chmod',
    'sys_chown',
    'sys_access',
    'sys_brk',
    'sys_ptrace',
    'sys_kill',
    'sys_nice',
    'sys_setpriority',
    'sys_syslog',
    'sys_time',
    'sys_settimeofday',
    'sys_uname',
    'sys_utsname',
    'sys_sync',
    'sys_shutdown',
    'sys_reboot',
    'sys_mount',
    'sys_umount',
    'sys_sethostname',
    'sys_setdomainname',
    'sys_getuid',
    'sys_getgid',
    'sys_geteuid',
    'sys_getegid',
    'sys_getresuid',
    'sys_getresgid',
    'sys_getgroups',
    'sys_setgroups',
    'sys_getpgid',
    'sys_setpgid',
    'sys_getsid',
    'sys_setsid',
    'sys_getpriority',
    'sys_wait4',
    'sys_waitpid',
    'sys_sigaction',
    'sys_sigprocmask',
    'sys_sigpending',
    'sys_sigsuspend',
    'sys_sigreturn',
    'sys_pause',
    'sys_alarm',
    'sys_setitimer',
    'sys_getitimer',
    'sys_timex',
    'sys_getrusage',
    'sys_gettimeofday',
    'sys_times',
    'sys_ptrace',
    'sys_lseek',
    'sys_readlink',
    'sys_access',
    'sys_chdir',
    'sys_fchdir',
    'sys_chroot',
    'sys_sync',
    'sys_fsync',
    'sys_fdatasync',
    'sys_truncate',
    'sys_ftruncate',
    'sys_getdents',
    'sys_getcwd',
    'sys_chmod',
    'sys_fchmod',
    'sys_chown',
    'sys_fchown',
    'sys_umask',
    'sys_setreuid',
    'sys_setregid',
    'sys_getgroups',
    'sys_setgroups',
    'sys_getpgid',
    'sys_setpgid',
    'sys_getsid',
    'sys_setsid',
    'sys_getpriority',
    'sys_setpriority',
    'sys_wait4',
    'sys_waitpid',
    'sys_sigaction',
    'sys_sigprocmask',
    'sys_sigpending',
    'sys_sigsuspend',
    'sys_sigreturn',
    'sys_pause',
    'sys_alarm',
    'sys_setitimer',
    'sys_getitimer',
    'sys_timex',
    'sys_getrusage',
    'sys_gettimeofday',
    'sys_times',
]

KERNEL_DRIVER_DANGEROUS_FUNCTIONS = [
    'MmCopyVirtualMemory',
    'MmMapIoSpace',
    'MmUnmapIoSpace',
    'MmAllocatePagesForMdl',
    'MmFreePagesFromMdl',
    'MmBuildMdlForNonPagedPool',
    'MmAllocateNonPagedPool',
    'MmAllocateNonPagedPoolWithTag',
    'MmAllocatePagedPool',
    'MmAllocatePagedPoolWithTag',
    'ExAllocatePool',
    'ExAllocatePoolWithTag',
    'ExAllocatePool2',
    'ExFreePool',
    'ExFreePoolWithTag',
    'IoCreateDevice',
    'IoCreateDeviceSecure',
    'IoDeleteDevice',
    'IoCreateSymbolicLink',
    'IoDeleteSymbolicLink',
    'IoAttachDeviceToDeviceStack',
    'IoDetachDevice',
    'IoCreateFile',
    'IoOpenFile',
    'IoReadFile',
    'IoWriteFile',
    'IoClose',
    'NtCreateFile',
    'NtOpenFile',
    'NtReadFile',
    'NtWriteFile',
    'NtClose',
    'ZwCreateFile',
    'ZwOpenFile',
    'ZwReadFile',
    'ZwWriteFile',
    'ZwClose',
    'RtlCopyMemory',
    'RtlMoveMemory',
    'RtlZeroMemory',
    'RtlFillMemory',
    'RtlCompareMemory',
    'RtlAppendUnicodeToString',
    'RtlCopyUnicodeString',
    'RtlInitUnicodeString',
    'RtlFreeUnicodeString',
    'RtlAnsiStringToUnicodeString',
    'RtlUnicodeStringToAnsiString',
    'DbgPrint',
    'DbgPrintEx',
    'KdPrint',
    'KdPrintEx',
    'KeWaitForSingleObject',
    'KeWaitForMultipleObjects',
    'KeSetEvent',
    'KeResetEvent',
    'KeInitializeEvent',
    'KeInitializeMutex',
    'KeAcquireMutex',
    'KeReleaseMutex',
    'KeInitializeSpinLock',
    'KeAcquireSpinLock',
    'KeReleaseSpinLock',
    'ExInitializeResourceLite',
    'ExAcquireResourceExclusiveLite',
    'ExAcquireResourceSharedLite',
    'ExReleaseResourceLite',
    'PsCreateSystemThread',
    'PsTerminateSystemThread',
    'PsGetCurrentProcess',
    'PsGetCurrentThread',
    'ObReferenceObjectByHandle',
    'ObDereferenceObject',
    'SeAccessCheck',
    'SePrivilegeCheck',
    'SeAssignPrimaryToken',
    'SeImpersonateClientOfPort',
    'SeQueryInformationToken',
    'ZwQueryInformationProcess',
    'ZwSetInformationProcess',
    'ZwQueryInformationThread',
    'ZwSetInformationThread',
    'MmGetPhysicalAddress',
    'MmGetVirtualForPhysical',
    'HalTranslateBusAddress',
    'HalGetBusData',
    'HalSetBusData',
    'IoRegisterDeviceInterface',
    'IoUnregisterDeviceInterface',
    'IoCreateCompletionPort',
    'IoSetCompletionRoutine',
    'IoCancelIo',
    'IoCompleteRequest',
    'PoRegisterPowerSettingCallback',
    'PoUnregisterPowerSettingCallback',
    'WdfDeviceCreate',
    'WdfDeviceDelete',
    'WdfDeviceGetIoTarget',
    'WdfIoTargetSendIoctlSynchronously',
    'WdfMemoryCreate',
    'WdfMemoryDelete',
    'WdfRequestSend',
    'WdfRequestComplete',
    'WdfSpinLockAcquire',
    'WdfSpinLockRelease',
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
        r'\$\(')
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
        abs_path = os.path.abspath(os.path.expanduser(binary_path

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


def detect_binary_format(binary_path: str, force_kernel: bool = False) -> str:
    """
    检测二进制文件格式，支持内核模块识别
    
    Args:
        binary_path: 文件路径
        force_kernel: 是否强制以内核模式检测
        
    Returns:
        'ELF', 'PE', 'MACH-O', 'LINUX_KERNEL_MODULE', 'WINDOWS_DRIVER', 或 'UNKNOWN'
    """
    try:
        with open(binary_path, 'rb') as f:
            header = f.read(16)
            
        if len(header) < 4:
            return 'UNKNOWN'
            
        if header[:4] == b'\x7fELF':
            if force_kernel or _is_linux_kernel_module(binary_path):
                return 'LINUX_KERNEL_MODULE'
            return 'ELF'
        elif header[:2] == b'MZ':
            if force_kernel or _is_windows_driver(binary_path):
                return 'WINDOWS_DRIVER'
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
    判断文件是否为 Linux 内核模块(.ko)
    
    Args:
        binary_path: 文件路径
        
    Returns:
        True 如果是内核模块，否则 False
    """
    try:
        import os
        
        if binary_path.lower().endswith('.ko'):
            return True
            
        with open(binary_path, 'rb') as f:
            f.seek(0, os.SEEK_END)
            file_size = f.tell()
            f.seek(max(0, file_size - 1024

            tail_data = f.read(1024)
            
        if b'module_init' in tail_data or b'module_exit' in tail_data:
            return True
            
        if b'.modinfo' in tail_data or b'__this_module' in tail_data:
            return True
            
        return False
    except Exception as e:
        logger.debug(f"检测内核模块失败: {e}")
        return False


def _is_windows_driver(binary_path: str) -> bool:
    """
    判断文件是否为 Windows 驱动(.sys)
    
    Args:
        binary_path: 文件路径
        
    Returns:
        True 如果是驱动文件，否则 False
    """
    try:
        if binary_path.lower().endswith('.sys'):
            return True
            
        with open(binary_path, 'rb') as f:
            f.seek(0x3C)
            pe_offset = int.from_bytes(f.read(4), 'little')
            f.seek(pe_offset)
            pe_signature = f.read(4)
            
            if pe_signature != b'PE\x00\x00':
                return False
            
            f.seek(pe_offset + 24)
            subsystem = int.from_bytes(f.read(2), 'little')
            
            if subsystem == 0x01:
                return True
                
        return False
    except Exception as e:
        logger.debug(f"检测 Windows 驱动失败: {e}")
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
        
        logger.info(f"ELF 保护机制: NX={checksec['nx']}, PIE={checksec['pie']}, ")
                   f"RELRO={checksec['relro']}, Canary={checksec['canary']}"
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
                            checksec['canary'] = True,
                        if hasattr(entry, 'SEHandlerTable'):
                            checksec['safeseh'] = not no_seh
            else:
                logger.warning("PE 文件缺少 OPTIONAL_HEADER")
        elif 'pwnlib' in module_name:
            checksec['nx'] = getattr(pe, 'nx', False)
            checksec['pie'] = getattr(pe, 'pie', False)
            checksec['relro'] = getattr(pe, 'relro', None)
            checksec['canary'] = getattr(pe, 'canary', None)
        
        logger.info(f"PE 保护机制: NX/DEP={checksec['nx']}, ASLR={checksec['aslr']}, ")
                   f"SafeSEH={checksec['safeseh']}, CFG={checksec['cfg']}, GS={checksec['gs']}"
        
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
                        LC_ENCRYPTION_INFO_64 = 0x2C,
                        if cmd_type in [LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64]:
                            checksec['encrypted'] = True
        elif 'pwnlib' in module_name:
            checksec['nx'] = getattr(macho, 'nx', True)
            checksec['pie'] = getattr(macho, 'pie', False)
        
        logger.info(f"Mach-O 保护机制: NX={checksec['nx']}, PIE={checksec['pie']}, ")
                   f"Canary={checksec['canary']}, ARC={checksec['arc']}"
        
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
            'dangerous_functions': list(set(dangerous_found

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
        
        result['dangerous_functions'] = list(set(result['dangerous_functions']

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
        result = subprocess.run()
            cmd,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=Config.SUBPROCESS_TIMEOUT
        
        
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
                        
                        functions.append({)
                            'name': func_name,
                            'address': addr,
                            'size': size
                        }
                    except (ValueError, IndexError):
                        continue
            
            functions.sort(key=lambda x: x['size'], reverse=True)
        
    except Exception as e:
        logger.debug(f"使用 radare2 获取函数失败: {e}")
    
    return functions


def get_binary_info(binary_path: str, force_kernel: bool = False) -> Dict[str, Any]:
    """
    获取完整的二进制文件信息，自动检测格式，支持内核模块
    
    Args:
        binary_path: 二进制文件路径
        force_kernel: 是否强制以内核模式检测
        
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
    
    binary_format = detect_binary_format(validated_path, force_kernel)
    logger.info(f"检测到文件格式: {binary_format}")
    
    if binary_format == 'UNKNOWN':
        logger.error(f"不支持的文件格式")
        return {}
    
    binary_obj = None
    try:
        if binary_format == 'ELF':
            binary_obj = load_elf(validated_path)
            if not binary_obj:
                return {}
        elif binary_format == 'PE':
            binary_obj = load_pe(validated_path)
        elif binary_format == 'LINUX_KERNEL_MODULE':
            binary_obj = load_elf(validated_path)
        elif binary_format == 'WINDOWS_DRIVER':
            binary_obj = load_pe(validated_path)
        elif binary_format == 'MACH-O':
            binary_obj = load_macho(validated_path)
        
        if binary_format in ['LINUX_KERNEL_MODULE', 'WINDOWS_DRIVER']:
            kernel_info = extract_kernel_module_info(validated_path, binary_format)
            
            if binary_obj:
                info = {
                    'binary_path': validated_path,
                    'format': binary_format,
                    'arch': getattr(binary_obj, 'arch', 'unknown') if binary_format == 'LINUX_KERNEL_MODULE' else _detect_pe_arch(binary_obj),
                    'bits': getattr(binary_obj, 'bits', 0) if binary_format == 'LINUX_KERNEL_MODULE' else _detect_pe_bits(binary_obj),
                    'endian': getattr(binary_obj, 'endian', 'little') if binary_format == 'LINUX_KERNEL_MODULE' else 'little',
                    'checksec': {'format': binary_format, 'is_kernel_module': True},
                    'imports': {'all_imports': {}, 'dangerous_functions': kernel_info.get('kernel_dangerous_functions', [])},
                    'key_strings': get_key_strings_generic(validated_path),
                    'symbols': get_symbols(binary_obj) if binary_format == 'LINUX_KERNEL_MODULE' else get_symbols_pe(binary_obj),
                    'functions': get_functions(binary_obj) if binary_format == 'LINUX_KERNEL_MODULE' else get_functions_pe(binary_obj, validated_path),
                    'kernel_info': kernel_info
                }
            else:
                info = {
                    'binary_path': validated_path,
                    'format': binary_format,
                    'arch': 'unknown',
                    'bits': 0,
                    'endian': 'little',
                    'checksec': {'format': binary_format, 'is_kernel_module': True},
                    'imports': {'all_imports': {}, 'dangerous_functions': kernel_info.get('kernel_dangerous_functions', [])},
                    'key_strings': get_key_strings_generic(validated_path),
                    'symbols': {},
                    'functions': get_functions_generic(validated_path),
                    'kernel_info': kernel_info
                }
            logger.info("内核模块信息收集完成")
            return info
        
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
        
        try:
            mobile_platform = detect_mobile_platform(binary_path)
            if mobile_platform in ['android', 'ios']:
                from .mobile_analysis import MobileBinaryAnalyzer
                mobile_analyzer = MobileBinaryAnalyzer(binary_path, platform=mobile_platform)
                mobile_result = mobile_analyzer.analyze()
                info['mobile_analysis'] = {
                    'platform': mobile_platform,
                    'jni_functions': mobile_result.jni_functions,
                    'objective_c_classes': mobile_result.objective_c_classes,
                    'sensitive_strings': mobile_result.sensitive_strings,
                    'vulnerabilities': mobile_result.vulnerabilities,
                    'android_specific': mobile_result.android_specific,
                    'ios_specific': mobile_result.ios_specific
                }
        except ImportError:
            logger.warning("MobileBinaryAnalyzer 模块未找到，跳过移动平台分析")
        except Exception as e:
            logger.error(f"移动平台分析失败: {e}")
        
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
        result = subprocess.run()
            cmd,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=Config.SUBPROCESS_TIMEOUT
        
        
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


def extract_kernel_module_info(binary_path: str, binary_format: str) -> Dict[str, Any]:
    """
    提取内核模块专用信息
    
    Args:
        binary_path: 内核模块文件路径
        binary_format: 文件格式 ('LINUX_KERNEL_MODULE' 或 'WINDOWS_DRIVER')
        
    Returns:
        包含内核模块信息的字典
    """
    info = {
        'module_parameters': [],
        'entry_points': {},
        'exported_symbols': [],
        'ioctl_handlers': [],
        'kernel_dangerous_functions': [],
        'module_type': binary_format
    }
    
    try:
        if binary_format == 'LINUX_KERNEL_MODULE':
            info.update(_extract_linux_kernel_module_info(binary_path

        elif binary_format == 'WINDOWS_DRIVER':
            info.update(_extract_windows_driver_info(binary_path

            
    except Exception as e:
        logger.error(f"提取内核模块信息失败: {e}")
    
    return info


def _extract_linux_kernel_module_info(binary_path: str) -> Dict[str, Any]:
    """
    提取 Linux 内核模块信息
    
    Args:
        binary_path: 内核模块文件路径
        
    Returns:
        包含 Linux 内核模块信息的字典
    """
    info = {
        'module_parameters': [],
        'entry_points': {},
        'exported_symbols': [],
        'ioctl_handlers': [],
        'kernel_dangerous_functions': []
    }
    
    try:
        functions = get_functions_generic(binary_path)
        
        for func in functions:
            func_name = func['name']
            
            if func_name == 'module_init' or func_name.endswith('_init'):
                info['entry_points']['init'] = {
                    'name': func_name,
                    'address': func['address'],
                    'size': func['size']
                }
            elif func_name == 'module_exit' or func_name.endswith('_exit'):
                info['entry_points']['exit'] = {
                    'name': func_name,
                    'address': func['address'],
                    'size': func['size']
                }
            elif 'ioctl' in func_name.lower():
                info['ioctl_handlers'].append({)
                    'name': func_name,
                    'address': func['address'],
                    'size': func['size']
                }
            elif func_name in KERNEL_DANGEROUS_FUNCTIONS:
                info['kernel_dangerous_functions'].append(func_name)
                
        strings = get_key_strings_generic(binary_path)
        for s in strings:
            if 'param_' in s.lower() or 'module_param' in s.lower():
                info['module_parameters'].append(s)
                
        symbols = get_symbols(load_elf(binary_path

        for name, addr in symbols.items():
            if not name.startswith('_'):
                info['exported_symbols'].append({)
                    'name': name,
                    'address': addr
                }
                
        logger.info(f"提取到 Linux 内核模块信息: {len(info['module_parameters'])} 个参数, ")
                   f"{len(info['entry_points'])} 个入口点, {len(info['ioctl_handlers'])} 个 ioctl 处理函数"
                   
    except Exception as e:
        logger.error(f"提取 Linux 内核模块信息失败: {e}")
    
    return info


def _extract_windows_driver_info(binary_path: str) -> Dict[str, Any]:
    """
    提取 Windows 驱动信息
    
    Args:
        binary_path: 驱动文件路径
        
    Returns:
        包含 Windows 驱动信息的字典
    """
    info = {
        'module_parameters': [],
        'entry_points': {},
        'exported_symbols': [],
        'ioctl_handlers': [],
        'kernel_dangerous_functions': []
    }
    
    try:
        functions = get_functions_generic(binary_path)
        
        for func in functions:
            func_name = func['name']
            
            if func_name == 'DriverEntry' or 'DriverInit' in func_name:
                info['entry_points']['DriverEntry'] = {
                    'name': func_name,
                    'address': func['address'],
                    'size': func['size']
                }
            elif 'Unload' in func_name:
                info['entry_points']['Unload'] = {
                    'name': func_name,
                    'address': func['address'],
                    'size': func['size']
                }
            elif 'Dispatch' in func_name or 'Ioctl' in func_name:
                info['ioctl_handlers'].append({)
                    'name': func_name,
                    'address': func['address'],
                    'size': func['size']
                }
            elif any(kernel_func.lower() in func_name.lower() for kernel_func in KERNEL_DRIVER_DANGEROUS_FUNCTIONS):
                info['kernel_dangerous_functions'].append(func_name)
                
        strings = get_key_strings_generic(binary_path)
        for s in strings:
            if 'RegistryPath' in s or 'DriverName' in s:
                info['module_parameters'].append(s)
                
        pe_obj = load_pe(binary_path)
        if pe_obj:
            symbols = get_symbols_pe(pe_obj)
            for name, addr in symbols.items():
                info['exported_symbols'].append({)
                    'name': name,
                    'address': addr
                }
                
        logger.info(f"提取到 Windows 驱动信息: {len(info['module_parameters'])} 个参数, ")
                   f"{len(info['entry_points'])} 个入口点, {len(info['ioctl_handlers'])} 个 ioctl 处理函数"
                   
    except Exception as e:
        logger.error(f"提取 Windows 驱动信息失败: {e}")
    
    return info


GO_DANGEROUS_FUNCTIONS = [
    'syscall.RawSyscall',
    'syscall.Syscall',
    'syscall.Syscall6',
    'syscall.Write',
    'syscall.Read',
    'syscall.Close',
    'os.StartProcess',
    'os.Exec',
    'os.ForkExec',
    'crypto/tls.NewListener',
    'crypto/tls.Server',
    'net/http.ListenAndServe',
    'net/http.Serve',
    'reflect.Value.Set',
    'reflect.Value.Elem',
    'unsafe.Pointer',
    'unsafe.Sizeof',
    'unsafe.Offsetof',
    'unsafe.Alignof',
    'runtime.Stack',
    'runtime.Goexit',
    'runtime.Panic',
    'runtime.Throw',
    'sync.Mutex.Unlock',
    'sync.RWMutex.Unlock',
]


RUST_DANGEROUS_FUNCTIONS = [
    'std::ptr::read',
    'std::ptr::write',
    'std::ptr::copy',
    'std::ptr::copy_nonoverlapping',
    'std::ptr::drop_in_place',
    'std::mem::transmute',
    'std::mem::forget',
    'std::mem::uninitialized',
    'std::mem::zeroed',
    'std::slice::from_raw_parts',
    'std::slice::from_raw_parts_mut',
    'std::str::from_utf8_unchecked',
    'std::str::from_utf8_unchecked_mut',
    'std::ffi::CString::new',
    'std::ffi::CStr::from_ptr',
    'std::os::raw::c_char',
    'core::ptr::read',
    'core::ptr::write',
    'core::mem::transmute',
    'alloc::alloc::alloc',
    'alloc::alloc::dealloc',
    'alloc::alloc::realloc',
]


GO_SYMBOLS = [
    'runtime.main',
    'runtime.init',
    'go.buildid',
    'runtime.gc',
    'runtime.mallocgc',
    'runtime.free',
    'runtime.stack',
    'runtime.schedule',
    'runtime.panic',
    'runtime.recover',
    'runtime.deferproc',
    'runtime.deferreturn',
    'sync.(*Mutex).Lock',
    'sync.(*RWMutex).Lock',
    'net/http.(*Server).Serve',
    'encoding/json.Marshal',
    'encoding/json.Unmarshal',
]


RUST_SYMBOLS = [
    'rust_eh_personality',
    '_Unwind_Resume',
    'panic',
    'panic_bounds_check',
    'std::rt::lang_start',
    'std::panicking::panic',
    'std::panicking::try',
    'std::process::exit',
    'core::ptr::drop_in_place',
    'core::fmt::write',
    'alloc::alloc::handle_alloc_error',
    '__rust_start_panic',
    '__rust_foreign_exception',
    '_ZN4core3ptr4read17h',
    '_ZN4core3ptr5write17h',
]


GO_SECTIONS = [
    '.gopclntab',
    '.go.buildinfo',
    '.gosymtab',
    '_rt0_amd64_linux',
    '_rt0_amd64_darwin',
    '_rt0_amd64_windows',
]


RUST_SECTIONS = [
    '.rustc_demangle',
    '.rustc_std_workspace',
    '.rustc_debug_gdb_scripts_section',
    '.eh_frame',
    '.gcc_except_table',
]


def detect_language(binary_path: str, binary_format: str = 'ELF') -> str:
    """
    检测二进制文件的编程语言
    
    Args:
        binary_path: 二进制文件路径
        binary_format: 二进制格式 (ELF/PE/MACH-O)
    
    Returns:
        检测到的语言: 'go', 'rust', 'c/c++', 或 'unknown'
    """
    try:
        go_score = 0
        rust_score = 0
        
        with open(binary_path, 'rb') as f:
            header = f.read(4096)
            
            if b'go.buildid' in header:
                go_score += 3,
            if b'.gopclntab' in header:
                go_score += 2,
            if b'__go_eh_frame' in header:
                go_score += 2
            
            if b'rust_eh_personality' in header:
                rust_score += 3,
            if b'__rustc_demangle' in header:
                rust_score += 2,
            if b'.rustc_' in header:
                rust_score += 2
        
        strings = get_key_strings_generic(binary_path)
        symbols = _get_binary_symbols(binary_path)
        
        for sym in GO_SYMBOLS:
            if any(sym.lower() in s.lower() for s in strings + symbols):
                go_score += 1
        
        for sym in RUST_SYMBOLS:
            if any(sym.lower() in s.lower() for s in strings + symbols):
                rust_score += 1
        
        if binary_format == 'ELF':
            try:
                import subprocess
                cmd = ['r2', '-q', '-e', 'io.color=false', '-c', 'iS', binary_path]
                result = subprocess.run()
                    cmd,
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    errors='replace',
                    timeout=30
                
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        for sec in GO_SECTIONS:
                            if sec in line:
                                go_score += 1,
                        for sec in RUST_SECTIONS:
                            if sec in line:
                                rust_score += 1
            except Exception:
                pass
        
        logger.debug(f"语言检测分数 - Go: {go_score}, Rust: {rust_score}")
        
        if go_score >= 5:
            logger.info(f"检测到 Go 二进制文件")
            return 'go'
        elif rust_score >= 5:
            logger.info(f"检测到 Rust 二进制文件")
            return 'rust'
        else:
            logger.info(f"检测到 C/C++ 二进制文件 (或其他语言)")
            return 'c/c++'
    
    except Exception as e:
        logger.error(f"检测语言失败: {e}")
        return 'unknown'


def _get_binary_symbols(binary_path: str) -> List[str]:
    """
    获取二进制文件的符号列表（简化版）
    
    Args:
        binary_path: 二进制文件路径
    
    Returns:
        符号名称列表
    """
    symbols = []
    
    try:
        import subprocess
        cmd = ['r2', '-q', '-e', 'io.color=false', '-c', 'is', binary_path]
        result = subprocess.run()
            cmd,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=30
        
        
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                parts = line.split()
                if len(parts) >= 7:
                    name = ' '.join(parts[6:])
                    symbols.append(name)
    
    except Exception:
        pass
    
    return symbols


def get_language_specific_dangerous_functions(language: str) -> List[str]:
    """
    获取特定语言的危险函数列表
    
    Args:
        language: 编程语言 ('go', 'rust', 'c/c++')
    
    Returns:
        危险函数列表
    """
    if language == 'go':
        return GO_DANGEROUS_FUNCTIONS
    elif language == 'rust':
        return RUST_DANGEROUS_FUNCTIONS
    elif language == 'c/c++':
        return DANGEROUS_FUNCTIONS
    else:
        return DANGEROUS_FUNCTIONS


def get_language_analysis_hints(language: str) -> Dict[str, Any]:
    """
    获取特定语言的分析提示信息
    
    Args:
        language: 编程语言
    
    Returns:
        包含分析提示的字典
    """
    hints = {
        'go': {
            'calling_convention': 'Go uses register-based calling convention (DI, SI, DX, CX, R8, R9 for args)',
            'stack_management': 'Go uses segmented stacks that grow automatically',
            'error_handling': 'Go uses explicit error returns, check for nil errors',
            'concurrency': 'Look for goroutine-related issues, race conditions',
            'memory_safety': 'Go has garbage collection but can still have memory leaks',
            'key_areas': ['defer/panic/recover misuse', 'unsafe package usage', 'channel mismanagement']
        },
        'rust': {
            'calling_convention': 'Rust uses standard System V AMD64 calling convention',
            'stack_management': 'Rust uses RAII and borrow checker',
            'error_handling': 'Rust uses Result<T, E> and panic! macro',
            'concurrency': 'Rust has excellent concurrency safety with Send/Sync traits',
            'memory_safety': 'Memory safety guaranteed by compiler (except unsafe blocks)',
            'key_areas': ['unsafe blocks', 'FFI boundaries', 'unwrap() misuse', 'concurrency bugs']
        },
        'c/c++': {
            'calling_convention': 'Depends on platform (stdcall, cdecl, fastcall)',
            'stack_management': 'Manual memory management',
            'error_handling': 'Return codes and exceptions (C++)',
            'concurrency': 'Manual thread management',
            'memory_safety': 'No built-in memory safety',
            'key_areas': ['buffer overflows', 'use-after-free', 'format strings', 'race conditions']
        },
        'unknown': {
            'note': 'Language detection failed, using default analysis'
        }
    }
    
    return hints.get(language, hints['unknown'])


def detect_mobile_platform(binary_path: str) -> str:
    """
    检测二进制文件是否为移动平台二进制
    
    Args:
        binary_path: 二进制文件路径
        
    Returns:
        'android', 'ios', 或 'unknown'
    """
    try:
        with open(binary_path, 'rb') as f:
            header = f.read(4096)
        
        binary_format = detect_binary_format(binary_path)
        
        if binary_format == 'ELF':
            if b'Android' in header or b'__android_log' in header:
                return 'android'
            if binary_path.lower().endswith('.so'):
                return 'android'
        
        elif binary_format == 'MACH-O':
            if b'iOS' in header or b'iPhone' in header or b'Apple' in header:
                return 'ios'
            if binary_path.lower().endswith('.mach-o') or binary_path.lower().endswith('.ipa'):
                return 'ios'
        
        return 'unknown'
    except Exception as e:
        logger.error(f"检测移动平台失败: {e}")
        return 'unknown'


def extract_jni_functions(elf_obj: object) -> List[Dict[str, Any]]:
    """
    从 ELF 文件中提取 JNI 函数信息
    
    Args:
        elf_obj: ELF 对象
        
    Returns:
        JNI 函数列表
    """
    jni_funcs = []
    
    try:
        symbols = getattr(elf_obj, 'symbols', {})
        
        for name, addr in symbols.items():
            if name.startswith('Java_'):
                parts = name.split('_')
                if len(parts) >= 3:
                    java_class = '/'.join(parts[1:-1])
                    java_method = parts[-1]
                    
                    jni_funcs.append({)
                        'name': name,
                        'java_class': java_class,
                        'java_method': java_method,
                        'address': addr
                    }
        
        logger.info(f"提取到 {len(jni_funcs)} 个 JNI 函数")
    except Exception as e:
        logger.error(f"提取 JNI 函数失败: {e}")
    
    return jni_funcs


def extract_android_specific_info(binary_path: str, elf_obj: object = None) -> Dict[str, Any]:
    """
    提取 Android 特定信息
    
    Args:
        binary_path: 二进制文件路径
        elf_obj: ELF 对象（可选）
        
    Returns:
        Android 特定信息字典
    """
    info = {
        'is_android': True,
        'jni_functions': [],
        'framework_calls': [],
        'sensitive_strings': []
    }
    
    try:
        if elf_obj:
            info['jni_functions'] = extract_jni_functions(elf_obj)
        
        strings = get_key_strings_generic(binary_path)
        for s in strings:
            if any(pattern.lower() in s.lower() for pattern in ['secret', 'key', 'password', 'token']):
                info['sensitive_strings'].append(s)
        
        imports = {}
        if elf_obj:
            imports = get_imported_functions(elf_obj)
        
        for func in MOBILE_DANGEROUS_FUNCTIONS:
            if func in imports.get('all_imports', {}).values() or func in imports.get('dangerous_functions', []):
                info['framework_calls'].append(func)
        
        logger.info(f"提取 Android 信息完成")
    except Exception as e:
        logger.error(f"提取 Android 信息失败: {e}")
    
    return info


def extract_ios_specific_info(binary_path: str, macho_obj: object = None) -> Dict[str, Any]:
    """
    提取 iOS 特定信息
    
    Args:
        binary_path: 二进制文件路径
        macho_obj: Mach-O 对象（可选）
        
    Returns:
        iOS 特定信息字典
    """
    info = {
        'is_ios': True,
        'objc_classes': [],
        'swift_features': [],
        'sensitive_strings': [],
        'jailbreak_detection': []
    }
    
    try:
        strings = get_key_strings_generic(binary_path)
        
        jailbreak_patterns = ['Cydia', 'Sileo', 'MobileSubstrate', '/Applications/Cydia.app']
        for pattern in jailbreak_patterns:
            if any(pattern.lower() in s.lower() for s in strings):
                info['jailbreak_detection'].append(pattern)
        
        for s in strings:
            if 'NSUserDefaults' in s:
                info['sensitive_strings'].append({'content': s, 'type': 'insecure_storage'})
            if 'sqlite' in s.lower() and ('password' in s.lower() or 'secret' in s.lower()):
                info['sensitive_strings'].append({'content': s, 'type': 'insecure_database'})
        
        swift_patterns = ['type metadata', 'protocol witness table', '$s', 'Swift.']
        for pattern in swift_patterns:
            if any(pattern in s for s in strings):
                info['swift_features'].append(pattern)
        
        logger.info(f"提取 iOS 信息完成")
    except Exception as e:
        logger.error(f"提取 iOS 信息失败: {e}")
    
    return info


def collect_mobile_info(binary_path: str, platform: str = 'auto') -> Dict[str, Any]:
    """
    收集移动平台二进制文件信息
    
    Args:
        binary_path: 二进制文件路径
        platform: 平台类型 ('auto', 'android', 'ios')
        
    Returns:
        移动平台信息字典
    """
    info = {
        'mobile_platform': 'unknown',
        'mobile_specific': {}
    }
    
    try:
        if platform == 'auto':
            detected_platform = detect_mobile_platform(binary_path)
        else:
            detected_platform = platform
        
        info['mobile_platform'] = detected_platform
        
        if detected_platform == 'android':
            binary_obj = load_elf(binary_path)
            info['mobile_specific'] = extract_android_specific_info(binary_path, binary_obj)
            if binary_obj and hasattr(binary_obj, 'close'):
                binary_obj.close()
        
        elif detected_platform == 'ios':
            binary_obj = load_macho(binary_path)
            info['mobile_specific'] = extract_ios_specific_info(binary_path, binary_obj)
            if binary_obj and hasattr(binary_obj, 'close'):
                binary_obj.close()
        
        logger.info(f"移动平台信息收集完成: {detected_platform}")
    except Exception as e:
        logger.error(f"收集移动平台信息失败: {e}")
    
    return info))))))))))))))