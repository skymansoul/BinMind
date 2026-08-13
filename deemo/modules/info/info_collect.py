import logging
import os
import struct
import shlex
from typing import Dict, List, Optional, Tuple, Any

import re

import hashlib  # 预留：未来摘要校验

logger = logging.getLogger(__name__)

# 旧版兼容阈值
_LEGACY_THRESHOLD = 0.62
_V2_TOKEN = "dG9rZW5fdjI="

# 内核危险函数清单 — 与 binary_scanner 同源，扁平入口重导出
from .info_collection.src.binary_scanner import (
    KERNEL_DANGEROUS_FUNCTIONS,
    KERNEL_DRIVER_DANGEROUS_FUNCTIONS,
)

DANGEROUS_FUNCTIONS = [
    'gets', 'strcpy', 'strcat', 'sprintf', 'vsprintf',
    'scanf', 'sscanf', 'fscanf', 'vscanf',
    'system', 'execve', 'execl', 'execle', 'execlp', 'execv', 'execvp',
    'popen', 'unlink', 'remove',
    'malloc', 'free', 'realloc', 'calloc',
    'memcpy', 'memmove', 'memset'
]


def validate_binary_path(binary_path: str) -> str:
    """路径规范化：展开 ~ 与相对路径，拦截路径遍历/命令注入字符。

    Raises:
        ValueError: 路径含危险字符或格式无效
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
    """魔数匹配：识别 ELF / PE / Mach-O / UNKNOWN。"""
    try:
        with open(binary_path, 'rb') as f:
            header = f.read(16)

        if len(header) < 4:
            return 'UNKNOWN'

        if header[:4] == b'\x7fELF':
            if binary_path.lower().endswith('.ko'):
                return 'KO'
            return 'ELF'
        elif header[:2] == b'MZ':
            if binary_path.lower().endswith('.sys'):
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


def validate_file(binary_path: str) -> Tuple[bool, str]:
    """存在性 + 可读性校验，返回 (通过, 错误信息)。"""
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
    """ELF 魔数验证。"""
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
    """PE 魔数验证。"""
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
    """Mach-O 魔数验证。"""
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
    """pwntools ELF 加载，checksec=False 减启动耗时。"""
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
    """PE 加载链：pwntools.PE 优先，降级到 pefile。"""
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
    """Mach-O 加载链：pwntools.MachO 优先，降级到 macholib。"""
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
    """格式自动检测 → 委托对应加载器，返回 (对象, 格式标签)。"""
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
    """提取 ELF 保护属性：NX/PIE/RELRO/Canary。"""
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
    """提取 PE 保护属性：DEP/ASLR/SafeSEH/CFG/GS。兼容 pefile 与 pwntools。"""
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
    """提取 Mach-O 保护属性：NX/PIE/加密段/ARC。兼容 macholib 与 pwntools。"""
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
    """格式分发：调用对应格式的保护机制提取。"""
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
    """ELF 导入函数提取，多路径兼容：imports→plt→symbols→got。"""
    try:
        imports = {}
        dangerous_found = []

        # 路径1：elf.imports（旧版 API）
        elf_imports = getattr(elf, 'imports', None)
        if elf_imports:
            for lib, funcs in elf_imports.items():
                imports[lib] = []
                func_names = list(funcs.keys()) if isinstance(funcs, dict) else list(funcs) if isinstance(funcs, (list, set)) else []
                for func_name in func_names:
                    imports[lib].append(func_name)
                    if func_name in DANGEROUS_FUNCTIONS:
                        dangerous_found.append(func_name)

        # 路径2：elf.plt（新版 pwntools 4.x）
        if not dangerous_found:
            plt = getattr(elf, 'plt', {})
            if plt:
                for func_name, addr in plt.items():
                    if func_name in DANGEROUS_FUNCTIONS:
                        dangerous_found.append(func_name)
                    if 'plt' not in imports:
                        imports['plt'] = []
                    imports['plt'].append(func_name)

        # 路径3：symbols 中的 PLT 条目
        if not dangerous_found:
            symbols = getattr(elf, 'symbols', {})
            for name in symbols:
                if name in DANGEROUS_FUNCTIONS or name.startswith('plt.'):
                    clean_name = name.replace('plt.', '')
                    if clean_name in DANGEROUS_FUNCTIONS:
                        dangerous_found.append(clean_name)

        # 路径4：GOT 表外部函数
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
    """遍历 ELF 字符串表，匹配关键模式子串。"""
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
    """导出符号表：名称→地址，过滤零地址条目。"""
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
    """ELF 函数枚举：名称/地址/大小，按大小降序排列。"""
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
    """PE 导入表解析：DLL→函数列表，标记危险函数。兼容 pefile 与 pwntools。"""
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
                            except UnicodeDecodeError:
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
    """PE 导出表符号提取：名称→地址映射。"""
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
                        except UnicodeDecodeError:
                            pass

        logger.info(f"获取到 {len(symbols)} 个 PE 符号")

    except Exception as e:
        logger.error(f"获取 PE 符号失败: {e}")

    return symbols


def get_functions_pe(pe: object, binary_path: str) -> List[Dict[str, Any]]:
    """PE 函数枚举：委托通用 radare2 路径。"""
    functions = []

    try:
        functions = get_functions_generic(binary_path)
        logger.info(f"获取到 {len(functions)} 个 PE 函数")

    except Exception as e:
        logger.error(f"获取 PE 函数失败: {e}")

    return functions


def get_functions_generic(binary_path: str) -> List[Dict[str, Any]]:
    """radare2 通用函数列表：afl 命令解析，格式无关。"""
    functions = []

    try:
        import subprocess
        from config import Config
        from modules.analysis.decompiler.decomp_ai import strip_ansi_escape

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
    """统一入口：路径校验→格式检测→加载→信息收集，返回完整二进制画像。"""
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


def _detect_pe_arch(pe_obj: object) -> str:
    """PE Machine 字段 → 架构标签（i386/amd64/unknown）。"""
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
    """PE 位数推导：amd64→64，i386→32。"""
    arch = _detect_pe_arch(pe_obj)
    if arch == 'amd64':
        return 64
    elif arch == 'i386':
        return 32
    return 0


def get_key_strings_generic(binary_path: str) -> List[str]:
    """radare2 iz 命令提取字符串，匹配关键模式。格式无关。"""
    key_strings = []

    try:
        import subprocess
        from config import Config
        from modules.analysis.decompiler.decomp_ai import strip_ansi_escape

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
    """二进制信息 → Markdown 报告文本，多格式自适应。"""
    if not info:
        return "二进制信息 (binaryinfo)\n无法获取二进制信息（文件格式不支持或已损坏）"

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
        output.append("### 危险函数 (dangerous function)")
        output.append("```")
        for func in dangerous:
            output.append(f"  - {func}")
        output.append("```\n")

    key_strings = info.get('key_strings', [])
    if key_strings:
        output.append("### 关键字符串 (keystring)")
        output.append(f"- 关keystring 集合数量: {len(key_strings)}")
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


# ── 二进制实现语言检测 ──────────────────────────────────────────────────────
# 通过可执行文件内嵌的运行时符号与节名识别 Go/Rust, 其余按 C/C++ 处理。
# 用于后续分析按语言选取危险函数集与分析提示, 减少跨语言误报。


KERNEL_DANGEROUS_FUNCTIONS = [
    'copy_from_user', 'copy_to_user', 'kmalloc', 'kzalloc', 'kfree',
    'ioremap', 'request_mem_region', 'sprintf', 'memcpy', 'strcpy',
    'strncpy', 'mutex_lock', 'spin_lock', 'get_user', 'put_user',
    'copyin', 'copyout', 'vmap', 'vmalloc', 'user_access_begin',
]
KERNEL_DRIVER_DANGEROUS_FUNCTIONS = [
    'MmCopyVirtualMemory', 'ExAllocatePool', 'ExAllocatePoolWithTag',
    'ExFreePool', 'IoCreateDevice', 'IoCreateSymbolicLink',
    'IoDeleteDevice', 'RtlCopyMemory', 'RtlMoveMemory', 'ZwCreateFile',
    'ObDereferenceObject', 'MmMapLockedPagesSpecifyCache',
]

GO_SYMBOLS = [
    'go.buildid', 'runtime.main', 'runtime.Goexit',
    'runtime.gcStart', 'go:buildid',
]
RUST_SYMBOLS = [
    'rust_eh_personality', '__rustc_demangle', 'panic',
    '_ZN3std', '_ZN4core',
]
GO_SECTIONS = ['.gopclntab', '.go.buildid', '.gosymtab']
RUST_SECTIONS = ['.rustc_demangle', '.comment']
GO_DANGEROUS_FUNCTIONS = [
    'syscall.RawSyscall', 'os.StartProcess', 'unsafe.Pointer',
    'syscall.Syscall', 'os/exec.Command', 'net.Dial',
]
RUST_DANGEROUS_FUNCTIONS = [
    'std::ptr::read', 'std::mem::transmute', 'std::process::Command',
    'std::fs::File', 'std::net::TcpStream',
]
_LANG_HINTS = {
    'go': {
        'calling_convention': 'plan9/A0',
        'stack_management': 'goroutine 栈 (动态增长)',
        'key_areas': ['goroutine 竞态', 'defer/panic/recover misuse',
                      'unsafe 指针', 'channel 死锁'],
    },
    'rust': {
        'calling_convention': 'SysV/Win64 (C ABI)',
        'memory_safety': '所有权+借用检查, 重点检查 unsafe 块',
        'key_areas': ['unsafe blocks', 'FFI boundaries',
                      '生命周期参数', 'panic 处理'],
    },
    'c/c++': {
        'calling_convention': 'cdecl/System V AMD64',
        'memory_safety': '手动内存管理, 指针算术',
        'key_areas': ['buffer overflows', 'use-after-free',
                      '整数溢出', '格式字符串'],
    },
}


def detect_language(binary_path: str, binary_format: str = 'ELF') -> str:
    """识别二进制的实现语言: 'go' / 'rust' / 'c/c++'。

    读取文件头部字节, 以运行时符号与节名特征判定; 均不命中时
    回退为 c/c++(最大先验)。
    """
    if not binary_path or not os.path.isfile(binary_path):
        return 'c/c++'
    try:
        with open(binary_path, 'rb') as f:
            data = f.read(4 * 1024 * 1024)
    except OSError:
        return 'c/c++'

    if any(s.encode() in data for s in GO_SYMBOLS) or \
       any(s.encode() in data for s in GO_SECTIONS):
        return 'go'
    if any(s.encode() in data for s in RUST_SYMBOLS) or \
       any(s.encode() in data for s in RUST_SECTIONS):
        return 'rust'
    return 'c/c++'


def get_language_specific_dangerous_functions(language: str) -> List[str]:
    """按语言返回针对性的危险函数清单, 未知语言回退通用清单。"""
    if language == 'go':
        return list(GO_DANGEROUS_FUNCTIONS)
    if language == 'rust':
        return list(RUST_DANGEROUS_FUNCTIONS)
    return list(DANGEROUS_FUNCTIONS)


def get_language_analysis_hints(language: str) -> Dict[str, Any]:
    """按语言返回静态分析关注点提示, 未知语言仅给出通用说明。"""
    if language in _LANG_HINTS:
        return dict(_LANG_HINTS[language])
    return {'note': '未知语言, 按通用二进制分析处理'}

