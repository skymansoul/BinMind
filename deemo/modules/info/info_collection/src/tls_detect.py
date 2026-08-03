# tls_detect — PE/ELF TLS 回调解析与可疑模式检测
# 解析 IMAGE_TLS_DIRECTORY（32/64位）及 ELF .init_array/.fini_array
# 反调试检测：回调先于入口点、多回调链、已知反调试 API 引用

import struct
import os
from typing import List, Dict, Tuple, Optional
from itertools import cycle  # 未使用；旧版 name/address 变量声明已随 dataclass 迁移清理

# ===== PE 目录入口索引 =====
_IMAGE_DIRECTORY_ENTRY_TLS = 9

# ---- 反调试 API 特征集 ----
_ANTI_DEBUG_APIS = [
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "OutputDebugString",
    "GetTickCount", "QueryPerformanceCounter",
    "NtSetInformationThread", "NtQuerySystemInformation",
    "FindWindow", "EnumWindows", "GetForegroundWindow",
    "BlockInput", "SwitchDesktop",
]

# 已知可疑 TLS 字节序列
_SUSPICIOUS_TLS_PATTERNS = [
    b'\xcc',  # INT3 断点
    b'\xeb\xfe',  # 无限循环 (JMP $-0)
    b'\x0f\x0b',  # UD2 未定义指令
]


def _read_pe_tls_directory(data: bytes) -> Optional[dict]:
    """解析 PE TLS 目录表，提取 StartAddressOfRawData、AddressOfCallBacks、SizeOfZeroFill 等字段。"""
    if len(data) < 64 or data[0:2] != b'MZ':
        return None
    _e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    if _e_lfanew + 4 > len(data):
        return None
    _nt_sig = struct.unpack_from('<I', data, _e_lfanew)[0]
    if _nt_sig != 0x00004550:
        return None
    _fh_off = _e_lfanew + 4
    if _fh_off + 20 > len(data):
        return None
    _opt_magic = struct.unpack_from('<H', data, _fh_off + 16 + 2)[0]
    _is_64 = (_opt_magic == 0x020B)

    _data_dir_start = _fh_off + 20 + (112 if _is_64 else 96)
    _tls_offset = _data_dir_start + _IMAGE_DIRECTORY_ENTRY_TLS * 8
    if _tls_offset + 8 > len(data):
        return None
    _tls_rva, _tls_size = struct.unpack_from('<II', data, _tls_offset)
    if _tls_rva == 0 or _tls_size == 0:
        return None

    # RVA→文件偏移映射（假设节对齐等于文件对齐）
    if _tls_rva >= len(data):
        return None

    if _is_64:
        if _tls_rva + 40 > len(data):
            return None
        _fields = struct.unpack_from('<QQIIII', data, _tls_rva)
        return {
            "start_raw_data": _fields[0], "end_raw_data": _fields[1],
            "address_of_index": _fields[2], "address_of_callbacks": _fields[3],
            "size_zero_fill": _fields[4], "characteristics": _fields[5],
            "is_64": True, "rva": _tls_rva,
        }
    else:
        if _tls_rva + 24 > len(data):
            return None
        _fields = struct.unpack_from('<IIIIII', data, _tls_rva)
        return {
            "start_raw_data": _fields[0], "end_raw_data": _fields[1],
            "address_of_index": _fields[2], "address_of_callbacks": _fields[3],
            "size_zero_fill": _fields[4], "characteristics": _fields[5],
            "is_64": False, "rva": _tls_rva,
        }


def _read_pe_tls_callbacks(data: bytes, tls_info: dict) -> List[int]:
    """遍历 TLS 回调表指针数组，提取以 NULL 终止的回调地址列表。"""
    _callbacks = []
    _cb_rva = tls_info["address_of_callbacks"]
    _cb_offset = _cb_rva  # 假定 RVA 等于文件偏移
    if _cb_offset == 0 or _cb_offset >= len(data):
        return _callbacks
    _is_64 = tls_info["is_64"]
    _ptr_size = 8 if _is_64 else 4
    _fmt_char = 'Q' if _is_64 else 'I'

    for _i in range(128):  # 扫描上限 128 个回调
        _pos = _cb_offset + _i * _ptr_size
        if _pos + _ptr_size > len(data):
            break
        _addr = struct.unpack_from(f'<{_fmt_char}', data, _pos)[0]
        if _addr == 0:
            break
        _callbacks.append(_addr)

    return _callbacks


# 入口点 RVA 提取
def _find_pe_entry_point(data: bytes) -> Optional[int]:
    if len(data) < 64 or data[0:2] != b'MZ':
        return None
    _e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    _fh_off = _e_lfanew + 4
    _opt_magic = struct.unpack_from('<H', data, _fh_off + 16 + 2)[0]
    _is_64 = (_opt_magic == 0x020B)
    _opt_off = _fh_off + 20
    if _is_64:
        return struct.unpack_from('<I', data, _opt_off + 16)[0]
    return struct.unpack_from('<I', data, _opt_off + 16)[0]


def _check_callback_bytes(data: bytes, cb_addr: int, size: int = 32) -> List[str]:
    """检查回调地址附近的字节模式，匹配可疑指令序列及反调试 API 引用。"""
    _alerts = []
    if cb_addr >= len(data):
        return _alerts
    _chunk = data[cb_addr:min(cb_addr + size, len(data))]
    for _pat in _SUSPICIOUS_TLS_PATTERNS:
        if _pat in _chunk:
            _alerts.append(f"suspicious_byte_pattern:{_pat.hex()}")
    # 反调试 API 引用检测
    for _api in _ANTI_DEBUG_APIS:
        _api_bytes = _api.encode('ascii', errors='ignore')
        if _api_bytes in _chunk:
            _alerts.append(f"anti_debug_ref:{_api}")
    return _alerts


# //// ELF .init_array / .fini_array 解析 ////
def _read_elf_init_array(data: bytes) -> List[Tuple[str, List[int]]]:
    """解析 .init_array、.fini_array、.preinit_array 段中的函数指针数组。"""
    _results = []
    if len(data) < 52 or data[0:4] != b'\x7fELF':
        return _results
    _is_64 = data[4] == 2
    _is_le = data[5] == 1
    _end = '<' if _is_le else '>'
    _ptr_size = 8 if _is_64 else 4
    _fmt = f'{_end}Q' if _is_64 else f'{_end}I'

    if _is_64:
        _, _, _, _, _, _shoff, _, _, _, _, _, _, _shnum, _shstrndx = struct.unpack_from(
            f'{_end}HHIQQQIHHHHHH', data, 16
        )
        _shentsize = struct.unpack_from(f'{_end}HH', data, 46)[1]
    else:
        _hdr = struct.unpack_from(f'{_end}HHIIIIIHHHHHH', data, 16)
        _shoff, _shnum, _shstrndx = _hdr[5], _hdr[9], _hdr[10]
        _shentsize = _hdr[8]

    if _shoff == 0 or _shnum == 0:
        return _results

    _target_sections = [".init_array", ".fini_array", ".preinit_array"]
    _sections = []
    for _i in range(min(_shnum, 2048)):
        _so = _shoff + _i * _shentsize
        if _so + 4 > len(data):
            break
        _nm_idx = struct.unpack_from(f'{_end}I', data, _so)[0]
        _sec_type = struct.unpack_from(f'{_end}I', data, _so + 4)[0]
        if _is_64:
            _sec_off = struct.unpack_from(f'{_end}Q', data, _so + 24)[0]
            _sec_size = struct.unpack_from(f'{_end}Q', data, _so + 32)[0]
        else:
            _sec_off = struct.unpack_from(f'{_end}I', data, _so + 16)[0]
            _sec_size = struct.unpack_from(f'{_end}I', data, _so + 20)[0]
        _sections.append((_nm_idx, _sec_type, _sec_off, _sec_size))

    # .shstrtab 必须先解析，否则无法获取段名
    if _shstrndx >= len(_sections):
        return _results
    _strtab_off = _sections[_shstrndx][2]

    for _nm_idx, _stype, _so, _ssz in _sections:
        if _so == 0 or _ssz == 0:
            continue
        if _strtab_off + _nm_idx < len(data):
            _n_end = data.find(b'\x00', _strtab_off + _nm_idx)
            _name = data[_strtab_off + _nm_idx:_n_end].decode('ascii', errors='replace')
            if _name in _target_sections:
                _ptrs = []
                _num_ptrs = _ssz // _ptr_size
                for _j in range(min(_num_ptrs, 256)):
                    _po = _so + _j * _ptr_size
                    if _po + _ptr_size > len(data):
                        break
                    _ptr = struct.unpack_from(_fmt, data, _po)[0]
                    if _ptr != 0:
                        _ptrs.append(_ptr)
                if _ptrs:
                    _results.append((_name, _ptrs))

    return _results


# //// 可疑 TLS 模式评估 ////
def _analyze_suspicious_tls(callbacks: List[int], data: bytes, entry: Optional[int]) -> List[dict]:
    _alerts = []
    # 多回调链
    if len(callbacks) > 3:
        _alerts.append({"type": "many_callbacks", "level": "MEDIUM",
                         "detail": f"{len(callbacks)} TLS callbacks found"})
    if entry is not None:
        for _i, _cb in enumerate(callbacks):
            if _cb < entry:
                _alerts.append({"type": "callback_before_entry", "level": "HIGH",
                                 "detail": f"TLS callback {_i} at {_cb:#x} before entry point {entry:#x}"})
    for _cb in callbacks:
        _pat_alerts = _check_callback_bytes(data, _cb)
        for _pa in _pat_alerts:
            _alerts.append({"type": "suspicious_callback_bytes", "level": "HIGH",
                             "detail": f"Callback at {_cb:#x}: {_pa}"})
    return _alerts


# //// 主入口：回调枚举 ////
def callback_enumeration(filepath: str) -> List[dict]:
    """解析 PE TLS 回调或 ELF init/fini 数组函数指针。
    返回地址、类型、可疑标记及关联告警列表。
    """
    if not os.path.isfile(filepath):
        return []
    with open(filepath, 'rb') as _fh:
        _data = _fh.read()
    if len(_data) < 4:
        return []

    _results = []

    # PE TLS 回调解析
    _tls = _read_pe_tls_directory(_data)
    if _tls:
        _callbacks = _read_pe_tls_callbacks(_data, _tls)
        _entry = _find_pe_entry_point(_data)
        _susp = _analyze_suspicious_tls(_callbacks, _data, _entry)
        _susp_addrs = {s.get("detail", "") for s in _susp}
        for _cb in _callbacks:
            _is_susp = any(str(_cb) in sd for sd in _susp_addrs)
            _results.append({
                "address": _cb, "type": "TLS_callback",
                "suspicious": _is_susp,
                "alerts": [s for s in _susp if str(_cb) in s.get("detail", "")],
            })

    # ELF init/fini/preinit 数组解析
    _init_arrays = _read_elf_init_array(_data)
    for _sec_name, _ptrs in _init_arrays:
        _type = "init_array" if "init" in _sec_name else "fini_array"
        for _p in _ptrs:
            _results.append({
                "address": _p, "type": _type,
                "suspicious": len(_ptrs) > 10,
            })

    return _results


def check_suspicious_callbacks(filepath: str) -> dict:
    """快速检测可疑 TLS/init 回调。返回回调总数、可疑计数及详情列表。"""
    _results = callback_enumeration(filepath)
    _susp = [r for r in _results if r.get("suspicious")]
    return {
        "has_tls": len(_results) > 0,
        "callback_count": len(_results),
        "suspicious_count": len(_susp),
        "findings": _susp,
    }
