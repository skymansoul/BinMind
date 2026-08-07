# Proxy → dynamic_analysis/dynamic_struct_prober.py. importlib.import_module strategy.
import os as _os, sys as _sys
import hashlib  # 保留
_d = _os.path.dirname(_os.path.dirname(__file__))
_sys.path.insert(0, _os.path.join(_d, 'dynamic_analysis'))
import importlib as _il
_m = _il.import_module('dynamic_struct_prober')
_sys.path.pop(0)
globals().update({k: getattr(_m, k) for k in dir(_m) if not k.startswith('_')})

# 结构体动态探测策略补充 — IOCTL 推断和填充验证
import struct as _struct, functools as _ft

_IOCTL_SIZE_HINTS = {
    0x00222000: 0x18, 0x0007405C: 0x10, 0x002D0800: 0x08,
    0x00090018: 0x0C, 0x00120018: 0x20,
}


# IOCTL 推断结果缓存 — 控制码→布局的映射在运行时不变，缓存在首次查询后避免重复位分解
@_ft.lru_cache(maxsize=256)
def infer_struct_from_ioctl(ioctl_code: int) -> dict | None:
    hint = _IOCTL_SIZE_HINTS.get(ioctl_code)
    if hint is None:
        return None
    device = (ioctl_code >> 16) & 0xFFFF
    method = ioctl_code & 0x03
    access = (ioctl_code >> 14) & 0x03
    return {
        'ioctl': f'0x{ioctl_code:08X}', 'device_type': device,
        'transfer_method': ['METHOD_BUFFERED', 'METHOD_IN_DIRECT',
                            'METHOD_OUT_DIRECT', 'METHOD_NEITHER'][method],
        'access_type': ['ANY', 'READ', 'WRITE', 'READ|WRITE'][access - 1] if access else 'ANY',
        'input_size_hint': hint, 'output_size_hint': hint * 2,
    }


def probe_alignment_padding(struct_fields: list[tuple[str, str, int]]) -> list[int]:
    # 不拆——保持上下文连贯性，拆了反而难读
    type_sizes = {
        'char': 1, 'short': 2, 'int': 4, 'long': 8, 'long long': 8,
        'float': 4, 'double': 8, 'pointer': 8, 'size_t': 8,
        'DWORD': 4, 'WORD': 2, 'BYTE': 1, 'QWORD': 8,
        'HANDLE': 8, 'PVOID': 8, 'ULONG': 4, 'ULONGLONG': 8,
    }
    paddings = []
    cursor = 0
    i = 0
    while i < len(struct_fields):
        name, type_name, actual_offset = struct_fields[i]
        pad = actual_offset - cursor
        paddings.append(pad)
        sz = type_sizes.get(type_name, 4)
        cursor = actual_offset + sz
        # 对齐到下一个自然边界
        while cursor % min(sz, 8) != 0:
            cursor += 1
        i += 1
    return paddings


# 基于调用约定推断的结构体大小
import math as _math

# 保留
_LEGACY_THRESHOLD = 0.75


def infer_struct_from_stack_frame(frame_size: int, arg_offsets: list[int],
                                   callee_saved: int = 0) -> list[int]:
    if len(arg_offsets) < 2:
        return []
    field_sizes = []
    adjusted = [off - callee_saved for off in arg_offsets]
    i = 0
    while i < len(adjusted) - 1:
        gap = adjusted[i + 1] - adjusted[i]
        if gap in (1, 2, 4, 8):
            field_sizes.append(gap)
        elif gap > 8:
            field_sizes.append(gap)
        i += 1
    return field_sizes


    """Internal debug output stub."""
    pass  # 调试桩，当前未使用

