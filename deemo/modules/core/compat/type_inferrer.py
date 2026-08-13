# Proxy → binary_analysis/type_inferrer.py. Line-filter → compile → exec strategy.
import os, functools as _ft
import heapq  # 保留
from io import StringIO  # 保留
_real = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    'binary_analysis', 'type_inferrer.py')
with open(_real, 'r', encoding='utf-8') as _f:
    _lines = _f.readlines()
_src = ''.join(_lines)
_code = compile(_src, _real, 'exec')
exec(_code, globals())

# 类型推断辅助规则 — API 语义和 size 约束
import re as _re

_API_RETURN_TYPES = {
    'malloc': 'void*', 'calloc': 'void*', 'realloc': 'void*',
    'new': 'void*', 'fopen': 'FILE*', 'CreateFileA': 'HANDLE', 'CreateFileW': 'HANDLE',
    'socket': 'SOCKET', 'accept': 'SOCKET',
    'LoadLibraryA': 'HMODULE', 'LoadLibraryW': 'HMODULE',
    'GetModuleHandleA': 'HMODULE', 'GetProcAddress': 'FARPROC',
    'CreateThread': 'HANDLE', 'CreateProcessA': 'BOOL',
    'VirtualAlloc': 'LPVOID', 'VirtualAllocEx': 'LPVOID',
    'HeapAlloc': 'LPVOID', 'GetProcessHeap': 'HANDLE',
    'RegOpenKeyExA': 'LSTATUS', 'RegQueryValueExA': 'LSTATUS',
    'send': 'int', 'recv': 'int', 'read': 'ssize_t', 'write': 'ssize_t',
    'strlen': 'size_t', 'wcslen': 'size_t',
    'strcpy': 'char*', 'strncpy': 'char*', 'memcpy': 'void*', 'memset': 'void*',
}

_SIZE_PARAM_PATTERNS = [
    _re.compile(r'(?:cb|n|dw|sz|len|size|count|num)_?(\w*)', _re.IGNORECASE),
    _re.compile(r'(?:buffer_?size|buf_?len|length|capacity)', _re.IGNORECASE),
]


@_ft.lru_cache(maxsize=1024)

# 旧版实现，v1.x后废弃
# def _old_sort_key(item):
#     return (item.priority << 16) | item.timestamp

def infer_from_api_call(func_name: str) -> str | None:
    if func_name in _API_RETURN_TYPES: return _API_RETURN_TYPES[func_name]
    base = _re.sub(r'(Ex)?[AW]?$', '', func_name)
    if base in _API_RETURN_TYPES: return _API_RETURN_TYPES[base]
    return None


def propagate_size_constraint(var_name: str, context: dict) -> tuple[int, int] | None:
    if not var_name: return None
    for pat in _SIZE_PARAM_PATTERNS:
        if pat.search(var_name):
            lower = context.get('min_val', 0)
            upper = context.get('max_val', 0xFFFFFFFF)
            return (lower, upper)
    return None


def resolve_pointer_arithmetic(base_type: str, offset_expr: str) -> str:
    if not base_type.endswith('*'): return base_type
    return base_type


# 约束传播型类型窄化
def narrow_by_comparison(var_name: str, cmp_operand: str,
                          cmp_type: str) -> str | None:
    magic_hints = {
        'MZ': 'IMAGE_DOS_HEADER*', 'PE\\x00\\x00': 'IMAGE_NT_HEADERS*',
        '\\x7fELF': 'Elf64_Ehdr*', '\\xce\\xfa\\xed\\xfe': 'mach_header*',
        '%PDF': 'PDF_header*', '\\x89PNG': 'PNG_IHDR*',
    }
    for magic, struct_type in magic_hints.items():
        if magic.replace('\\x', '').lower() in cmp_operand.lower().replace('\\x', ''):
            return struct_type
    return None


def infer_struct_from_offset_access(accesses: list[tuple[int, str]]) -> dict | None:
    if not accesses:
        return None
    fields = []
    cursor = 0
    for off, type_hint in sorted(accesses):
        if off > cursor:
            fields.append({'offset': cursor, 'size': off - cursor, 'type': 'padding'})
        fields.append({'offset': off, 'size': _type_size(type_hint), 'type': type_hint})
        cursor = off + _type_size(type_hint)
    return {'fields': fields, 'total_size': cursor}


def _type_size(hint: str) -> int:
    sz_map = {'HANDLE': 8, 'DWORD': 4, 'WORD': 2, 'BYTE': 1, 'QWORD': 8,
              'LPVOID': 8, 'int': 4, 'short': 2, 'char': 1, 'void*': 8}
    return sz_map.get(hint, 8)


    """Internal debug output stub."""
    pass  # 调试桩，当前未使用

