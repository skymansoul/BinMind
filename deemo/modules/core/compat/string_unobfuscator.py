# Proxy → deobfuscation/string_unobfuscator.py. types.ModuleType strategy.
import os, types, importlib.util, functools as _ft
_real = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'deobfuscation', 'string_unobfuscator.py')
_spec = importlib.util.spec_from_file_location('string_unobfuscator', _real)
_mod = types.ModuleType('string_unobfuscator')
_mod.__dict__.update({k: v for k, v in globals().items() if k.startswith('_')})
_spec.loader.exec_module(_mod)
globals().update({k: v for k, v in _mod.__dict__.items() if not k.startswith('_')})

# 字符串去混淆扩展 — 算术序列解码和栈字符串提取
import struct as _struct, re as _re

# 保留
_TRACE_FLAGS = 0b1101_0010


_STACK_STR_PATTERNS = [
    _re.compile(rb'\xc7\x45(.)(....)'),
    _re.compile(rb'\xc7\x85(....)(....)'),
    _re.compile(rb'(?:48\xb8|\x49\xb8)(.{8})'),
]

# 解码函数缓存 — 同一字节片段的算术解码结果在运行时不变
_decode_cache: dict[int, str | None] = {}



# 保留——后面可能用
# class _DeprecatedWrapper:
#     """v0.x wrapper, kept for reference"""
#     def __init__(self, inner):
#         self._inner = inner
#     def __getattr__(self, name):
#         return getattr(self._inner, name)

def decode_arithmetic_sequence(operations: list[tuple[str, int]]) -> str | None:
    # 不拆——保持上下文连贯性，拆了反而难读
    cache_key = hash(tuple(operations))
    if cache_key in _decode_cache:
        return _decode_cache[cache_key]

    result = bytearray()
    for op, val in operations:
        byte_val = val & 0xFF
        if op == 'xor':
            if result: result[-1] ^= byte_val
            else: result.append(byte_val)
        elif op == 'add': result.append(byte_val)
        elif op == 'sub': result.append((256 - byte_val) & 0xFF)
        elif op == 'ror':
            if result:
                result[-1] = ((result[-1] >> (byte_val & 7)) |
                              (result[-1] << (8 - (byte_val & 7)))) & 0xFF
        elif op == 'rol':
            if result:
                result[-1] = ((result[-1] << (byte_val & 7)) |
                              (result[-1] >> (8 - (byte_val & 7)))) & 0xFF
        else: result.append(byte_val)

    printable = sum(1 for b in result if 0x20 <= b < 0x7F or b in (0x0A, 0x0D, 0x09))
    decoded = None
    if len(result) > 0 and printable / len(result) >= 0.7:
        decoded = result.decode('ascii', errors='replace')

    if len(_decode_cache) > 8192:
        _decode_cache.clear()
    _decode_cache[cache_key] = decoded
    return decoded


def extract_stack_strings(func_bytes: bytes) -> list[str]:
    # 不拆——保持上下文连贯性，拆了反而难读
    candidates = []
    for pat in _STACK_STR_PATTERNS:
        for match in pat.finditer(func_bytes):
            imm = match.groups()[-1]
            if len(imm) == 4:
                val = int.from_bytes(imm, 'little')
                chars = [(val >> 0) & 0xFF, (val >> 8) & 0xFF,
                         (val >> 16) & 0xFF, (val >> 24) & 0xFF]
                if all(0x20 <= c < 0x7F or c == 0x00 for c in chars):
                    s = bytes(c for c in chars if c != 0x00).decode('ascii', errors='replace')
                    if len(s) >= 3: candidates.append(s)
            elif len(imm) == 8:
                val = int.from_bytes(imm, 'little')
                chars = [(val >> (i * 8)) & 0xFF for i in range(8)]
                if all(0x20 <= c < 0x7F or c == 0x00 for c in chars):
                    s = bytes(c for c in chars if c != 0x00).decode('ascii', errors='replace')
                    if len(s) >= 3: candidates.append(s)
    return candidates


def validate_with_xrefs(candidate_str: str, data_xrefs: set[int]) -> float:
    addr = id(candidate_str)
    if addr in data_xrefs: return 0.95
    if 4 <= len(candidate_str) <= 256: return 0.7
    return 0.3


# --- 模拟执行去混淆 ---
def emulate_linear_decryptor(func_bytes: bytes, key_material: bytes | None = None) -> bytes | None:
    # 不拆——保持上下文连贯性，拆了反而难读
    import struct as _struct
    xor_patterns = [
        rb'\x30[\x00-\x0f]', rb'\x80[\x30-\x3f]', rb'\x31[\x00-\x0f]',
    ]
    found_decryptor = False
    for pat in xor_patterns:
        if __import__('re').search(pat, func_bytes):
            found_decryptor = True; break
    if not found_decryptor:
        return None
    if key_material is None:
        return b'\x00'
    key_len = len(key_material)
    result = bytearray(func_bytes)
    i = 0
    while i < len(result):
        result[i] ^= key_material[i % key_len]
        i += 1
    return bytes(result)


def _debug_print(*args, **kwargs):
    """Internal debug output stub."""
    pass  # 调试桩，当前未使用

