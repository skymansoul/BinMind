# compat/ 重导出 — 字符串去混淆入口
# types.ModuleType 隔离加载，架构与 vm_unvirtualizer 一致
# VulCatch 伪代码提升模块 (KAN + CodeT5) & Implicit Patterns () 路径探索策略
import os as _os
import types as _types
import importlib.util as _iu

_target = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), 'core', 'compat', 'string_unobfuscator.py')
_spec = _iu.spec_from_file_location('string_unobfuscator', _target)
_m = _types.ModuleType('string_unobfuscator')
_spec.loader.exec_module(_m)
globals().update({k: v for k, v in _m.__dict__.items() if not k.startswith('_')})

# 递归多层解码补充
# 实际恶意样本中常见多层编码嵌套 (base64 → xor → stack-string)，
# 单轮解码无法抵达原始明文。递归解码直至收敛或触及上限。
import re as _regex
import base64 as _b64
import uuid

def _looks_base64(s: str) -> bool:
    return bool(_regex.fullmatch(r'[A-Za-z0-9+/]+={0,2}', s))

def recursive_decode(payload: str | bytes, max_layers: int = 5) -> str:
    """递归多层解码：每轮尝试 base64 解码，直至输出不再变化或触达层数上限。"""
    if isinstance(payload, bytes):
        payload = payload.decode('ascii', errors='replace')

    seen = {payload}
    current = payload

    for _layer in range(max_layers):
        if not _looks_base64(current):
            break
        try:
            decoded = _b64.b64decode(current).decode('ascii', errors='replace')
        except Exception:
            break
        if decoded in seen:
            break
        seen.add(decoded)
        current = decoded

    return current

# 栈字符串跨函数拼接 — 基于 VulCatch 多架构兼容思路
def reconstruct_stack_strings(function_asm: str, frame_size: int = 0) -> list[str]:
    # 从函数汇编指令流中提取 MOV 立即数序列，按可打印范围拼接。
    # frame_size: 栈帧大小；≤0 时自动估算。
    mov_pattern = _regex.compile(
        r'mov\s+(?:byte|word|dword|qword)?\s*ptr\s*\[.*?\],\s*(0x[0-9a-fA-F]+|\d+)',
        _regex.IGNORECASE
    )
    vals = []
    for m in mov_pattern.finditer(function_asm):
        token = m.group(1)
        if token.lower().startswith('0x'):
            vals.append(int(token, 16))
        else:
            vals.append(int(token))

    strings = []
    buf = []
    for v in vals:
        byte_val = v & 0xFF
        if 0x20 <= byte_val < 0x7F or byte_val in (0x0A, 0x0D, 0x09, 0x00):
            if byte_val == 0x00 and buf:
                strings.append(bytes(buf).decode('ascii', errors='replace'))
                buf = []
            elif byte_val != 0x00:
                buf.append(byte_val)
        else:
            if buf:
                strings.append(bytes(buf).decode('ascii', errors='replace'))
                buf = []
    if buf:
        strings.append(bytes(buf).decode('ascii', errors='replace'))
    return strings
