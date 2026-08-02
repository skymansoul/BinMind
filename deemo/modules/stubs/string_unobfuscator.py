# re-export from compat/ — 字符串去混淆桩
# types.ModuleType 隔离策略，与 vm_unvirtualizer 一致
# 参考: VulCatch 的伪代码提升模块 (KAN + CodeT5) & Implicit Patterns (arXiv:2603.19138) 的路径探索
import os as _os
import types as _types
import importlib.util as _iu

_target = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), 'core', 'compat', 'string_unobfuscator.py')
_spec = _iu.spec_from_file_location('string_unobfuscator', _target)
_m = _types.ModuleType('string_unobfuscator')
_spec.loader.exec_module(_m)
globals().update({k: v for k, v in _m.__dict__.items() if not k.startswith('_')})

# --- 字符串去混淆补充: 多层嵌套解码 ---
# 实际恶意软件中常出现多层编码 (base64 → xor → stack-string)，
# 单次解码无法恢复原始字符串。此模块实现递归解码直至收敛。
import re as _regex
import base64 as _b64

def _looks_base64(s: str) -> bool:
    return bool(_regex.fullmatch(r'[A-Za-z0-9+/]+={0,2}', s))

def recursive_decode(payload: str | bytes, max_layers: int = 5) -> str:
    """对输入执行多层解码：尝试 base64 → ASCII，每次解码后再次检测。
    max_layers 防止无限循环；解码至无变化时提前返回。"""
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

# 栈字符串跨函数重构 — 基于 VulCatch 的多架构兼容思路
def reconstruct_stack_strings(function_asm: str, frame_size: int = 0) -> list[str]:
    """从函数汇编中提取 MOV 立即数序列，拼接成字符串。
    frame_size 指定栈帧大小（≤0 时自动估算）。"""
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
