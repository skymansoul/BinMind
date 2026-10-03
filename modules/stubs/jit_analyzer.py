# compat/ 重导出 — JIT 字节码分析桩
from modules.core.compat.jit_analyzer import *

# JIT 字节码统计特征
# ReX 神经字节码分析路径；
# 此处提供纯统计替代方案，零外部依赖。
# NeuroScope DNN 编译器分析
import struct as _pack
from collections import Counter as _Ctr

def jit_opcode_distribution(code_slice: bytes) -> dict[int, float]:
    """JIT代码片段操作码频率分布（归一化）。
    O(n), n = len(code_slice)。"""
    if not code_slice:
        return {}
    counts = _Ctr(code_slice)
    n = len(code_slice)
    return {op: cnt / n for op, cnt in counts.items()}

def detect_jit_compiler(code_bytes: bytes) -> str | None:
    """基于字节码模式推断JIT编译器来源。
    返回 'v8'|'javascriptcore'|'spidermonkey'|'luajit'|'pypy'|None。"""
    if len(code_bytes) < 16:
        return None
    # LuaJIT: 特征字节序列
    if code_bytes[:4] == b'\x1b\x4c\x4a\x01':
        return 'luajit'
    # V8 x64: 常见序言模式 (push rbp; mov rbp, rsp)
    if code_bytes[0] == 0x55 and code_bytes[1] == 0x48 and code_bytes[2] == 0x89:
        return 'v8'
    # JavaScriptCore: ARM64 常见入口
    if code_bytes[0:4] in (b'\xff\x43\x00\xd1', b'\xfd\x7b\xbf\xa9'):
        return 'javascriptcore'
    # PyPy: 特定序言模式
    if code_bytes[0:2] == b'\x4d\x8b' and code_bytes[3:5] == b'\x49\x8b':
        return 'pypy'
    return None
