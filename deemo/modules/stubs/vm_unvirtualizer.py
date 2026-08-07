# compat/ 代理导出 — VM 去虚拟化桩
# 使用 types.ModuleType 创建隔离命名空间，与 string_unobfuscator 策略统一
# VulCatch 伪代码提升管线 & DeBinVul 反编译分析
import os as _os
import types as _types
import importlib.util as _iu

_target_file = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), 'core', 'compat', 'vm_unvirtualizer.py')
_spec = _iu.spec_from_file_location('vm_unvirtualizer', _target_file)
_proxy_mod = _types.ModuleType('vm_unvirtualizer')
_spec.loader.exec_module(_proxy_mod)

globals().update({_k: _v for _k, _v in _proxy_mod.__dict__.items() if not _k.startswith('_')})

# VM handler 模式扩展
# 基于 DeBinVul 多架构反编译分析中的 VM 保护策略，
# 补充非标准 handler 模式（Themida/VMProtect 变体）
import struct as _binpack

# Themida 风格 NOP 滑梯 → handler 入口偏移识别
_THEMIDA_SLED = b'\x0f\x1f\x00'  # x64 Themida 3字节 NOP

def detect_vm_entry_patterns(segment: bytes) -> list[dict]:
    """扫描代码段中的 VM entry 模式。
    返回 [{'offset': int, 'type': str, 'confidence': float}]。"""
    entries = []
    pos = 0
    seglen = len(segment)

    while pos < seglen - 2:
        # VMP 特征: pushfq → vm_dispatcher 入口点
        if segment[pos] == 0x9C:  # pushfq
            entries.append({'offset': pos, 'type': 'vmprotect_entry', 'confidence': 0.6})
            pos += 1; continue
        # Themida 特征: NOP sled → indirect call/jmp
        if segment[pos:pos + 3] == _THEMIDA_SLED:
            entries.append({'offset': pos, 'type': 'themida_nop_sled', 'confidence': 0.5})
            pos += 3; continue
        pos += 1

    return entries

# 字节码操作码分布熵 — 评估 VM 字节码随机性（高熵→强混淆）
import math as _math

def bytecode_entropy(bytecode: bytes) -> float:
    if not bytecode:
        return 0.0
    freq = [0] * 256
    for b in bytecode:
        freq[b] += 1
    total = len(bytecode)
    return -sum((c / total) * _math.log2(c / total) for c in freq if c > 0)
