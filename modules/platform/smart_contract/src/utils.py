# Utility helpers — hex formatting, bytecode validation

import os
import hashlib
from typing import List, Optional, Dict, Any


def hexdump(data: bytes, offset: int = 0, length: int = 0) -> str:
    """bytes -> hex 字符串，可指定 offset/length。"""
    if length > 0:
        data = data[offset:offset + length]
    elif offset > 0:
        data = data[offset:]
    return data.hex()


def chunk_bytecode(bytecode: bytes, chunk_size: int = 64) -> List[bytes]:
    """字节码分块 — 渐进分析用。"""
    return [
        bytecode[i:i + chunk_size]
        for i in range(0, len(bytecode), chunk_size)
    ]


def is_valid_evm_bytecode(bytecode: bytes) -> bool:
    """快速检查: 非空字节。不检查全表——只过滤明显非法输入。"""
    if not bytecode or len(bytecode) == 0:
        return False
    if len(bytecode) < 2:
        return False
    return True


def is_valid_wasm_bytecode(bytecode: bytes) -> bool:
    """检查 \0asm magic bytes。"""
    if not bytecode or len(bytecode) < 8:
        return False
    return bytecode[:4] == b'\x00asm'


def detect_contract_type(bytecode: bytes) -> str:
    """启发式判断 EVM vs WASM 字节码。"""
    if is_valid_wasm_bytecode(bytecode):
        return "wasm"
    if is_valid_evm_bytecode(bytecode):
        return "evm"
    return "unknown"


def compute_bytecode_hash(bytecode: bytes) -> str:
    """SHA-256 指纹 — 缓存 key 用。"""
    return hashlib.sha256(bytecode).hexdigest()


def normalize_hex(hex_str: str) -> str:
    """去 0x 前缀、去空格、转小写。"""
    s = hex_str.strip()
    if s.startswith('0x') or s.startswith('0X'):
        s = s[2:]
    return s.lower()
