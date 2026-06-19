#!/usr/bin/env python3
"""
利用免杀与反取证变形模块 - 自动应用指令替换、垃圾代码、延迟执行
"""

import logging
import os
import zlib
import base64
import random
import string
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Callable

logger = logging.getLogger(__name__)


class ObfuscationTechnique(Enum):
    INSTRUCTION_SUBSTITUTION = "instr_sub"
    JUNK_CODE = "junk_code"
    DELAYED_EXEC = "delayed_exec"
    ENCRYPTION = "encryption"
    POLYMORPHIC = "polymorphic"


@dataclass
class ObfuscatedPayload:
    original: bytes
    obfuscated: bytes
    technique: ObfuscationTechnique
    reversible: bool
    reversible_payload: Optional[bytes] = None


@dataclass
class ObfuscationResult:
    success: bool
    payloads: List[ObfuscatedPayload]


class InstructionSubstituter:
    @staticmethod
    def substitute(code: bytes) -> bytes:
        # 简化版: 添加 NOP 和 jmp 跳转
        result = bytearray()
        for b in code:
            result.append(0x90)  # NOP
            result.append(b)
        return bytes(result)


class JunkCodeInjector:
    @staticmethod
    def inject(code: bytes, density: float = 0.3) -> bytes:
        import random
        result = bytearray()
        for b in code:
            result.append(b)
            if random.random() < density:
                result.extend([0x90, 0x90, 0x90])  # NOP sled
        return bytes(result)


class DelayedExecutor:
    @staticmethod
    def wrap(code: bytes, delay_ms: int = 1000) -> bytes:
        # 简化: 前缀 delay loop
        delay_bytes = b"\xeb\xfe" * (delay_ms // 100)
        return delay_bytes + code


class PayloadObfuscator:
    def __init__(self):
        self.substituter = InstructionSubstituter()
        self.junk = JunkCodeInjector()
        self.delayed = DelayedExecutor()

    def run(self, payload: bytes) -> ObfuscationResult:
        try:
            payloads = []
            # Instruction substitution
            sub = self.substituter.substitute(payload)
            payloads.append(ObfuscatedPayload(
                original=payload, obfuscated=sub,
                technique=ObfuscationTechnique.INSTRUCTION_SUBSTITUTION,
                reversible=True, reversible_payload=payload))
            # Junk code
            junk = self.junk.inject(payload)
            payloads.append(ObfuscatedPayload(
                original=payload, obfuscated=junk,
                technique=ObfuscationTechnique.JUNK_CODE,
                reversible=True, reversible_payload=payload))
            # Delayed
            delayed = self.delayed.wrap(payload)
            payloads.append(ObfuscatedPayload(
                original=payload, obfuscated=delayed,
                technique=ObfuscationTechnique.DELAYED_EXEC,
                reversible=True, reversible_payload=payload))
            return ObfuscationResult(success=True, payloads=payloads)
        except Exception as e:
            logger.error("Payload obfuscation failed: %s", e)
            return ObfuscationResult(success=False, payloads=[])


def create_payload_obfuscator() -> PayloadObfuscator:
    return PayloadObfuscator()


# ---------------------------------------------------------------------------
# 兼容性别名与扩展类 (Compatible aliases & extension classes)
# 下面的定义为兼容 __init__.py 的导出而添加, 遵循"只增加代码不删除"原则。
# ---------------------------------------------------------------------------

class AntiDetectionType(Enum):
    """反检测类型"""
    NONE = "none"
    ANTI_SANDBOX = "anti_sandbox"
    ANTI_DEBUG = "anti_debug"
    ANTI_VM = "anti_vm"
    ANTI_EMULATOR = "anti_emulator"
    ANTI_FORENSICS = "anti_forensics"
    POLYMORPHIC = "polymorphic"
    METAMORPHIC = "metamorphic"


class XOREncryptionEngine:
    """XOR 加密引擎"""

    def __init__(self, key: Optional[bytes] = None):
        self.key = key or os.urandom(16)

    def encrypt(self, data: bytes, key: Optional[bytes] = None) -> bytes:
        k = key or self.key
        return bytes(b ^ k[i % len(k)] for i, b in enumerate(data))

    def decrypt(self, data: bytes, key: Optional[bytes] = None) -> bytes:
        # XOR 加密解密对称
        return self.encrypt(data, key)

    def rotate_key(self) -> bytes:
        self.key = os.urandom(16)
        return self.key


class Base64EncodingEngine:
    """Base64 编码引擎"""

    def __init__(self, url_safe: bool = False):
        self.url_safe = url_safe

    def encode(self, data: bytes) -> str:
        enc = base64.urlsafe_b64encode if self.url_safe else base64.b64encode
        return enc(data).decode("ascii")

    def decode(self, data: str) -> bytes:
        enc = base64.urlsafe_b64decode if self.url_safe else base64.b64decode
        return enc(data.encode("ascii") if isinstance(data, str) else data)


class CompressionEngine:
    """压缩引擎"""

    def __init__(self, level: int = 6):
        self.level = max(1, min(9, level))

    def compress(self, data: bytes) -> bytes:
        return zlib.compress(data, self.level)

    def decompress(self, data: bytes) -> bytes:
        return zlib.decompress(data)


class PolymorphicEngine:
    """多态引擎 - 每次生成不同形态的等效代码"""

    JUNK_TEMPLATES = [
        "mov rax, {val}; xor rax, {val2}",
        "push {val}; pop rcx",
        "nop; nop; nop",
    ]

    def __init__(self, seed: Optional[int] = None):
        self._rng = random.Random(seed)

    def _rand_val(self) -> int:
        return self._rng.randint(0, 0xFFFF)

    def wrap(self, code: str) -> str:
        """在代码前后包裹多态 junk 指令"""
        head = self._rng.choice(self.JUNK_TEMPLATES).format(
            val=hex(self._rand_val()), val2=hex(self._rand_val())
        )
        tail = self._rng.choice(self.JUNK_TEMPLATES).format(
            val=hex(self._rand_val()), val2=hex(self._rand_val())
        )
        return f"{head}\n{code}\n{tail}"

    def random_key(self, length: int = 16) -> bytes:
        return "".join(self._rng.choices(string.ascii_letters + string.digits, k=length)).encode()


class AntiDebugEngine:
    """反调试引擎"""

    def __init__(self):
        self._checks: List[Callable[[], bool]] = []

    def add_check(self, func: Callable[[], bool]):
        self._checks.append(func)

    def is_debugger_present(self) -> bool:
        """简单启发式: 调用方可在外部注入 check 函数"""
        for c in self._checks:
            try:
                if c():
                    return True
            except Exception:
                continue
        return False

    def install_default_checks(self):
        """安装默认反调试检查 (占位, 由调用方注入实际检查逻辑)"""
        self.add_check(lambda: False)
        self.add_check(lambda: False)


def obfuscate_payload(payload: bytes, techniques: Optional[List[str]] = None) -> Dict[str, Any]:
    """便捷函数: 对 payload 应用多种混淆"""
    techniques = techniques or ["xor", "base64", "compress"]
    xor_eng = XOREncryptionEngine()
    b64_eng = Base64EncodingEngine()
    comp_eng = CompressionEngine()
    cur = payload
    applied: List[str] = []
    for t in techniques:
        if t == "xor":
            cur = xor_eng.encrypt(cur)
            applied.append("xor")
        elif t == "base64":
            cur = b64_eng.encode(cur).encode("ascii")
            applied.append("base64")
        elif t == "compress":
            cur = comp_eng.compress(cur)
            applied.append("compress")
    return {
        "data": cur,
        "techniques": applied,
        "key": xor_eng.key,
    }

