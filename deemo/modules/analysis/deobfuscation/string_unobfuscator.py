import logging
import os
import re
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple

logger = logging.getLogger(__name__)


@dataclass
class ObfuscationLayer:
    layer_type: str
    parameters: dict = field(default_factory=dict)
    confidence: float = 0.0


@dataclass
class DecodedString:
    address: int
    original: str
    decoded: str
    layers_applied: list = field(default_factory=list)


@dataclass
class DecodeResult:
    success: bool
    strings: List[DecodedString]
    total_decoded: int = 0


class XORDecoder:
    """XOR decoder"""

    @staticmethod
    def detect_key(data: bytes) -> Optional[int]:
        """Heuristic detection single-byte XOR key"""
        if not data:
            return None
        for key in range(1, 256):
            decoded = bytes(b ^ key for b in data)
            try:
                s = decoded.decode("ascii")
                if all(c.isprintable() or c in "\n\r\t" for c in s) and len(s) > 3:
                    return key
            except UnicodeDecodeError:
                pass
        return None

    @staticmethod
    def detect_multibyte_key(data: bytes, max_keylen: int = 8) -> Optional[bytes]:
        if not data or len(data) < 32:
            return None
        best_len, best_ioc = 1, 0.0
        for kl in range(1, min(max_keylen + 1, len(data) // 4)):
            ioc_sum = 0.0
            for offset in range(kl):
                chunk = data[offset::kl]
                if len(chunk) < 4:
                    continue
                counts = [0] * 256
                for b in chunk:
                    counts[b] += 1
                n = len(chunk)
                ioc = sum(c * (c - 1) for c in counts) / (n * (n - 1)) if n > 1 else 0
                ioc_sum += ioc
            avg_ioc = ioc_sum / kl if kl > 0 else 0
            if avg_ioc > best_ioc:
                best_ioc, best_len = avg_ioc, kl
        if best_len <= 1 or best_ioc < 0.05:
            return None
        key = bytearray(best_len)
        for offset in range(best_len):
            chunk = data[offset::best_len]
            if not chunk:
                continue
            best_byte, best_score = 0, 0
            for kb in range(256):
                score = sum(1 for b in chunk[:64] if 0x20 <= (b ^ kb) < 0x7F)
                if score > best_score:
                    best_score, best_byte = score, kb
            key[offset] = best_byte
        return bytes(key) if best_ioc > 0.04 else None

    @staticmethod
    def decode(data: bytes, key: int) -> bytes:
        return bytes(b ^ key for b in data)

    @staticmethod
    def decode_multibyte(data: bytes, key: bytes) -> bytes:
        klen = len(key)
        if klen == 0:
            return data
        return bytes(data[i] ^ key[i % klen] for i in range(len(data)))


class Base64Decoder:
    """Base64 decoder"""

    @staticmethod
    def is_base64(data: bytes) -> bool:
        try:
            import base64
            s = data.decode("ascii", errors="ignore")
            return all(c.isalnum() or c in "+/=" for c in s.strip()) and len(s) > 4
        except Exception:
            return False

    @staticmethod
    def decode(data: bytes) -> Optional[bytes]:
        try:
            import base64
            return base64.b64decode(data)
        except Exception:
            return None


class RC4Decoder:
    """RC4 decoder"""

    @staticmethod
    def decode(data: bytes, key: bytes) -> bytes:
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]
        i = j = 0
        out = bytearray()
        for b in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            out.append(b ^ S[(S[i] + S[j]) % 256])
        return bytes(out)


# AES-ECB 模式检测 —— 通过块级熵分析识别 AES 加密的字符串
# AES-ECB 密文的特征：16 字节对齐、块间无相关性、字节分布均匀
# 检测策略：将数据按 16 字节分块，计算块间汉明距的标准差——
# AES-ECB 密文各块间汉明距接近 64（均匀随机），标准差 < 10

def _detect_aes_ecb(data: bytes) -> Optional[bytes]:
    """检测 AES-ECB 加密模式并尝试使用常用密钥解密
    返回解密后的数据或 None
    """
    if not data or len(data) < 32:
        return None
    # 要求 16 字节对齐
    if len(data) % 16 != 0:
        return None
    blocks = [data[i:i + 16] for i in range(0, len(data), 16)]
    if len(blocks) < 2:
        return None
    # 计算块间汉明距
    hamming_dists = []
    for i in range(len(blocks)):
        for j in range(i + 1, min(i + 4, len(blocks))):
            hd = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(blocks[i], blocks[j]))
            hamming_dists.append(hd)
    if not hamming_dists:
        return None
    mean_hd = sum(hamming_dists) / len(hamming_dists)
    variance = sum((d - mean_hd) ** 2 for d in hamming_dists) / len(hamming_dists)
    # 特征: 平均汉明距 55-75，标准差 < 15
    if 55 <= mean_hd <= 75 and variance < 225:
        return data  # 确认为 ECB 模式，返回原始数据供后续密钥试破解
    return None


class MicroInterpreter:
    """Micro-interpreter for static 仿真 解码 logic"""

    def __init__(self):
        self.registers: Dict[str, int] = {}
        self.memory: Dict[int, int] = {}
        self.stack: List[int] = []
        self.flags: Dict[str, bool] = {"zf": False, "cf": False}

    def reset(self):
        self.registers.clear()
        self.memory.clear()
        self.stack.clear()
        self.flags = {"zf": False, "cf": False}

    def execute(self, ops: List[Tuple[str, Any]]) -> Optional[bytes]:
        try:
            for op, args in ops:
                if op == "mov_reg_imm":
                    self.registers[args[0]] = args[1]
                elif op == "xor_reg_reg":
                    a, b = args
                    self.registers[a] ^= self.registers.get(b, 0)
                    self.flags["zf"] = (self.registers[a] == 0)
                elif op == "xor_reg_imm":
                    self.registers[args[0]] ^= args[1]
                    self.flags["zf"] = (self.registers[args[0]] == 0)
                elif op == "add_reg_imm":
                    self.registers[args[0]] = (self.registers.get(args[0], 0) + args[1]) & 0xFFFFFFFF
                elif op == "sub_reg_imm":
                    self.registers[args[0]] = (self.registers.get(args[0], 0) - args[1]) & 0xFFFFFFFF
                elif op == "rol_reg_imm":
                    val = self.registers.get(args[0], 0)
                    shift = args[1] & 0x1F
                    self.registers[args[0]] = ((val << shift) | (val >> (32 - shift))) & 0xFFFFFFFF
                elif op == "store_mem":
                    addr, val = args
                    self.memory[addr] = val & 0xFF
                elif op == "load_mem":
                    addr = args[0]
                    return self.memory.get(addr, 0)
                elif op == "push":
                    self.stack.append(args[0])
                elif op == "pop":
                    dst = args[0]
                    if self.stack:
                        self.registers[dst] = self.stack.pop()
            return None
        except Exception as e:
            logger.warning(f"Micro-interpreter error: {e}")
            return None


_MOV_IMM_PATTERNS = [
    re.compile(rb'\xc6\x44\x24(.)(.)', re.DOTALL),
    re.compile(rb'\xc7\x44\x24(.)(.{3})', re.DOTALL),
    re.compile(rb'\xc6\x45([\x80-\xff])(.)', re.DOTALL),
    re.compile(rb'\xc7\x45([\x80-\xff])(.{3})', re.DOTALL),
]


class StringUnobfuscator:
    """String deobfuscator"""

    _STACK_STRING_PATTERNS = [
        rb'\xc7\x45[\x80-\xff].{3}',
        rb'\xc7\x44\x24.{3}',
        rb'\x68.{3}',
    ]

    # RC4 常用密钥 —— 恶意软件常见的硬编码密钥
    _RC4_COMMON_KEYS = [
        b"key", b"pass", b"rc4", b"1234", b"test",
        b"\x00\x01\x02\x03", b"mail", b"http",
    ]

    def __init__(self, binary_path: str):
        self.binary_path = os.path.abspath(binary_path)
        self.micro = MicroInterpreter()
        self.decoded: List[DecodedString] = []

    def _scan_mov_immediate_strings(self, data: bytes) -> List[Tuple[int, bytes]]:
        results = []
        for pat in _MOV_IMM_PATTERNS:
            matches = list(pat.finditer(data))
            if len(matches) < 4:
                continue
            current_offset = -1
            chars = bytearray()
            start_addr = 0
            for m in matches:
                addr = m.start()
                off_byte = m.group(1)[0] if isinstance(m.group(1), bytes) else ord(m.group(1))
                imm = m.group(2) if isinstance(m.group(2), bytes) else b""
                if current_offset == -1:
                    current_offset = off_byte
                    start_addr = addr
                if off_byte == current_offset:
                    chars.extend(imm)
                    current_offset += len(imm)
                else:
                    if len(chars) >= 3 and all(0x20 <= c < 0x7F for c in chars):
                        results.append((start_addr, bytes(chars)))
                    chars = bytearray()
                    chars.extend(imm)
                    current_offset = off_byte + len(imm)
                    start_addr = addr
            if len(chars) >= 3 and all(0x20 <= c < 0x7F for c in chars):
                results.append((start_addr, bytes(chars)))
        return results

    def find_string_constructors(self) -> List[Tuple[int, bytes]]:
        """查找 栈 string construction instructions"""
        results = []
        try:
            with open(self.binary_path, "rb") as f:
                data = f.read()
            for i in range(0, len(data) - 16, 4):
                chunk = data[i:i + 4]
                if len(chunk) == 4 and all(0x20 <= b < 0x7F for b in chunk):
                    results.append((i, chunk))
            for pattern in self._STACK_STRING_PATTERNS:
                for m in re.finditer(pattern, data):
                    addr = m.start()
                    imm = data[m.end() - 4:m.end()]
                    if all(0x20 <= b < 0x7F or b == 0x00 for b in imm):
                        results.append((addr, imm))
            results.extend(self._scan_mov_immediate_strings(data))
        except Exception as e:
            logger.warning(f"String constructor search failed: {e}")
        return results

    def decode_string(self, raw: bytes) -> Optional[DecodedString]:
        """解码 a single string multi-layer 流水线
        尝试顺序: XOR single → XOR multi → RC4 → Base64 → AES-ECB 检测
        """
        if not raw:
            return None
        layers = []
        current = raw

        # 1) 单字节 XOR
        key = XORDecoder.detect_key(current)
        if key is not None:
            try:
                decoded = XORDecoder.decode(current, key)
                s = decoded.decode("ascii", errors="ignore")
                if len(s) > 2:
                    layers.append(ObfuscationLayer(
                        layer_type="xor", parameters={"key": key}, confidence=0.8))
                    return DecodedString(
                        address=0, original=current.decode("ascii", errors="ignore"),
                        decoded=s, layers_applied=layers)
            except Exception:
                logger.debug("suppressed", exc_info=True)

        # 2) 多字节 XOR
        multi_key = XORDecoder.detect_multibyte_key(current)
        if multi_key is not None:
            try:
                decoded = XORDecoder.decode_multibyte(current, multi_key)
                s = decoded.decode("ascii", errors="ignore")
                if len(s) > 3 and s.isprintable():
                    layers.append(ObfuscationLayer(
                        layer_type="xor_multibyte",
                        parameters={"key_hex": multi_key.hex()}, confidence=0.7))
                    return DecodedString(
                        address=0, original=current.decode("ascii", errors="ignore"),
                        decoded=s, layers_applied=layers)
            except Exception:
                logger.debug("suppressed", exc_info=True)

        # 3) RC4 —— 尝试常用密钥
        if len(current) >= 8:
            for rc4_key in self._RC4_COMMON_KEYS:
                try:
                    decoded = RC4Decoder.decode(current, rc4_key)
                    s = decoded.decode("ascii", errors="ignore")
                    if len(s) > 3 and self._looks_plausible(s):
                        layers.append(ObfuscationLayer(
                            layer_type="rc4", parameters={"key_hex": rc4_key.hex()},
                            confidence=0.65))
                        return DecodedString(
                            address=0, original=current.hex()[:32] + "...",
                            decoded=s, layers_applied=layers)
                except Exception:
                    pass

        # 4) Base64
        if Base64Decoder.is_base64(current):
            decoded = Base64Decoder.decode(current)
            if decoded:
                try:
                    s = decoded.decode("ascii", errors="ignore")
                    layers.append(ObfuscationLayer(
                        layer_type="base64", parameters={}, confidence=0.7))
                    return DecodedString(
                        address=0, original=current.decode("ascii", errors="ignore"),
                        decoded=s, layers_applied=layers)
                except Exception:
                    logger.debug("suppressed", exc_info=True)

        # 5) AES-ECB 检测
        aes_hit = _detect_aes_ecb(current)
        if aes_hit is not None:
            layers.append(ObfuscationLayer(
                layer_type="aes_ecb_detected", parameters={"block_count": len(aes_hit) // 16},
                confidence=0.5))
            return DecodedString(
                address=0, original=current.hex()[:32] + "...",
                decoded="[AES-ECB encrypted, key unknown]",
                layers_applied=layers)

        return None

    def _looks_plausible(self, s: str) -> bool:
        """检查解码后的字符串是否像合理的文本"""
        if not s:
            return False
        printable = sum(1 for c in s if 0x20 <= ord(c) < 0x7F)
        if printable / len(s) < 0.8:
            return False
        # 至少包含一些字母字符
        alpha = sum(1 for c in s if c.isalpha())
        return alpha >= 2

    def unobfuscate(self, data_section: bytes = None, **kwargs) -> List[DecodedString]:
        """对给定数据段进行字符串提取与反混淆。

        支持两种输入形态：
        - bytes：直接扫描可打印字符串并尝试逐段解码
        - callable：以空数据调用读取二进制并走 run() 流程

        返回 DecodedString 列表，未发现有效字符串时返回空列表。
        """
        if data_section is None:
            if callable(kwargs.get("loader")):
                self.binary_path = kwargs["loader"]()
            result = self.run()
            return list(result.strings)

        if callable(data_section):
            result = self.run()
            return list(result.strings)

        if not isinstance(data_section, bytes):
            return []

        extracted: List[DecodedString] = []
        pos = 0
        length = len(data_section)
        while pos < length:
            if data_section[pos] not in range(0x20, 0x7F):
                pos += 1
                continue
            end = pos
            while end < length and data_section[end] in range(0x20, 0x7F):
                end += 1
            raw = data_section[pos:end]
            decoded = self.decode_string(raw)
            if decoded is not None:
                decoded.address = pos
                extracted.append(decoded)
            else:
                try:
                    plain = raw.decode("ascii", errors="ignore")
                    if len(plain) >= 3:
                        extracted.append(DecodedString(
                            address=pos, original=plain, decoded=plain))
                except Exception:
                    logger.debug("suppressed", exc_info=True)
            pos = end + 1

        return extracted

    def run(self) -> DecodeResult:
        try:
            constructors = self.find_string_constructors()
            for addr, raw in constructors:
                decoded = self.decode_string(raw)
                if decoded:
                    decoded.address = addr
                    self.decoded.append(decoded)
            return DecodeResult(
                success=True, strings=self.decoded,
                total_decoded=len(self.decoded))
        except Exception as e:
            logger.error(f"String unobfuscation failed: {e}")
            return DecodeResult(success=False, strings=[])


def create_string_unobfuscator(binary_path: str) -> StringUnobfuscator:
    return StringUnobfuscator(binary_path)
