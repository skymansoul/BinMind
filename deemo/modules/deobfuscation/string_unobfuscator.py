import logging
import os
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
    """XOR decoder."""

    @staticmethod
    def detect_key(data: bytes) -> Optional[int]:
        """Heuristic detection of single-byte XOR key."""
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
    def decode(data: bytes, key: int) -> bytes:
        return bytes(b ^ key for b in data)


class Base64Decoder:
    """Base64 decoder."""

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
    """RC4 decoder."""

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


class MicroInterpreter:
    """Micro-interpreter for static emulation of decode logic."""

    def __init__(self):
        self.registers: Dict[str, int] = {}
        self.memory: Dict[int, int] = {}
        self.stack: List[int] = []

    def reset(self):
        self.registers.clear()
        self.memory.clear()
        self.stack.clear()

    def execute(self, ops: List[Tuple[str, Any]]) -> Optional[bytes]:
        """Execute a sequence of micro-operations."""
        try:
            for op, args in ops:
                if op == "mov_reg_imm":
                    self.registers[args[0]] = args[1]
                elif op == "xor_reg_reg":
                    a, b = args
                    self.registers[a] ^= self.registers.get(b, 0)
                elif op == "store_mem":
                    addr, val = args
                    self.memory[addr] = val & 0xFF
                elif op == "load_mem":
                    addr = args[0]
                    return self.memory.get(addr, 0)
            return None
        except Exception as e:
            logger.warning(f"Micro-interpreter error: {e}")
            return None


class StringUnobfuscator:
    """String deobfuscator."""

    def __init__(self, binary_path: str):
        self.binary_path = os.path.abspath(binary_path)
        self.micro = MicroInterpreter()
        self.decoded: List[DecodedString] = []

    def find_string_constructors(self) -> List[Tuple[int, bytes]]:
        """Find stack string construction instructions."""
        results = []
        try:
            with open(self.binary_path, "rb") as f:
                data = f.read()
            for i in range(0, len(data) - 16, 4):
                chunk = data[i:i + 4]
                if len(chunk) == 4 and all(0x20 <= b < 0x7F for b in chunk):
                    results.append((i, chunk))
        except Exception as e:
            logger.warning(f"String constructor search failed: {e}")
        return results

    def decode_string(self, raw: bytes) -> Optional[DecodedString]:
        """Decode a single string."""
        if not raw:
            return None
        layers = []
        current = raw

        key = XORDecoder.detect_key(current)
        if key is not None:
            try:
                decoded = XORDecoder.decode(current, key)
                s = decoded.decode("ascii", errors="ignore")
                if len(s) > 2:
                    layers.append(ObfuscationLayer(
                        layer_type="xor",
                        parameters={"key": key},
                        confidence=0.8
                    ))
                    return DecodedString(
                        address=0,
                        original=current.decode("ascii", errors="ignore"),
                        decoded=s,
                        layers_applied=layers
                    )
            except Exception:
                logger.debug("suppressed", exc_info=True)

        if Base64Decoder.is_base64(current):
            decoded = Base64Decoder.decode(current)
            if decoded:
                try:
                    s = decoded.decode("ascii", errors="ignore")
                    layers.append(ObfuscationLayer(
                        layer_type="base64",
                        parameters={},
                        confidence=0.7
                    ))
                    return DecodedString(
                        address=0,
                        original=current.decode("ascii", errors="ignore"),
                        decoded=s,
                        layers_applied=layers
                    )
                except Exception:
                    logger.debug("suppressed", exc_info=True)

        return None

    def run(self) -> DecodeResult:
        try:
            constructors = self.find_string_constructors()
            for addr, raw in constructors:
                decoded = self.decode_string(raw)
                if decoded:
                    decoded.address = addr
                    self.decoded.append(decoded)
            return DecodeResult(
                success=True,
                strings=self.decoded,
                total_decoded=len(self.decoded)
            )
        except Exception as e:
            logger.error(f"String unobfuscation failed: {e}")
            return DecodeResult(success=False, strings=[])


def create_string_unobfuscator(binary_path: str) -> StringUnobfuscator:
    return StringUnobfuscator(binary_path)
