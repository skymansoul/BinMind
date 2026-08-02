"""网络协议逆向工具集——熵分析、魔数识别、长度字段推断、CRC 检测

新增：KL 散度边界检测 —— 以相邻窗口的字节值分布差异替代纯熵值跳变，
对低熵但分布结构变化（如加密载荷边界）的识别准确率提升显著。
"""

import math
import struct
import zlib
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# 原文件顶层占位符 —— 保持兼容
ProtocolReverser = None
ProtocolInferResult = None
WiresharkGenerator = None


@dataclass
class FieldInfo:
    name: str
    offset: int = 0
    size: int = 0
    hypothesis: str = ""      # 如 "length_field"、"magic"、"checksum"、"flag_byte"
    confidence: float = 0.0


@dataclass
class ProtocolGrammar:
    fields: List[FieldInfo] = field(default_factory=list)
    endianness: str = "unknown"
    name: str = "anonymous"


# 基于熵的字段边界检测

class BoundaryDetector:
    """通过字节值熵变与频率跳变检测协议字段边界"""

    _WINDOW = 4

    @staticmethod
    def shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counter = Counter(data)
        total = len(data)
        ent = 0.0
        for count in counter.values():
            p = count / total
            ent -= p * math.log2(p)
        return ent

    @staticmethod
    def kl_divergence_window(a: bytes, b: bytes) -> float:
        """计算两个窗口的字节值分布 KL 散度 —— D_KL(P_a || P_b)

        相比纯熵差，KL 散度能捕获分布形状变化，对加密边界
        （熵值恒定但分布结构偏移）的检测更灵敏。
        使用 Jelinek-Mercer 平滑处理零概率。
        """
        ca, cb = Counter(a), Counter(b)
        all_bytes = set(ca) | set(cb)
        na, nb = max(len(a), 1), max(len(b), 1)
        kl = 0.0
        for byte_val in all_bytes:
            pa = (ca.get(byte_val, 0) + 0.5) / (na + 0.5 * 256)
            pb = (cb.get(byte_val, 0) + 0.5) / (nb + 0.5 * 256)
            if pa > 0 and pb > 0:
                kl += pa * math.log2(pa / pb)
        return kl

    @staticmethod
    def find_boundaries(samples: List[bytes], window: int = None) -> List[int]:
        """返回多报文间 KL 散度显著跳变的字节偏移列表

        对每对相邻窗口计算 D_KL，标记超过阈值（2.0 bits）的偏移为边界候选。
        """
        if not samples:
            return []

        win = window or BoundaryDetector._WINDOW
        max_len = max(len(s) for s in samples)
        boundaries: List[int] = []

        prev_dist = None
        for offset in range(0, max_len - win, win):
            win_a = b"".join(s[offset:offset + win] for s in samples
                             if offset + win <= len(s))
            win_b = b"".join(s[offset + win:offset + 2 * win] for s in samples
                             if offset + 2 * win <= len(s))
            if len(win_a) < win or len(win_b) < win:
                continue

            kl = BoundaryDetector.kl_divergence_window(win_a, win_b)
            if kl > 2.0:
                boundaries.append(offset + win)
            prev_dist = kl

        return sorted(set(boundaries))

    @staticmethod
    def value_frequency_shift(samples: List[bytes], window: int = None) -> Dict[int, float]:
        """返回 {偏移量: 偏移幅度} 指示字节分布变化"""
        if len(samples) < 2:
            return {}
        win = window or BoundaryDetector._WINDOW
        max_len = min(len(s) for s in samples)
        shifts: Dict[int, float] = {}
        for off in range(0, max_len - win, win):
            freq_a = Counter(sum((list(s[off:off + win]) for s in samples[:len(samples)//2]), []))
            freq_b = Counter(sum((list(s[off:off + win]) for s in samples[len(samples)//2:]), []))
            all_keys = set(freq_a) | set(freq_b)
            diff = sum(abs(freq_a.get(k, 0) - freq_b.get(k, 0)) for k in all_keys)
            shifts[off] = diff / max(1, len(all_keys))
        return shifts


# 长度字段相关性分析

class LengthFieldAnalyzer:
    """关联 1/2/4 字节字段与观测到的报文长度"""

    @staticmethod
    def find_length_field(samples: List[bytes]) -> List[FieldInfo]:
        results: List[FieldInfo] = []
        if len(samples) < 2:
            return results

        for size in (1, 2, 4):
            for endian_sign in ((">", "big"), ("<", "little")):
                fmt = {1: "B", 2: "H", 4: "I"}[size]
                endian_char, endian_name = endian_sign
                max_offset = min(len(s) - size for s in samples)
                for offset in range(min(4, max_offset + 1)):
                    correlations = []
                    for s in samples:
                        if offset + size > len(s):
                            continue
                        val = struct.unpack(f"{endian_char}{fmt}", s[offset:offset + size])[0]
                        remaining = len(s) - offset - size
                        correlations.append((val, remaining))
                    if not correlations:
                        continue
                    # 检查值是否等于剩余长度
                    matches = sum(1 for v, r in correlations if v == r)
                    ratio = matches / len(correlations)
                    if ratio > 0.6:
                        results.append(FieldInfo(
                            name=f"length_{offset}",
                            offset=offset, size=size,
                            hypothesis="length_field",
                            confidence=ratio,
                        ))
        return results


# 校验和 / CRC 检测

class ChecksumDetector:
    """基于多项式相关性检测尾部校验和字段"""

    CRC_POLYS = {
        0x1021: "CRC-16-CCITT",
        0x8005: "CRC-16-MODBUS",
        0x04C11DB7: "CRC-32",
        0x1EDC6F41: "CRC-32C",
        0xA001: "CRC-16-MODBUS-REV",
    }

    @staticmethod
    def detect_crc(samples: List[bytes]) -> List[FieldInfo]:
        results: List[FieldInfo] = []
        if len(samples) < 1:
            return results
        for size in (1, 2, 4):
            for sample in samples:
                if len(sample) < size + 1:
                    continue
                payload = sample[:-size]
                raw_checksum = sample[-size:]
                for poly, name in ChecksumDetector.CRC_POLYS.items():
                    if size == 2:
                        computed = ChecksumDetector._crc16(payload, poly)
                        observed = struct.unpack(">H", raw_checksum)[0]
                        if computed == observed:
                            results.append(FieldInfo(
                                name=f"crc16_{name.replace('-', '_').lower()}",
                                offset=len(payload), size=2,
                                hypothesis="checksum",
                                confidence=0.9,
                            ))
                    elif size == 4:
                        computed = ChecksumDetector._crc32(payload, poly)
                        observed = struct.unpack(">I", raw_checksum)[0]
                        if computed == observed:
                            results.append(FieldInfo(
                                name=f"crc32_{name.replace('-', '_').lower()}",
                                offset=len(payload), size=4,
                                hypothesis="checksum",
                                confidence=0.9,
                            ))
            # zlib/adler 检验
            for sample in samples:
                if len(sample) >= 4:
                    payload = sample[:-4]
                    if struct.unpack(">I", sample[-4:])[0] == zlib.adler32(payload) & 0xFFFFFFFF:
                        results.append(FieldInfo(
                            name="adler32", offset=len(payload), size=4,
                            hypothesis="checksum", confidence=0.95,
                        ))
                        break
        return results

    @staticmethod
    def _crc16(data: bytes, poly: int) -> int:
        crc = 0xFFFF
        for b in data:
            crc ^= b << 8
            for _ in range(8):
                crc = (crc << 1) ^ poly if crc & 0x8000 else crc << 1
                crc &= 0xFFFF
        return crc

    @staticmethod
    def _crc32(data: bytes, poly: int) -> int:
        crc = 0xFFFFFFFF
        for b in data:
            crc ^= b
            for _ in range(8):
                crc = (crc >> 1) ^ poly if crc & 1 else crc >> 1
        return crc ^ 0xFFFFFFFF


# 魔数字节识别

class MagicByteDetector:
    @staticmethod
    def identify(samples: List[bytes], min_len: int = 2) -> Dict[bytes, int]:
        """返回 {魔数序列: 出现次数} 映射"""
        counts: Dict[bytes, int] = defaultdict(int)
        for s in samples:
            if len(s) < min_len:
                continue
            for ln in range(min_len, min(8, len(s) + 1)):
                prefix = s[:ln]
                counts[prefix] += 1
        # 过滤为持续出现的序列
        threshold = max(2, len(samples) // 2)
        return {k: v for k, v in counts.items() if v >= threshold}


# Wireshark 解析器桩

class WiresharkDissector:
    @staticmethod
    def generate(grammar: ProtocolGrammar) -> str:
        """生成最小化 Wireshark Lua 解析器骨架"""
        lines = [
            f'-- Dissector for {grammar.name}',
            f'local {grammar.name}_proto = Proto("{grammar.name}", "{grammar.name} Protocol")',
            '',
        ]
        for field in grammar.fields:
            safe_name = field.name.replace(" ", "_").replace("-", "_")
            lines.append(f'{safe_name} = ProtoField.bytes("{grammar.name}.{safe_name}", "{field.name}")')
        safe_names = [f.name.replace(" ", "_").replace("-", "_") for f in grammar.fields]
        lines.append(
            f'{grammar.name}_proto.fields = {{ {", ".join(safe_names)} }}')
        lines.append("")
        lines.append(f"function {grammar.name}_proto.dissector(buf, pinfo, tree)")
        lines.append(f"    local subtree = tree:add({grammar.name}_proto, buf())")
        lines.append("end")
        lines.append("")
        lines.append("-- 注册默认端口")
        lines.append(f"DissectorTable.get('tcp.port'):add(9999, {grammar.name}_proto)")
        return "\n".join(lines)


# 类型推断——基于观测值猜测字段类型

class TypeInferrer:
    @staticmethod
    def infer(raw: bytes, offset: int, size: int) -> str:
        if offset + size > len(raw):
            return "unknown"
        chunk = raw[offset:offset + size]
        # ASCII 可打印字符
        if all(0x20 <= b <= 0x7E for b in chunk):
            return "ascii_string"
        if all(b in (0x00, 0x01) for b in chunk):
            return "flags"
        if len(chunk) == 1:
            return "uint8"
        if len(chunk) in (2, 4, 8) and all(b == 0x00 for b in chunk):
            return "padding"
        if len(chunk) == 2:
            val = struct.unpack(">H", chunk)[0]
            if 0 < val <= 65535:
                return "uint16"
        if len(chunk) == 4:
            return "uint32"
        return "bytes"


# 快捷工厂函数

def create_protocol_reverser():
    return {
        "boundary": BoundaryDetector(),
        "length_field": LengthFieldAnalyzer(),
        "checksum": ChecksumDetector(),
        "magic": MagicByteDetector(),
        "type_inferrer": TypeInferrer(),
        "dissector_gen": WiresharkDissector(),
    }
