import logging
import os
import re
import struct
from dataclasses import dataclass, field
from typing import Any, Optional, List, Tuple

logger = logging.getLogger(__name__)
name: str = "unpacker"
module: str = "unpacker"

_UPX_SIGNATURES = [
    b"UPX!", b"UPX0", b"UPX1", b"UPX2",
    re.compile(rb"UPX [0-9]\.[0-9]{2}", re.DOTALL),
]
_ASPACK_SIGNATURES = [b".aspack", b".adata", b"ASPack"]
_MPRESS_SIGNATURES = [b"MPRESS1", b"MPRESS2", b".MPRESS1", b".MPRESS2"]
_FSG_SIGNATURES = [b".fsg", b"FSG!"]
_PECOMPACT_SIGS = [b"PEC2", b"PEC2O", b"PECompact2"]
_PETITE_SIGS = [b"PEPACK!!", b"PEBundle"]
_TELOCK_SIGS = [b".tls", b"TeLock"]
_ENIGMA_SIGS = [b".enigma1", b".enigma2"]

_ASPROTECT_SIGS = [b"ASProtect", b".aspack", b"ASPROTECT"]
_ARMADILLO_SIGS = [b"Armadillo", b".arm", b"SIRIUS"]
_ACPROTECT_SIGS = [b"ACProtect", b"acp\0"]
_DOTFUSCATOR_SIGS = [b"Dotfuscator", b"DotfuscatorAttribute"]
_CONFUSEREX_SIGS = [b"ConfuserEx", b"Confuser", b"ConfusedBy"]
_YP_SIGS = [b"yoda's Protector", b"yP", b"yoda"]
_NSPACK_SIGS = [b"nspack", b"NsPack", b".nsp0"]
_OBSIDIUM_SIGS = [b"Obsidium", b".obsidium", b"obs"]

_PACKER_DB: dict[str, list[bytes | re.Pattern]] = {
    "UPX": _UPX_SIGNATURES, "ASPack": _ASPACK_SIGNATURES,
    "MPRESS": _MPRESS_SIGNATURES, "FSG": _FSG_SIGNATURES,
    "PECompact": _PECOMPACT_SIGS, "Petite": _PETITE_SIGS,
    "TeLock": _TELOCK_SIGS, "Enigma": _ENIGMA_SIGS,
    "ASProtect": _ASPROTECT_SIGS, "Armadillo": _ARMADILLO_SIGS,
    "ACProtect": _ACPROTECT_SIGS, "Dotfuscator": _DOTFUSCATOR_SIGS,
    "ConfuserEx": _CONFUSEREX_SIGS, "yoda": _YP_SIGS,
    "NsPack": _NSPACK_SIGS, "Obsidium": _OBSIDIUM_SIGS,
}

# UPX 魔数字节
_UPX_MAGIC_LZMA = b"UPX;"
_UPX_MAGIC_NRV2B = b"UPX\x00"
_UPX_MAGIC_NRV2D = b"UPX\x01"
_UPX_MAGIC_NRV2E = b"UPX\x02"
_UPX_MAGIC_LZMA_OLD = bytes([0x55, 0x50, 0x58, 0x21])

_SECTION_ENTROPY_THRESHOLD = 7.5
_IMPORT_COUNT_THRESHOLD = 3
_SECTION_NAME_INDICATORS = {"UPX0", "UPX1", "UPX2", ".aspack", ".adata", ".pec",
                             ".MPRESS1", ".MPRESS2", ".petite", ".fsg", ".enigma1", ".enigma2",
                             ".nsp0", ".nsp1", ".obsidium", ".arm", ".asp", ".yP"}

_PE_MAGIC = b"PE\x00\x00"


# 微型 NRV2B 解压器 —— 纯 Python 实现，参考 UCL/NRV 规范
# NRV (Not Really Vanished) 是 UPX 使用的 LZSS 变种算法家族。
# NRV2B 格式: 逐 bit 解码，0=literal byte, 1=(offset, length) 对
# 允许在没有外部 upx 二进制时直接从 stub 进行静态解压

def _nrv2b_decompress(src: bytes, dst_size: int) -> Optional[bytes]:
    """NRV2B 解压——UPX 最常用的压缩算法变种
    输入: 压缩数据（不含 UPX 魔数头）
    输出: 解压后的字节，失败返回 None
    """
    if not src or dst_size <= 0:
        return None
    dst = bytearray(dst_size)
    src_pos = 0
    dst_pos = 0
    # NRV2B 使用特殊的初始偏移量
    off = 0

    src_byte = 0
    src_mask = 0

    def _get_bit() -> int:
        nonlocal src_byte, src_mask, src_pos
        if src_mask == 0:
            if src_pos >= len(src):
                return -1
            src_byte = src[src_pos]
            src_pos += 1
            src_mask = 128
        bit = 1 if (src_byte & src_mask) != 0 else 0
        src_mask >>= 1
        return bit

    last_m_off = 1
    try:
        while dst_pos < dst_size:
            bit = _get_bit()
            if bit < 0:
                break
            if bit == 0:
                # literal byte
                if src_pos >= len(src):
                    break
                dst[dst_pos] = src[src_pos]
                src_pos += 1
                dst_pos += 1
            else:
                # match: (offset, length)
                m_off = 0
                bit = _get_bit()
                if bit < 0:
                    break
                if bit == 0:
                    m_off = 1
                while bit == 1:
                    m_off = m_off * 2 + _get_bit()
                    bit = _get_bit()
                    if bit < 0:
                        break
                if bit < 0:
                    break
                if m_off > 1:
                    m_off = m_off - 2 + last_m_off
                else:
                    # 读取额外 offset 字节
                    if src_pos >= len(src):
                        break
                    m_off = src[src_pos]
                    src_pos += 1
                last_m_off = m_off

                # 读取 match length
                m_len = _get_bit()
                if m_len < 0:
                    break
                m_len += 2
                if m_len == 2:
                    m_len = _get_bit() + 4
                    if m_len < 0:
                        break
                elif m_len == 3:
                    m_len = _get_bit() * 2 + _get_bit() + 5
                    if m_len < 0:
                        break

                if dst_pos - m_off < 0 or dst_pos + m_len > dst_size:
                    break
                for _ in range(m_len):
                    dst[dst_pos] = dst[dst_pos - m_off]
                    dst_pos += 1

        if dst_pos >= dst_size:
            return bytes(dst)
    except (IndexError, ValueError):
        pass
    return None


def _try_builtin_upx_unpack(raw: bytes, out_path: str) -> Optional[str]:
    """尝试从 UPX stub 中直接提取解压数据——无需外部 upx 二进制
    支持 NRV2B/NRV2D/NRV2E/LZMA 四种 UPX 压缩算法
    """
    # 定位 UPX 尾部标记
    magic_positions = []
    for magic in (_UPX_MAGIC_NRV2B, _UPX_MAGIC_NRV2D, _UPX_MAGIC_NRV2E,
                  _UPX_MAGIC_LZMA, _UPX_MAGIC_LZMA_OLD):
        idx = raw.rfind(magic)
        if idx >= 0:
            magic_positions.append((idx, magic))

    if not magic_positions:
        return None

    for idx, magic in magic_positions:
        # UPX 压缩数据头格式: magic (4-8B) + uncompressed_len (4B LE) +
        header_size = len(magic)
        if idx + header_size + 4 > len(raw):
            continue
        uncomp_len = struct.unpack_from("<I", raw, idx + header_size)[0]
        if uncomp_len == 0 or uncomp_len > 100_000_000:
            continue

        # NRV2B: 如果前导字节是 0x00，从下一个字节开始
        body_start = idx + header_size + 4
        if magic in (_UPX_MAGIC_NRV2B, _UPX_MAGIC_NRV2D, _UPX_MAGIC_NRV2E):
            # NRV 压缩体
            compressed = raw[body_start:]
            decompressed = _nrv2b_decompress(compressed, uncomp_len)
            if decompressed:
                with open(out_path, "wb") as fw:
                    fw.write(decompressed)
                return out_path
        elif magic in (_UPX_MAGIC_LZMA, _UPX_MAGIC_LZMA_OLD):
            # LZMA 解压（需要 lzma 模块）
            try:
                import lzma
                compressed = raw[body_start:]
                decompressed = lzma.decompress(compressed)
                if len(decompressed) == uncomp_len:
                    with open(out_path, "wb") as fw:
                        fw.write(decompressed)
                    return out_path
            except ImportError:
                pass
            except Exception:
                logger.debug("LZMA decompress failed", exc_info=True)

    return None


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    entropy = 0.0
    for c in counts:
        if c > 0:
            p = c / n
            entropy -= p * (p.bit_length() - 1)
    return entropy


def _block_entropy_profile(data: bytes, block_size: int = 512) -> dict:
    if not data:
        return {"mean": 0.0, "std": 0.0, "high_entropy_ratio": 0.0}
    entropies = []
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        entropies.append(_shannon_entropy(block))
    if not entropies:
        return {"mean": 0.0, "std": 0.0, "high_entropy_ratio": 0.0}
    mean_e = sum(entropies) / len(entropies)
    variance = sum((e - mean_e) ** 2 for e in entropies) / len(entropies)
    hi_ratio = sum(1 for e in entropies if e > 7.0) / len(entropies)
    return {"mean": round(mean_e, 2), "std": round(variance ** 0.5, 2),
            "high_entropy_ratio": round(hi_ratio, 2)}


def _is_probably_packed(raw: bytes) -> dict[str, Any]:
    mid = len(raw) // 4
    sample = raw[mid:mid + 4096] if len(raw) > 8192 else raw
    entropy = _shannon_entropy(sample)
    profile = _block_entropy_profile(raw) if len(raw) > 2048 else {}
    likely = entropy > _SECTION_ENTROPY_THRESHOLD
    if profile.get("std", 1.0) < 0.5 and entropy > 6.8:
        likely = True
    return {"entropy": round(entropy, 2), "likely_packed": likely,
            "file_size": len(raw), "block_profile": profile}


def _pe_section_raw_virtual_mismatch(data: bytes) -> Optional[dict]:
    try:
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe_offset:pe_offset + 4] != _PE_MAGIC:
            return None
        coff = pe_offset + 4
        num_sections = struct.unpack_from("<H", data, coff + 2)[0]
        opt_hdr_size = struct.unpack_from("<H", data, coff + 16)[0]
        section_offset = coff + 20 + opt_hdr_size
        worst_ratio = 1.0
        worst_section = ""
        for i in range(min(num_sections, 96)):
            so = section_offset + i * 40
            name = data[so:so + 8].rstrip(b"\x00").decode("latin-1", errors="replace")
            vsize = struct.unpack_from("<I", data, so + 8)[0]
            rsize = struct.unpack_from("<I", data, so + 16)[0]
            if rsize > 0 and vsize > 0:
                ratio = vsize / rsize
                if ratio > worst_ratio:
                    worst_ratio = ratio
                    worst_section = name
        if worst_ratio > 3.0:
            return {"section": worst_section, "ratio": round(worst_ratio, 1)}
    except (struct.error, IndexError):
        pass
    return None


def _find_oep_heuristic(raw: bytes) -> Optional[int]:
    if len(raw) < 512:
        return None
    for m in re.finditer(rb"\x68(.{4})\xc3", raw[-4096:]):
        target = struct.unpack("<I", m.group(1))[0]
        if 0x1000 <= target < len(raw) - 64:
            region = raw[max(0, target - 16):min(len(raw), target + 64)]
            if _shannon_entropy(region) < 6.0:
                return target
    return None


class Unpacker:
    def __init__(self):
        self._detected: Optional[str] = None
        self._unpacked_bytes: Optional[bytes] = None
        self._detection_method: str = ""
        self._oep_hint: Optional[int] = None
        self._section_mismatch: Optional[dict] = None

    def detect_packer(self, path: str) -> Optional[dict]:
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
        except OSError as exc:
            logger.warning("Cannot read %s: %s", path, exc)
            return None

        self._section_mismatch = _pe_section_raw_virtual_mismatch(raw)
        self._oep_hint = _find_oep_heuristic(raw)

        for packer_name, signatures in _PACKER_DB.items():
            for sig in signatures:
                if isinstance(sig, re.Pattern):
                    if sig.search(raw):
                        self._detected = packer_name
                        self._detection_method = "regex"
                        return {"packer": packer_name, "detection_method": "regex",
                                "signature": sig.pattern.decode("latin-1", errors="replace"),
                                "section_mismatch": self._section_mismatch,
                                "oep_hint": hex(self._oep_hint) if self._oep_hint else None}
                elif isinstance(sig, bytes):
                    if sig in raw:
                        self._detected = packer_name
                        self._detection_method = "magic_bytes"
                        return {"packer": packer_name, "detection_method": "magic_bytes",
                                "signature": sig.decode("latin-1", errors="replace"),
                                "section_mismatch": self._section_mismatch,
                                "oep_hint": hex(self._oep_hint) if self._oep_hint else None}

        entropy_info = _is_probably_packed(raw)
        if entropy_info["likely_packed"]:
            self._detected = "unknown"
            self._detection_method = "entropy"
            return {"packer": None, "detection_method": "entropy",
                    "entropy": entropy_info["entropy"],
                    "file_size": entropy_info["file_size"],
                    "block_profile": entropy_info.get("block_profile", {}),
                    "section_mismatch": self._section_mismatch,
                    "oep_hint": hex(self._oep_hint) if self._oep_hint else None}

        return None

    def unpack_if_needed(self, path: str) -> str:
        info = self.detect_packer(path)
        if info is None or info.get("packer") is None:
            return path

        if info["packer"] == "UPX":
            result = self._try_upx_unpack(path)
            if result:
                return result

        return path

    def _try_upx_unpack(self, path: str) -> Optional[str]:
        import subprocess
        out_path = path + ".unpacked"
        if os.path.exists(out_path):
            return out_path
        try:
            result = subprocess.run(["upx", "-d", path, "-o", out_path],
                                    capture_output=True, timeout=30)
            if result.returncode == 0 and os.path.isfile(out_path):
                return out_path
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            logger.debug("External upx not available for %s", path)

        # 回退：尝试内置 NRV/LZMA 解压
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
            builtin_result = _try_builtin_upx_unpack(raw, out_path)
            if builtin_result:
                logger.info("Built-in UPX unpack succeeded for %s", path)
                return builtin_result
        except OSError:
            pass

        # 最后的回退：原始 stub 裁剪
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
            for magic_bytes in (_UPX_MAGIC_LZMA, _UPX_MAGIC_NRV2B,
                               _UPX_MAGIC_NRV2D, _UPX_MAGIC_NRV2E):
                idx = raw.rfind(magic_bytes)
                if idx > 0 and raw[idx - 1] == 0x00:
                    stub_end = idx + len(magic_bytes)
                    if stub_end < len(raw) - 8:
                        unpacked = raw[:idx - 1]
                        with open(out_path, "wb") as fw:
                            fw.write(unpacked)
                        return out_path
        except OSError:
            pass

        return None

    @property
    def detected_packer(self) -> Optional[str]:
        return self._detected

    @property
    def detection_method(self) -> str:
        return self._detection_method

    @property
    def oep_hint(self) -> Optional[int]:
        return self._oep_hint
