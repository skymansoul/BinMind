import logging
import re
import struct
import os
from typing import Any

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

_PACKER_DB: dict[str, list[bytes | re.Pattern]] = {
    "UPX": _UPX_SIGNATURES,
    "ASPack": _ASPACK_SIGNATURES,
    "MPRESS": _MPRESS_SIGNATURES,
    "FSG": _FSG_SIGNATURES,
    "PECompact": _PECOMPACT_SIGS,
    "Petite": _PETITE_SIGS,
    "TeLock": _TELOCK_SIGS,
    "Enigma": _ENIGMA_SIGS,
}

_UPX_MAGIC_LZMA = b"UPX;"
_UPX_MAGIC_NRV2B = b"UPX\x00"
_UPX_MAGIC_NRV2D = b"UPX\x01"
_UPX_MAGIC_NRV2E = b"UPX\x02"
_UPX_MAGIC_LZMA_OLD = bytes([0x55, 0x50, 0x58, 0x21])  # UPX!

_SECTION_ENTROPY_THRESHOLD = 7.5
_IMPORT_COUNT_THRESHOLD = 3
_SECTION_NAME_INDICATORS = {"UPX0", "UPX1", "UPX2", ".aspack", ".adata", ".pec",
                             ".MPRESS1", ".MPRESS2", ".petite", ".fsg", ".enigma1", ".enigma2"}


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


def _is_probably_packed(raw: bytes) -> dict[str, Any]:
    mid = len(raw) // 4
    sample = raw[mid:mid + 4096] if len(raw) > 8192 else raw
    entropy = _shannon_entropy(sample)
    return {
        "entropy": round(entropy, 2),
        "likely_packed": entropy > _SECTION_ENTROPY_THRESHOLD,
        "file_size": len(raw),
    }


class Unpacker:
    def __init__(self):
        self._detected: str | None = None
        self._unpacked_bytes: bytes | None = None

    def detect_packer(self, path: str) -> dict | None:
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
        except OSError as exc:
            logger.warning("Cannot read %s: %s", path, exc)
            return None

        for packer_name, signatures in _PACKER_DB.items():
            for sig in signatures:
                if isinstance(sig, re.Pattern):
                    if sig.search(raw):
                        self._detected = packer_name
                        return {"packer": packer_name, "detection_method": "regex",
                                "signature": sig.pattern.decode("latin-1", errors="replace")}
                elif isinstance(sig, bytes):
                    if sig in raw:
                        self._detected = packer_name
                        return {"packer": packer_name, "detection_method": "magic_bytes",
                                "signature": sig.decode("latin-1", errors="replace")}

        entropy_info = _is_probably_packed(raw)
        if entropy_info["likely_packed"]:
            self._detected = "unknown"
            return {"packer": None, "detection_method": "entropy",
                    "entropy": entropy_info["entropy"],
                    "file_size": entropy_info["file_size"]}

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

    def _try_upx_unpack(self, path: str) -> str | None:
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

        try:
            with open(path, "rb") as fh:
                raw = fh.read()
            for magic, offset in [(_UPX_MAGIC_LZMA, -4), (_UPX_MAGIC_NRV2B, -4),
                                   (_UPX_MAGIC_NRV2D, -4), (_UPX_MAGIC_NRV2E, -4)]:
                idx = raw.rfind(magic)
                if idx > 0 and raw[idx - 1] == 0x00:
                    stub_end = idx + len(magic)
                    if stub_end < len(raw) - 8:
                        unpacked = raw[:idx - 1]
                        with open(out_path, "wb") as fw:
                            fw.write(unpacked)
                        return out_path
        except OSError:
            pass

        return None

    @property
    def detected_packer(self) -> str | None:
        return self._detected
