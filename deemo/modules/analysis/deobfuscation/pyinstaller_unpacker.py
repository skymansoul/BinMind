"""提取 Python 字节码 PyInstaller-packed 可执行文件s (CArchive + PYZ)"""

import io
import logging
import os
import struct
import sys
import tempfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_log = logging.getLogger(__name__)

PYTHON_MAGIC_NUMBERS = {
    0x16D: (3, 3), 0x16E: (3, 3), 0x16F: (3, 3),
    0x170: (3, 4), 0x171: (3, 4), 0x172: (3, 4), 0x173: (3, 4),
    0x1F0: (3, 5), 0x1F1: (3, 5), 0x1F2: (3, 5), 0x1F3: (3, 5),
    0x20D: (3, 6), 0x20E: (3, 6), 0x20F: (3, 6), 0x210: (3, 6),
    0x21A: (3, 7), 0x21B: (3, 7), 0x21C: (3, 7), 0x21D: (3, 7),
    0x22B: (3, 8), 0x22C: (3, 8), 0x22D: (3, 8), 0x22E: (3, 8),
    0x255: (3, 9), 0x256: (3, 9), 0x257: (3, 9), 0x258: (3, 9),
    0x26C: (3, 10), 0x26D: (3, 10), 0x26E: (3, 10), 0x26F: (3, 10),
    0x2D1: (3, 11), 0x2D2: (3, 11), 0x2D3: (3, 11), 0x2D4: (3, 11),
    0x2F5: (3, 12), 0x2F6: (3, 12), 0x2F7: (3, 12), 0x2F8: (3, 12),
    0x3D45: (3, 13), 0x3DC0: (3, 13),
    0x3F2B: (3, 14), 0x3FB0: (3, 14),
    0x4A0D: (3, 15), 0x4A8E: (3, 15),
}

PYINSTALLER_MAGIC = b"MEI\014\013\012\013\016"
PYZ_MAGIC = b"PYZ\x00"
_STRUCT_COOKIE = struct.Struct("!8s i i i i i i i i i i i i i i i")
_STRUCT_TOC_ENTRY = struct.Struct("!i i i i")

_TOC_TYPECODES = {
    b'z': 'pyz_archive', b'Z': 'zip_archive', b'm': 'python_module',
    b'M': 'python_package', b's': 'python_script', b'b': 'binary_shared_lib',
    b'x': 'data_file', b'd': 'runtime_dependency', b'o': 'runtime_option',
    b'l': 'splash_resources',
}

_NUITKA_MARKERS = [b"nuitka", b"Nuitka", b"__compiled__"]
_PYARMOR_MARKERS = [b"pyarmor", b"PyArmor", b"__pyarmor__", b"pytransform"]
_CXFREEZE_MARKERS = [b"cx_Freeze", b"cx-freeze"]


@dataclass
class PycFile:
    path: str; size: int = 0
    python_version: Optional[Tuple[int, int]] = None
    source: str = ""; is_package: bool = False; entry_type: str = ""


@dataclass
class UnpackResult:
    output_dir: str
    extracted_files: List[PycFile] = field(default_factory=list)
    decompiled_files: List[PycFile] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    pyinstaller_version: Optional[str] = None
    is_onefile: bool = True; bootloader_type: str = ""
    packer_type: str = "pyinstaller"; anti_tamper_detected: bool = False
    # 新增：叠加 CArchive 计数
    overlay_archives: int = 0


class CArchiveHeader:
    def __init__(self, raw: bytes):
        vals = _STRUCT_COOKIE.unpack(raw)
        self.magic = vals[0]; self.len_of_package = vals[1]
        self.toc = vals[2]; self.toc_count = vals[3]
        self.pyvers = vals[4]
        self.pylib_name_offset = vals[5] if vals[5] != 0 else None
        self.major, self.minor = (self.pyvers // 100, self.pyvers % 100) if self.pyvers else (0, 0)

    def is_valid(self) -> bool:
        return self.magic[:4] == PYINSTALLER_MAGIC[:4]


class PyInstallerUnpacker:

    def __init__(self):
        self._tmpdir: Optional[str] = None; self._header_offset: int = 0

    # 多 CArchive 叠加扫描 —— 某些 PyInstaller 打包器会在 PE overlay
    # 区域附加多个 CArchive（典型场景：多阶段解包器）
    # 主 CArchive 解析后继续向后扫描额外的 MAGIC 标记

    def _find_all_carchive_headers(self, data: bytes) -> List[Tuple[int, CArchiveHeader]]:
        """扫描所有 CArchive MAGIC 位置，返回多个 header"""
        headers = []
        idx = 0
        while True:
            idx = data.find(PYINSTALLER_MAGIC, idx)
            if idx == -1: break
            if idx + _STRUCT_COOKIE.size <= len(data):
                try:
                    hdr = CArchiveHeader(data[idx:idx + _STRUCT_COOKIE.size])
                    if hdr.is_valid() and 0 < hdr.toc_count < 100000:
                        headers.append((idx, hdr))
                except struct.error: pass
            idx += 1
        return headers

    def unpack(self, path: str, output: Optional[str] = None) -> UnpackResult:
        if not os.path.isfile(path):
            return UnpackResult(output_dir="", errors=[f"File not found: {path}"])
        out_dir = output or tempfile.mkdtemp(prefix="pyi_unpack_")
        self._tmpdir = out_dir
        os.makedirs(out_dir, exist_ok=True)
        result = UnpackResult(output_dir=out_dir)

        data = self._read_file(path)
        if data is None:
            result.errors.append(f"Could not read {path}"); return result

        packer_type, anti_tamper = self._detect_packer_type(data)
        result.packer_type = packer_type; result.anti_tamper_detected = anti_tamper

        if packer_type != "pyinstaller":
            result.errors.append(f"Detected packer '{packer_type}' rather than PyInstaller")

        all_headers = self._find_all_carchive_headers(data)
        if not all_headers:
            result.errors.append("No CArchive headers found"); return result

        result.overlay_archives = len(all_headers)
        if len(all_headers) > 1:
            _log.info("Found %d CArchive headers (multi-stage)", len(all_headers))

        for hdr_idx, (hdr_pos, header) in enumerate(all_headers):
            self._header_offset = hdr_pos
            result.is_onefile = True
            result.pyinstaller_version = f"{header.major}.{header.minor}"

            entries = self._parse_toc(data, header)
            for entry in entries:
                extracted = self._extract_entry(data, entry, out_dir)
                if extracted:
                    result.extracted_files.append(extracted)
                    decompiled = self._decompile(extracted.path)
                    if decompiled:
                        extracted.source = decompiled
                        result.decompiled_files.append(extracted)

            pyz_entries = [e for e in entries if e.get("typecode") == b'z']
            if pyz_entries:
                result.bootloader_type = "pyz_archive"
                for pyz in pyz_entries:
                    _log.info("PYZ archive: %s, extracting via marshal...", pyz["name"])
                    pyz_files = self._extract_pyz_improved(data, pyz, out_dir)
                    result.extracted_files.extend(pyz_files)

        return result

    def _extract_pyz_improved(self, data, pyz_entry, out_dir):
        extracted = []
        offset = pyz_entry["data_offset"]
        size = max(pyz_entry.get("compressed_size", 0), pyz_entry.get("original_size", 0))
        if offset <= 0 or offset + size > len(data): return extracted
        compressed = data[offset:offset + size]
        try: pyz_raw = zlib.decompress(compressed)
        except zlib.error:
            _log.debug("PYZ zlib failed"); return extracted
        if pyz_raw[:4] != PYZ_MAGIC: return extracted
        _log.info("PYZ: %d -> %d bytes", len(compressed), len(pyz_raw))
        if pyz_raw[4] != 0:
            _log.warning("Encrypted PYZ, skipping"); return extracted
        try:
            import marshal
            toc = marshal.loads(pyz_raw[5:])
        except (ValueError, EOFError, struct.error) as e:
            _log.warning("PYZ TOC parse: %s", e); return extracted
        if not isinstance(toc, dict): return extracted
        for mod_name, mod_info in toc.items():
            if not isinstance(mod_info, (list, tuple)) or len(mod_info) < 2: continue
            mod_off, mod_sz = int(mod_info[0]), int(mod_info[1])
            mod_tc = mod_info[2] if len(mod_info) > 2 else 0
            if mod_off + mod_sz > len(pyz_raw): continue
            try: mod_data = zlib.decompress(pyz_raw[mod_off:mod_off + mod_sz])
            except zlib.error: continue
            try:
                code_obj = marshal.loads(mod_data)
            except (ValueError, EOFError):
                safe_name = (mod_name.decode("utf-8", errors="replace") if isinstance(mod_name, bytes)
                            else mod_name).replace(".", "/")
                out_path = os.path.join(out_dir, f"{safe_name}.pyz_data")
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                with open(out_path, "wb") as fw: fw.write(mod_data)
                extracted.append(PycFile(path=out_path, size=len(mod_data))); continue
            safe_name = (mod_name.decode("utf-8", errors="replace") if isinstance(mod_name, bytes)
                        else mod_name).replace(".", "/")
            out_path = os.path.join(out_dir, f"{safe_name}.pyc" if mod_tc != 1 else os.path.join(safe_name, "__init__.pyc"))
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, "wb") as fw:
                import time as _time
                magic_bytes = struct.pack("<H", list(PYTHON_MAGIC_NUMBERS.keys())[-1])
                fw.write(magic_bytes); fw.write(b"\x00\x00\x00\x00")
                fw.write(struct.pack("<I", int(_time.time())))
                fw.write(struct.pack("<I", len(mod_data))); fw.write(mod_data)
            pyver = PYTHON_MAGIC_NUMBERS.get(struct.unpack("<H", magic_bytes)[0])
            extracted.append(PycFile(path=out_path, size=len(mod_data),
                python_version=pyver, is_package=(mod_tc == 1), entry_type="pyz_marshal"))
        return extracted

    def _detect_packer_type(self, data):
        if any(m in data for m in _PYARMOR_MARKERS): return "pyarmor", True
        if any(m in data for m in _NUITKA_MARKERS): return "nuitka", False
        if any(m in data for m in _CXFREEZE_MARKERS): return "cx_freeze", False
        return "pyinstaller", False

    def _read_file(self, path):
        try:
            with open(path, "rb") as fh: return fh.read()
        except OSError as exc:
            _log.error("Read error: %s", exc); return None

    def _parse_toc(self, data, header):
        toc_data = data[header.toc:header.toc + header.toc_count * _STRUCT_TOC_ENTRY.size]
        entries = []
        for i in range(header.toc_count):
            off = i * _STRUCT_TOC_ENTRY.size
            name_offset, data_offset, comp_size, orig_size = _STRUCT_TOC_ENTRY.unpack(
                toc_data[off:off + _STRUCT_TOC_ENTRY.size])
            name_end = data.find(b"\x00", name_offset)
            name = data[name_offset:name_end].decode("utf-8", errors="replace")
            typecode = data[name_end + 1:name_end + 2] if name_end + 1 < len(data) else b''
            entries.append({"name": name, "data_offset": data_offset,
                "compressed_size": comp_size, "original_size": orig_size,
                "typecode": typecode, "typecode_name": _TOC_TYPECODES.get(typecode, f"unknown")})
        return entries

    def _extract_entry(self, data, entry, out_dir):
        name = entry["name"]; data_offset = entry["data_offset"]
        orig_size = entry["original_size"]; comp_size = entry["compressed_size"]
        if data_offset <= 0 or data_offset >= len(data): return None
        safe_name = name.replace("\\", "/").rstrip("/")
        if safe_name.startswith("/"): safe_name = safe_name[1:]
        out_path = os.path.join(out_dir, safe_name)
        raw = data[data_offset:data_offset + max(comp_size, orig_size)]
        if comp_size != orig_size and comp_size > 0:
            try: raw = zlib.decompress(raw)
            except zlib.error: raw = raw[:orig_size] if orig_size > 0 else raw
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        try:
            with open(out_path, "wb") as fh: fh.write(raw)
        except OSError: return None
        pyver = None
        try:
            if len(raw) >= 2:
                magic = struct.unpack("<H", raw[:2])[0]
                pyver = PYTHON_MAGIC_NUMBERS.get(magic)
        except struct.error: pass
        return PycFile(path=out_path, size=len(raw), python_version=pyver,
                       entry_type=entry.get("typecode_name", ""))

    def _decompile(self, pyc_path):
        if not pyc_path.endswith((".pyc", ".pyo")): return ""
        try:
            import uncompyle6
            buf = io.StringIO(); uncompyle6.decompile_file(pyc_path, buf); return buf.getvalue()
        except ImportError: pass
        except Exception: _log.debug("suppressed", exc_info=True)
        try:
            import subprocess
            proc = subprocess.run(["pycdc", pyc_path], capture_output=True, text=True, timeout=10)
            if proc.returncode == 0: return proc.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired): pass
        except Exception: _log.debug("suppressed", exc_info=True)
        try:
            import dis, marshal
            with open(pyc_path, "rb") as fh:
                fh.read(4); fh.read(8); code = marshal.load(fh)
            buf = io.StringIO(); dis.dis(code, file=buf); return buf.getvalue()
        except Exception: return ""
