"""Extract Python bytecode from PyInstaller-packed executables (CArchive + PYZ)."""

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
}

PYINSTALLER_MAGIC = b"MEI\014\013\012\013\016"
_STRUCT_COOKIE = struct.Struct("!8s i i i i i i i i i i i i i i i")
_STRUCT_TOC_ENTRY = struct.Struct("!i i i i")

# CArchive cookie layout:
# magic, lenofPackage, TOC, TOCcount, pyvers, pylibname...


@dataclass
class PycFile:
    path: str
    size: int = 0
    python_version: Optional[Tuple[int, int]] = None
    source: str = ""   # decompiled or empty

@dataclass
class UnpackResult:
    output_dir: str
    extracted_files: List[PycFile] = field(default_factory=list)
    decompiled_files: List[PycFile] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class CArchiveHeader:
    """Parsed CArchive cookie from a PyInstaller executable."""

    def __init__(self, raw: bytes):
        vals = _STRUCT_COOKIE.unpack(raw)
        self.magic = vals[0]
        self.len_of_package = vals[1]
        self.toc = vals[2]
        self.toc_count = vals[3]
        self.pyvers = vals[4]
        self.pylib_name_offset = vals[5] if vals[5] != 0 else None
        self.major, self.minor = (self.pyvers // 100, self.pyvers % 100) if self.pyvers else (0, 0)

    def is_valid(self) -> bool:
        return self.magic[:4] == PYINSTALLER_MAGIC[:4]


class PyInstallerUnpacker:
    """Handles extraction from PyInstaller one-file executables.

    Usage::

        unpacker = PyInstallerUnpacker()
        result = unpacker.unpack("./dist/myapp.exe", output="./extracted")
    """

    def __init__(self):
        self._tmpdir: Optional[str] = None

    # -- public ---------------------------------------------------------------

    def unpack(self, path: str, output: Optional[str] = None) -> UnpackResult:
        """Extract .pyc files from a PyInstaller executable.

        Returns an UnpackResult with extracted and decompiled file lists.
        If output is given, files land there; otherwise a temp dir is used.
        """
        if not os.path.isfile(path):
            return UnpackResult(output_dir="", errors=[f"File not found: {path}"])

        out_dir = output or tempfile.mkdtemp(prefix="pyi_unpack_")
        self._tmpdir = out_dir
        os.makedirs(out_dir, exist_ok=True)
        result = UnpackResult(output_dir=out_dir)

        data = self._read_file(path)
        if data is None:
            result.errors.append(f"Could not read {path}")
            return result

        header = self._find_carchive_header(data)
        if header is None:
            result.errors.append("CArchive header not found -- may not be a PyInstaller executable")
            return result

        _log.info("CArchive found: TOC count=%d, Python %d.%d",
                  header.toc_count, header.major, header.minor)

        entries = self._parse_toc(data, header)
        for entry in entries:
            extracted = self._extract_entry(data, entry, out_dir)
            if extracted:
                result.extracted_files.append(extracted)
                # Attempt decompilation
                decompiled = self._decompile(extracted.path)
                if decompiled:
                    extracted.source = decompiled
                    result.decompiled_files.append(extracted)

        return result

    # -- internals ------------------------------------------------------------

    def _read_file(self, path: str) -> Optional[bytes]:
        try:
            with open(path, "rb") as fh:
                return fh.read()
        except OSError as exc:
            _log.error("Read error: %s", exc)
            return None

    def _find_carchive_header(self, data: bytes) -> Optional[CArchiveHeader]:
        magic_positions = []
        idx = 0
        while True:
            idx = data.find(PYINSTALLER_MAGIC, idx)
            if idx == -1:
                break
            magic_positions.append(idx)
            idx += 1

        for pos in magic_positions:
            if pos + _STRUCT_COOKIE.size <= len(data):
                try:
                    header = CArchiveHeader(data[pos:pos + _STRUCT_COOKIE.size])
                    if header.is_valid() and 0 < header.toc_count < 100000:
                        self._header_offset = pos
                        return header
                except struct.error:
                    continue
        return None

    def _parse_toc(self, data: bytes, header: CArchiveHeader) -> List[Dict]:
        toc_data = data[header.toc:header.toc + header.toc_count * _STRUCT_TOC_ENTRY.size]
        entries = []
        for i in range(header.toc_count):
            offset = i * _STRUCT_TOC_ENTRY.size
            name_offset, data_offset, comp_size, orig_size = _STRUCT_TOC_ENTRY.unpack(
                toc_data[offset:offset + _STRUCT_TOC_ENTRY.size])
            # Read name string
            name_end = data.find(b"\x00", name_offset)
            name = data[name_offset:name_end].decode("utf-8", errors="replace")
            entries.append({
                "name": name,
                "data_offset": data_offset,
                "compressed_size": comp_size,
                "original_size": orig_size,
            })
        return entries

    def _extract_entry(self, data: bytes, entry: Dict, out_dir: str) -> Optional[PycFile]:
        name = entry["name"]
        data_offset = entry["data_offset"]
        orig_size = entry["original_size"]
        comp_size = entry["compressed_size"]

        if data_offset <= 0 or data_offset >= len(data):
            return None

        # Determine output path
        safe_name = name.replace("\\", "/").rstrip("/")
        if safe_name.startswith("/"):
            safe_name = safe_name[1:]
        out_path = os.path.join(out_dir, safe_name)

        raw = data[data_offset:data_offset + max(comp_size, orig_size)]
        if comp_size != orig_size and comp_size > 0:
            try:
                raw = zlib.decompress(raw)
            except zlib.error:
                _log.debug("zlib decompress failed for %s", name)
                raw = raw[:orig_size] if orig_size > 0 else raw

        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        try:
            with open(out_path, "wb") as fh:
                fh.write(raw)
        except OSError:
            return None

        pyver = None
        if raw[:2] in PYTHON_MAGIC_NUMBERS:
            pyver = PYTHON_MAGIC_NUMBERS.get(raw[:2])

        return PycFile(path=out_path, size=len(raw), python_version=pyver)

    def _decompile(self, pyc_path: str) -> str:
        """Attempt decompilation via uncompyle6 or pycdc."""
        if not pyc_path.endswith((".pyc", ".pyo")):
            return ""

        # Try uncompyle6
        try:
            import uncompyle6
            buf = io.StringIO()
            uncompyle6.decompile_file(pyc_path, buf)
            return buf.getvalue()
        except ImportError:
            pass
        except Exception:
            _log.debug("suppressed", exc_info=True)

        # Fallback: pycdc (external binary)
        try:
            import subprocess
            proc = subprocess.run(
                ["pycdc", pyc_path],
                capture_output=True, text=True, timeout=10,
            )
            if proc.returncode == 0:
                return proc.stdout
        except FileNotFoundError:
            pass
        except Exception:
            _log.debug("suppressed", exc_info=True)

        # Best-effort: dis module
        try:
            import dis
            import marshal
            with open(pyc_path, "rb") as fh:
                magic = fh.read(4)
                # Skip PEP 552 flags for 3.7+
                fh.read(8)
                code = marshal.load(fh)
            buf = io.StringIO()
            dis.dis(code, file=buf)
            return buf.getvalue()
        except Exception:
            return ""
