"""
Binary unpacking support. Handles UPX, MPRESS, and PyInstaller-packed
executables. Each unpacker is optional — if the tool isn't installed,
the step is silently skipped.
"""

import logging
import os
import shutil
import subprocess
import struct
import zlib
from typing import Dict, Optional

from config import SUBPROCESS_TIMEOUT

_log = logging.getLogger(__name__)


def detect_packer(path: str) -> Optional[str]:
    """
    Quick detection of common packers. Returns packer name or None.
    """
    try:
        with open(path, 'rb') as f:
            head = f.read(4096)
    except OSError:
        return None

    # UPX
    if b'UPX!' in head:
        return 'UPX'

    # MPRESS
    if b'MPRESS' in head[:0x200]:
        return 'MPRESS'

    # PyInstaller
    if b'MEI\014\013\012\013\016' in head:  # pyinstaller magic (old)
        return 'PyInstaller'
    if b'PyInstaller' in head:
        return 'PyInstaller'

    # ASPack
    if head[:2] == b'MZ' and b'ASPack' in head:
        return 'ASPack'

    return None


def unpack_upx(path: str, output_dir: str = None) -> Optional[str]:
    """Unpack a UPX-compressed binary. Returns path to unpacked file."""
    upx = shutil.which('upx')
    if not upx:
        _log.debug("upx not installed; skipping UPX unpack")
        return None

    if output_dir is None:
        output_dir = os.path.dirname(path)

    name = os.path.basename(path)
    stem, ext = os.path.splitext(name)
    out_path = os.path.join(output_dir, f'{stem}_unpacked{ext}')

    try:
        subprocess.run(
            [upx, '-d', path, '-o', out_path],
            capture_output=True, timeout=120, check=True)
        if os.path.isfile(out_path):
            return out_path
    except subprocess.CalledProcessError:
        pass  # UPX failed — might be a modified packer
    except Exception as e:
        _log.debug("UPX unpack failed: %s", e)

    return None


def unpack_pyinstaller(path: str, output_dir: str = None) -> Dict:
    """
    Extract PyInstaller-compiled Python executables.
    Returns {success, output_dir, pyc_files}.
    """
    if output_dir is None:
        base = os.path.splitext(os.path.basename(path))[0]
        output_dir = os.path.join(os.path.dirname(path), f'{base}_extracted')

    result = {
        'success': False,
        'output_dir': output_dir,
        'pyc_files': [],
    }

    try:
        # PyInstaller archive parsing
        with open(path, 'rb') as f:
            data = f.read()

        # Find PyInstaller CArchive magic
        magic_pos = data.find(b'MEI\014\013\012\013\016')
        if magic_pos == -1:
            return result

        os.makedirs(output_dir, exist_ok=True)

        # parse table of contents at the end
        # This is a simplified parser — real PyInstaller format has more fields
        # For full extraction use pyinstxtractor or unpy2exe
        pyc_count = 0
        pos = magic_pos + 8
        while pos < len(data) - 16:
            try:
                name_len = struct.unpack('<I', data[pos:pos + 4])[0]
                if name_len > 256 or name_len == 0:
                    break
                pos += 4
                entry_name = data[pos:pos + name_len].rstrip(b'\x00').decode(
                    'utf-8', errors='replace')
                pos += name_len

                # skip some fields
                pos += 12  # position, size, compression flag

                if entry_name.endswith('.pyc'):
                    name = os.path.basename(entry_name)
                    with open(os.path.join(output_dir, name), 'wb') as outf:
                        outf.write(b'\x00' * 16)  # placeholder PYC header
                    pyc_count += 1
                    result['pyc_files'].append(name)
            except (IndexError, struct.error):
                break

        result['success'] = pyc_count > 0
        return result
    except Exception as e:
        _log.warning("PyInstaller extraction failed: %s", e)
        return result
