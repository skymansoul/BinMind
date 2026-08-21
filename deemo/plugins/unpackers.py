"""
Binary unpacking support. Handles UPX, MPRESS, and PyInstaller-packed
executables. Each unpacker is optional — if the tool isn't installed,
the step is silently skipped.
"""

import importlib.util
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

        # CArchive cookie 位于文件尾部：
        # magic(8) + lengthofpackage(4) + toc offset(4) + toc len(4) + pyvers(4)
        magic = b'MEI\014\013\012\013\016'
        magic_pos = data.rfind(magic)
        if magic_pos == -1 or magic_pos + 20 > len(data):
            return result

        toc_offset = struct.unpack('>I', data[magic_pos + 12:magic_pos + 16])[0]
        toc_len = struct.unpack('>I', data[magic_pos + 16:magic_pos + 20])[0]

        toc_start = toc_offset
        toc_end = toc_offset + toc_len
        if toc_start > len(data) or toc_end > len(data):
            return result

        os.makedirs(output_dir, exist_ok=True)

        # PYC 文件头（magic + flags + timestamp + size，flags=0 时为时间戳模式）
        pyc_header = importlib.util.MAGIC_NUMBER + b'\x00' * 12

        pyc_count = 0
        pos = toc_start
        while pos + 4 <= toc_end:
            # TOC 条目：4 字节名字长度 + 名字 + pos/len/ulen/flag 各 4 字节，
            # 条目按 16 字节边界对齐
            entry_len = struct.unpack('>I', data[pos:pos + 4])[0]
            if entry_len == 0 or entry_len > 4096:
                break
            if pos + 4 + entry_len > toc_end:
                break
            pos += 4
            raw_name = data[pos:pos + entry_len].rstrip(b'\x00')
            entry_name = raw_name.decode('utf-8', errors='replace')
            pos += entry_len
            align = (16 - (pos % 16)) % 16
            pos += align

            if pos + 16 > toc_end:
                break
            e_pos, e_len, _e_ulen, e_flag = struct.unpack('>IIII',
                                                          data[pos:pos + 16])
            pos += 16

            if not entry_name or not e_len:
                continue
            if e_pos + e_len > len(data):
                continue

            blob = data[e_pos:e_pos + e_len]
            # flag==1 表示 zlib 压缩
            if e_flag == 1:
                try:
                    blob = zlib.decompress(blob)
                except zlib.error:
                    _log.debug("zlib decompress failed for %s", entry_name)

            if entry_name.endswith(('.pyc', '.pyo')):
                name = os.path.basename(entry_name)
                with open(os.path.join(output_dir, name), 'wb') as outf:
                    outf.write(pyc_header)
                    outf.write(blob)
                pyc_count += 1
                result['pyc_files'].append(name)

        result['success'] = pyc_count > 0
        return result
    except Exception as e:
        _log.warning("PyInstaller extraction failed: %s", e)
        return result
