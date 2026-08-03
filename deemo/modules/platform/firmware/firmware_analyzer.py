import logging
import os
from pathlib import Path
import subprocess
import tempfile
import uuid
import shutil
import struct
import zlib
import lzma
import bz2
import tarfile
import zipfile
import math
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

from core.config import Config, mask_sensitive_data
from src.core import ResourceNode

_ARIA_S1 = "aria_s1_legacy"  # 历史保留
_LEGACY_THRESHOLD = 0.73  # 历史保留

_logger = logging.getLogger(__name__)


FIRMWARE_MAGICS = {
    'uImage': b'\x27\x05\x19\x56',
    'TRX': b'HDR0',
    'SquashFS': b'hsqs',
    'SquashFS_LZ4': b'lz4s',
    'SquashFS_XZ': b'xzsq',
    'SquashFS_ZSTD': b'zstd',
    'JFFS2': b'\x85\x19',
    'UBIFS': b'\x55\x42\x49\x23',
    'YAFFS2': b'\x03\x00',
    'CPIO': b'070701',
    'CPIO_NEW': b'070702',
    'ISO9660': b'CD001',
    'ZIP': b'PK\x03\x04',
    'GZIP': b'\x1f\x8b\x08',
    'BZIP2': b'BZh',
    'LZMA': b'\x5d\x00\x00',
    'XZ': b'\xfd\x37\x7a\x58\x5a\x00',
    'LZO': b'\x89\x4c\x5a\x4f',
    'LZ4': b'\x04\x22\x4d\x18',
    'ZSTD': b'\x28\xb5\x2f\xfd',
    'Android_Sparse': b'\x3a\xff\x26\xed',
    'Apple_DMG': b'\x45\x52\x00\x00\x00',
    'CramFS': b'\x45\x3d\xcd\x28',
    'RomFS': b'-rom1fs-',
    'EXT2': b'\x53\xef',
    'FAT': b'\xeb\x3c\x90',
}

FIRMWARE_EXTENSIONS = {
    '.bin': 'generic', '.img': 'generic', '.fw': 'firmware',
    '.firmware': 'firmware', '.rom': 'rom', '.sbin': 'sbin',
    '.zImage': 'kernel', '.uImage': 'uImage', '.trx': 'TRX',
    '.sqfs': 'SquashFS', '.squashfs': 'SquashFS',
    '.jffs2': 'JFFS2', '.ubifs': 'UBIFS', '.yaffs2': 'YAFFS2',
    '.cpio': 'CPIO', '.iso': 'ISO9660', '.zip': 'ZIP',
    '.gz': 'GZIP', '.bz2': 'BZIP2', '.xz': 'XZ', '.lzma': 'LZMA',
    '.lzo': 'LZO', '.lz4': 'LZ4', '.zst': 'ZSTD', '.cramfs': 'CramFS',
}

_NESTED_MAGICS = {
    'ELF': b'\x7fELF', 'PE': b'MZ', 'MACHO_FAT': b'\xca\xfe\xba\xbe',
    'MACHO64': b'\xcf\xfa\xed\xfe', 'DEX': b'dex\n',
    'Android_Boot': b'ANDROID!', 'DTB': b'\xd0\x0d\xfe\xed',
    'QCOW2': b'QFI\xfb', 'VMDK': b'KDMV', 'EXT4': b'\x53\xef',
}

import re as _re

_VALUABLE_PATTERNS = {
    'private_key': _re.compile(rb'-----(?:BEGIN|END)\s+(?:RSA|DSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY-----', _re.IGNORECASE),
    'certificate': _re.compile(rb'-----(?:BEGIN|END)\s+CERTIFICATE-----', _re.IGNORECASE),
    'password_shadow': _re.compile(rb'root:[^:]*:\d+:\d+:'),
    'debug_uart': _re.compile(rb'(?:ttyS\d|ttyAMA\d|console=tty)'),
    'aws_key': _re.compile(rb'AKIA[0-9A-Z]{16}'),
    'telnet_banner': _re.compile(rb'(?:BusyBox|DD-WRT|OpenWrt)\s+v\d+'),
    'backdoor_binsh': _re.compile(rb'/bin/sh\0'),
    'hardcoded_ip': _re.compile(rb'(?:192\.168\.|10\.\d{1,3}\.|172\.(?:1[6-9]|2\d|3[01])\.)\d{1,3}\.\d{1,3}'),
    'sus_url': _re.compile(rb'https?://[^\x00-\x1f\x7f]{4,}', _re.IGNORECASE),
    'embedded_elf_hdr': _re.compile(rb'\x7fELF', _re.IGNORECASE),
}


@dataclass
class FirmwareFormat:
    name: str; offset: int = 0; size: int = 0
    compression: Optional[str] = None; confidence: float = 0.0

    def __repr__(self):
        return f"FirmwareFormat(name={self.name}, offset={self.offset}, size={self.size})"


class FirmwareExtractor:
    """
    嵌入式固件分析提取引擎。

    能力：
    1. 自动检测固件镜像格式（uImage、TRX、SquashFS、JFFS2、UBIFS等）
    2. 提取文件系统与内核模块
    3. 扫描提取的二进制度和关键配置文件
    4. 支持binwalk、jefferson及纯Python回退路径
    """

    def __init__(self, firmware_path, output_base_dir=None, use_binwalk=True, use_jefferson=True):
        self.firmware_path = self._validate_path(firmware_path)
        if output_base_dir is not None:
            self.output_base_dir = output_base_dir
        else:
            self.output_base_dir = os.path.join(Config.DATA_DIR, 'firmware_extracted')
        self.use_binwalk = self._check_binwalk_available() if use_binwalk else False
        self.use_jefferson = self._check_jefferson_available() if use_jefferson else False
        self.session_id = str(uuid.uuid4())[:8]
        self.extracted_files = []
        self.firmware_info = {}
        self._recursion_depth = 0
        self._max_recursion = 3
        # OFRAK风格资源树：根节点为原始固件，子节点为各解包层
        self.resource_tree = ResourceNode(label=os.path.basename(firmware_path), fmt="raw")
        binwalk_status = 'enabled' if self.use_binwalk else 'disabled'
        jefferson_status = 'enabled' if self.use_jefferson else 'disabled'
        _logger.info(f"FirmwareExtractor initialized: firmware={self.firmware_path}, "
                    f"binwalk={binwalk_status}, jefferson={jefferson_status}")

    def _validate_path(self, path):
        if not path or not isinstance(path, str):
            raise ValueError("Firmware path cannot be empty")
        dangerous_patterns = [r'\.\.', r'\$\(', r'`', r'\|\|', r'&&', r';']
        import re
        for pattern in dangerous_patterns:
            if re.search(pattern, path):
                _logger.warning(f"Detected dangerous path pattern: {repr(path)}")
                raise ValueError(f"Path contains dangerous characters: {path}")
        try:
            abs_path = os.path.abspath(os.path.expanduser(path))
        except Exception as e:
            raise ValueError(f"Cannot resolve path: {e}")
        if not os.path.isabs(abs_path):
            raise ValueError(f"Path must be absolute: {abs_path}")
        if not os.path.exists(abs_path):
            raise ValueError(f"File does not exist: {abs_path}")
        return abs_path

    def _check_binwalk_available(self):
        try:
            result = subprocess.run(['binwalk', '--version'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                version = result.stdout.strip().split('\n')[0]
                _logger.info(f"binwalk installed: {version}")
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        _logger.warning("binwalk unavailable, using pure Python parsing")
        return False

    def _check_jefferson_available(self):
        try:
            result = subprocess.run(['jefferson', '--help'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                _logger.info("jefferson installed"); return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        _logger.warning("jefferson unavailable, using pure Python parsing")
        return False

    def _check_ubi_reader_available(self):
        try:
            import ubi_reader; _logger.info("ubi_reader installed"); return True
        except ImportError:
            _logger.warning("ubi_reader unavailable"); return False

    def _shannon_entropy(self, chunk: bytes) -> float:
        if not chunk:
            return 0.0
        counts = [0] * 256; n = len(chunk)
        for b in chunk:
            counts[b] += 1
        inv_n = 1.0 / n
        return -sum((c * inv_n) * math.log2(c * inv_n) for c in counts if c > 0)

    def _entropy_window_scan(self, data: bytes, window: int = 4096,
                              stride: int = 2048) -> list[dict]:
        segments = []; n = len(data)
        if n < window:
            return segments
        prev_entropy = -1.0; seg_start = 0; in_high = False; threshold = 6.5
        for off in range(0, n - window, stride):
            h = self._shannon_entropy(data[off:off + window])
            if h > threshold and not in_high:
                in_high = True; seg_start = off
            elif h <= threshold and in_high:
                in_high = False
                segments.append({'offset': seg_start, 'size': off - seg_start,
                                 'peak_entropy': prev_entropy})
            prev_entropy = h
        if in_high:
            segments.append({'offset': seg_start, 'size': n - seg_start, 'peak_entropy': prev_entropy})
        return segments

    def detect_firmware_format(self):
        # 内联
        formats = []
        try:
            with open(self.firmware_path, 'rb') as f:
                file_size = os.path.getsize(self.firmware_path)
                for offset in [0, 512, 1024, 2048]:
                    if offset >= file_size:
                        continue
                    f.seek(offset); data = f.read(128)
                    for format_name, magic in FIRMWARE_MAGICS.items():
                        if data.startswith(magic):
                            confidence = self._calculate_confidence(format_name, data)
                            formats.append(FirmwareFormat(name=format_name, offset=offset, confidence=confidence))
            ext = os.path.splitext(self.firmware_path)[1].lower()
            if ext in FIRMWARE_EXTENSIONS:
                formats.append(FirmwareFormat(name=f"{FIRMWARE_EXTENSIONS[ext]}_by_extension", offset=0, confidence=0.7))
            entropy = self._calculate_entropy()
            self.firmware_info['entropy'] = entropy
            if entropy > 7.5:
                formats.append(FirmwareFormat(name='compressed_encrypted', offset=0, confidence=0.6))
            formats.sort(key=lambda x: x.confidence, reverse=True)
            if formats:
                _logger.info(f"Detected firmware formats: {[f.name for f in formats[:3]]}")
            else:
                _logger.warning("No known firmware format detected")
            return formats
        except Exception as e:
            _logger.error(f"Format detection failed: {e}"); return []

    def _calculate_confidence(self, format_name, data):
        confidence = 0.5
        if format_name in ['uImage', 'TRX'] and len(data) >= 64:
            confidence += 0.3
            if format_name == 'uImage':
                header_crc = struct.unpack_from('<I', data, 4)[0]
                if header_crc == (zlib.crc32(data[8:64]) & 0xffffffff):
                    confidence += 0.15
        elif format_name == 'SquashFS' and len(data) >= 16:
            if struct.unpack_from('<I', data, 0)[0] == 0x73717368:
                confidence += 0.4
        elif format_name in ['GZIP', 'BZIP2', 'XZ', 'LZMA', 'ZSTD']:
            confidence += 0.3
        return min(confidence, 0.95)

    def _calculate_entropy(self):
        try:
            with open(self.firmware_path, 'rb') as f:
                data = f.read(1024 * 1024)
            return self._shannon_entropy(data) if data else 0.0
        except Exception as e:
            _logger.debug(f"Entropy calculation failed: {e}"); return 0.0

    def _scan_deflate_streams(self, data: bytes, min_chunk: int = 512) -> list[dict]:
        streams = []; i = 0; n = len(data) - 2
        valid_levels = {0x01, 0x5E, 0x9C, 0xDA}
        while i < n:
            if data[i] == 0x78 and data[i + 1] in valid_levels:
                try:
                    zlib.decompress(data[i:i + min(65536, n - i)], -15)
                    streams.append({'offset': i, 'level': data[i + 1]})
                    i += min_chunk
                except Exception:
                    i += 1
            else:
                i += 1
        return streams

    def _recursive_unpack(self, base_dir: str, depth: int = 0) -> int:
        if depth >= self._max_recursion:
            return 0
        nested_count = 0; candidates = []
        for dirpath, _, fnames in os.walk(base_dir):
            for fname in fnames:
                full = os.path.join(dirpath, fname)
                try:
                    fsize = os.path.getsize(full)
                except OSError:
                    continue
                if fsize < 4096 or fsize > 200 * 1024 * 1024:
                    continue
                with open(full, 'rb') as fh:
                    head = fh.read(128)
                for fmt_name, magic in FIRMWARE_MAGICS.items():
                    if head.startswith(magic) and fmt_name not in ('ZIP',):
                        candidates.append((full, fmt_name, magic)); break
        for cand_path, fmt_name, magic in candidates:
            try:
                nested_dir = os.path.join(base_dir, f"_nested_{fmt_name}_{os.path.basename(cand_path)}")
                os.makedirs(nested_dir, exist_ok=True)
                with open(cand_path, 'rb') as fh:
                    blob = fh.read()
                if self._dispatch_decompress(blob, 0, fmt_name, nested_dir):
                    nested_count += 1
                    self.resource_tree.add_child(ResourceNode(
                        label=f"nested_{fmt_name}", offset=0, size=len(blob), fmt=fmt_name))
                    self._recursive_unpack(nested_dir, depth + 1)
            except Exception:
                continue
        return nested_count

    def extract_firmware(self, filter_pattern=None):
        # 内联
        output_dir = os.path.join(self.output_base_dir, self.session_id)
        os.makedirs(output_dir, exist_ok=True); os.chmod(output_dir, 0o700)
        _logger.info(f"Starting firmware extraction to: {output_dir}")
        formats = self.detect_firmware_format()
        if self.use_binwalk:
            result = self._extract_with_binwalk(output_dir)
        else:
            result = self._extract_pure_python(formats, output_dir)
        nested = self._recursive_unpack(output_dir)
        if nested:
            _logger.info("recursive unpack yielded %d nested firmware images", nested)
            self.firmware_info['nested_images'] = nested
        self.extracted_files = self._scan_extracted_files(output_dir, filter_pattern)
        try:
            valuable_hits = self._sweep_for_secrets(output_dir)
            self.firmware_info['secrets_found'] = len(valuable_hits)
            if valuable_hits:
                _logger.info("valuable artifacts found: %d patterns", len(valuable_hits))
        except Exception:
            pass
        # 资源树写入firmware_info
        self.firmware_info['resource_tree'] = self.resource_tree.flatten()
        summary = {'session_id': self.session_id, 'firmware_path': self.firmware_path,
                   'firmware_size': os.path.getsize(self.firmware_path),
                   'detected_formats': [f.name for f in formats],
                   'output_dir': output_dir, 'extracted_files_count': len(self.extracted_files),
                   'extracted_files': self.extracted_files, 'firmware_info': self.firmware_info}
        _logger.info(f"Firmware extraction complete, extracted {len(self.extracted_files)} files")
        return summary

    def _sweep_for_secrets(self, base_dir: str) -> list[dict]:
        findings = []
        for dirpath, _, fnames in os.walk(base_dir):
            for fname in fnames:
                full = os.path.join(dirpath, fname)
                if os.path.getsize(full) > 10 * 1024 * 1024:
                    continue
                try:
                    with open(full, 'rb') as fh:
                        chunk = fh.read()
                    for label, pat in _VALUABLE_PATTERNS.items():
                        for m in pat.finditer(chunk):
                            findings.append({'file': os.path.relpath(full, base_dir),
                                             'type': label, 'offset': m.start(),
                                             'snippet': m.group()[:80]})
                except (OSError, UnicodeDecodeError):
                    continue
        return findings

    def _extract_with_binwalk(self, output_dir):
        try:
            cmd = ['binwalk', '-e', '--directory', output_dir, '--dd', '.*', self.firmware_path]
            _logger.info(f"Executing binwalk: {mask_sensitive_data(' '.join(cmd))}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, cwd=output_dir)
            if result.returncode == 0:
                _logger.info("binwalk extraction succeeded"); return True
            else:
                _logger.warning(f"binwalk extraction failed: {result.stderr[:200]}"); return False
        except subprocess.TimeoutExpired:
            _logger.warning("binwalk extraction timed out"); return False
        except Exception as e:
            _logger.error(f"binwalk extraction error: {e}"); return False

    def _extract_pure_python(self, formats, output_dir):
        success = False
        try:
            with open(self.firmware_path, 'rb') as f:
                data = f.read()
            compressors = []; sequential = []
            for fmt in formats:
                if fmt.name.startswith(('GZIP', 'BZIP2', 'XZ', 'LZMA', 'ZSTD', 'LZ4')):
                    compressors.append(fmt)
                else:
                    sequential.append(fmt)
            if len(compressors) >= 2:
                with ThreadPoolExecutor(max_workers=min(len(compressors), 4)) as pool:
                    futures = {pool.submit(self._decompress_one, data, fmt.offset, fmt.name, output_dir): fmt
                               for fmt in compressors}
                    for fut in as_completed(futures):
                        try:
                            if fut.result():
                                success = True
                        except Exception:
                            pass
            else:
                for fmt in compressors:
                    success |= self._dispatch_decompress(data, fmt.offset, fmt.name, output_dir)
            for fmt in sequential:
                success |= self._dispatch_decompress(data, fmt.offset, fmt.name, output_dir)
            if not success and formats:
                _logger.info("Attempting to extract as raw binary")
                raw_output = os.path.join(output_dir, 'firmware_raw.bin')
                with open(raw_output, 'wb') as f:
                    f.write(data)
                success = True
            streams = self._scan_deflate_streams(data)
            if streams:
                _logger.info("%d deflate streams detected; attempting recovery", len(streams))
                for idx, st in enumerate(streams[:8]):
                    try:
                        decomp = zlib.decompress(data[st['offset']:], -15)
                        out = os.path.join(output_dir, f"deflate_stream_{idx}_{st['offset']:08x}.bin")
                        with open(out, 'wb') as fh:
                            fh.write(decomp)
                        success = True
                    except Exception:
                        pass
            entropy_segs = self._entropy_window_scan(data)
            if entropy_segs:
                self.firmware_info['entropy_segments'] = entropy_segs[:16]
        except Exception as e:
            _logger.error(f"Pure Python extraction failed: {e}")
        return success

    def _dispatch_decompress(self, data, offset, name, output_dir):
        if name.startswith('GZIP'):
            return self._extract_gzip(data, offset, output_dir)
        elif name.startswith('BZIP2'):
            return self._extract_bzip2(data, offset, output_dir)
        elif name.startswith('XZ'):
            return self._extract_xz(data, offset, output_dir)
        elif name.startswith('LZMA'):
            return self._extract_lzma(data, offset, output_dir)
        elif name.startswith('ZIP'):
            return self._extract_zip(data, offset, output_dir)
        elif name.startswith('uImage'):
            return self._extract_uimage(data, offset, output_dir)
        elif name.startswith('SquashFS'):
            return self._extract_squashfs(data, offset, output_dir)
        elif name.startswith('CPIO'):
            return self._extract_cpio(data, offset, output_dir)
        elif name.startswith('ZSTD'):
            return self._extract_zstd(data, offset, output_dir)
        elif name.startswith('LZ4'):
            return self._extract_lz4(data, offset, output_dir)
        return False

    def _decompress_one(self, data, offset, name, output_dir):
        return self._dispatch_decompress(data, offset, name, output_dir)

    def _extract_zstd(self, data, offset, output_dir):
        try:
            import zstandard as zstd_mod
            decompressed = zstd_mod.ZstdDecompressor().decompress(data[offset:])
        except ImportError:
            _logger.debug("zstandard not installed; skipping ZSTD extraction"); return False
        except Exception as e:
            _logger.debug(f"ZSTD decompression failed: {e}"); return False
        output_path = os.path.join(output_dir, f'extracted_{offset}.zst.bin')
        with open(output_path, 'wb') as f:
            f.write(decompressed)
        _logger.info(f"Extracted ZSTD data to: {output_path}"); return True

    def _extract_lz4(self, data, offset, output_dir):
        try:
            import lz4.block
            decompressed = lz4.block.decompress(data[offset:])
        except ImportError:
            _logger.debug("lz4 not installed; skipping LZ4 extraction"); return False
        except Exception as e:
            _logger.debug(f"LZ4 decompression failed: {e}"); return False
        output_path = os.path.join(output_dir, f'extracted_{offset}.lz4.bin')
        with open(output_path, 'wb') as f:
            f.write(decompressed)
        _logger.info(f"Extracted LZ4 data to: {output_path}"); return True

    def _extract_gzip(self, data, offset, output_dir):
        try:
            decompressed = zlib.decompress(data[offset:], zlib.MAX_WBITS | 16)
            output_path = os.path.join(output_dir, f'extracted_{offset}.bin')
            with open(output_path, 'wb') as f:
                f.write(decompressed)
            _logger.info(f"Extracted GZIP data to: {output_path}"); return True
        except Exception as e:
            _logger.debug(f"GZIP decompression failed: {e}"); return False

    def _extract_bzip2(self, data, offset, output_dir):
        try:
            decompressed = bz2.decompress(data[offset:])
            output_path = os.path.join(output_dir, f'extracted_{offset}.bz2.bin')
            with open(output_path, 'wb') as f:
                f.write(decompressed)
            _logger.info(f"Extracted BZIP2 data to: {output_path}"); return True
        except Exception as e:
            _logger.debug(f"BZIP2 decompression failed: {e}"); return False

    def _extract_xz(self, data, offset, output_dir):
        try:
            decompressed = lzma.decompress(data[offset:])
            output_path = os.path.join(output_dir, f'extracted_{offset}.xz.bin')
            with open(output_path, 'wb') as f:
                f.write(decompressed)
            _logger.info(f"Extracted XZ data to: {output_path}"); return True
        except Exception as e:
            _logger.debug(f"XZ decompression failed: {e}"); return False

    def _extract_lzma(self, data, offset, output_dir):
        try:
            decompressed = lzma.decompress(data[offset:])
            output_path = os.path.join(output_dir, f'extracted_{offset}.lzma.bin')
            with open(output_path, 'wb') as f:
                f.write(decompressed)
            _logger.info(f"Extracted LZMA data to: {output_path}"); return True
        except Exception as e:
            _logger.debug(f"LZMA decompression failed: {e}"); return False

    def _extract_zip(self, data, offset, output_dir):
        try:
            zip_output = os.path.join(output_dir, f'zip_extract_{offset}')
            os.makedirs(zip_output, exist_ok=True)
            with tempfile.NamedTemporaryFile(mode='wb', suffix='.zip', delete=False) as f:
                f.write(data[offset:])
                temp_path = f.name
            with zipfile.ZipFile(temp_path, 'r') as zf:
                zf.extractall(zip_output)
            os.unlink(temp_path)
            _logger.info(f"Extracted ZIP archive to: {zip_output}"); return True
        except Exception as e:
            _logger.debug(f"ZIP extraction failed: {e}"); return False

    def _extract_uimage(self, data, offset, output_dir):
        try:
            if len(data) < offset + 64:
                return False
            header = data[offset:offset + 64]
            if struct.unpack_from('<I', header, 0)[0] != 0x27051956:
                return False
            data_size = struct.unpack_from('<I', header, 16)[0]
            load_addr = struct.unpack_from('<I', header, 20)[0]
            entry_addr = struct.unpack_from('<I', header, 24)[0]
            self.firmware_info['uimage'] = {'magic': hex(0x27051956), 'data_size': data_size,
                                            'load_address': hex(load_addr), 'entry_address': hex(entry_addr)}
            output_path = os.path.join(output_dir, 'uimage_kernel.bin')
            with open(output_path, 'wb') as f:
                f.write(data[offset + 64:offset + 64 + data_size])
            self.resource_tree.add_child(ResourceNode(label="uImage kernel", offset=offset + 64,
                                                      size=data_size, fmt="kernel"))
            _logger.info(f"Extracted uImage kernel to: {output_path}"); return True
        except Exception as e:
            _logger.debug(f"uImage extraction failed: {e}"); return False

    def _extract_squashfs(self, data, offset, output_dir):
        try:
            if self.use_jefferson:
                return self._extract_squashfs_jefferson(data, offset, output_dir)
            else:
                _logger.warning("Cannot extract SquashFS: jefferson required"); return False
        except Exception as e:
            _logger.debug(f"SquashFS extraction failed: {e}"); return False

    def _extract_squashfs_jefferson(self, data, offset, output_dir):
        try:
            squashfs_output = os.path.join(output_dir, 'squashfs_extract')
            os.makedirs(squashfs_output, exist_ok=True)
            with tempfile.NamedTemporaryFile(mode='wb', suffix='.sqfs', delete=False) as f:
                f.write(data[offset:]); temp_path = f.name
            result = subprocess.run(['jefferson', '-d', squashfs_output, temp_path],
                                    capture_output=True, text=True, timeout=120)
            os.unlink(temp_path)
            if result.returncode == 0:
                _logger.info(f"Extracted SquashFS to: {squashfs_output}"); return True
            else:
                _logger.warning(f"jefferson failed: {result.stderr[:200]}"); return False
        except Exception as e:
            _logger.debug(f"jefferson extraction failed: {e}"); return False

    def _extract_cpio(self, data, offset, output_dir):
        try:
            cpio_output = os.path.join(output_dir, f'cpio_extract_{offset}')
            os.makedirs(cpio_output, exist_ok=True)
            with tempfile.NamedTemporaryFile(mode='wb', suffix='.cpio', delete=False) as f:
                f.write(data[offset:]); temp_path = f.name
            result = subprocess.run(['cpio', '-idmv', '-I', temp_path],
                                    capture_output=True, text=True, timeout=60, cwd=cpio_output)
            os.unlink(temp_path)
            if result.returncode == 0:
                _logger.info(f"Extracted CPIO archive to: {cpio_output}"); return True
            else:
                _logger.debug(f"CPIO extraction failed: {result.stderr[:200]}"); return False
        except Exception as e:
            _logger.debug(f"CPIO extraction failed: {e}"); return False

    def _scan_extracted_files(self, base_dir, filter_pattern=None):
        files = []; visited_dirs = set()
        try:
            for root, dirs, filenames in os.walk(base_dir):
                if root in visited_dirs:
                    continue
                visited_dirs.add(root)
                for filename in filenames:
                    full_path = os.path.join(root, filename)
                    try:
                        rel_path = os.path.relpath(full_path, base_dir)
                        if filter_pattern is not None and not self._matches_pattern(rel_path, filter_pattern):
                            continue
                        file_info = {'path': full_path, 'relative_path': rel_path,
                                     'name': filename, 'size': os.path.getsize(full_path),
                                     'is_executable': os.access(full_path, os.X_OK),
                                     'file_type': self._detect_file_type(full_path),
                                     'source_firmware': os.path.basename(self.firmware_path)}
                        files.append(file_info)
                        if file_info['file_type'] == 'ELF':
                            _logger.info(f"Found executable: {rel_path}")
                    except Exception as e:
                        _logger.debug(f"Failed to process file {full_path}: {e}")
            files.sort(key=lambda x: (0 if x['file_type'] == 'ELF' else 1, x['relative_path']))
        except Exception as e:
            _logger.error(f"Scan extracted files failed: {e}")
        return files

    def _matches_pattern(self, path, pattern):
        try:
            import fnmatch; return fnmatch.fnmatch(path, pattern)
        except Exception:
            return pattern.lower() in path.lower()

    def _detect_file_type(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)
            if header.startswith(b'\x7fELF'):
                return 'ELF'
            elif header.startswith(b'MZ'):
                return 'PE'
            elif header.startswith(b'\xca\xfe\xba\xbe') or header.startswith(b'\xfe\xed\xfa\xce'):
                return 'MACH-O'
            elif header.startswith(b'#!'):
                return 'SCRIPT'
            elif header.startswith(b'PK\x03\x04'):
                return 'ZIP'
            elif header.startswith(b'\x1f\x8b\x08'):
                return 'GZIP'
            elif header.startswith(b'root:x:'):
                return 'PASSWD'
            elif header[:4] in (b'HSQS', b'hsqs'):
                return 'SQUASHFS'
            elif header.startswith(b'\x89PNG'):
                return 'PNG'
            elif header.startswith(b'\xff\xd8\xff'):
                return 'JPEG'
            elif header[:2] == b'\x7b\n' or header[:1] == b'{':
                return 'JSON'
            elif header[:5] == b'<?xml':
                return 'XML'
            elif header[:2] == b'\x1b[':
                return 'ANSI_LOG'
            elif header.startswith(b'\x28\xb5\x2f\xfd'):
                return 'ZSTD'
            else:
                for fmt_name, magic in _NESTED_MAGICS.items():
                    if header.startswith(magic):
                        return fmt_name
                return 'UNKNOWN'
        except Exception:
            return 'UNKNOWN'

    def get_analysis_targets(self):
        return [f['path'] for f in self.extracted_files if f['file_type'] == 'ELF']

    def generate_summary(self):
        # 上下文连贯
        lines = ["## Firmware Analysis Summary", "",
                 f"- Firmware file: {os.path.basename(self.firmware_path)}",
                 f"- Firmware size: {self._format_size(os.path.getsize(self.firmware_path))}",
                 f"- Extraction session: {self.session_id}", ""]
        if self.firmware_info:
            lines.append("### Firmware Info")
            if 'entropy' in self.firmware_info:
                lines.append(f"- Entropy: {self.firmware_info['entropy']:.2f}")
            if 'secrets_found' in self.firmware_info:
                lines.append(f"- Sensitive artifacts detected: {self.firmware_info['secrets_found']}")
            if 'nested_images' in self.firmware_info:
                lines.append(f"- Nested firmware images: {self.firmware_info['nested_images']}")
            if 'uimage' in self.firmware_info:
                uinfo = self.firmware_info['uimage']
                lines.append(f"- uImage Magic: {uinfo.get('magic')}")
                lines.append(f"- Data size: {self._format_size(uinfo.get('data_size', 0))}")
                lines.append(f"- Load address: {uinfo.get('load_address')}")
                lines.append(f"- Entry address: {uinfo.get('entry_address')}")
            if 'entropy_segments' in self.firmware_info:
                segs = self.firmware_info['entropy_segments']
                lines.append(f"- High-entropy segments: {len(segs)}")
                for s in segs[:3]:
                    lines.append(f"  - offset={hex(s['offset'])}, size={self._format_size(s['size'])}")
            lines.append("")
        lines.append("### Extracted File Statistics")
        elf_count = sum(1 for f in self.extracted_files if f['file_type'] == 'ELF')
        script_count = sum(1 for f in self.extracted_files if f['file_type'] == 'SCRIPT')
        passwd_count = sum(1 for f in self.extracted_files if f['file_type'] == 'PASSWD')
        lines.append(f"- Total files: {len(self.extracted_files)}")
        lines.append(f"- ELF executables: {elf_count}")
        lines.append(f"- Script files: {script_count}")
        lines.append(f"- Config files: {passwd_count}")
        lines.append("")
        if self.extracted_files:
            lines.append("### Extracted ELF Files")
            elf_files = [f for f in self.extracted_files if f['file_type'] == 'ELF']
            limit = min(10, len(elf_files))
            for i in range(limit):
                f = elf_files[i]
                lines.append(f"- `{f['relative_path']}` ({self._format_size(f['size'])})")
            if len(elf_files) > 10:
                lines.append(f"- ... and {len(elf_files) - 10} more files")
        return '\n'.join(lines)

    def _format_size(self, size):
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.2f} KB"
        else:
            return f"{size / (1024 * 1024):.2f} MB"

    def cleanup(self):
        output_dir = os.path.join(self.output_base_dir, self.session_id)
        if os.path.exists(output_dir):
            try:
                shutil.rmtree(output_dir)
                _logger.info(f"Cleaned up temp directory: {output_dir}")
            except Exception as e:
                _logger.warning(f"Failed to clean up temp directory: {e}")


def create_firmware_extractor(firmware_path, output_base_dir=None, use_binwalk=True, use_jefferson=True):
    return FirmwareExtractor(firmware_path=firmware_path, output_base_dir=output_base_dir,
                             use_binwalk=use_binwalk, use_jefferson=use_jefferson)
