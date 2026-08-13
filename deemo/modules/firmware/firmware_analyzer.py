import logging
import os
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
from dataclasses import dataclass, field
from typing import Optional

from core.config import Config, mask_sensitive_data

logger = logging.getLogger(__name__)


FIRMWARE_MAGICS = {
    'uImage': b'\x27\x05\x19\x56',
    'TRX': b'HDR0',
    'SquashFS': b'hsqs',
    'SquashFS_LZ4': b'lz4s',
    'SquashFS_XZ': b'xzsq',
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
    'Android_Sparse': b'\x3a\xff\x26\xed',
    'Apple_DMG': b'\x45\x52\x00\x00\x00',
}

FIRMWARE_EXTENSIONS = {
    '.bin': 'generic',
    '.img': 'generic',
    '.fw': 'firmware',
    '.firmware': 'firmware',
    '.rom': 'rom',
    '.sbin': 'sbin',
    '.zImage': 'kernel',
    '.uImage': 'uImage',
    '.trx': 'TRX',
    '.sqfs': 'SquashFS',
    '.squashfs': 'SquashFS',
    '.jffs2': 'JFFS2',
    '.ubifs': 'UBIFS',
    '.yaffs2': 'YAFFS2',
    '.cpio': 'CPIO',
    '.iso': 'ISO9660',
    '.zip': 'ZIP',
    '.gz': 'GZIP',
    '.bz2': 'BZIP2',
    '.xz': 'XZ',
    '.lzma': 'LZMA',
    '.lzo': 'LZO',
    '.lz4': 'LZ4',
}


@dataclass
class FirmwareFormat:
    name: str
    offset: int = 0
    size: int = 0
    compression: Optional[str] = None
    confidence: float = 0.0

    def __repr__(self):
        return f"FirmwareFormat(name={self.name}, offset={self.offset}, size={self.size})"

class FirmwareExtractor:
    """
    Embedded firmware analysis and extraction engine.

    Capabilities:
    1. Auto-detect firmware image format (uImage, TRX, SquashFS, JFFS2, UBIFS, etc.)
    2. Extract file systems and kernel modules
    3. Scan extracted binaries and key configuration files
    4. Support binwalk, jefferson, and pure-Python fallback paths
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

        binwalk_status = 'enabled' if self.use_binwalk else 'disabled'
        jefferson_status = 'enabled' if self.use_jefferson else 'disabled'
        logger.info(
            f"FirmwareExtractor initialized: "
            f"firmware={self.firmware_path}, "
            f"binwalk={binwalk_status}, "
            f"jefferson={jefferson_status}"
        )

    def _validate_path(self, path):
        if not path or not isinstance(path, str):
            raise ValueError("Firmware path cannot be empty")

        dangerous_patterns = [r'\.\.', r'\$\(', r'`', r'\|\|', r'&&', r';']

        import re
        for pattern in dangerous_patterns:
            if re.search(pattern, path):
                logger.warning(f"Detected dangerous path pattern: {repr(path)}")
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
            result = subprocess.run(
                ['binwalk', '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                version = result.stdout.strip().split('\n')[0]
                logger.info(f"binwalk installed: {version}")
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        logger.warning("binwalk unavailable, using pure Python parsing")
        return False

    def _check_jefferson_available(self):
        try:
            result = subprocess.run(
                ['jefferson', '--help'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                logger.info("jefferson installed")
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        logger.warning("jefferson unavailable, using pure Python parsing")
        return False

    def _check_ubi_reader_available(self):
        try:
            import ubi_reader
            logger.info("ubi_reader installed")
            return True
        except ImportError:
            logger.warning("ubi_reader unavailable")
            return False

    def detect_firmware_format(self):
        """Identify firmware image format via magic bytes, extension, and entropy heuristics."""
        formats = []

        try:
            with open(self.firmware_path, 'rb') as f:
                file_size = os.path.getsize(self.firmware_path)

                offsets_to_check = [0, 512, 1024, 2048]
                for offset in offsets_to_check:
                    if offset >= file_size:
                        continue

                    f.seek(offset)
                    data = f.read(128)

                    for format_name, magic in FIRMWARE_MAGICS.items():
                        if data.startswith(magic):
                            confidence = self._calculate_confidence(format_name, data)
                            formats.append(FirmwareFormat(
                                name=format_name,
                                offset=offset,
                                confidence=confidence
                            ))

            ext = os.path.splitext(self.firmware_path)[1].lower()
            if ext in FIRMWARE_EXTENSIONS:
                ext_format = FIRMWARE_EXTENSIONS[ext]
                formats.append(FirmwareFormat(
                    name=f"{ext_format}_by_extension",
                    offset=0,
                    confidence=0.7
                ))

            entropy = self._calculate_entropy()
            self.firmware_info['entropy'] = entropy
            if entropy > 7.5:
                formats.append(FirmwareFormat(
                    name='compressed_encrypted',
                    offset=0,
                    confidence=0.6
                ))

            formats.sort(key=lambda x: x.confidence, reverse=True)

            if formats:
                names = [f.name for f in formats[:3]]
                logger.info(f"Detected firmware formats: {names}")
            else:
                logger.warning("No known firmware format detected")

            return formats

        except Exception as e:
            logger.error(f"Format detection failed: {e}")
            return []

    def _calculate_confidence(self, format_name, data):
        confidence = 0.5

        if format_name in ['uImage', 'TRX']:
            if len(data) >= 64:
                confidence += 0.3
                if format_name == 'uImage':
                    header_crc = struct.unpack_from('<I', data, 4)[0]
                    actual_crc = zlib.crc32(data[8:64]) & 0xffffffff
                    if header_crc == actual_crc:
                        confidence += 0.15

        elif format_name == 'SquashFS':
            if len(data) >= 16:
                magic = struct.unpack_from('<I', data, 0)[0]
                if magic == 0x73717368:
                    confidence += 0.4

        elif format_name in ['GZIP', 'BZIP2', 'XZ', 'LZMA']:
            confidence += 0.3

        return min(confidence, 0.95)

    def _calculate_entropy(self):
        """Estimate Shannon entropy over the first 1 MB; values above 7.5 suggest compression or encryption."""
        try:
            with open(self.firmware_path, 'rb') as f:
                data = f.read(1024 * 1024)

            if not data:
                return 0.0

            byte_counts = [0] * 256

            for byte_val in data:
                byte_counts[byte_val] += 1

            total = len(data)
            entropy = 0.0
            for cnt in byte_counts:
                if cnt > 0:
                    prob = cnt / total
                    entropy -= prob * (prob ** -1).bit_length() / 8

            return entropy

        except Exception as e:
            logger.debug(f"Entropy calculation failed: {e}")
            return 0.0

    def extract_firmware(self, filter_pattern=None):
        """Extract firmware contents: detect format, decompress, and scan output tree."""
        output_dir = os.path.join(self.output_base_dir, self.session_id)
        os.makedirs(output_dir, exist_ok=True)
        os.chmod(output_dir, 0o700)

        logger.info(f"Starting firmware extraction to: {output_dir}")

        formats = self.detect_firmware_format()

        if self.use_binwalk:
            result = self._extract_with_binwalk(output_dir)
        else:
            result = self._extract_pure_python(formats, output_dir)

        self.extracted_files = self._scan_extracted_files(output_dir, filter_pattern)

        summary = {
            'session_id': self.session_id,
            'firmware_path': self.firmware_path,
            'firmware_size': os.path.getsize(self.firmware_path),
            'detected_formats': [f.name for f in formats],
            'output_dir': output_dir,
            'extracted_files_count': len(self.extracted_files),
            'extracted_files': self.extracted_files,
            'firmware_info': self.firmware_info
        }

        logger.info(f"Firmware extraction complete, extracted {len(self.extracted_files)} files")

        return summary

    def _extract_with_binwalk(self, output_dir):
        try:
            cmd = [
                'binwalk',
                '-e',
                '--directory', output_dir,
                '--dd', '.*',
                self.firmware_path
            ]

            safe_cmd = mask_sensitive_data(' '.join(cmd))

            logger.info(f"Executing binwalk: {safe_cmd}")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                cwd=output_dir
            )

            if result.returncode == 0:
                logger.info("binwalk extraction succeeded")
                return True
            else:
                logger.warning(f"binwalk extraction failed: {result.stderr[:200]}")
                return False

        except subprocess.TimeoutExpired:
            logger.warning("binwalk extraction timed out")
            return False
        except Exception as e:
            logger.error(f"binwalk extraction error: {e}")
            return False

    def _extract_pure_python(self, formats, output_dir):
        success = False

        try:
            with open(self.firmware_path, 'rb') as f:
                data = f.read()

            for fmt in formats:
                name = fmt.name

                if name.startswith('GZIP'):
                    success |= self._extract_gzip(data, fmt.offset, output_dir)
                elif name.startswith('BZIP2'):
                    success |= self._extract_bzip2(data, fmt.offset, output_dir)
                elif name.startswith('XZ'):
                    success |= self._extract_xz(data, fmt.offset, output_dir)
                elif name.startswith('LZMA'):
                    success |= self._extract_lzma(data, fmt.offset, output_dir)
                elif name.startswith('ZIP'):
                    success |= self._extract_zip(data, fmt.offset, output_dir)
                elif name.startswith('uImage'):
                    success |= self._extract_uimage(data, fmt.offset, output_dir)
                elif name.startswith('SquashFS'):
                    success |= self._extract_squashfs(data, fmt.offset, output_dir)
                elif name.startswith('CPIO'):
                    success |= self._extract_cpio(data, fmt.offset, output_dir)

            if not success and formats:
                logger.info("Attempting to extract as raw binary")
                raw_output = os.path.join(output_dir, 'firmware_raw.bin')
                with open(raw_output, 'wb') as f:
                    f.write(data)
                success = True

        except Exception as e:
            logger.error(f"Pure Python extraction failed: {e}")

        return success

    def _extract_gzip(self, data, offset, output_dir):
        try:
            decompressed = zlib.decompress(data[offset:], zlib.MAX_WBITS | 16)
            output_path = os.path.join(output_dir, f'extracted_{offset}.bin')
            with open(output_path, 'wb') as f:
                f.write(decompressed)
            logger.info(f"Extracted GZIP data to: {output_path}")
            return True
        except Exception as e:
            logger.debug(f"GZIP decompression failed: {e}")
            return False

    def _extract_bzip2(self, data, offset, output_dir):
        try:
            decompressed = bz2.decompress(data[offset:])
            output_path = os.path.join(output_dir, f'extracted_{offset}.bz2.bin')
            with open(output_path, 'wb') as f:
                f.write(decompressed)
            logger.info(f"Extracted BZIP2 data to: {output_path}")
            return True
        except Exception as e:
            logger.debug(f"BZIP2 decompression failed: {e}")
            return False

    def _extract_xz(self, data, offset, output_dir):
        try:
            decompressed = lzma.decompress(data[offset:])
            output_path = os.path.join(output_dir, f'extracted_{offset}.xz.bin')
            with open(output_path, 'wb') as f:
                f.write(decompressed)
            logger.info(f"Extracted XZ data to: {output_path}")
            return True
        except Exception as e:
            logger.debug(f"XZ decompression failed: {e}")
            return False

    def _extract_lzma(self, data, offset, output_dir):
        try:
            decompressed = lzma.decompress(data[offset:])
            output_path = os.path.join(output_dir, f'extracted_{offset}.lzma.bin')
            with open(output_path, 'wb') as f:
                f.write(decompressed)
            logger.info(f"Extracted LZMA data to: {output_path}")
            return True
        except Exception as e:
            logger.debug(f"LZMA decompression failed: {e}")
            return False

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
            logger.info(f"Extracted ZIP archive to: {zip_output}")
            return True
        except Exception as e:
            logger.debug(f"ZIP extraction failed: {e}")
            return False

    def _extract_uimage(self, data, offset, output_dir):
        try:
            if len(data) < offset + 64:
                return False

            header = data[offset:offset + 64]
            magic = struct.unpack_from('<I', header, 0)[0]
            if magic != 0x27051956:
                return False

            data_size = struct.unpack_from('<I', header, 16)[0]
            load_addr = struct.unpack_from('<I', header, 20)[0]
            entry_addr = struct.unpack_from('<I', header, 24)[0]

            self.firmware_info['uimage'] = {
                'magic': hex(magic),
                'data_size': data_size,
                'load_address': hex(load_addr),
                'entry_address': hex(entry_addr)
            }

            output_path = os.path.join(output_dir, 'uimage_kernel.bin')
            with open(output_path, 'wb') as f:
                f.write(data[offset + 64:offset + 64 + data_size])

            logger.info(f"Extracted uImage kernel to: {output_path}")
            return True
        except Exception as e:
            logger.debug(f"uImage extraction failed: {e}")
            return False

    def _extract_squashfs(self, data, offset, output_dir):
        try:
            if self.use_jefferson:
                return self._extract_squashfs_jefferson(data, offset, output_dir)
            else:
                logger.warning("Cannot extract SquashFS: jefferson required")
                return False
        except Exception as e:
            logger.debug(f"SquashFS extraction failed: {e}")
            return False

    def _extract_squashfs_jefferson(self, data, offset, output_dir):
        try:
            squashfs_output = os.path.join(output_dir, 'squashfs_extract')
            os.makedirs(squashfs_output, exist_ok=True)

            with tempfile.NamedTemporaryFile(mode='wb', suffix='.sqfs', delete=False) as f:
                f.write(data[offset:])
                temp_path = f.name

            cmd = ['jefferson', '-d', squashfs_output, temp_path]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )

            os.unlink(temp_path)

            if result.returncode == 0:
                logger.info(f"Extracted SquashFS to: {squashfs_output}")
                return True
            else:
                logger.warning(f"jefferson failed: {result.stderr[:200]}")
                return False

        except Exception as e:
            logger.debug(f"jefferson extraction failed: {e}")
            return False

    def _extract_cpio(self, data, offset, output_dir):
        try:
            cpio_output = os.path.join(output_dir, f'cpio_extract_{offset}')
            os.makedirs(cpio_output, exist_ok=True)

            with tempfile.NamedTemporaryFile(mode='wb', suffix='.cpio', delete=False) as f:
                f.write(data[offset:])
                temp_path = f.name

            cmd = ['cpio', '-idmv', '-I', temp_path]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                cwd=cpio_output
            )

            os.unlink(temp_path)

            if result.returncode == 0:
                logger.info(f"Extracted CPIO archive to: {cpio_output}")
                return True
            else:
                logger.debug(f"CPIO extraction failed: {result.stderr[:200]}")
                return False

        except Exception as e:
            logger.debug(f"CPIO extraction failed: {e}")
            return False

    def _scan_extracted_files(self, base_dir, filter_pattern=None):
        files = []
        visited_dirs = set()

        try:
            for root, dirs, filenames in os.walk(base_dir):
                if root in visited_dirs:
                    continue
                visited_dirs.add(root)

                for filename in filenames:
                    full_path = os.path.join(root, filename)

                    try:
                        rel_path = os.path.relpath(full_path, base_dir)

                        if filter_pattern is not None:
                            if not self._matches_pattern(rel_path, filter_pattern):
                                continue

                        file_info = {
                            'path': full_path,
                            'relative_path': rel_path,
                            'name': filename,
                            'size': os.path.getsize(full_path),
                            'is_executable': os.access(full_path, os.X_OK),
                            'file_type': self._detect_file_type(full_path),
                            'source_firmware': os.path.basename(self.firmware_path)
                        }

                        files.append(file_info)

                        if file_info['file_type'] == 'ELF':
                            logger.info(f"Found executable: {rel_path}")

                    except Exception as e:
                        logger.debug(f"Failed to process file {full_path}: {e}")

            files.sort(key=lambda x: (
                0 if x['file_type'] == 'ELF' else 1,
                x['relative_path']
            ))

        except Exception as e:
            logger.error(f"Scan extracted files failed: {e}")

        return files

    def _matches_pattern(self, path, pattern):
        try:
            import fnmatch
            return fnmatch.fnmatch(path, pattern)
        except Exception:
            return pattern.lower() in path.lower()

    def _detect_file_type(self, file_path):
        """Classify file by reading the first 16 bytes and matching against known magic signatures."""
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
            elif header[:4] == b'HSQS' or header[:4] == b'hsqs':
                return 'SQUASHFS'
            else:
                return 'UNKNOWN'

        except Exception:
            return 'UNKNOWN'

    def get_analysis_targets(self):
        targets = []
        for file_info in self.extracted_files:
            if file_info['file_type'] == 'ELF':
                targets.append(file_info['path'])
        return targets

    def generate_summary(self):
        lines = []
        lines.append("## Firmware Analysis Summary")
        lines.append("")
        lines.append(f"- Firmware file: {os.path.basename(self.firmware_path)}")
        lines.append(f"- Firmware size: {self._format_size(os.path.getsize(self.firmware_path))}")
        lines.append(f"- Extraction session: {self.session_id}")
        lines.append("")

        if self.firmware_info:
            lines.append("### Firmware Info")
            if 'entropy' in self.firmware_info:
                lines.append(f"- Entropy: {self.firmware_info['entropy']:.2f}")
            if 'uimage' in self.firmware_info:
                uinfo = self.firmware_info['uimage']
                lines.append(f"- uImage Magic: {uinfo.get('magic')}")
                lines.append(f"- Data size: {self._format_size(uinfo.get('data_size', 0))}")
                lines.append(f"- Load address: {uinfo.get('load_address')}")
                lines.append(f"- Entry address: {uinfo.get('entry_address')}")
            lines.append("")

        lines.append("### Extracted File Statistics")

        elf_count = 0
        script_count = 0
        passwd_count = 0
        for file_info in self.extracted_files:
            ftype = file_info['file_type']
            if ftype == 'ELF':
                elf_count += 1
            elif ftype == 'SCRIPT':
                script_count += 1
            elif ftype == 'PASSWD':
                passwd_count += 1

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
        """Render byte count as B / KB / MB with 2 decimal places."""
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
                logger.info(f"Cleaned up temp directory: {output_dir}")
            except Exception as e:
                logger.warning(f"Failed to clean up temp directory: {e}")


def create_firmware_extractor(firmware_path, output_base_dir=None, use_binwalk=True, use_jefferson=True):
    """Factory: construct a FirmwareExtractor with the given parameters."""
    return FirmwareExtractor(
        firmware_path=firmware_path,
        output_base_dir=output_base_dir,
        use_binwalk=use_binwalk,
        use_jefferson=use_jefferson
    )
