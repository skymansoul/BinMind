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
from typing import Dict, List, Optional, Tuple, Any, Set
from pathlib import Path

from config import Config, mask_sensitive_data

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


class FirmwareFormat:
    """固件格式识别结果"""
    
    def __init__(
        self,
        name: str,
        offset: int = 0,
        size: int = 0,
        compression: str = None,
        confidence: float = 0.0
    ):
        self.name = name
        self.offset = offset
        self.size = size
        self.compression = compression
        self.confidence = confidence
    
    def __repr__(self):
        return f"FirmwareFormat(name={self.name}, offset={self.offset}, size={self.size})"


class FirmwareExtractor:
    """
    嵌入式固件分析与解包模块
    
    核心功能：
    1. 自动识别固件镜像格式（uImage、TRX、SquashFS、JFFS2、UBIFS等）
    2. 提取文件系统和内核模块
    3. 扫描提取出的二进制文件和关键配置文件
    4. 支持 binwalk、jefferson 等工具，以及纯 Python 回退方案
    """
    
    def __init__(
        self,
        firmware_path: str,
        output_base_dir: str = None,
        use_binwalk: bool = True,
        use_jefferson: bool = True
    ):
        """
        初始化固件提取器
        
        Args:
            firmware_path: 固件文件路径
            output_base_dir: 输出基础目录
            use_binwalk: 是否使用 binwalk 工具
            use_jefferson: 是否使用 jefferson 工具
        """
        self.firmware_path = self._validate_path(firmware_path)
        self.output_base_dir = output_base_dir or os.path.join(Config.DATA_DIR, 'firmware_extracted')
        
        self.use_binwalk = use_binwalk and self._check_binwalk_available()
        self.use_jefferson = use_jefferson and self._check_jefferson_available()
        
        self.session_id = str(uuid.uuid4())[:8]
        self.extracted_files: List[Dict[str, Any]] = []
        self.firmware_info: Dict[str, Any] = {}
        
        logger.info(
            f"FirmwareExtractor 初始化完成: "
            f"firmware={self.firmware_path}, "
            f"binwalk={'enabled' if self.use_binwalk else 'disabled'}, "
            f"jefferson={'enabled' if self.use_jefferson else 'disabled'}"
        )
    
    def _validate_path(self, path: str) -> str:
        """验证并规范化固件路径"""
        if not path or not isinstance(path, str):
            raise ValueError("固件路径不能为空")
        
        dangerous_patterns = [r'\.\.', r'\$\(', r'`', r'\|\|', r'&&', r';']
        for pattern in dangerous_patterns:
            import re
            if re.search(pattern, path):
                logger.warning(f"检测到危险路径模式: {repr(path)}")
                raise ValueError(f"路径包含危险字符: {path}")
        
        try:
            abs_path = os.path.abspath(os.path.expanduser(path))
        except Exception as e:
            raise ValueError(f"无法解析路径: {e}")
        
        if not os.path.isabs(abs_path):
            raise ValueError(f"路径必须是绝对路径: {abs_path}")
        
        if not os.path.exists(abs_path):
            raise ValueError(f"文件不存在: {abs_path}")
        
        return abs_path
    
    def _check_binwalk_available(self) -> bool:
        """检查 binwalk 是否可用"""
        try:
            result = subprocess.run(
                ['binwalk', '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                logger.info(f"binwalk 已安装: {result.stdout.strip().split('\n')[0]}")
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        logger.warning("binwalk 不可用，将使用纯 Python 解析")
        return False
    
    def _check_jefferson_available(self) -> bool:
        """检查 jefferson 是否可用"""
        try:
            result = subprocess.run(
                ['jefferson', '--help'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                logger.info("jefferson 已安装")
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        logger.warning("jefferson 不可用，将使用纯 Python 解析")
        return False
    
    def _check_ubi_reader_available(self) -> bool:
        """检查 ubi_reader 是否可用"""
        try:
            import ubi_reader
            logger.info("ubi_reader 已安装")
            return True
        except ImportError:
            logger.warning("ubi_reader 不可用")
            return False
    
    def detect_firmware_format(self) -> List[FirmwareFormat]:
        """
        检测固件镜像格式
        
        Returns:
            检测到的格式列表，按置信度排序
        """
        formats = []
        
        try:
            with open(self.firmware_path, 'rb') as f:
                file_size = os.path.getsize(self.firmware_path)
                
                for offset in [0, 512, 1024, 2048]:
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
            
            file_ext = os.path.splitext(self.firmware_path)[1].lower()
            if file_ext in FIRMWARE_EXTENSIONS:
                ext_format = FIRMWARE_EXTENSIONS[file_ext]
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
                logger.info(f"检测到固件格式: {[f.name for f in formats[:3]]}")
            else:
                logger.warning("未检测到已知固件格式")
            
            return formats
            
        except Exception as e:
            logger.error(f"检测固件格式失败: {e}")
            return []
    
    def _calculate_confidence(self, format_name: str, data: bytes) -> float:
        """计算格式识别置信度"""
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
    
    def _calculate_entropy(self) -> float:
        """计算文件熵值"""
        try:
            with open(self.firmware_path, 'rb') as f:
                data = f.read(1024 * 1024)
            
            if not data:
                return 0.0
            
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            entropy = 0.0
            total = len(data)
            for count in byte_counts:
                if count > 0:
                    prob = count / total
                    entropy -= prob * (prob ** -1).bit_length() / 8
            
            return entropy
        
        except Exception as e:
            logger.debug(f"计算熵值失败: {e}")
            return 0.0
    
    def extract_firmware(self, filter_pattern: str = None) -> Dict[str, Any]:
        """
        提取固件内容
        
        Args:
            filter_pattern: 文件过滤模式（如 '/bin/*'）
        
        Returns:
            提取结果摘要
        """
        output_dir = os.path.join(self.output_base_dir, self.session_id)
        os.makedirs(output_dir, exist_ok=True)
        os.chmod(output_dir, 0o700)
        
        logger.info(f"开始提取固件到: {output_dir}")
        
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
        
        logger.info(f"固件提取完成，共提取 {len(self.extracted_files)} 个文件")
        
        return summary
    
    def _extract_with_binwalk(self, output_dir: str) -> bool:
        """使用 binwalk 提取固件"""
        try:
            cmd = [
                'binwalk',
                '-e',
                '--directory', output_dir,
                '--dd', '.*',
                self.firmware_path
            ]
            
            safe_cmd = mask_sensitive_data(' '.join(cmd))
            logger.info(f"执行 binwalk: {safe_cmd}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                cwd=output_dir
            )
            
            if result.returncode == 0:
                logger.info("binwalk 提取成功")
                return True
            else:
                logger.warning(f"binwalk 提取失败: {result.stderr[:200]}")
                return False
        
        except subprocess.TimeoutExpired:
            logger.warning("binwalk 提取超时")
            return False
        except Exception as e:
            logger.error(f"binwalk 提取出错: {e}")
            return False
    
    def _extract_pure_python(self, formats: List[FirmwareFormat], output_dir: str) -> bool:
        """使用纯 Python 解析固件"""
        success = False
        
        try:
            with open(self.firmware_path, 'rb') as f:
                data = f.read()
            
            for fmt in formats:
                if fmt.name.startswith('GZIP'):
                    success |= self._extract_gzip(data, fmt.offset, output_dir)
                elif fmt.name.startswith('BZIP2'):
                    success |= self._extract_bzip2(data, fmt.offset, output_dir)
                elif fmt.name.startswith('XZ'):
                    success |= self._extract_xz(data, fmt.offset, output_dir)
                elif fmt.name.startswith('LZMA'):
                    success |= self._extract_lzma(data, fmt.offset, output_dir)
                elif fmt.name.startswith('ZIP'):
                    success |= self._extract_zip(data, fmt.offset, output_dir)
                elif fmt.name.startswith('uImage'):
                    success |= self._extract_uimage(data, fmt.offset, output_dir)
                elif fmt.name.startswith('SquashFS'):
                    success |= self._extract_squashfs(data, fmt.offset, output_dir)
                elif fmt.name.startswith('CPIO'):
                    success |= self._extract_cpio(data, fmt.offset, output_dir)
            
            if not success and formats:
                logger.info("尝试提取整个文件作为原始二进制")
                raw_output = os.path.join(output_dir, 'firmware_raw.bin')
                with open(raw_output, 'wb') as f:
                    f.write(data)
                success = True
            
        except Exception as e:
            logger.error(f"纯 Python 提取失败: {e}")
        
        return success
    
    def _extract_gzip(self, data: bytes, offset: int, output_dir: str) -> bool:
        """提取 GZIP 压缩数据"""
        try:
            decompressed = zlib.decompress(data[offset:], zlib.MAX_WBITS | 16)
            output_path = os.path.join(output_dir, f'extracted_{offset}.bin')
            with open(output_path, 'wb') as f:
                f.write(decompressed)
            logger.info(f"提取 GZIP 数据到: {output_path}")
            return True
        except Exception as e:
            logger.debug(f"GZIP 解压失败: {e}")
            return False
    
    def _extract_bzip2(self, data: bytes, offset: int, output_dir: str) -> bool:
        """提取 BZIP2 压缩数据"""
        try:
            decompressed = bz2.decompress(data[offset:])
            output_path = os.path.join(output_dir, f'extracted_{offset}.bz2.bin')
            with open(output_path, 'wb') as f:
                f.write(decompressed)
            logger.info(f"提取 BZIP2 数据到: {output_path}")
            return True
        except Exception as e:
            logger.debug(f"BZIP2 解压失败: {e}")
            return False
    
    def _extract_xz(self, data: bytes, offset: int, output_dir: str) -> bool:
        """提取 XZ 压缩数据"""
        try:
            decompressed = lzma.decompress(data[offset:])
            output_path = os.path.join(output_dir, f'extracted_{offset}.xz.bin')
            with open(output_path, 'wb') as f:
                f.write(decompressed)
            logger.info(f"提取 XZ 数据到: {output_path}")
            return True
        except Exception as e:
            logger.debug(f"XZ 解压失败: {e}")
            return False
    
    def _extract_lzma(self, data: bytes, offset: int, output_dir: str) -> bool:
        """提取 LZMA 压缩数据"""
        try:
            decompressed = lzma.decompress(data[offset:])
            output_path = os.path.join(output_dir, f'extracted_{offset}.lzma.bin')
            with open(output_path, 'wb') as f:
                f.write(decompressed)
            logger.info(f"提取 LZMA 数据到: {output_path}")
            return True
        except Exception as e:
            logger.debug(f"LZMA 解压失败: {e}")
            return False
    
    def _extract_zip(self, data: bytes, offset: int, output_dir: str) -> bool:
        """提取 ZIP 归档"""
        try:
            zip_output = os.path.join(output_dir, f'zip_extract_{offset}')
            os.makedirs(zip_output, exist_ok=True)
            
            with tempfile.NamedTemporaryFile(mode='wb', suffix='.zip', delete=False) as f:
                f.write(data[offset:])
                temp_path = f.name
            
            with zipfile.ZipFile(temp_path, 'r') as zf:
                zf.extractall(zip_output)
            
            os.unlink(temp_path)
            logger.info(f"提取 ZIP 归档到: {zip_output}")
            return True
        except Exception as e:
            logger.debug(f"ZIP 提取失败: {e}")
            return False
    
    def _extract_uimage(self, data: bytes, offset: int, output_dir: str) -> bool:
        """提取 uImage 格式"""
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
            
            logger.info(f"提取 uImage 内核到: {output_path}")
            return True
        except Exception as e:
            logger.debug(f"uImage 提取失败: {e}")
            return False
    
    def _extract_squashfs(self, data: bytes, offset: int, output_dir: str) -> bool:
        """提取 SquashFS 文件系统"""
        try:
            if self.use_jefferson:
                return self._extract_squashfs_jefferson(data, offset, output_dir)
            else:
                logger.warning("无法提取 SquashFS：需要 jefferson")
                return False
        except Exception as e:
            logger.debug(f"SquashFS 提取失败: {e}")
            return False
    
    def _extract_squashfs_jefferson(self, data: bytes, offset: int, output_dir: str) -> bool:
        """使用 jefferson 提取 SquashFS"""
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
                logger.info(f"提取 SquashFS 到: {squashfs_output}")
                return True
            else:
                logger.warning(f"jefferson 失败: {result.stderr[:200]}")
                return False
        
        except Exception as e:
            logger.debug(f"jefferson 提取失败: {e}")
            return False
    
    def _extract_cpio(self, data: bytes, offset: int, output_dir: str) -> bool:
        """提取 CPIO 归档"""
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
                logger.info(f"提取 CPIO 归档到: {cpio_output}")
                return True
            else:
                logger.debug(f"CPIO 提取失败: {result.stderr[:200]}")
                return False
        
        except Exception as e:
            logger.debug(f"CPIO 提取失败: {e}")
            return False
    
    def _scan_extracted_files(self, base_dir: str, filter_pattern: str = None) -> List[Dict[str, Any]]:
        """扫描提取出的文件"""
        files = []
        visited_dirs: Set[str] = set()
        
        try:
            for root, dirs, filenames in os.walk(base_dir):
                if root in visited_dirs:
                    continue
                visited_dirs.add(root)
                
                for filename in filenames:
                    full_path = os.path.join(root, filename)
                    
                    try:
                        rel_path = os.path.relpath(full_path, base_dir)
                        
                        if filter_pattern and not self._matches_pattern(rel_path, filter_pattern):
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
                            logger.info(f"发现可执行文件: {rel_path}")
                        
                    except Exception as e:
                        logger.debug(f"处理文件失败 {full_path}: {e}")
            
            files.sort(key=lambda x: (x['file_type'] != 'ELF', x['relative_path']))
            
        except Exception as e:
            logger.error(f"扫描提取文件失败: {e}")
        
        return files
    
    def _matches_pattern(self, path: str, pattern: str) -> bool:
        """检查路径是否匹配过滤模式"""
        try:
            import fnmatch
            return fnmatch.fnmatch(path, pattern)
        except Exception:
            return pattern.lower() in path.lower()
    
    def _detect_file_type(self, file_path: str) -> str:
        """检测文件类型"""
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
    
    def get_analysis_targets(self) -> List[str]:
        """获取可分析的二进制文件列表"""
        return [f['path'] for f in self.extracted_files if f['file_type'] == 'ELF']
    
    def generate_summary(self) -> str:
        """生成固件分析摘要报告"""
        lines = []
        lines.append("## 固件分析摘要")
        lines.append("")
        lines.append(f"- 固件文件: {os.path.basename(self.firmware_path)}")
        lines.append(f"- 固件大小: {self._format_size(os.path.getsize(self.firmware_path))}")
        lines.append(f"- 提取会话: {self.session_id}")
        lines.append("")
        
        if self.firmware_info:
            lines.append("### 固件信息")
            if 'entropy' in self.firmware_info:
                lines.append(f"- 熵值: {self.firmware_info['entropy']:.2f}")
            if 'uimage' in self.firmware_info:
                uinfo = self.firmware_info['uimage']
                lines.append(f"- uImage Magic: {uinfo.get('magic')}")
                lines.append(f"- 数据大小: {self._format_size(uinfo.get('data_size', 0))}")
                lines.append(f"- 加载地址: {uinfo.get('load_address')}")
                lines.append(f"- 入口地址: {uinfo.get('entry_address')}")
            lines.append("")
        
        lines.append("### 提取文件统计")
        elf_count = sum(1 for f in self.extracted_files if f['file_type'] == 'ELF')
        script_count = sum(1 for f in self.extracted_files if f['file_type'] == 'SCRIPT')
        passwd_count = sum(1 for f in self.extracted_files if f['file_type'] == 'PASSWD')
        
        lines.append(f"- 总文件数: {len(self.extracted_files)}")
        lines.append(f"- ELF 可执行文件: {elf_count}")
        lines.append(f"- 脚本文件: {script_count}")
        lines.append(f"- 配置文件: {passwd_count}")
        lines.append("")
        
        if self.extracted_files:
            lines.append("### 提取的 ELF 文件")
            elf_files = [f for f in self.extracted_files if f['file_type'] == 'ELF']
            for f in elf_files[:10]:
                lines.append(f"- `{f['relative_path']}` ({self._format_size(f['size'])})")
            if len(elf_files) > 10:
                lines.append(f"- ... 还有 {len(elf_files) - 10} 个文件")
        
        return '\n'.join(lines)
    
    def _format_size(self, size: int) -> str:
        """格式化文件大小"""
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.2f} KB"
        else:
            return f"{size / (1024 * 1024):.2f} MB"
    
    def cleanup(self):
        """清理临时文件"""
        output_dir = os.path.join(self.output_base_dir, self.session_id)
        if os.path.exists(output_dir):
            try:
                shutil.rmtree(output_dir)
                logger.info(f"已清理临时目录: {output_dir}")
            except Exception as e:
                logger.warning(f"清理临时目录失败: {e}")


def create_firmware_extractor(
    firmware_path: str,
    output_base_dir: str = None,
    use_binwalk: bool = True,
    use_jefferson: bool = True
) -> FirmwareExtractor:
    """
    创建固件提取器的便捷函数
    
    Args:
        firmware_path: 固件文件路径
        output_base_dir: 输出基础目录
        use_binwalk: 是否使用 binwalk
        use_jefferson: 是否使用 jefferson
    
    Returns:
        FirmwareExtractor 实例
    """
    return FirmwareExtractor(
        firmware_path=firmware_path,
        output_base_dir=output_base_dir,
        use_binwalk=use_binwalk,
        use_jefferson=use_jefferson
    )