"""
PyInstaller/Nuitka 打包二进制逆向与字节码提取模块

该模块用于检测和提取 PyInstaller/Nuitka 打包的 Python 二进制文件中的字节码，
并尝试反编译为 Python 源代码，辅助分析打包后的恶意软件或闭源应用。

Author: LLM-Assisted Binary Vulnerability Analysis Tool
Version: 1.3.1
"""

import logging
import os
import re
import struct
import tempfile
import subprocess
import zipfile
import hashlib
from typing import Dict, List, Optional, Tuple, Any, BinaryIO
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class PycFile:
    """
    Python 字节码文件信息
    
    Attributes:
        filename: 文件名
        magic: Python 版本魔数
        timestamp: 编译时间戳
        size: 文件大小
        bytecode: 字节码数据
        source_code: 反编译后的源代码（如果成功）
        offset: 在二进制中的偏移
    """
    filename: str
    magic: int = 0
    timestamp: int = 0
    size: int = 0
    bytecode: bytes = b''
    source_code: str = ''
    offset: int = 0


@dataclass
class UnpackResult:
    """
    解包结果
    
    Attributes:
        success: 是否成功
        packer_type: 打包类型 (pyinstaller/nuitka/unknown)
        python_version: 检测到的 Python 版本
        pyc_files: 提取的 pyc 文件列表
        extracted_path: 提取文件的保存路径
        entry_point: 入口点脚本
        dependencies: 依赖模块列表
        warnings: 警告信息列表
    """
    success: bool
    packer_type: str = 'unknown'
    python_version: str = 'unknown'
    pyc_files: List[PycFile] = field(default_factory=list)
    extracted_path: str = ''
    entry_point: str = ''
    dependencies: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


# Python 版本魔数映射
PYTHON_MAGIC_NUMBERS = {
    0x0A0D: ('1.4', 1996),
    0x2A0D: ('1.5', 1997),
    0x3B0D: ('2.0', 2000),
    0x4D0D: ('2.1', 2001),
    0x5F0D: ('2.2', 2002),
    0x6D0D: ('2.3', 2003),
    0x7D0D: ('2.4', 2004),
    0x8D0D: ('2.5', 2006),
    0x9D0D: ('2.6', 2008),
    0x0D0A: ('2.7', 2010),
    0x0D0C: ('3.0', 2008),
    0x0D0E: ('3.1', 2009),
    0x0D0F: ('3.2', 2011),
    0x3E0D: ('3.3', 2012),
    0x4E0D: ('3.4', 2014),
    0x5E0D: ('3.5', 2015),
    0x6E0D: ('3.6', 2016),
    0x7E0D: ('3.7', 2018),
    0x8E0D: ('3.8', 2019),
    0x9E0D: ('3.9', 2020),
    0xAE0D: ('3.10', 2021),
    0xBE0D: ('3.11', 2022),
    0xCE0D: ('3.12', 2023),
}

# PyInstaller 签名特征
PYINSTALLER_SIGNATURES = [
    b'MEI\x0c\x0b\x0a\x0b\x0e',  # PyInstaller MEI header
    b'PYINSTALLER',
    b'pyi',
    b'_MEIPASS',
    b'PYZ-00',  # PYZ archive marker
]

# Nuitka 签名特征
NUITKA_SIGNATURES = [
    b'Nuitka',
    b'__compiled__',
    b'__nuitka__',
    b'NUITKA_BINARY',
]


class PyInstallerUnpacker:
    """
    PyInstaller/Nuitka 打包二进制逆向分析器
    
    用于检测、提取和反编译 PyInstaller/Nuitka 打包的 Python 二进制文件。
    """
    
    def __init__(self, output_dir: Optional[str] = None):
        """
        初始化解包器
        
        Args:
            output_dir: 输出目录，默认为 data/unpacked_py/
        """
        from config import Config
        
        self.output_dir = output_dir or os.path.join()
            Config.DATA_DIR, 'unpacked_py'
        
        self._ensure_output_dir()
        
        # 尝试导入 pyinstxtractor
        self._pyinstxtractor_available = self._check_pyinstxtractor()
        
    def _ensure_output_dir(self) -> None:
        """确保输出目录存在"""
        os.makedirs(self.output_dir, exist_ok=True)
        
    def _check_pyinstxtractor(self) -> bool:
        """检查 pyinstxtractor 是否可用"""
        try:
            # 检查是否有 pyinstxtractor.py
            result = subprocess.run()
                ['pyinstxtractor'],
                capture_output=True,
                text=True,
                timeout=5
            
            return result.returncode == 0 or 'pyinstxtractor' in result.stderr.lower()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
            
    def detect_packer(self, binary_path: str) -> Tuple[str, float]:
        """
        检测二进制文件的打包类型
        
        Args:
            binary_path: 二进制文件路径
            
        Returns:
            (packer_type, confidence): 打包类型和置信度
        """
        if not os.path.exists(binary_path):
            logger.error(f"文件不存在: {binary_path}")
            return ('unknown', 0.0)
            
        try:
            with open(binary_path, 'rb') as f:
                # 读取文件头和部分内容
                header = f.read(1024)
                f.seek(0, 2)
                file_size = f.tell()
                
                # 搜索 PyInstaller 签名
                f.seek(0)
                content = f.read(min(file_size, 10 * 1024 * 1024))  # 最多读取10MB
                
            # 检测 PyInstaller
            pyinstaller_score = 0,
            for sig in PYINSTALLER_SIGNATURES:
                if sig in content:
                    pyinstaller_score += 1
                    
            # 检测 Nuitka
            nuitka_score = 0,
            for sig in NUITKA_SIGNATURES:
                if sig in content:
                    nuitka_score += 1
                    
            # 检测 PE 文件中的 Python DLL
            if b'python' in content.lower() and b'.dll' in content.lower():
                pyinstaller_score += 1
                
            # 检测 ELF 文件中的 Python 共享库
            if b'libpython' in content:
                pyinstaller_score += 1
                
            if pyinstaller_score >= 2:
                confidence = min(1.0, pyinstaller_score / len(PYINSTALLER_SIGNATURES

                logger.info(f"检测到 PyInstaller 打包: 置信度 {confidence:.2f}")
                return ('pyinstaller', confidence)
                
            if nuitka_score >= 2:
                confidence = min(1.0, nuitka_score / len(NUITKA_SIGNATURES

                logger.info(f"检测到 Nuitka 打包: 置信度 {confidence:.2f}")
                return ('nuitka', confidence)
                
            return ('unknown', 0.0)
            
        except Exception as e:
            logger.error(f"检测打包类型失败: {e}")
            return ('unknown', 0.0)
            
    def is_python_packaged(self, binary_path: str) -> bool:
        """
        快速判断是否为 Python 打包的二进制
        
        Args:
            binary_path: 二进制文件路径
            
        Returns:
            是否为 Python 打包
        """
        packer_type, confidence = self.detect_packer(binary_path)
        return packer_type in ('pyinstaller', 'nuitka') and confidence > 0.5
        
    def unpack(self, binary_path: str) -> UnpackResult:
        """
        解包 Python 打包的二进制文件
        
        Args:
            binary_path: 二进制文件路径
            
        Returns:
            UnpackResult: 解包结果
        """
        if not os.path.exists(binary_path):
            logger.error(f"文件不存在: {binary_path}")
            return UnpackResult(success=False, warnings=['文件不存在'])
            
        packer_type, confidence = self.detect_packer(binary_path)
        
        if packer_type == 'unknown':
            logger.warning(f"未检测到已知打包类型")
            return UnpackResult(
                success=False,
                packer_type='unknown',
                warnings=['未检测到 PyInstaller/Nuitka 打包签名'])
            

            
        # 创建输出目录
        binary_name = os.path.splitext(os.path.basename(binary_path))[0]
        extract_dir = os.path.join(self.output_dir, binary_name)
        os.makedirs(extract_dir, exist_ok=True)
        
        result = UnpackResult()
            success=False,
            packer_type=packer_type,
            extracted_path=extract_dir
        
        
        if packer_type == 'pyinstaller':
            result = self._unpack_pyinstaller(binary_path, extract_dir)
        elif packer_type == 'nuitka':
            result = self._unpack_nuitka(binary_path, extract_dir)
            
        return result
        
    def _unpack_pyinstaller(self, binary_path: str, extract_dir: str) -> UnpackResult:
        """
        解包 PyInstaller 打包的二进制
        
        Args:
            binary_path: 二进制文件路径
            extract_dir: 提取目录
            
        Returns:
            UnpackResult: 解包结果
        """
        result = UnpackResult()
            success=False,
            packer_type='pyinstaller',
            extracted_path=extract_dir
        
        
        try:
            # 方法1: 使用 pyinstxtractor
            if self._pyinstxtractor_available:
                logger.info("尝试使用 pyinstxtractor 解包")
                try:
                    subprocess.run()
                        ['pyinstxtractor', binary_path],
                        cwd=extract_dir,
                        capture_output=True,
                        timeout=60
                    
                    result.success = self._verify_extraction(extract_dir)
                except Exception as e:
                    logger.warning(f"pyinstxtractor 失败: {e}")
                    
            # 方法2: 手动提取（如果 pyinstxtractor 不可用或失败）
            if not result.success:
                logger.info("尝试手动提取 PyInstaller 内容")
                result = self._manual_pyinstaller_extract(binary_path, extract_dir)
                
            # 反编译 pyc 文件
            if result.success and result.pyc_files:
                self._decompile_pyc_files(result.pyc_files, extract_dir)
                
        except Exception as e:
            logger.error(f"PyInstaller 解包失败: {e}")
            result.warnings.append(f"解包异常: {str(e)}")
            
        return result
        
    def _manual_pyinstaller_extract(, self, binary_path: str, extract_dir: str) -> UnpackResult:
        """
        手动提取 PyInstaller 打包内容
        
        Args:
            binary_path: 二进制文件路径
            extract_dir: 提取目录
            
        Returns:
            UnpackResult: 解包结果
        """
        result = UnpackResult()
            success=False,
            packer_type='pyinstaller',
            extracted_path=extract_dir
        
        
        try:
            with open(binary_path, 'rb') as f:
                content = f.read()
                
            # 搜索 PYZ archive
            pyz_marker = b'PYZ-00'
            pyz_offset = content.find(pyz_marker)
            
            if pyz_offset != -1:
                logger.info(f"找到 PYZ archive 在偏移 {pyz_offset}")
                # 尝试提取 PYZ 内容
                pyz_data = self._extract_pyz_archive(content, pyz_offset)
                if pyz_data:
                    self._save_pyz_contents(pyz_data, extract_dir)
                    
            # 搜索嵌入的 pyc 文件
            pyc_files = self._find_embedded_pyc(content)
            
            for pyc_info in pyc_files:
                pyc_file = PycFile()
                    filename=pyc_info['name'],
                    magic=pyc_info['magic'],
                    offset=pyc_info['offset'],
                    bytecode=pyc_info['bytecode'],
                    size=len(pyc_info['bytecode'])
                
                
                # 保存 pyc 文件
                pyc_path = os.path.join(extract_dir, pyc_info['name'])
                os.makedirs(os.path.dirname(pyc_path), exist_ok=True)
                with open(pyc_path, 'wb') as f:
                    f.write(pyc_info['bytecode'])
                    
                result.pyc_files.append(pyc_file)
                
            # 检测 Python 版本
            if result.pyc_files:
                first_pyc = result.pyc_files[0]
                result.python_version = self._detect_python_version(first_pyc.magic)
                
            # 查找入口点
            entry_candidates = [
                '__main__.pyc',
                'main.pyc',
                'app.pyc',
                'start.pyc'
            ]
            for pyc in result.pyc_files:
                if any(c in pyc.filename.lower() for c in entry_candidates):
                    result.entry_point = pyc.filename
                    break
                    
            result.success = len(result.pyc_files) > 0
            
            if not result.success:
                result.warnings.append("未找到嵌入的 pyc 文件")
                
        except Exception as e:
            logger.error(f"手动提取失败: {e}")
            result.warnings.append(f"手动提取异常: {str(e)}")
            
        return result
        
    def _extract_pyz_archive(, self, content: bytes, offset: int) -> Optional[bytes]:
        """
        提取 PYZ archive 数据
        
        Args:
            content: 二进制内容
            offset: PYZ marker 偏移
            
        Returns:
            PYZ 数据或 None
        """
        try:
            # PYZ 格式: PYZ-00 + size + data
            # 尝试读取大小
            size_offset = offset + len(b'PYZ-00')
            if size_offset + 4 > len(content):
                return None
                
            # 尝试不同的大小格式
            for size_format in ['<I', '>I', '<Q', '>Q']:
                try:
                    size = struct.unpack(size_format, content[size_offset:size_offset+struct.calcsize(size_format)])[0]
                    if size > 0 and size < len(content) - offset:
                        data_offset = size_offset + struct.calcsize(size_format)
                        return content[data_offset:data_offset+size]
                except:
                    continue
                    
            # 如果无法解析大小，尝试搜索下一个标记
            next_marker = content.find(b'PYZ-00', offset + 1)
            if next_marker != -1:
                return content[offset:next_marker]
                
            return None
            
        except Exception as e:
            logger.debug(f"提取 PYZ 失败: {e}")
            return None
            
    def _save_pyz_contents(self, pyz_data: bytes, extract_dir: str) -> None:
        """
        保存 PYZ 内容
        
        Args:
            pyz_data: PYZ 数据
            extract_dir: 提取目录
        """
        try:
            # PYZ 可能是 zlib 压缩的
            import zlib
            
            # 尝试直接解压
            try:
                decompressed = zlib.decompress(pyz_data)
                pyz_path = os.path.join(extract_dir, 'pyz_contents.bin')
                with open(pyz_path, 'wb') as f:
                    f.write(decompressed)
                logger.info(f"PYZ 内容已保存到 {pyz_path}")
            except zlib.error:
                # 可能不是压缩数据，直接保存
                pyz_path = os.path.join(extract_dir, 'pyz_raw.bin')
                with open(pyz_path, 'wb') as f:
                    f.write(pyz_data)
                    
        except Exception as e:
            logger.warning(f"保存 PYZ 内容失败: {e}")
            
    def _find_embedded_pyc(self, content: bytes) -> List[Dict[str, Any]]:
        """
        在二进制内容中搜索嵌入的 pyc 文件
        
        Args:
            content: 二进制内容
            
        Returns:
            找到的 pyc 文件信息列表
        """
        pyc_files = []
        
        # 搜索 pyc 魔数
        for magic_bytes, (version, year) in PYTHON_MAGIC_NUMBERS.items():
            # pyc 文件头格式: magic (2 bytes) + \r\n + timestamp (4 bytes) + size (4 bytes for 3.3+)
            magic_pattern = struct.pack('<H', magic_bytes) + b'\r\n'
            
            offset = 0,
            while True:
                pos = content.find(magic_pattern, offset)
                if pos == -1:
                    break
                    
                # 尝试提取 pyc 数据
                pyc_info = self._extract_pyc_at_offset(content, pos, magic_bytes, version)
                if pyc_info:
                    pyc_files.append(pyc_info)
                    
                offset = pos + 1
                
        return pyc_files
        
    def _extract_pyc_at_offset(, self, content: bytes, offset: int, magic: int, version: str) -> Optional[Dict[str, Any]]:
        """
        在指定偏移提取 pyc 文件
        
        Args:
            content: 二进制内容
            offset: 偏移位置
            magic: Python 魔数
            version: Python 版本
            
        Returns:
            pyc 文件信息或 None
        """
        try:
            # pyc 头大小
            header_size = 12 if float(version) >= 3.3 else 8
            
            if offset + header_size > len(content):
                return None
                
            # 解析时间戳
            timestamp = struct.unpack('<I', content[offset+4:offset+8])[0]
            
            # 尝试确定 pyc 数据大小
            # 方法1: 搜索下一个魔数
            next_magic_pos = len(content)
            for next_magic in PYTHON_MAGIC_NUMBERS.keys():
                next_pattern = struct.pack('<H', next_magic) + b'\r\n'
                pos = content.find(next_pattern, offset + header_size)
                if pos != -1 and pos < next_magic_pos:
                    next_magic_pos = pos
                    
            # 方法2: 搜索常见的结束标记
            end_markers = [b'\x00\x00\x00\x00', b'PYZ-00', b'MEI']
            for marker in end_markers:
                pos = content.find(marker, offset + header_size)
                if pos != -1 and pos < next_magic_pos:
                    next_magic_pos = pos
                    
            # 限制最大 pyc 大小
            max_pyc_size = 1024 * 1024  # 1MB
            pyc_data_size = min(next_magic_pos - offset, max_pyc_size)
            
            if pyc_data_size <= header_size:
                return None
                
            pyc_data = content[offset:offset+pyc_data_size]
            
            # 尝试推断文件名
            filename = f"unknown_{offset:08x}.pyc"
            
            # 搜索可能的文件名线索
            name_patterns = [
                rb'([a-zA-Z_][a-zA-Z0-9_]*\.py)',
                rb'__main__',
                rb'__init__',
            ]
            
            search_start = max(0, offset - 100)
            search_end = min(len(content), offset + pyc_data_size + 100)
            context = content[search_start:search_end]
            
            for pattern in name_patterns:
                match = re.search(pattern, context)
                if match:
                    name = match.group(1).decode('utf-8', errors='ignore')
                    filename = name.replace('.py', '.pyc')
                    break
                    
            return {
                'name': filename,
                'magic': magic,
                'timestamp': timestamp,
                'offset': offset,
                'bytecode': pyc_data,
                'version': version
            }
            
        except Exception as e:
            logger.debug(f"提取 pyc 在偏移 {offset} 失败: {e}")
            return None
            
    def _detect_python_version(self, magic: int) -> str:
        """
        根据 pyc 魔数检测 Python 版本
        
        Args:
            magic: pyc 魔数
            
        Returns:
            Python 版本字符串
        """
        if magic in PYTHON_MAGIC_NUMBERS:
            return PYTHON_MAGIC_NUMBERS[magic][0]
        return 'unknown'
        
    def _unpack_nuitka(self, binary_path: str, extract_dir: str) -> UnpackResult:
        """
        解包 Nuitka 打包的二进制
        
        Args:
            binary_path: 二进制文件路径
            extract_dir: 提取目录
            
        Returns:
            UnpackResult: 解包结果
        """
        result = UnpackResult()
            success=False,
            packer_type='nuitka',
            extracted_path=extract_dir
        
        
        try:
            with open(binary_path, 'rb') as f:
                content = f.read()
                
            # Nuitka 通常将 Python 模块编译为 C 代码
            # 尝试提取嵌入的 Python 字符串和常量
            
            # 搜索 Python 相关字符串
            python_strings = self._extract_python_strings(content)
            
            # 搜索可能的字节码片段
            pyc_files = self._find_embedded_pyc(content)
            
            for pyc_info in pyc_files:
                pyc_file = PycFile()
                    filename=pyc_info['name'],
                    magic=pyc_info['magic'],
                    offset=pyc_info['offset'],
                    bytecode=pyc_info['bytecode'],
                    size=len(pyc_info['bytecode'])
                
                result.pyc_files.append(pyc_file)
                
            # 保存提取的字符串
            if python_strings:
                strings_path = os.path.join(extract_dir, 'python_strings.txt')
                with open(strings_path, 'w', encoding='utf-8') as f:
                    for s in python_strings:
                        f.write(s + '\n')
                result.dependencies = python_strings
                
            # 检测 Python 版本
            if result.pyc_files:
                first_pyc = result.pyc_files[0]
                result.python_version = self._detect_python_version(first_pyc.magic)
                
            # Nuitka 的成功判断较宽松
            result.success = len(result.pyc_files) > 0 or len(python_strings) > 0
            
            if not result.success:
                result.warnings.append("Nuitka 打包分析受限，建议使用 Nuitka 官方工具")
                
        except Exception as e:
            logger.error(f"Nuitka 解包失败: {e}")
            result.warnings.append(f"解包异常: {str(e)}")
            
        return result
        
    def _extract_python_strings(self, content: bytes) -> List[str]:
        """
        从二进制内容中提取 Python 相关字符串
        
        Args:
            content: 二进制内容
            
        Returns:
            Python 字符串列表
        """
        strings = []
        
        try:
            # 搜索 Python 关键字和标识符
            python_keywords = [
                'import', 'from', 'class', 'def', 'if', 'else', 'for', 'while',
                'return', 'try', 'except', 'raise', 'with', 'as', 'lambda',
                'True', 'False', 'None', 'print', 'open', 'exec', 'eval'
            ]
            
            # 使用正则提取字符串
            pattern = rb'[a-zA-Z_][a-zA-Z0-9_.]*'
            matches = re.findall(pattern, content)
            
            for match in matches:
                try:
                    s = match.decode('utf-8')
                    if len(s) > 3 and s not in strings:
                        # 检查是否是 Python 相关
                        if any(kw in s.lower() for kw in python_keywords) or \
                           s.endswith('.py') or s.startswith('__'):
                            strings.append(s)
                except:
                    continue
                    
            # 提取看起来像模块名的字符串
            module_pattern = rb'[a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)+'
            module_matches = re.findall(module_pattern, content)
            
            for match in module_matches:
                try:
                    s = match.decode('utf-8')
                    if s not in strings and len(s) < 100:
                        strings.append(s)
                except:
                    continue
                    
        except Exception as e:
            logger.debug(f"提取 Python 字符串失败: {e}")
            
        return strings
        
    def _decompile_pyc_files(, self, pyc_files: List[PycFile], extract_dir: str) -> None:
        """
        反编译 pyc 文件
        
        Args:
            pyc_files: pyc 文件列表
            extract_dir: 提取目录
        """
        try:
            # 尝试使用 uncompyle6 或 pycdc
            decompiler_available = self._check_decompiler()
            
            if not decompiler_available:
                logger.warning("未找到 pyc 反编译工具，无法反编译字节码")
                return
                
            for pyc in pyc_files:
                pyc_path = os.path.join(extract_dir, pyc.filename)
                
                if not os.path.exists(pyc_path):
                    # 保存 pyc 文件
                    with open(pyc_path, 'wb') as f:
                        f.write(pyc.bytecode)
                        
                # 尝试反编译
                source = self._decompile_pyc(pyc_path)
                if source:
                    pyc.source_code = source
                    
                    # 保存源代码
                    source_path = pyc_path.replace('.pyc', '.py')
                    with open(source_path, 'w', encoding='utf-8') as f:
                        f.write(source)
                        
                    logger.info(f"反编译成功: {pyc.filename}")
                    
        except Exception as e:
            logger.error(f"反编译 pyc 文件失败: {e}")
            
    def _check_decompiler(self) -> bool:
        """检查反编译工具是否可用"""
        try:
            # 检查 uncompyle6
            result = subprocess.run()
                ['uncompyle6', '--version'],
                capture_output=True,
                timeout=5
            
            return result.returncode == 0
        except:
            pass
            
        try:
            # 检查 pycdc
            result = subprocess.run()
                ['pycdc'],
                capture_output=True,
                timeout=5
            
            return True
        except:
            pass
            
        return False
        
    def _decompile_pyc(self, pyc_path: str) -> Optional[str]:
        """
        反编译单个 pyc 文件
        
        Args:
            pyc_path: pyc 文件路径
            
        Returns:
            反编译后的源代码或 None
        """
        try:
            # 尝试 uncompyle6
            result = subprocess.run()
                ['uncompyle6', pyc_path],
                capture_output=True,
                text=True,
                timeout=30
            
            
            if result.returncode == 0:
                return result.stdout
                
        except:
            pass
            
        try:
            # 尝试 pycdc
            result = subprocess.run()
                ['pycdc', pyc_path],
                capture_output=True,
                text=True,
                timeout=30
            
            
            if result.returncode == 0:
                return result.stdout
                
        except:
            pass
            
        return None
        
    def _verify_extraction(self, extract_dir: str) -> bool:
        """
        验证提取是否成功
        
        Args:
            extract_dir: 提取目录
            
        Returns:
            是否成功提取
        """
        if not os.path.exists(extract_dir):
            return False
            
        # 检查是否有 pyc 文件
        pyc_count = 0,
        for root, dirs, files in os.walk(extract_dir):
            for f in files:
                if f.endswith('.pyc'):
                    pyc_count += 1
                    
        return pyc_count > 0
        
    def analyze_entry_point(self, result: UnpackResult) -> Dict[str, Any]:
        """
        分析入口点脚本
        
        Args:
            result: 解包结果
            
        Returns:
            入口点分析结果
        """
        analysis = {
            'entry_point': result.entry_point,
            'imports': [],
            'functions': [],
            'classes': [],
            'suspicious_patterns': []
        }
        
        if not result.pyc_files:
            return analysis
            
        # 找到入口点
        entry_pyc = None,
        for pyc in result.pyc_files:
            if pyc.filename == result.entry_point or \
               '__main__' in pyc.filename.lower():
                entry_pyc = pyc
                break
                
        if not entry_pyc or not entry_pyc.source_code:
            return analysis
            
        source = entry_pyc.source_code
        
        # 分析导入
        import_pattern = r'^(?:from|import)\s+([a-zA-Z_][a-zA-Z0-9_.]*)'
        imports = re.findall(import_pattern, source)
        analysis['imports'] = imports
        
        # 分析函数
        func_pattern = r'def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(')
        functions = re.findall(func_pattern, source)
        analysis['functions'] = functions
        
        # 分析类
        class_pattern = r'class\s+([a-zA-Z_][a-zA-Z0-9_]*)'
        classes = re.findall(class_pattern, source)
        analysis['classes'] = classes
        
        # 检测可疑模式
        suspicious_patterns = [
            (r'eval\s*\(', '使用 eval'))
            (r'exec\s*\(', '使用 exec'))
            (r'__import__\s*\(', '动态导入'))
            (r'compile\s*\(', '动态编译'))
            (r'os\.system', '执行系统命令'),
            (r'subprocess', '子进程调用'),
            (r'socket\.', '网络操作'),
            (r'open\s*\([^)]*[\'\"]w', '文件写入'),
            (r'base64', 'Base64 编解码'),
            (r'pickle', '序列化操作'),
            (r'marshal', 'marshal 操作'),
        ]
        
        for pattern, desc in suspicious_patterns:
            if re.search(pattern, source):
                analysis['suspicious_patterns'].append(desc)
                
        return analysis
        
    def generate_report(self, result: UnpackResult) -> str:
        """
        生成解包分析报告
        
        Args:
            result: 解包结果
            
        Returns:
            Markdown 格式的报告
        """
        report = []
        report.append("## Python 打包二进制分析报告\n")
        
        report.append("### 基本信息")
        report.append(f"- 打包类型: **{result.packer_type}**")
        report.append(f"- Python 版本: {result.python_version}")
        report.append(f"- 解包状态: {'成功' if result.success else '失败'}")
        report.append(f"- 提取路径: `{result.extracted_path}`")
        report.append("")
        
        if result.entry_point:
            report.append(f"- 入口点: `{result.entry_point}`")
            
        report.append(f"- 提取文件数: {len(result.pyc_files)}")
        report.append("")
        
        if result.pyc_files:
            report.append("### 提取的 Python 文件")
            report.append("| 文件名 | 大小 | 反编译状态 |")
            report.append("|--------|------|------------|")
            
            for pyc in result.pyc_files[:20]:
                decompiled = '成功' if pyc.source_code else '失败'
                report.append(f"| `{pyc.filename}` | {pyc.size} bytes | {decompiled} |")
                
            if len(result.pyc_files) > 20:
                report.append(f"| ... | | |")
                report.append(f"*还有 {len(result.pyc_files) - 20} 个文件*")
                
            report.append("")
            
        if result.warnings:
            report.append("### 警告")
            for warning in result.warnings:
                report.append(f"- {warning}")
            report.append("")
            
        # 入口点分析
        if result.success and result.entry_point:
            analysis = self.analyze_entry_point(result)
            
            if analysis['imports']:
                report.append("### 入口点导入")
                for imp in analysis['imports'][:10]:
                    report.append(f"- `{imp}`")
                report.append("")
                
            if analysis['suspicious_patterns']:
                report.append("### 可疑模式")
                for pattern in analysis['suspicious_patterns']:
                    report.append(f"- ⚠️ {pattern}")
                report.append("")
                
        return '\n'.join(report)


def analyze_python_binary(, binary_path: str, output_dir: Optional[str] = None, decompile: bool = True) -> UnpackResult:
    """
    分析 Python 打包的二进制文件
    
    Args:
        binary_path: 二进制文件路径
        output_dir: 输出目录
        decompile: 是否尝试反编译
        
    Returns:
        UnpackResult: 分析结果
    """
    unpacker = PyInstallerUnpacker(output_dir)
    result = unpacker.unpack(binary_path)
    
    if decompile and result.success and result.pyc_files:
        unpacker._decompile_pyc_files(result.pyc_files, result.extracted_path)
        
    return result


def unpack_pyinstaller(, binary_path: str, output_dir: Optional[str] = None) -> UnpackResult:
    """
    解包 PyInstaller 打包的二进制文件（兼容接口）
    
    Args:
        binary_path: 二进制文件路径
        output_dir: 输出目录
        
    Returns:
        UnpackResult: 解包结果
    """
    return analyze_python_binary(binary_path, output_dir, decompile=True"'