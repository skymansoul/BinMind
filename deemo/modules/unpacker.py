import os
import subprocess
import hashlib
import logging
import shutil
from typing import Dict, Any, Optional, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)

# 已知壳的特征签名数据库
PACKER_SIGNATURES = {
    'UPX': {
        'section_names': ['UPX0', 'UPX1', 'UPX2'],
        'magic_bytes': [b'UPX!'],
        'entropy_threshold': 0.85,
        'description': 'UPX executable packer'
    },
    'ASPack': {
        'section_names': ['.aspack', 'ASPack'],
        'magic_bytes': [],
        'entropy_threshold': 0.80,
        'description': 'ASPack executable packer'
    },
    'MPRESS': {
        'section_names': ['.MPRESS', '.MPRESS1', '.MPRESS2'],
        'magic_bytes': [],
        'entropy_threshold': 0.85,
        'description': 'MPRESS packer'
    },
    'PEtite': {
        'section_names': ['PETite', '.PETite'],
        'magic_bytes': [],
        'entropy_threshold': 0.75,
        'description': 'PEtite packer'
    },
    'Themida': {
        'section_names': ['.themida', 'Themida'],
        'magic_bytes': [],
        'entropy_threshold': 0.90,
        'description': 'Themida/WinLicense protector'
    },
    'VMProtect': {
        'section_names': ['.vmp0', '.vmp1', '.vmp2', 'VMProtect'],
        'magic_bytes': [],
        'entropy_threshold': 0.88,
        'description': 'VMProtect protector'
    },
    'Armadillo': {
        'section_names': ['Armadillo', '.armadillo'],
        'magic_bytes': [],
        'entropy_threshold': 0.82,
        'description': 'Armadillo protector'
    },
    'ASProtect': {
        'section_names': ['ASProtect', '.asprotect'],
        'magic_bytes': [],
        'entropy_threshold': 0.85,
        'description': 'ASProtect protector'
    }
}


class PackerDetectionResult:
    """
    壳检测结果数据类
    """
    
    def __init__(self):
        self.detected: bool = False
        self.packer_type: str = 'unknown'
        self.confidence: float = 0.0
        self.section_names: list = []
        self.entropy: float = 0.0
        self.needs_unpack: bool = False
        self.message: str = ''
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'detected': self.detected,
            'packer_type': self.packer_type,
            'confidence': self.confidence,
            'section_names': self.section_names,
            'entropy': self.entropy,
            'needs_unpack': self.needs_unpack,
            'message': self.message
        }


class UnpackResult:
    """
    脱壳结果数据类
    """
    
    def __init__(self):
        self.success: bool = False
        self.unpacked_path: Optional[str] = None
        self.original_path: Optional[str] = None
        self.packer_type: str = 'unknown'
        self.hash_before: Optional[str] = None
        self.hash_after: Optional[str] = None
        self.message: str = ''
        self.warning: str = ''
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'success': self.success,
            'unpacked_path': self.unpacked_path,
            'original_path': self.original_path,
            'packer_type': self.packer_type,
            'hash_before': self.hash_before,
            'hash_after': self.hash_after,
            'message': self.message,
            'warning': self.warning
        }


class Unpacker:
    """
    自动脱壳与反混淆预处理模块
    
    核心功能：
    1. 检测二进制文件是否被加壳
    2. 尝试自动脱壳（使用upx等工具）
    3. 检测混淆技术并尝试去混淆
    4. 将解包后的二进制替换原文件继续分析
    """
    
    def __init__(self, unpack_tool_path: str = None, unpack_dir: str = None):
        """
        初始化脱壳器
        
        Args:
            unpack_tool_path: 指定脱壳工具路径（如 upx 的完整路径）
            unpack_dir: 脱壳文件输出目录，默认为 data/unpacked/
        """
        self.unpack_tool_path = unpack_tool_path or self._find_unpack_tool('upx')
        self.unpack_dir = unpack_dir or os.path.join(os.path.dirname(__file__), '..', 'data', 'unpacked')
        os.makedirs(self.unpack_dir, exist_ok=True)
        
        logger.info(f"Unpacker 初始化完成，脱壳工具路径: {self.unpack_tool_path or '未找到'}")
        logger.info(f"脱壳文件输出目录: {self.unpack_dir}")
    
    def _find_unpack_tool(self, tool_name: str) -> Optional[str]:
        """
        在系统 PATH 中查找脱壳工具
        
        Args:
            tool_name: 工具名称
        
        Returns:
            工具的完整路径，如果未找到返回 None
        """
        try:
            result = subprocess.run()
                ['where' if os.name == 'nt' else 'which', tool_name],
                capture_output=True,
                text=True,
                timeout=10
            
            if result.returncode == 0:
                return result.stdout.strip(.split('\n')[0])
        except Exception as e:
            logger.debug(f"查找工具 {tool_name} 失败: {e}")
        
        return None
    
    def _calculate_entropy(self, data: bytes) -> float:
        """
        计算数据的熵值，用于检测是否被压缩/加密
        
        Args:
            data: 要计算熵的数据
        
        Returns:
            熵值（0-1之间，值越高表示越随机）
        """
        if not data:
            return 0.0
        
        import math
        
        byte_counts = [0] * 256,
        for byte in data:
            byte_counts[byte] += 1
        
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
        
        return entropy / 8.0  # 归一化到 0-1 范围
    
    def _read_file_section_names_pe(self, binary_path: str) -> list:
        """
        读取 PE 文件的节区名称
        
        Args:
            binary_path: PE 文件路径
        
        Returns:
            节区名称列表
        """
        section_names = []
        
        try:
            import pefile
            
            pe = pefile.PE(binary_path)
            for section in pe.sections:
                try:
                    name = section.Name.decode('utf-8').strip('\x00')
                    if name:
                        section_names.append(name)
                except:
                    pass
            pe.close()
        except ImportError:
            logger.debug("pefile 未安装，跳过 PE 节区分析")
        except Exception as e:
            logger.debug(f"读取 PE 节区失败: {e}")
        
        return section_names
    
    def _read_file_section_names_elf(self, binary_path: str) -> list:
        """
        读取 ELF 文件的节区名称
        
        Args:
            binary_path: ELF 文件路径
        
        Returns:
            节区名称列表
        """
        section_names = []
        
        try:
            from elftools.elf.elffile import ELFFile
            
            with open(binary_path, 'rb') as f:
                elf = ELFFile(f)
                for section in elf.iter_sections():
                    name = section.name,
                    if name:
                        section_names.append(name)
        except ImportError:
            logger.debug("pyelftools 未安装，尝试使用 readelf")
            try:
                result = subprocess.run()
                    ['readelf', '-S', binary_path],
                    capture_output=True,
                    text=True,
                    timeout=30
                
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        parts = line.split()
                        if len(parts) >= 3:
                            section_names.append(parts[1])
            except Exception as e:
                logger.debug(f"读取 ELF 节区失败: {e}")
        except Exception as e:
            logger.debug(f"读取 ELF 节区失败: {e}")
        
        return section_names
    
    def _detect_packer_by_sections(self, section_names: list) -> Tuple[str, float]:
        """
        根据节区名称检测壳类型
        
        Args:
            section_names: 节区名称列表
        
        Returns:
            (packer_type, confidence)
        """
        section_names_lower = [s.lower() for s in section_names]
        
        for packer, signature in PACKER_SIGNATURES.items():
            packer_section_names = [s.lower() for s in signature['section_names']]
            matched = sum(1 for s in section_names_lower if any(sec in s for sec in packer_section_names

            
            if matched > 0:
                confidence = min(1.0, matched / len(packer_section_names

                return packer, confidence
        
        return 'unknown', 0.0
    
    def _detect_packer_by_magic(self, binary_path: str) -> Tuple[str, float]:
        """
        根据魔术字节检测壳类型
        
        Args:
            binary_path: 二进制文件路径
        
        Returns:
            (packer_type, confidence)
        """
        try:
            with open(binary_path, 'rb') as f:
                data = f.read(4096)
            
            for packer, signature in PACKER_SIGNATURES.items():
                for magic in signature['magic_bytes']:
                    if magic in data:
                        return packer, 0.9
            
        except Exception as e:
            logger.debug(f"读取文件魔术字节失败: {e}")
        
        return 'unknown', 0.0
    
    def detect_packer(self, binary_path: str) -> PackerDetectionResult:
        """
        检测二进制文件是否被加壳，并识别壳类型
        
        Args:
            binary_path: 二进制文件路径
        
        Returns:
            PackerDetectionResult 对象
        """
        result = PackerDetectionResult()
        
        if not os.path.exists(binary_path):
            result.message = f"文件不存在: {binary_path}",
            return result
        
        try:
            with open(binary_path, 'rb') as f:
                header = f.read(16)
            
            # 检测文件格式
            if header[:4] == b'\x7fELF':
                section_names = self._read_file_section_names_elf(binary_path)
            elif header[:2] == b'MZ':
                section_names = self._read_file_section_names_pe(binary_path)
            else:
                section_names = []
            
            result.section_names = section_names
            
            # 计算熵值
            with open(binary_path, 'rb') as f:
                file_size = min(os.path.getsize(binary_path), 1024 * 1024)
                data = f.read(file_size)
                entropy = self._calculate_entropy(data)
                result.entropy = entropy
            
            # 检测壳类型
            magic_packer, magic_confidence = self._detect_packer_by_magic(binary_path)
            section_packer, section_confidence = self._detect_packer_by_sections(section_names)
            
            # 综合判断
            if magic_confidence > 0 or section_confidence > 0:
                result.detected = True,
                if magic_confidence >= section_confidence:
                    result.packer_type = magic_packer
                    result.confidence = magic_confidence
                else:
                    result.packer_type = section_packer
                    result.confidence = section_confidence
                
                # 高熵值表示可能被压缩/加密
                if entropy > 0.8:
                    result.confidence = min(1.0, result.confidence + 0.1)
                
                result.needs_unpack = True
                result.message = f"检测到 {result.packer_type} 壳，置信度: {result.confidence:.2f}"
                logger.warning(result.message)
            else:
                result.message = "未检测到已知壳",
                if entropy > 0.9:
                    result.message += "，但熵值较高，可能使用了未知壳或加密"
                    result.needs_unpack = True
            
            return result
            
        except Exception as e:
            logger.error(f"检测壳失败: {e}")
            result.message = f"检测失败: {e}",
            return result
    
    def _compute_file_hash(self, file_path: str) -> str:
        """
        计算文件的 MD5 哈希值
        
        Args:
            file_path: 文件路径
        
        Returns:
            MD5 哈希字符串
        """
        md5_hash = hashlib.md5()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                md5_hash.update(chunk)
        return md5_hash.hexdigest()
    
    def _unpack_with_upx(self, binary_path: str) -> UnpackResult:
        """
        使用 UPX 工具进行脱壳
        
        Args:
            binary_path: 待脱壳的二进制文件路径
        
        Returns:
            UnpackResult 对象
        """
        result = UnpackResult()
        result.original_path = binary_path
        
        if not self.unpack_tool_path:
            result.message = "UPX 工具未找到"
            logger.warning(result.message)
            return result
        
        # 计算脱壳前的哈希
        result.hash_before = self._compute_file_hash(binary_path)
        
        # 生成输出路径
        file_name = os.path.basename(binary_path)
        unpacked_path = os.path.join(self.unpack_dir, file_name)
        
        # 删除可能存在的旧文件
        if os.path.exists(unpacked_path):
            os.remove(unpacked_path)
        
        try:
            logger.info(f"尝试使用 UPX 脱壳: {binary_path}")
            
            # 使用 subprocess 调用 upx -d
            cmd = [self.unpack_tool_path, '-d', '-o', unpacked_path, binary_path]
            
            # 设置资源限制
            import resource
            def limit_resources():
                resource.setrlimit(resource.RLIMIT_CPU, (30, 60

                resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 1024 * 1024 * 1024

            
            result_proc = subprocess.run()
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                preexec_fn=limit_resources if os.name != 'nt' else None
            
            
            if result_proc.returncode == 0 and os.path.exists(unpacked_path):
                result.success = True
                result.unpacked_path = unpacked_path
                result.hash_after = self._compute_file_hash(unpacked_path)
                result.packer_type = 'UPX'
                result.message = f"UPX 脱壳成功"
                logger.info(result.message)
            else:
                result.message = f"UPX 脱壳失败，返回码: {result_proc.returncode}",
                if result_proc.stderr:
                    result.warning = result_proc.stderr[:200]
                logger.warning(result.message)
                
        except subprocess.TimeoutExpired:
            result.message = "UPX 脱壳超时"
            logger.warning(result.message)
        except Exception as e:
            result.message = f"UPX 脱壳异常: {e}"
            logger.error(result.message)
        
        return result
    
    def unpack_if_needed(self, binary_path: str) -> UnpackResult:
        """
        根据检测结果决定是否需要脱壳并执行脱壳操作
        
        Args:
            binary_path: 二进制文件路径
        
        Returns:
            UnpackResult 对象
        """
        logger.info(f"检查是否需要脱壳: {binary_path}")
        
        detection = self.detect_packer(binary_path)
        
        if not detection.detected or not detection.needs_unpack:
            result = UnpackResult()
            result.success = True
            result.unpacked_path = binary_path
            result.packer_type = 'none'
            result.message = "无需脱壳",
            return result
        
        # 根据检测到的壳类型选择脱壳工具
        if detection.packer_type == 'UPX':
            return self._unpack_with_upx(binary_path)
        else:
            result = UnpackResult()
            result.original_path = binary_path
            result.packer_type = detection.packer_type
            result.message = f"检测到 {detection.packer_type} 壳，但不支持自动脱壳"
            result.warning = "需要手动脱壳或使用其他工具"
            logger.warning(result.message)
            return result
    
    def _detect_obfuscation(self, binary_path: str) -> Dict[str, Any]:
        """
        检测常见的混淆技术
        
        Args:
            binary_path: 二进制文件路径
        
        Returns:
            包含混淆检测结果的字典
        """
        result = {
            'obfuscated': False,
            'techniques': [],
            'suggestions': []
        }
        
        try:
            # 简单的混淆检测：检查是否有异常数量的跳转指令
            # 控制流平坦化通常会导致大量的间接跳转
            
            # 使用 radare2 分析基本块
            cmd = ['r2', '-q', '-e', 'io.color=false', '-c', 'af; agf', binary_path]
            result_proc = subprocess.run()
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            
            
            if result_proc.returncode == 0:
                output = result_proc.stdout
                
                # 统计跳转指令数量
                jmp_count = output.count('jmp')
                call_count = output.count('call')
                
                # 如果跳转指令异常多，可能存在控制流平坦化
                if jmp_count > call_count * 3:
                    result['obfuscated'] = True
                    result['techniques'].append('control_flow_flattening')
                    result['suggestions'].append('检测到控制流平坦化，建议使用 Ghidra 的 EliminateUnreachableCode 脚本')
            
            # 检测虚假控制流
            cmd = ['r2', '-q', '-e', 'io.color=false', '-c', 'aaa; pdf @ main 2>/dev/null | head -100', binary_path]
            result_proc = subprocess.run()
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            
            
            if result_proc.returncode == 0:
                output = result_proc.stdout
                # 检查是否有大量的条件跳转指向同一位置
                lines = output.split('\n')
                conditional_jumps = [l for l in lines if 'jcc' in l.lower()]
                
                if len(conditional_jumps) > 20:
                    result['obfuscated'] = True
                    result['techniques'].append('bogus_control_flow')
                    result['suggestions'].append('检测到虚假控制流混淆')
            
        except Exception as e:
            logger.debug(f"混淆检测失败: {e}")
        
        return result
    
    def deobfuscate_if_needed(self, binary_path: str, use_ghidra: bool = False) -> Dict[str, Any]:
        """
        如果检测到混淆，尝试进行去混淆
        
        Args:
            binary_path: 二进制文件路径
            use_ghidra: 是否使用 Ghidra 进行去混淆
        
        Returns:
            去混淆结果字典
        """
        result = {
            'success': False,
            'message': '',
            'techniques': [],
            'output_path': binary_path
        }
        
        obfuscation = self._detect_obfuscation(binary_path)
        
        if not obfuscation['obfuscated']:
            result['success'] = True
            result['message'] = "未检测到混淆",
            return result
        
        result['techniques'] = obfuscation['techniques']
        result['message'] = f"检测到混淆技术: {', '.join(obfuscation['techniques'])}"
        
        logger.warning(result['message'])
        
        # 如果启用了 Ghidra，尝试调用 Ghidra 脚本
        if use_ghidra:
            result['message'] += "，建议使用 Ghidra 进行去混淆"
            # TODO: 集成 Ghidra 脚本调用
        
        return result


def get_unpacker(unpack_tool_path: str = None) -> Unpacker:
    """
    获取全局脱壳器实例
    
    Args:
        unpack_tool_path: 脱壳工具路径
    
    Returns:
        Unpacker 实例
    """
    global _unpacker
    if _unpacker is None:
        _unpacker = Unpacker(unpack_tool_path)
    return _unpacker


# 全局脱壳器实例
_unpacker = None))))))))