import os
import re
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class CryptoMisuse:
    """密码误用数据类"""
    misuse_type: str
    severity: str  # 'high', 'medium', 'low'
    location: str  # 函数名或地址
    description: str
    recommendation: str
    evidence: str


@dataclass
class CryptoMisuseResult:
    """密码误用检测结果"""
    filename: str
    misuses: List[CryptoMisuse]
    summary: str


class CryptoMisuseDetector:
    """密码误用自动化检测器"""
    
    WEAK_RANDOM_FUNCTIONS = [
        'rand', 'srand', 'random', 'srandom',
        'rand_r', 'random_r',
        'rand_s',  # Windows weak random
        'arc4random',  # 实际上是安全的，但包含在这里以便与其他随机函数一起检查
    ]
    
    SECURE_RANDOM_FUNCTIONS = [
        'getrandom', 'getentropy',
        'arc4random', 'arc4random_buf', 'arc4random_uniform',
        'RAND_bytes', 'RAND_pseudo_bytes',
        'CryptGenRandom', 'BCryptGenRandom',
        'SecureRandom', 'RandomNumberGenerator',
    ]
    
    ENCRYPTION_FUNCTIONS = [
        ('AES_', 'AES加密'),
        ('DES_', 'DES加密（已废弃）'),
        ('3DES_', 'Triple DES（已废弃）'),
        ('Blowfish_', 'Blowfish（已废弃）'),
        ('RC4_', 'RC4（已废弃）'),
        ('ChaCha20_', 'ChaCha20加密'),
    ]
    
    HASH_FUNCTIONS = [
        ('MD5_', 'MD5（已废弃）', 'high'),
        ('SHA1_', 'SHA-1（已废弃）', 'high'),
        ('SHA256_', 'SHA-256', 'low'),
        ('SHA512_', 'SHA-512', 'low'),
        ('SHA3_', 'SHA-3', 'low'),
        ('BLAKE2_', 'BLAKE2', 'low'),
    ]
    
    KDF_FUNCTIONS = [
        'PKCS5_PBKDF2_HMAC',
        'scrypt',
        'argon2',
        'bcrypt',
        'CryptDeriveKey',
    ]
    
    def __init__(self, binary_path: str = ""):
        self.binary_path = binary_path
        self.misuses: List[CryptoMisuse] = []
        self.strings: List[str] = []
        self.imports: List[str] = []
        self.functions: List[str] = []
    
    def _extract_strings(self) -> List[str]:
        """从二进制文件中提取字符串"""
        strings = []
        try:
            with open(self.binary_path, 'rb') as f:
                data = f.read()
            
            current_string = []
            for byte in data:
                if 32 <= byte <= 126:
                    current_string.append(chr(byte))
                else:
                    if len(current_string) >= 4:
                        strings.append(''.join(current_string))
                    current_string = []
            
            if len(current_string) >= 4:
                strings.append(''.join(current_string))
            
        except Exception as e:
            logger.error(f"提取字符串失败: {e}")
        
        return strings
    
    def _extract_imports(self) -> List[str]:
        """提取导入函数"""
        imports = []
        
        try:
            with open(self.binary_path, 'rb') as f:
                data = f.read()
            
            patterns = [
                rb'\x4d\x5a',  # PE
                rb'\x7fELF',    # ELF
            ]
            
            if b'\x7fELF' in data[:16]:
                imports = self._parse_elf_imports(data)
            elif b'MZ' in data[:2]:
                imports = self._parse_pe_imports(data)
            
        except Exception as e:
            logger.error(f"提取导入失败: {e}")
        
        return imports
    
    def _parse_elf_imports(self, data: bytes) -> List[str]:
        """解析ELF导入表"""
        imports = []
        try:
            e_shoff = int.from_bytes(data[40:48], 'little')
            e_shentsize = int.from_bytes(data[48:50], 'little')
            e_shnum = int.from_bytes(data[50:52], 'little')
            
            for i in range(e_shnum):
                sh_offset = e_shoff + i * e_shentsize
                sh_name = int.from_bytes(data[sh_offset:sh_offset+4], 'little')
                sh_type = int.from_bytes(data[sh_offset+4:sh_offset+8], 'little')
                
                if sh_type == 2:  # SHT_SYMTAB
                    sh_offset_sym = int.from_bytes(data[sh_offset+16:sh_offset+24], 'little')
                    sh_size = int.from_bytes(data[sh_offset+24:sh_offset+32], 'little')
                    sh_entsize = int.from_bytes(data[sh_offset+32:sh_offset+40], 'little')
                    
                    for j in range(sh_size // sh_entsize):
                        sym_offset = sh_offset_sym + j * sh_entsize
                        st_name = int.from_bytes(data[sym_offset:sym_offset+4], 'little')
                        if st_name > 0 and st_name < len(data):
                            null_pos = data[st_name:].find(b'\x00')
                            if null_pos > 0:
                                name = data[st_name:st_name+null_pos].decode('ascii', errors='ignore')
                                imports.append(name)
        except:
            pass
        
        return imports
    
    def _parse_pe_imports(self, data: bytes) -> List[str]:
        """解析PE导入表"""
        imports = []
        try:
            e_lfanew = int.from_bytes(data[60:64], 'little')
            pe_header = e_lfanew + 24
            number_of_rva_and_sizes = int.from_bytes(data[pe_header:pe_header+4], 'little')
            
            import_table_rva = None
            for i in range(number_of_rva_and_sizes):
                if i == 1:  # IMAGE_DIRECTORY_ENTRY_IMPORT
                    import_table_rva = int.from_bytes(data[pe_header + 8 + i*8 : pe_header + 12 + i*8], 'little')
            
            if import_table_rva:
                offset = import_table_rva
                while True:
                    name_rva = int.from_bytes(data[offset:offset+4], 'little')
                    if name_rva == 0:
                        break
                    
                    name_offset = name_rva
                    null_pos = data[name_offset:].find(b'\x00')
                    if null_pos > 0:
                        dll_name = data[name_offset:name_offset+null_pos].decode('ascii', errors='ignore')
                        
                        thunk_offset = offset + 12
                        while True:
                            thunk_data = int.from_bytes(data[thunk_offset:thunk_offset+4], 'little')
                            if thunk_data == 0:
                                break
                            
                            if (thunk_data & 0x80000000) == 0:
                                hint_name_rva = thunk_data
                                hint = int.from_bytes(data[hint_name_rva:hint_name_rva+2], 'little')
                                func_name_offset = hint_name_rva + 2
                                null_pos2 = data[func_name_offset:].find(b'\x00')
                                if null_pos2 > 0:
                                    func_name = data[func_name_offset:func_name_offset+null_pos2].decode('ascii', errors='ignore')
                                    imports.append(func_name)
                            
                            thunk_offset += 4
                    
                    offset += 20
        except:
            pass
        
        return imports
    
    def detect_weak_random(self) -> List[CryptoMisuse]:
        """检测弱随机数生成器使用"""
        misuses = []
        
        weak_found = [f for f in self.imports if any(wf in f for wf in self.WEAK_RANDOM_FUNCTIONS)]
        secure_found = [f for f in self.imports if any(sf in f for sf in self.SECURE_RANDOM_FUNCTIONS)]
        
        for weak_func in weak_found:
            if not secure_found:
                misuses.append(CryptoMisuse(
                    misuse_type='WEAK_RANDOM',
                    severity='high',
                    location=weak_func,
                    description=f"使用弱随机数生成器 {weak_func}，可能导致可预测的随机值",
                    recommendation=f"使用安全的随机数生成器，如 getrandom()、arc4random() 或 crypto/rand",
                    evidence=f"导入函数: {weak_func}"
                ))
        
        return misuses
    
    def detect_hardcoded_iv(self) -> List[CryptoMisuse]:
        """检测硬编码的IV"""
        misuses = []
        
        iv_patterns = [
            (r'0x[0-9a-fA-F]{16}', '128-bit 常量（可能是硬编码IV）'),
            (r'[0-9a-fA-F]{32}', '32位十六进制常量（可能是硬编码IV）'),
            (r'\\x[0-9a-fA-F]{2}', '字节常量序列（可能是硬编码IV）'),
        ]
        
        for pattern, desc in iv_patterns:
            for string in self.strings:
                matches = re.findall(pattern, string)
                for match in matches[:3]:
                    if len(match) >= 16:
                        misuses.append(CryptoMisuse(
                            misuse_type='HARDCODED_IV',
                            severity='high',
                            location=f"字符串: {match[:20]}...",
                            description=f"检测到硬编码的常量 {desc}",
                            recommendation="不要在代码中硬编码加密参数（IV、密钥等），应从安全来源获取",
                            evidence=f"匹配字符串: {match}"
                        ))
        
        return misuses
    
    def detect_weak_hash(self) -> List[CryptoMisuse]:
        """检测弱哈希算法"""
        misuses = []
        
        for func_prefix, desc, severity in self.HASH_FUNCTIONS:
            found_funcs = [f for f in self.imports if f.startswith(func_prefix)]
            if found_funcs:
                for func in found_funcs:
                    if severity == 'high':
                        misuses.append(CryptoMisuse(
                            misuse_type='WEAK_HASH_ALGORITHM',
                            severity=severity,
                            location=func,
                            description=f"使用已废弃的哈希算法 {desc}",
                            recommendation=f"使用 SHA-256、SHA-512 或 SHA-3 替代 {desc}",
                            evidence=f"导入函数: {func}"
                        ))
        
        return misuses
    
    def detect_weak_cipher(self) -> List[CryptoMisuse]:
        """检测弱加密算法"""
        misuses = []
        
        weak_ciphers = ['DES_', '3DES_', 'Blowfish_', 'RC4_']
        
        for func_prefix, desc in self.ENCRYPTION_FUNCTIONS:
            found_funcs = [f for f in self.imports if func_prefix in f]
            if found_funcs and func_prefix in weak_ciphers:
                for func in found_funcs:
                    misuses.append(CryptoMisuse(
                        misuse_type='WEAK_CIPHER',
                        severity='high',
                        location=func,
                        description=f"使用已废弃的加密算法 {desc}",
                        recommendation=f"使用 AES 或 ChaCha20 替代 {desc}",
                        evidence=f"导入函数: {func}"
                    ))
        
        return misuses
    
    def detect_insecure_kdf(self) -> List[CryptoMisuse]:
        """检测不安全的密钥派生"""
        misuses = []
        
        kdf_patterns = [
            (r'PKCS5_PBKDF2_HMAC.*,.*,(\d+)', '低迭代次数的PBKDF2'),
        ]
        
        for string in self.strings:
            for pattern, desc in kdf_patterns:
                match = re.search(pattern, string)
                if match:
                    iterations = int(match.group(1))
                    if iterations < 10000:
                        misuses.append(CryptoMisuse(
                            misuse_type='INSECURE_KDF',
                            severity='medium',
                            location=f"字符串匹配",
                            description=f"{desc}，迭代次数仅为 {iterations}",
                            recommendation="增加 PBKDF2 迭代次数至少到 100000，或使用 scrypt/argon2",
                            evidence=f"匹配字符串: {string[:50]}..."
                        ))
        
        return misuses
    
    def detect_hardcoded_secrets(self) -> List[CryptoMisuse]:
        """检测硬编码密钥/密码"""
        misuses = []
        
        secret_patterns = [
            (r'(?i)secret.*[0-9a-fA-F]{16,}', '可能的硬编码密钥'),
            (r'(?i)key.*[0-9a-fA-F]{16,}', '可能的硬编码密钥'),
            (r'(?i)password.*=.*["\']', '可能的硬编码密码'),
            (r'(?i)api[_-]key.*=.*["\']', '可能的硬编码API密钥'),
            (r'(?i)token.*=.*["\']', '可能的硬编码令牌'),
        ]
        
        for pattern, desc in secret_patterns:
            for string in self.strings:
                if re.search(pattern, string):
                    misuses.append(CryptoMisuse(
                        misuse_type='HARDCODED_SECRET',
                        severity='high',
                        location=f"字符串匹配",
                        description=f"检测到 {desc}",
                        recommendation="不要在代码或二进制中硬编码敏感信息，使用安全的密钥管理方案",
                        evidence=f"匹配字符串: {string[:50]}..."
                    ))
        
        return misuses
    
    def analyze(self) -> CryptoMisuseResult:
        """执行密码误用分析"""
        self.misuses = []
        
        if self.binary_path:
            self.strings = self._extract_strings()
            self.imports = self._extract_imports()
        
        self.misuses.extend(self.detect_weak_random())
        self.misuses.extend(self.detect_hardcoded_iv())
        self.misuses.extend(self.detect_weak_hash())
        self.misuses.extend(self.detect_weak_cipher())
        self.misuses.extend(self.detect_insecure_kdf())
        self.misuses.extend(self.detect_hardcoded_secrets())
        
        summary = self._generate_summary()
        
        return CryptoMisuseResult(
            filename=os.path.basename(self.binary_path) if self.binary_path else 'unknown',
            misuses=self.misuses,
            summary=summary
        )
    
    def _generate_summary(self) -> str:
        """生成分析摘要"""
        high_count = sum(1 for m in self.misuses if m.severity == 'high')
        medium_count = sum(1 for m in self.misuses if m.severity == 'medium')
        low_count = sum(1 for m in self.misuses if m.severity == 'low')
        
        parts = [
            f"检测到 {len(self.misuses)} 个密码误用问题",
            f"- 高危: {high_count}",
            f"- 中危: {medium_count}",
            f"- 低危: {low_count}",
        ]
        
        return '\n'.join(parts)
    
    def generate_report(self) -> str:
        """生成分析报告"""
        result = self.analyze()
        
        lines = [
            "密码误用检测报告",
            "=================",
            "",
            f"文件: {result.filename}",
            "",
            "摘要:",
            "------",
            result.summary,
            ""
        ]
        
        if result.misuses:
            lines.append("发现的问题:")
            lines.append("------------")
            for i, misuse in enumerate(result.misuses, 1):
                lines.append(f"{i}. [{misuse.severity.upper()}] {misuse.misuse_type}")
                lines.append(f"   位置: {misuse.location}")
                lines.append(f"   描述: {misuse.description}")
                lines.append(f"   建议: {misuse.recommendation}")
                lines.append("")
        
        return '\n'.join(lines)


def detect_crypto_misuse(binary_path: str) -> CryptoMisuseResult:
    """检测密码误用的便捷函数"""
    detector = CryptoMisuseDetector(binary_path)
    return detector.analyze()


def scan_for_weak_random(binary_path: str) -> List[CryptoMisuse]:
    """扫描弱随机数生成器"""
    detector = CryptoMisuseDetector(binary_path)
    detector.strings = detector._extract_strings()
    detector.imports = detector._extract_imports()
    return detector.detect_weak_random()


def scan_for_hardcoded_secrets(binary_path: str) -> List[CryptoMisuse]:
    """扫描硬编码敏感信息"""
    detector = CryptoMisuseDetector(binary_path)
    detector.strings = detector._extract_strings()
    detector.imports = detector._extract_imports()
    return detector.detect_hardcoded_secrets()
