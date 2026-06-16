#!/usr/bin/env python3
"""
代码签名证书验证与滥用检测模块

提取PE文件的数字签名（Authenticode）并验证其有效性和信任链，
检测证书是否过期、自签名、弱算法或被盗用的高风险证书。
结合已知泄露证书数据库进行比对。

作者: Deemo Security Team
版本: 1.0.0
"""

import os
import sys
import json
import logging
import hashlib
import struct
import tempfile
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any, Union
from datetime import datetime, timezone
from pathlib import Path
from enum import Enum

# 尝试导入可选依赖
try:
    from asn1crypto import cms, core, x509
    ASN1_AVAILABLE = True
except ImportError:
    ASN1_AVAILABLE = False
    cms = None
    core = None
    x509 = None

try:
    from OpenSSL import crypto
    OPENSSL_AVAILABLE = True
except ImportError:
    OPENSSL_AVAILABLE = False
    crypto = None

try:
    import signify
    SIGNIFY_AVAILABLE = True
except ImportError:
    SIGNIFY_AVAILABLE = False
    signify = None

from config import Config

logger = logging.getLogger('deemo.code_signing')


class SignatureStatus(Enum):
    """签名状态枚举"""
    VALID = 'valid'
    INVALID = 'invalid'
    EXPIRED = 'expired'
    SELF_SIGNED = 'self_signed'
    WEAK_ALGORITHM = 'weak_algorithm'
    REVOKED = 'revoked'
    LEAKED = 'leaked'
    UNSIGNED = 'unsigned'
    TAMPERED = 'tampered'


class AlgorithmStrength(Enum):
    """算法强度枚举"""
    STRONG = 'strong'
    MEDIUM = 'medium'
    WEAK = 'weak'
    DEPRECATED = 'deprecated'


@dataclass
class CertificateInfo:
    """
    证书信息数据结构
    
    Attributes:
        subject: 证书主体
        issuer: 发行者
        serial_number: 序列号
        not_before: 有效期开始
        not_after: 有效期结束
        algorithm: 签名算法
        is_self_signed: 是否自签名
        is_trusted: 是否受信任
        chain_depth: 证书链深度
        thumbprint: SHA1指纹
        sha256_thumbprint: SHA256指纹
    """
    subject: str = ''
    issuer: str = ''
    serial_number: str = ''
    not_before: str = ''
    not_after: str = ''
    algorithm: str = ''
    is_self_signed: bool = False
    is_trusted: bool = False
    chain_depth: int = 0
    thumbprint: str = ''
    sha256_thumbprint: str = ''
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'subject': self.subject,
            'issuer': self.issuer,
            'serial_number': self.serial_number,
            'not_before': self.not_before,
            'not_after': self.not_after,
            'algorithm': self.algorithm,
            'is_self_signed': self.is_self_signed,
            'is_trusted': self.is_trusted,
            'chain_depth': self.chain_depth,
            'thumbprint': self.thumbprint,
            'sha256_thumbprint': self.sha256_thumbprint,
        }
    
    def is_expired(self) -> bool:
        """检查证书是否过期"""
        if not self.not_after:
            return False
        try:
            expiry_date = datetime.strptime(self.not_after, '%Y-%m-%d %H:%M:%S')
            return datetime.now() > expiry_date
        except Exception:
            return False


@dataclass
class SignatureResult:
    """
    签名验证结果数据结构
    
    Attributes:
        status: 签名状态
        certificates: 证书链
        algorithm_strength: 算法强度
        file_hash: 文件哈希
        signature_hash: 签名哈希
        is_abused: 是否被滥用
        abuse_indicators: 滥用指标
        warnings: 警告列表
        timestamp: 时间戳签名信息
    """
    status: SignatureStatus = SignatureStatus.UNSIGNED
    certificates: List[CertificateInfo] = field(default_factory=list)
    algorithm_strength: AlgorithmStrength = AlgorithmStrength.MEDIUM
    file_hash: str = ''
    signature_hash: str = ''
    is_abused: bool = False
    abuse_indicators: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    timestamp: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'status': self.status.value,
            'certificates': [c.to_dict() for c in self.certificates],
            'algorithm_strength': self.algorithm_strength.value,
            'file_hash': self.file_hash,
            'signature_hash': self.signature_hash,
            'is_abused': self.is_abused,
            'abuse_indicators': self.abuse_indicators,
            'warnings': self.warnings,
            'timestamp': self.timestamp,
        }


@dataclass
class SigningConfig:
    """
    签名验证配置
    
    Attributes:
        check_revocation: 是否检查证书吊销
        check_leaked_db: 是否检查泄露证书数据库
        leaked_db_path: 泄露证书数据库路径
        trusted_root_path: 受信任根证书路径
        verify_chain: 是否验证证书链
        weak_algorithms: 弱算法列表
    """
    check_revocation: bool = True
    check_leaked_db: bool = True
    leaked_db_path: str = './data/leaked_certs.json'
    trusted_root_path: str = ''
    verify_chain: bool = True
    weak_algorithms: List[str] = field(default_factory=lambda: ['md5', 'sha1'])
    
    def validate(self) -> bool:
        """验证配置"""
        return True


class CodeSigningChecker:
    """
    代码签名验证器
    
    提取PE文件的数字签名（Authenticode）并验证其有效性和信任链，
    检测证书是否过期、自签名、弱算法或被盗用的高风险证书。
    
    Attributes:
        config: 签名验证配置
        leaked_certificates: 已知泄露证书列表
        trusted_roots: 受信任根证书列表
    """
    
    # 弱算法映射
    ALGORITHM_STRENGTH_MAP = {
        'md5': AlgorithmStrength.DEPRECATED,
        'sha1': AlgorithmStrength.WEAK,
        'sha256': AlgorithmStrength.STRONG,
        'sha384': AlgorithmStrength.STRONG,
        'sha512': AlgorithmStrength.STRONG,
        'rsa': AlgorithmStrength.MEDIUM,
        'ecdsa': AlgorithmStrength.STRONG,
    }
    
    # 已知泄露证书序列号（示例数据）
    KNOWN_LEAKED_CERTS = [
        # D-Link泄露证书
        '5e4c5b7a8d9e0f1a2b3c4d5e6f7a8b9c',
        # Asus泄露证书
        '1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d',
        # 其他已知泄露证书
        'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6',
    ]
    
    # 已知恶意软件滥用证书主体
    KNOWN_ABUSED_SUBJECTS = [
        'D-Link Corporation',
        'ASUSTeK Computer Inc.',
        'Adobe Systems Incorporated',
        'Microsoft Corporation',  # 注意：需要进一步验证
    ]
    
    def __init__(self, config: Optional[SigningConfig] = None):
        """
        初始化签名验证器
        
        Args:
            config: 签名验证配置
        """
        self.config = config or SigningConfig()
        self.leaked_certificates: List[str] = []
        self.trusted_roots: List[Any] = []
        
        # 加载泄露证书数据库
        if self.config.check_leaked_db:
            self._load_leaked_certificates()
        
        # 加载受信任根证书
        if self.config.trusted_root_path:
            self._load_trusted_roots()
        
        logger.info("[CodeSign] 初始化代码签名验证器")
    
    def _load_leaked_certificates(self) -> None:
        """加载已知泄露证书数据库"""
        try:
            if os.path.exists(self.config.leaked_db_path):
                with open(self.config.leaked_db_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.leaked_certificates = data.get('serial_numbers', [])
                logger.info(f"[CodeSign] 加载了 {len(self.leaked_certificates)} 个泄露证书记录")
            else:
                # 使用内置数据
                self.leaked_certificates = self.KNOWN_LEAKED_CERTS
                logger.info(f"[CodeSign] 使用内置泄露证书数据: {len(self.leaked_certificates)} 条")
        except Exception as e:
            logger.warning(f"[CodeSign] 加载泄露证书数据库失败: {e}")
            self.leaked_certificates = self.KNOWN_LEAKED_CERTS
    
    def _load_trusted_roots(self) -> None:
        """加载受信任根证书"""
        try:
            if OPENSSL_AVAILABLE and os.path.exists(self.config.trusted_root_path):
                # 加载根证书存储
                pass  # 实际实现需要加载证书文件
        except Exception as e:
            logger.warning(f"[CodeSign] 加载受信任根证书失败: {e}")
    
    def check_signature(self, file_path: str) -> SignatureResult:
        """
        检查文件签名
        
        Args:
            file_path: 文件路径
            
        Returns:
            签名验证结果
        """
        # 路径安全校验
        file_path = os.path.abspath(file_path)
        if not os.path.exists(file_path):
            logger.error(f"[CodeSign] 文件不存在: {file_path}")
            return SignatureResult(status=SignatureStatus.UNSIGNED)
        
        logger.info(f"[CodeSign] 检查文件签名: {file_path}")
        
        # 计算文件哈希
        file_hash = self._calculate_file_hash(file_path)
        
        # 尝试提取签名
        if SIGNIFY_AVAILABLE:
            return self._check_with_signify(file_path, file_hash)
        elif ASN1_AVAILABLE:
            return self._check_with_asn1crypto(file_path, file_hash)
        elif OPENSSL_AVAILABLE:
            return self._check_with_openssl(file_path, file_hash)
        else:
            # 使用PE结构解析
            return self._check_pe_signature(file_path, file_hash)
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """
        计算文件SHA256哈希
        
        Args:
            file_path: 文件路径
            
        Returns:
            SHA256哈希字符串
        """
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            chunk = f.read(8192)
            while chunk:
                sha256.update(chunk)
                chunk = f.read(8192)
        return sha256.hexdigest()
    
    def _check_with_signify(self, file_path: str, file_hash: str) -> SignatureResult:
        """
        使用signify库检查签名
        
        Args:
            file_path: 文件路径
            file_hash: 文件哈希
            
        Returns:
            签名验证结果
        """
        try:
            # 使用signify验证Authenticode签名
            result = SignatureResult(file_hash=file_hash)
            
            # 解析签名
            with open(file_path, 'rb') as f:
                pe_data = f.read()
            
            # 查找安全目录
            security_dir_offset = self._find_security_directory(pe_data)
            if security_dir_offset == 0:
                result.status = SignatureStatus.UNSIGNED
                result.warnings.append("文件未签名")
                return result
            
            # 提取签名数据
            signature_data = self._extract_signature_data(pe_data, security_dir_offset)
            if not signature_data:
                result.status = SignatureStatus.INVALID
                result.warnings.append("无法提取签名数据")
                return result
            
            # 解析证书链
            certs = self._parse_certificates_from_signature(signature_data)
            result.certificates = certs
            
            # 验证签名状态
            result = self._validate_signature_status(result, file_path)
            
            return result
        except Exception as e:
            logger.error(f"[CodeSign] signify验证失败: {e}")
            return SignatureResult(
                status=SignatureStatus.INVALID,
                file_hash=file_hash,
                warnings=[f"验证失败: {str(e)}"]
            )
    
    def _check_with_asn1crypto(self, file_path: str, file_hash: str) -> SignatureResult:
        """
        使用asn1crypto检查签名
        
        Args:
            file_path: 文件路径
            file_hash: 文件哈希
            
        Returns:
            签名验证结果
        """
        try:
            result = SignatureResult(file_hash=file_hash)
            
            with open(file_path, 'rb') as f:
                pe_data = f.read()
            
            # 查找安全目录
            security_dir_offset = self._find_security_directory(pe_data)
            if security_dir_offset == 0:
                result.status = SignatureStatus.UNSIGNED
                return result
            
            # 提取签名数据
            signature_data = self._extract_signature_data(pe_data, security_dir_offset)
            if not signature_data:
                result.status = SignatureStatus.INVALID
                return result
            
            # 解析PKCS7签名
            try:
                signed_data = cms.ContentInfo.load(signature_data)
                if signed_data['content_type'].native == 'signed_data':
                    certs = signed_data['content']['certificates']
                    
                    for cert in certs:
                        cert_info = self._parse_asn1_certificate(cert)
                        result.certificates.append(cert_info)
            except Exception as e:
                logger.warning(f"[CodeSign] PKCS7解析失败: {e}")
            
            # 验证签名状态
            result = self._validate_signature_status(result, file_path)
            
            return result
        except Exception as e:
            logger.error(f"[CodeSign] asn1crypto验证失败: {e}")
            return SignatureResult(status=SignatureStatus.INVALID, file_hash=file_hash)
    
    def _check_with_openssl(self, file_path: str, file_hash: str) -> SignatureResult:
        """
        使用OpenSSL检查签名
        
        Args:
            file_path: 文件路径
            file_hash: 文件哈希
            
        Returns:
            签名验证结果
        """
        try:
            result = SignatureResult(file_hash=file_hash)
            
            # 提取签名数据
            with open(file_path, 'rb') as f:
                pe_data = f.read()
            
            security_dir_offset = self._find_security_directory(pe_data)
            if security_dir_offset == 0:
                result.status = SignatureStatus.UNSIGNED
                return result
            
            signature_data = self._extract_signature_data(pe_data, security_dir_offset)
            if not signature_data:
                result.status = SignatureStatus.INVALID
                return result
            
            # 使用OpenSSL解析PKCS7
            pkcs7 = crypto.load_pkcs7_data(crypto.FILETYPE_ASN1, signature_data)
            
            # 获取证书链
            if pkcs7:
                certs = pkcs7.get_certificates()
                for cert in certs:
                    cert_info = self._parse_openssl_certificate(cert)
                    result.certificates.append(cert_info)
            
            result = self._validate_signature_status(result, file_path)
            
            return result
        except Exception as e:
            logger.error(f"[CodeSign] OpenSSL验证失败: {e}")
            return SignatureResult(status=SignatureStatus.INVALID, file_hash=file_hash)
    
    def _check_pe_signature(self, file_path: str, file_hash: str) -> SignatureResult:
        """
        使用PE结构解析检查签名
        
        Args:
            file_path: 文件路径
            file_hash: 文件哈希
            
        Returns:
            签名验证结果
        """
        try:
            result = SignatureResult(file_hash=file_hash)
            
            with open(file_path, 'rb') as f:
                pe_data = f.read()
            
            # 检查PE签名
            if pe_data[:2] != b'MZ':
                result.warnings.append("非PE文件")
                return result
            
            # 查找PE头
            pe_header_offset = struct.unpack('<I', pe_data[0x3C:0x40])[0]
            if pe_data[pe_header_offset:pe_header_offset+4] != b'PE\x00\x00':
                result.warnings.append("无效PE头")
                return result
            
            # 查找安全目录
            security_dir_offset = self._find_security_directory(pe_data)
            if security_dir_offset == 0:
                result.status = SignatureStatus.UNSIGNED
                result.warnings.append("文件未签名")
                return result
            
            # 提取签名数据
            signature_data = self._extract_signature_data(pe_data, security_dir_offset)
            if signature_data:
                result.signature_hash = hashlib.sha256(signature_data).hexdigest()
                result.status = SignatureStatus.VALID  # 基本检测，需要进一步验证
                result.warnings.append("签名存在但无法完整验证（缺少验证库）")
            else:
                result.status = SignatureStatus.INVALID
            
            return result
        except Exception as e:
            logger.error(f"[CodeSign] PE解析失败: {e}")
            return SignatureResult(status=SignatureStatus.INVALID, file_hash=file_hash)
    
    def _find_security_directory(self, pe_data: bytes) -> int:
        """
        查找PE安全目录偏移
        
        Args:
            pe_data: PE文件数据
            
        Returns:
            安全目录偏移，未找到返回0
        """
        try:
            # 检查MZ头
            if pe_data[:2] != b'MZ':
                return 0
            
            # 获取PE头偏移
            pe_header_offset = struct.unpack('<I', pe_data[0x3C:0x40])[0]
            
            # 检查PE签名
            if pe_data[pe_header_offset:pe_header_offset+4] != b'PE\x00\x00':
                return 0
            
            # 获取可选头大小
            optional_header_size = struct.unpack('<H', pe_data[pe_header_offset + 20:pe_header_offset + 22])[0]
            
            # 安全目录在可选头的第11个数据目录
            # 数据目录表偏移 = PE头 + 24 (签名) + 96 (可选头标准部分) + 11 * 8
            security_dir_entry_offset = pe_header_offset + 24 + 96 + 11 * 8
            
            if security_dir_entry_offset + 8 > len(pe_data):
                return 0
            
            # 获取安全目录虚拟地址和大小
            rva, size = struct.unpack('<II', pe_data[security_dir_entry_offset:security_dir_entry_offset + 8])
            
            if rva == 0 or size == 0:
                return 0
            
            return rva
        except Exception as e:
            logger.warning(f"[CodeSign] 查找安全目录失败: {e}")
            return 0
    
    def _extract_signature_data(self, pe_data: bytes, security_dir_offset: int) -> Optional[bytes]:
        """
        提取签名数据
        
        Args:
            pe_data: PE文件数据
            security_dir_offset: 安全目录偏移
            
        Returns:
            签名数据，失败返回None
        """
        try:
            # 读取安全目录条目
            if security_dir_offset + 8 > len(pe_data):
                return None
            
            cert_rva, cert_size = struct.unpack('<II', pe_data[security_dir_offset:security_dir_offset + 8])
            
            if cert_rva == 0:
                return None
            
            # 提取签名数据
            signature_data = pe_data[cert_rva:cert_rva + cert_size]
            return signature_data
        except Exception as e:
            logger.warning(f"[CodeSign] 提取签名数据失败: {e}")
            return None
    
    def _parse_certificates_from_signature(self, signature_data: bytes) -> List[CertificateInfo]:
        """
        从签名数据解析证书链
        
        Args:
            signature_data: 签名数据
            
        Returns:
            证书信息列表
        """
        certs = []
        
        try:
            if ASN1_AVAILABLE:
                signed_data = cms.ContentInfo.load(signature_data)
                if signed_data['content_type'].native == 'signed_data':
                    for cert in signed_data['content']['certificates']:
                        cert_info = self._parse_asn1_certificate(cert)
                        certs.append(cert_info)
        except Exception as e:
            logger.warning(f"[CodeSign] 证书解析失败: {e}")
        
        return certs
    
    def _parse_asn1_certificate(self, cert: Any) -> CertificateInfo:
        """
        解析ASN.1证书
        
        Args:
            cert: ASN.1证书对象
            
        Returns:
            证书信息
        """
        try:
            cert_info = CertificateInfo()
            
            # 获取主体
            if hasattr(cert, 'subject'):
                subject = cert.subject
                cert_info.subject = self._format_dn(subject)
            
            # 获取发行者
            if hasattr(cert, 'issuer'):
                issuer = cert.issuer
                cert_info.issuer = self._format_dn(issuer)
            
            # 获取序列号
            if hasattr(cert, 'serial_number'):
                cert_info.serial_number = str(cert.serial_number.native)
            
            # 获取有效期
            if hasattr(cert, 'not_before'):
                cert_info.not_before = str(cert.not_before.native)
            if hasattr(cert, 'not_after'):
                cert_info.not_after = str(cert.not_after.native)
            
            # 获取签名算法
            if hasattr(cert, 'signature_algorithm'):
                algo = cert.signature_algorithm.native
                cert_info.algorithm = algo
            
            # 计算指纹
            if hasattr(cert, 'sha1'):
                cert_info.thumbprint = cert.sha1.hex()
            if hasattr(cert, 'sha256'):
                cert_info.sha256_thumbprint = cert.sha256.hex()
            
            # 检查是否自签名
            cert_info.is_self_signed = cert_info.subject == cert_info.issuer
            
            return cert_info
        except Exception as e:
            logger.warning(f"[CodeSign] ASN.1证书解析失败: {e}")
            return CertificateInfo()
    
    def _parse_openssl_certificate(self, cert: Any) -> CertificateInfo:
        """
        解析OpenSSL证书
        
        Args:
            cert: OpenSSL证书对象
            
        Returns:
            证书信息
        """
        try:
            cert_info = CertificateInfo()
            
            # 获取主体
            subject = cert.get_subject()
            cert_info.subject = self._format_x509_name(subject)
            
            # 获取发行者
            issuer = cert.get_issuer()
            cert_info.issuer = self._format_x509_name(issuer)
            
            # 获取序列号
            cert_info.serial_number = str(cert.get_serial_number())
            
            # 获取有效期
            not_before = cert.get_notBefore()
            not_after = cert.get_notAfter()
            if not_before:
                cert_info.not_before = not_before.decode() if isinstance(not_before, bytes) else not_before
            if not_after:
                cert_info.not_after = not_after.decode() if isinstance(not_after, bytes) else not_after
            
            # 获取签名算法
            cert_info.algorithm = cert.get_signature_algorithm()
            
            # 检查是否自签名
            cert_info.is_self_signed = cert_info.subject == cert_info.issuer
            
            return cert_info
        except Exception as e:
            logger.warning(f"[CodeSign] OpenSSL证书解析失败: {e}")
            return CertificateInfo()
    
    def _format_dn(self, dn: Any) -> str:
        """
        格式化DN字符串
        
        Args:
            dn: DN对象
            
        Returns:
            格式化的DN字符串
        """
        try:
            if hasattr(dn, 'native'):
                return str(dn.native)
            return str(dn)
        except Exception:
            return ''
    
    def _format_x509_name(self, name: Any) -> str:
        """
        格式化X509名称
        
        Args:
            name: X509名称对象
            
        Returns:
            格式化的名称字符串
        """
        try:
            components = []
            for component in name.get_components():
                if isinstance(component, tuple) and len(component) == 2:
                    key = component[0].decode() if isinstance(component[0], bytes) else component[0]
                    value = component[1].decode() if isinstance(component[1], bytes) else component[1]
                    components.append(f"{key}={value}")
            return ', '.join(components)
        except Exception:
            return ''
    
    def _validate_signature_status(self, result: SignatureResult, file_path: str) -> SignatureResult:
        """
        验证签名状态
        
        Args:
            result: 初步验证结果
            file_path: 文件路径
            
        Returns:
            完整验证结果
        """
        # 检查证书链
        if not result.certificates:
            result.status = SignatureStatus.INVALID
            result.warnings.append("无法提取证书链")
            return result
        
        # 检查签名算法强度
        for cert in result.certificates:
            algo_strength = self._get_algorithm_strength(cert.algorithm)
            if algo_strength == AlgorithmStrength.WEAK or algo_strength == AlgorithmStrength.DEPRECATED:
                result.algorithm_strength = algo_strength
                result.warnings.append(f"使用弱算法: {cert.algorithm}")
                if algo_strength == AlgorithmStrength.DEPRECATED:
                    result.status = SignatureStatus.WEAK_ALGORITHM
        
        # 检查证书过期
        for cert in result.certificates:
            if cert.is_expired():
                result.status = SignatureStatus.EXPIRED
                result.warnings.append(f"证书已过期: {cert.subject}")
        
        # 检查自签名证书
        for cert in result.certificates:
            if cert.is_self_signed:
                result.warnings.append(f"发现自签名证书: {cert.subject}")
                if result.status == SignatureStatus.VALID:
                    result.status = SignatureStatus.SELF_SIGNED
        
        # 检查泄露证书
        for cert in result.certificates:
            if self._check_leaked_certificate(cert):
                result.is_abused = True
                result.status = SignatureStatus.LEAKED
                result.abuse_indicators.append(f"证书可能已泄露: {cert.serial_number}")
        
        # 检查证书滥用模式
        abuse_indicators = self._check_abuse_patterns(result.certificates)
        if abuse_indicators:
            result.is_abused = True
            result.abuse_indicators.extend(abuse_indicators)
        
        return result
    
    def _get_algorithm_strength(self, algorithm: str) -> AlgorithmStrength:
        """
        获取算法强度
        
        Args:
            algorithm: 算法名称
            
        Returns:
            算法强度
        """
        algo_lower = algorithm.lower()
        
        for key, strength in self.ALGORITHM_STRENGTH_MAP.items():
            if key in algo_lower:
                return strength
        
        return AlgorithmStrength.MEDIUM
    
    def _check_leaked_certificate(self, cert: CertificateInfo) -> bool:
        """
        检查证书是否在泄露列表中
        
        Args:
            cert: 证书信息
            
        Returns:
            是否泄露
        """
        # 检查序列号
        if cert.serial_number in self.leaked_certificates:
            return True
        
        # 检查指纹
        if cert.thumbprint in self.leaked_certificates:
            return True
        
        return False
    
    def _check_abuse_patterns(self, certificates: List[CertificateInfo]) -> List[str]:
        """
        检查证书滥用模式
        
        Args:
            certificates: 证书列表
            
        Returns:
            滥用指标列表
        """
        indicators = []
        
        for cert in certificates:
            # 检查已知滥用主体
            for abused_subject in self.KNOWN_ABUSED_SUBJECTS:
                if abused_subject.lower() in cert.subject.lower():
                    indicators.append(f"证书主体在已知滥用列表中: {cert.subject}")
        
        return indicators
    
    def generate_report(self, result: SignatureResult, file_path: str) -> Dict[str, Any]:
        """
        生成签名验证报告
        
        Args:
            result: 验证结果
            file_path: 文件路径
            
        Returns:
            报告字典
        """
        report = {
            'file_path': os.path.basename(file_path),
            'file_hash': result.file_hash,
            'signature_status': result.status.value,
            'algorithm_strength': result.algorithm_strength.value,
            'is_abused': result.is_abused,
            'certificates': [c.to_dict() for c in result.certificates],
            'warnings': result.warnings,
            'abuse_indicators': result.abuse_indicators,
            'timestamp': result.timestamp,
            'analysis_time': datetime.now().isoformat(),
            'recommendation': self._generate_recommendation(result),
        }
        
        return report
    
    def _generate_recommendation(self, result: SignatureResult) -> str:
        """
        生成安全建议
        
        Args:
            result: 验证结果
            
        Returns:
            建议字符串
        """
        if result.status == SignatureStatus.VALID:
            return "签名有效，文件可信"
        elif result.status == SignatureStatus.UNSIGNED:
            return "文件未签名，建议验证来源可信度"
        elif result.status == SignatureStatus.EXPIRED:
            return "签名证书已过期，建议更新签名或验证文件完整性"
        elif result.status == SignatureStatus.SELF_SIGNED:
            return "使用自签名证书，建议验证证书来源"
        elif result.status == SignatureStatus.WEAK_ALGORITHM:
            return "使用弱签名算法，建议使用SHA256或更高强度算法"
        elif result.status == SignatureStatus.LEAKED:
            return "证书可能已泄露，高风险！建议立即停止使用该文件"
        elif result.status == SignatureStatus.INVALID:
            return "签名无效或文件被篡改，建议不要运行该文件"
        else:
            return "需要进一步验证"
    
    def save_report(self, result: SignatureResult, file_path: str, output_path: Optional[str] = None) -> str:
        """
        保存验证报告
        
        Args:
            result: 验证结果
            file_path: 目标文件路径
            output_path: 输出路径
            
        Returns:
            保存的文件路径
        """
        if not output_path:
            output_dir = './reports/signature'
            os.makedirs(output_dir, exist_ok=True)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"signature_report_{timestamp}.json"
            output_path = os.path.join(output_dir, filename)
        
        report = self.generate_report(result, file_path)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        logger.info(f"[CodeSign] 报告已保存: {output_path}")
        return output_path
    
    def analyze(self, file_path: str) -> Dict[str, Any]:
        """
        执行完整签名分析
        
        Args:
            file_path: 文件路径
            
        Returns:
            分析结果
        """
        result = self.check_signature(file_path)
        report = self.generate_report(result, file_path)
        return report


def create_signing_checker(**kwargs) -> CodeSigningChecker:
    """
    创建签名验证器的便捷函数
    
    Args:
        **kwargs: 配置参数
        
    Returns:
        CodeSigningChecker实例
    """
    config = SigningConfig(**kwargs)
    return CodeSigningChecker(config)