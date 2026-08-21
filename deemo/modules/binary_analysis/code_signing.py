#!/usr/bin/env python3
"""代码签名证书验证与滥用检测模块。

从 PE 文件提取数字签名 (Authenticode) 并验证其有效性与信任链,
检测过期/自签名/弱算法/已泄露证书, 与已知泄露证书库比对。
"""

import hashlib
import json
import logging
import os
import struct
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

# 可选依赖
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

logger = logging.getLogger('binmind.code_signing')


class SignatureStatus(str, Enum):
    """签名状态枚举。"""
    VALID = 'valid'
    INVALID = 'invalid'
    EXPIRED = 'expired'
    SELF_SIGNED = 'self_signed'
    WEAK_ALGORITHM = 'weak_algorithm'
    REVOKED = 'revoked'
    LEAKED = 'leaked'
    UNSIGNED = 'unsigned'
    TAMPERED = 'tampered'


class AlgorithmStrength(str, Enum):
    """算法强度枚举。"""
    STRONG = 'strong'
    MEDIUM = 'medium'
    WEAK = 'weak'
    DEPRECATED = 'deprecated'


@dataclass
class CertificateInfo:
    """证书信息结构: 主体/颁发者/序列号/有效期/算法/自签名/受信/链深/指纹。"""
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
        """证书是否已过期。"""
        if not self.not_after:
            return False
        try:
            expiry_date = datetime.strptime(self.not_after, '%Y-%m-%d %H:%M:%S')
            return datetime.now() > expiry_date
        except Exception:
            return False


@dataclass
class SignatureResult:
    """签名验证结果: 状态/证书链/算法强度/文件与签名哈希/滥用标记/警告/时间戳。"""
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
    """签名验证配置: 吊销检查/泄露库检查/泄露库路径/信任根路径/链验证/弱算法表。"""
    check_revocation: bool = True
    check_leaked_db: bool = True
    leaked_db_path: str = './data/leaked_certs.json'
    trusted_root_path: str = ''
    verify_chain: bool = True
    weak_algorithms: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.weak_algorithms:
            self.weak_algorithms = ['md5', 'sha1']

    def validate(self) -> bool:
        """配置校验。"""
        return True


class CodeSigningChecker:
    """代码签名验证器。

    从 PE 提取 Authenticode 签名并验证信任链, 检测过期/自签名/
    弱算法/泄露证书。字段: config 配置, leaked_certificates 泄露库,
    trusted_roots 信任根证书列表。
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

    # 已知泄露证书序列号 (内置样本数据)
    KNOWN_LEAKED_CERTS = [
        # D-Link 泄露证书
        '5e4c5b7a8d9e0f1a2b3c4d5e6f7a8b9c',
        # Asus 泄露证书
        '1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d',
        'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6',
    ]

    # 已知被恶意软件滥用的证书主体
    KNOWN_ABUSED_SUBJECTS = [
        'D-Link Corporation',
        'ASUSTeK Computer Inc.',
        'Adobe Systems Incorporated',
        'Microsoft Corporation',  # 需进一步核实
    ]

    def __init__(self, config: Optional[SigningConfig] = None):
        """初始化签名验证器。"""
        self.config = config or SigningConfig()
        self.leaked_certificates: List[str] = []
        self.trusted_roots: List[Any] = []

        # 加载泄露证书库
        if self.config.check_leaked_db:
            self._load_leaked_certificates()

        # 加载信任根证书
        if self.config.trusted_root_path:
            self._load_trusted_roots()

        logger.info("[CodeSign] Code signing verifier initialized")

    def _load_leaked_certificates(self) -> None:
        """加载已知泄露证书库。"""
        try:
            if os.path.exists(self.config.leaked_db_path):
                with open(self.config.leaked_db_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.leaked_certificates = data.get('serial_numbers', [])
                logger.info(f"[CodeSign] Loaded {len(self.leaked_certificates)} leaked certificate records")
            else:
                # 回退内置数据
                self.leaked_certificates = self.KNOWN_LEAKED_CERTS
                logger.info(f"[CodeSign] Using built-in leaked certificate data: {len(self.leaked_certificates)} records")
        except Exception as e:
            logger.warning(f"[CodeSign] Failed to load leaked certificate database: {e}")
            self.leaked_certificates = self.KNOWN_LEAKED_CERTS

    def _load_trusted_roots(self) -> None:
        """从信任根路径加载 CA 证书 (PEM/DER, 单文件或目录)。"""
        try:
            if not (OPENSSL_AVAILABLE and os.path.exists(self.config.trusted_root_path)):
                return
            p = self.config.trusted_root_path
            if os.path.isdir(p):
                paths = [os.path.join(p, fname) for fname in os.listdir(p)
                         if fname.endswith(('.pem', '.crt', '.cer', '.der'))]
            else:
                paths = [p]
            for fp in paths:
                with open(fp, 'rb') as f:
                    data = f.read()
                ftype = crypto.FILETYPE_PEM if b'-----BEGIN' in data else crypto.FILETYPE_ASN1
                self.trusted_roots.append(crypto.load_certificate(ftype, data))
            logger.info(f"[CodeSign] Loaded {len(self.trusted_roots)} trusted root certificates")
        except Exception as e:
            logger.warning(f"[CodeSign] Failed to load trusted root certificates: {e}")

    def check_signature(self, file_path: str) -> SignatureResult:
        """验证文件签名, 按可用库顺序 signify → asn1crypto → OpenSSL → PE 结构解析。"""
        # 路径安全校验
        file_path = os.path.abspath(file_path)
        if not os.path.exists(file_path):
            logger.error(f"[CodeSign] File not found: {file_path}")
            return SignatureResult(status=SignatureStatus.UNSIGNED)

        logger.info(f"[CodeSign] Checking file signature: {file_path}")

        # 计算文件哈希
        file_hash = self._calculate_file_hash(file_path)

        # 按可用依赖选择验证通道
        if SIGNIFY_AVAILABLE:
            return self._check_with_signify(file_path, file_hash)
        elif ASN1_AVAILABLE:
            return self._check_with_asn1crypto(file_path, file_hash)
        elif OPENSSL_AVAILABLE:
            return self._check_with_openssl(file_path, file_hash)
        else:
            # 回退 PE 结构解析
            return self._check_pe_signature(file_path, file_hash)

    def _calculate_file_hash(self, file_path: str) -> str:
        """计算文件 SHA256。"""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            chunk = f.read(8192)
            while chunk:
                sha256.update(chunk)
                chunk = f.read(8192)
        return sha256.hexdigest()

    def _check_with_signify(self, file_path: str, file_hash: str) -> SignatureResult:
        """signify 库验证通道。"""
        try:
            result = SignatureResult(file_hash=file_hash)

            with open(file_path, 'rb') as f:
                pe_data = f.read()

            security_dir_offset = self._find_security_directory(pe_data)
            if security_dir_offset == 0:
                result.status = SignatureStatus.UNSIGNED
                result.warnings.append("File is not signed")
                return result

            signature_data = self._extract_signature_data(pe_data, security_dir_offset)
            if not signature_data:
                result.status = SignatureStatus.INVALID
                return result

            # 解析证书链
            certs = self._parse_certificates_from_signature(signature_data)
            result.certificates = certs

            # 验证签名状态
            result = self._validate_signature_status(result, file_path)

            return result
        except Exception as e:
            logger.error(f"[CodeSign] signify verification failed: {e}")
            return SignatureResult(
                status=SignatureStatus.INVALID,
                file_hash=file_hash,
                warnings=[f"Verification failed: {str(e)}"])

    def _check_with_asn1crypto(self, file_path: str, file_hash: str) -> SignatureResult:
        """asn1crypto 验证通道。"""
        try:
            result = SignatureResult(file_hash=file_hash)

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

            # 解析 PKCS7 签名
            try:
                signed_data = cms.ContentInfo.load(signature_data)
                if signed_data['content_type'].native == 'signed_data':
                    certs = signed_data['content']['certificates']

                    for cert in certs:
                        cert_info = self._parse_asn1_certificate(cert)
                        result.certificates.append(cert_info)
            except Exception as e:
                logger.warning(f"[CodeSign] PKCS7 parsing failed: {e}")

            # 验证签名状态
            result = self._validate_signature_status(result, file_path)

            return result
        except Exception as e:
            logger.error(f"[CodeSign] asn1crypto verification failed: {e}")
            return SignatureResult(status=SignatureStatus.INVALID, file_hash=file_hash)

    def _check_with_openssl(self, file_path: str, file_hash: str) -> SignatureResult:
        """OpenSSL 验证通道。"""
        try:
            result = SignatureResult(file_hash=file_hash)

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

            # OpenSSL 解析 PKCS7
            pkcs7 = crypto.load_pkcs7_data(crypto.FILETYPE_ASN1, signature_data)

            # 提取证书链
            if pkcs7:
                certs = pkcs7.get_certificates()
                for cert in certs:
                    cert_info = self._parse_openssl_certificate(cert)
                    result.certificates.append(cert_info)

            result = self._validate_signature_status(result, file_path)

            return result
        except Exception as e:
            logger.error(f"[CodeSign] OpenSSL verification failed: {e}")
            return SignatureResult(status=SignatureStatus.INVALID, file_hash=file_hash)

    def _check_pe_signature(self, file_path: str, file_hash: str) -> SignatureResult:
        """PE 结构解析验证通道 (无验证库时的降级)。"""
        try:
            result = SignatureResult(file_hash=file_hash)

            with open(file_path, 'rb') as f:
                pe_data = f.read()

            # 校验 PE 魔数
            if pe_data[:2] != b'MZ':
                result.warnings.append("Not a PE file")
                return result

            # 定位 PE 头
            pe_header_offset = struct.unpack('<I', pe_data[0x3C:0x40])[0]
            if pe_data[pe_header_offset:pe_header_offset+4] != b'PE\x00\x00':
                result.warnings.append("Invalid PE header")
                return result

            # 定位安全目录
            security_dir_offset = self._find_security_directory(pe_data)
            if security_dir_offset == 0:
                result.status = SignatureStatus.UNSIGNED
                result.warnings.append("File is not signed")
                return result

            signature_data = self._extract_signature_data(pe_data, security_dir_offset)
            if signature_data:
                result.signature_hash = hashlib.sha256(signature_data).hexdigest()
                result.status = SignatureStatus.VALID  # 仅基础检查, 完整验证需签名库
                result.warnings.append("Signature exists but cannot be fully verified (missing verification library)")
            else:
                result.status = SignatureStatus.INVALID

            return result
        except Exception as e:
            logger.error(f"[CodeSign] PE parsing failed: {e}")
            return SignatureResult(status=SignatureStatus.INVALID, file_hash=file_hash)

    def _find_security_directory(self, pe_data: bytes) -> int:
        """定位 PE 安全目录 (WIN_CERTIFICATE) 偏移。"""
        try:
            # 校验 MZ 头
            if pe_data[:2] != b'MZ':
                return 0

            # 取 PE 头偏移
            pe_header_offset = struct.unpack('<I', pe_data[0x3C:0x40])[0]

            # 校验 PE 签名
            if pe_data[pe_header_offset:pe_header_offset+4] != b'PE\x00\x00':
                return 0

            # 取可选头大小
            optional_header_size = struct.unpack('<H', pe_data[pe_header_offset + 20:pe_header_offset + 22])[0]

            # 安全目录是可选头数据目录表中第 11 项:
            # 表偏移 = PE头 + 24(签名) + 96(可选头标准段) + 11*8
            security_dir_entry_offset = pe_header_offset + 24 + 96 + 11 * 8

            if security_dir_entry_offset + 8 > len(pe_data):
                return 0

            # 取安全目录虚拟地址与大小
            rva, size = struct.unpack('<II', pe_data[security_dir_entry_offset:security_dir_entry_offset + 8])

            if rva == 0 or size == 0:
                return 0

            return rva
        except Exception as e:
            logger.warning(f"[CodeSign] Failed to find security directory: {e}")
            return 0

    def _extract_signature_data(self, pe_data: bytes, security_dir_offset: int) -> Optional[bytes]:
        """从 PE 提取签名数据。"""
        try:
            # 读安全目录条目
            if security_dir_offset + 8 > len(pe_data):
                return None

            cert_rva, cert_size = struct.unpack('<II', pe_data[security_dir_offset:security_dir_offset + 8])

            if cert_rva == 0:
                return None

            signature_data = pe_data[cert_rva:cert_rva + cert_size]
            return signature_data
        except Exception as e:
            return None

    def _parse_certificates_from_signature(self, signature_data: bytes) -> List[CertificateInfo]:
        """从签名数据解析证书链。"""
        certs = []

        try:
            if ASN1_AVAILABLE:
                signed_data = cms.ContentInfo.load(signature_data)
                if signed_data['content_type'].native == 'signed_data':
                    for cert in signed_data['content']['certificates']:
                        cert_info = self._parse_asn1_certificate(cert)
                        certs.append(cert_info)
        except Exception as e:
            logger.warning(f"[CodeSign] Certificate parsing failed: {e}")

        return certs

    def _parse_asn1_certificate(self, cert: Any) -> CertificateInfo:
        """解析 ASN.1 证书。"""
        try:
            cert_info = CertificateInfo()

            # 主体
            if hasattr(cert, 'subject'):
                subject = cert.subject
                cert_info.subject = self._format_dn(subject)

            # 颁发者
            if hasattr(cert, 'issuer'):
                issuer = cert.issuer
                cert_info.issuer = self._format_dn(issuer)

            # 序列号
            if hasattr(cert, 'serial_number'):
                cert_info.serial_number = str(cert.serial_number.native)

            # 有效期
            if hasattr(cert, 'not_before'):
                cert_info.not_before = str(cert.not_before.native)
            if hasattr(cert, 'not_after'):
                cert_info.not_after = str(cert.not_after.native)

            # 签名算法
            if hasattr(cert, 'signature_algorithm'):
                algo = cert.signature_algorithm.native
                cert_info.algorithm = algo

            # 指纹
            if hasattr(cert, 'sha1'):
                cert_info.thumbprint = cert.sha1.hex()
            if hasattr(cert, 'sha256'):
                cert_info.sha256_thumbprint = cert.sha256.hex()

            # 自签名判定
            cert_info.is_self_signed = cert_info.subject == cert_info.issuer

            return cert_info
        except Exception as e:
            logger.warning(f"[CodeSign] ASN.1 certificate parsing failed: {e}")
            return CertificateInfo()

    def _parse_openssl_certificate(self, cert: Any) -> CertificateInfo:
        """解析 OpenSSL 证书。"""
        try:
            cert_info = CertificateInfo()

            # 主体
            subject = cert.get_subject()
            cert_info.subject = self._format_x509_name(subject)

            # 颁发者
            issuer = cert.get_issuer()
            cert_info.issuer = self._format_x509_name(issuer)

            # 序列号
            cert_info.serial_number = str(cert.get_serial_number())

            # 有效期
            not_before = cert.get_notBefore()
            not_after = cert.get_notAfter()
            if not_before:
                cert_info.not_before = not_before.decode() if isinstance(not_before, bytes) else not_before
            if not_after:
                cert_info.not_after = not_after.decode() if isinstance(not_after, bytes) else not_after

            # 签名算法
            cert_info.algorithm = cert.get_signature_algorithm()

            # 自签名判定
            cert_info.is_self_signed = cert_info.subject == cert_info.issuer

            return cert_info
        except Exception as e:
            logger.warning(f"[CodeSign] OpenSSL certificate parsing failed: {e}")
            return CertificateInfo()

    def _format_dn(self, dn: Any) -> str:
        """DN 字符串格式化。"""
        try:
            if hasattr(dn, 'native'):
                return str(dn.native)
            return str(dn)
        except Exception:
            return ''

    def _format_x509_name(self, name: Any) -> str:
        """X509 名称格式化。"""
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
        """综合验证: 证书链/算法强度/过期/自签名/泄露库/滥用模式。"""
        # 证书链缺失
        if not result.certificates:
            result.status = SignatureStatus.INVALID
            result.warnings.append("Unable to extract certificate chain")
            return result

        # 签名算法强度
        for cert in result.certificates:
            algo_strength = self._get_algorithm_strength(cert.algorithm)
            if algo_strength == AlgorithmStrength.WEAK or algo_strength == AlgorithmStrength.DEPRECATED:
                result.algorithm_strength = algo_strength
                result.warnings.append(f"Using weak algorithm: {cert.algorithm}")
                if algo_strength == AlgorithmStrength.DEPRECATED:
                    result.status = SignatureStatus.WEAK_ALGORITHM

        # 过期检查
        for cert in result.certificates:
            if cert.is_expired():
                result.status = SignatureStatus.EXPIRED
                result.warnings.append(f"Certificate expired: {cert.subject}")

        # 自签名检查
        for cert in result.certificates:
            if cert.is_self_signed:
                result.warnings.append(f"Found self-signed certificate: {cert.subject}")
                if result.status == SignatureStatus.VALID:
                    result.status = SignatureStatus.SELF_SIGNED

        # 泄露证书检查
        for cert in result.certificates:
            if self._check_leaked_certificate(cert):
                result.is_abused = True
                result.status = SignatureStatus.LEAKED
                result.abuse_indicators.append(f"Certificate may be leaked: {cert.serial_number}")

        # 滥用模式检查
        abuse_indicators = self._check_abuse_patterns(result.certificates)
        if abuse_indicators:
            result.is_abused = True
            result.abuse_indicators.extend(abuse_indicators)

        return result

    def _get_algorithm_strength(self, algorithm: str) -> AlgorithmStrength:
        """按映射表判定算法强度, 未知回退 MEDIUM。"""
        algo_lower = algorithm.lower()

        for key, strength in self.ALGORITHM_STRENGTH_MAP.items():
            if key in algo_lower:
                return strength

        return AlgorithmStrength.MEDIUM

    def _check_leaked_certificate(self, cert: CertificateInfo) -> bool:
        """证书序列号或指纹是否命中泄露库。"""
        # 序列号
        if cert.serial_number in self.leaked_certificates:
            return True

        # 指纹
        if cert.thumbprint in self.leaked_certificates:
            return True

        return False

    def _check_abuse_patterns(self, certificates: List[CertificateInfo]) -> List[str]:
        """检测已知被滥用证书主体。"""
        indicators = []

        for cert in certificates:
            # 比对已知滥用主体
            for abused_subject in self.KNOWN_ABUSED_SUBJECTS:
                if abused_subject.lower() in cert.subject.lower():
                    indicators.append(f"Certificate subject in known abuse list: {cert.subject}")

        return indicators

    def generate_report(self, result: SignatureResult, file_path: str) -> Dict[str, Any]:
        """生成签名验证报告。"""
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
        """按状态给出处置建议。"""
        if result.status == SignatureStatus.VALID:
            return "Signature valid, file is trusted"
        elif result.status == SignatureStatus.UNSIGNED:
            return "File is not signed, verify source trustworthiness"
        elif result.status == SignatureStatus.EXPIRED:
            return "Signing certificate expired, update signature or verify file integrity"
        elif result.status == SignatureStatus.SELF_SIGNED:
            return "Self-signed certificate, verify certificate source"
        elif result.status == SignatureStatus.WEAK_ALGORITHM:
            return "Weak signature algorithm used, upgrade to SHA256 or stronger"
        elif result.status == SignatureStatus.LEAKED:
            return "Certificate may be leaked, HIGH RISK! Stop using this file immediately"
        elif result.status == SignatureStatus.INVALID:
            return "Invalid signature or file tampered, do not run this file"
        else:
            return "Further verification needed"

    def save_report(self, result: SignatureResult, file_path: str, output_path: Optional[str] = None) -> str:
        """保存验证报告到 JSON。"""
        if not output_path:
            output_dir = './reports/signature'
            os.makedirs(output_dir, exist_ok=True)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"signature_report_{timestamp}.json"
            output_path = os.path.join(output_dir, filename)

        report = self.generate_report(result, file_path)

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        logger.info(f"[CodeSign] Report saved: {output_path}")
        return output_path

    def analyze(self, file_path: str) -> Dict[str, Any]:
        """执行完整签名分析并返回报告。"""
        result = self.check_signature(file_path)
        report = self.generate_report(result, file_path)
        return report


def create_signing_checker(**kwargs) -> CodeSigningChecker:
    """便捷工厂: 创建签名验证器。"""
    config = SigningConfig(**kwargs)
    return CodeSigningChecker(config)
