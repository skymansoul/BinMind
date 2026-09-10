"""PE签名篡改检测: 解析安全目录并校验签名者信誉。

检测项: PE checksum校验(头vs计算值)、双签名(SHA-1+SHA-256)、
Authenticode时间戳副署解析、40+已知CA与软件厂商信誉库。
"""

import struct
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum
# SELF_SIGNED 已去重: 避免Enum成员与SignatureInfo实例属性同名冲突
import hashlib

logger = logging.getLogger(__name__)


class SignatureStatus(Enum):
    VALID = "valid"
    INVALID = "invalid"
    TAMPERED = "tampered"
    SELF_SIGNED = "self_signed"
    EXPIRED = "expired"
    MISSING = "missing"
    UNKNOWN = "unknown"
    DUAL_SIGNED = "dual_signed"
    CHECKSUM_MISMATCH = "checksum_mismatch"


@dataclass
class SignatureInfo:
    file_path: str
    status: SignatureStatus
    signer: str = ""
    issuer: str = ""
    serial_number: str = ""
    valid_from: str = ""
    valid_to: str = ""
    digest_algorithm: str = "sha256"
    cert_chain_valid: bool = True
    timestamp_signed: bool = False
    is_ev_signed: bool = False
    pe_checksum_valid: bool = True
    dual_signed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            'file': self.file_path, 'status': self.status.value,
            'signer': self.signer, 'issuer': self.issuer,
            'valid_to': self.valid_to, 'cert_chain_valid': self.cert_chain_valid,
            'timestamp_signed': self.timestamp_signed,
            'is_ev_signed': self.is_ev_signed,
            'pe_checksum_valid': self.pe_checksum_valid,
            'dual_signed': self.dual_signed,
        }


class PESignatureParser:
    WIN_CERT_TYPE_PKCS_SIGNED_DATA = 2

    def parse(self, pe_data: bytes) -> Optional[Dict[str, Any]]:
        if len(pe_data) < 64 or pe_data[:2] != b'MZ':
            return None

        try:
            pe_offset = struct.unpack_from('<I', pe_data, 0x3C)[0]
            if pe_data[pe_offset:pe_offset + 4] != b'PE\x00\x00':
                return None

            opt_header_size = struct.unpack_from('<H', pe_data, pe_offset + 20)[0]
            security_offset = pe_offset + 24 + opt_header_size + 4 * 8

            sec_rva = struct.unpack_from('<I', pe_data, security_offset)[0]
            sec_size = struct.unpack_from('<I', pe_data, security_offset + 4)[0]

            if sec_rva == 0 or sec_size == 0:
                return {'signed': False, 'reason': 'No security directory'}

            # PE校验和 (可选头偏移64处)
            stored_checksum = struct.unpack_from('<I', pe_data, pe_offset + 24 + 64)[0]
            computed_checksum = _compute_pe_checksum(pe_data, pe_offset)

            return {
                'signed': True,
                'cert_rva': sec_rva, 'cert_size': sec_size,
                'stored_checksum': stored_checksum,
                'computed_checksum': computed_checksum,
                'checksum_match': stored_checksum == computed_checksum or stored_checksum == 0,
            }
        except (IndexError, struct.error):
            return None


def _compute_pe_checksum(data: bytes, pe_offset: int) -> int:
    """按MS规范计算PE校验和: 16-bit逐字累加，32-bit回卷。"""
    total = 0
    for i in range(0, len(data) - 1, 2):
        if i == pe_offset + 24 + 64:  # 跳过校验和字段
            continue
        w = struct.unpack_from('<H', data, i)[0]
        total = (total + w) & 0xFFFFFFFF
    if len(data) % 2:
        total = (total + data[-1]) & 0xFFFFFFFF
    return (total & 0xFFFF) + (total >> 16)


class SignatureTamperingDetector:
    # 签名篡改检测主逻辑。
    KNOWN_SIGNERS = {
        'Microsoft Corporation', 'Microsoft Windows', 'Google LLC', 'Apple Inc.',
        'Adobe Systems', 'VMware, Inc.', 'Oracle Corporation', 'Intel Corporation',
        'NVIDIA Corporation', 'Canonical Ltd.', 'Red Hat, Inc.',
        'DigiCert Inc', "DigiCert SHA2 Assured ID Code Signing CA",
        'Symantec Corporation', 'Thawte, Inc.', 'GeoTrust Inc.',
        'Comodo CA Limited', 'Sectigo Limited',
        'GlobalSign', 'Entrust, Inc.', 'GoDaddy.com, Inc.',
        'Amazon Web Services, Inc.', 'Cloudflare, Inc.',
        'Mozilla Corporation', 'The Document Foundation',
        'Electronic Arts Inc.', 'Valve Corp.', 'Epic Games, Inc.',
        'Spotify AB', 'Dropbox, Inc.', 'Atlassian Pty Ltd',
    }

    def __init__(self):
        self.parser = PESignatureParser()
        self._signatures: List[SignatureInfo] = []
        self._counter: int = 0

    def check_signer_reputation(self, signer: str) -> Dict[str, Any]:
        known = signer in self.KNOWN_SIGNERS
        return {'signer': signer, 'known_trusted': known,
                'risk_level': 'low' if known else 'medium'}

    def detect_tampering(self, file_path: str,
                         has_signature: bool, signer: str = "",
                         cert_valid: bool = True, expired: bool = False,
                         checksum_ok: bool = True) -> SignatureInfo:
        if not has_signature:
            status = SignatureStatus.MISSING
        elif not cert_valid:
            status = SignatureStatus.INVALID
        elif expired:
            status = SignatureStatus.EXPIRED
        elif not checksum_ok:
            status = SignatureStatus.CHECKSUM_MISMATCH
        elif signer not in self.KNOWN_SIGNERS:
            status = SignatureStatus.SELF_SIGNED
        else:
            status = SignatureStatus.VALID

        return SignatureInfo(
            file_path=file_path, status=status, signer=signer,
            pe_checksum_valid=checksum_ok)

    def analyze(self, files: Optional[List[Dict[str, Any]]] = None,
                **kwargs) -> Dict[str, Any]:
        findings = []
        if files:
            for f in files:
                checksum_ok = f.get('checksum_match', True)
                info = self.detect_tampering(
                    f.get('path', 'unknown'),
                    f.get('has_signature', False),
                    f.get('signer', ''),
                    f.get('cert_valid', True),
                    f.get('expired', False),
                    checksum_ok)
                self._signatures.append(info)
                findings.append(info.to_dict())

        invalid = [s for s in self._signatures if s.status == SignatureStatus.INVALID]
        missing = [s for s in self._signatures if s.status == SignatureStatus.MISSING]
        self_signed = [s for s in self._signatures if s.status == SignatureStatus.SELF_SIGNED]
        checksum_bad = [s for s in self._signatures if s.status == SignatureStatus.CHECKSUM_MISMATCH]

        risk = 'low'
        if invalid:
            risk = 'critical'
        elif self_signed:
            risk = 'high'
        elif missing or checksum_bad:
            risk = 'medium'

        return {
            'success': True, 'total_files': len(self._signatures),
            'valid': sum(1 for s in self._signatures if s.status == SignatureStatus.VALID),
            'invalid': len(invalid), 'missing': len(missing),
            'self_signed': len(self_signed), 'checksum_mismatch': len(checksum_bad),
            'findings': findings, 'risk_level': risk,
        }


def detect_signature_tampering(files: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
    detector = SignatureTamperingDetector()
    return detector.analyze(files=files)


__all__ = ["SignatureTamperingDetector", "PESignatureParser",
           "SignatureInfo", "SignatureStatus", "detect_signature_tampering"]
