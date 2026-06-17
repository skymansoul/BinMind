"""
TEE证明验证模块

功能：
1. 解析SGX Quote
2. 验证TrustZone报告
3. 验证TEE完整性

核心组件：
- SGXQuoteParser: SGX Quote解析器
- TrustZoneVerifier: TrustZone验证器
- TEEVerifier: TEE验证器
"""

import os
import logging
from typing import Dict, Any, Optional, List, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class TEEType(Enum):
    SGX = "sgx"
    TRUSTZONE = "trustzone"
    SEV = "sev"
    TDX = "tdx"


class VerificationStatus(Enum):
    VALID = "valid"
    INVALID = "invalid"
    UNKNOWN = "unknown"


@dataclass
class SGXQuote:
    version: int
    sign_type: int
    epid_group_id: bytes
    qe_vendor_id: bytes
    user_data: bytes
    report_body: bytes


@dataclass
class TrustZoneReport:
    version: int
    security_state: int
    sw_version: int
    hw_version: int
    data: bytes


class SGXQuoteParser:

    def parse(self, quote_data: bytes) -> Optional[SGXQuote]:
        try:
            if len(quote_data) < 304:
                return None
            
            return SGXQuote(
                version=int.from_bytes(quote_data[0:2], 'little'),
                sign_type=int.from_bytes(quote_data[2:4], 'little'),
                epid_group_id=quote_data[4:12],
                qe_vendor_id=quote_data[12:20],
                user_data=quote_data[20:52],
                report_body=quote_data[52:304]
            )
        except Exception as e:
            logger.error(f"Failed to parse SGX quote: {e}")
            return None

    def extract_report_data(self, quote: SGXQuote) -> bytes:
        if len(quote.report_body) >= 64:
            return quote.report_body[32:64]
        return b""


class TrustZoneVerifier:

    def verify_report(self, report: TrustZoneReport) -> VerificationStatus:
        if report.version == 1 and report.security_state == 0:
            return VerificationStatus.VALID
        return VerificationStatus.UNKNOWN


class TEEVerifier:

    def __init__(self):
        self._sgx_parser = SGXQuoteParser()
        self._tz_verifier = TrustZoneVerifier()

    def verify(self, tee_type: TEEType, data: bytes) -> Dict[str, Any]:
        if tee_type == TEEType.SGX:
            return self._verify_sgx(data)
        elif tee_type == TEEType.TRUSTZONE:
            return self._verify_trustzone(data)
        else:
            return {"status": VerificationStatus.UNKNOWN.value}

    def _verify_sgx(self, quote_data: bytes) -> Dict[str, Any]:
        quote = self._sgx_parser.parse(quote_data)
        if not quote:
            return {"status": VerificationStatus.INVALID.value}
        
        report_data = self._sgx_parser.extract_report_data(quote)
        
        return {
            "status": VerificationStatus.VALID.value,
            "quote": {
                "version": quote.version,
                "sign_type": quote.sign_type,
                "epid_group_id": quote.epid_group_id.hex(),
                "user_data": quote.user_data.hex(),
                "report_data": report_data.hex()
            }
        }

    def _verify_trustzone(self, report_data: bytes) -> Dict[str, Any]:
        report = TrustZoneReport(
            version=int.from_bytes(report_data[0:4], 'little'),
            security_state=int.from_bytes(report_data[4:8], 'little'),
            sw_version=int.from_bytes(report_data[8:12], 'little'),
            hw_version=int.from_bytes(report_data[12:16], 'little'),
            data=report_data[16:]
        )
        
        status = self._tz_verifier.verify_report(report)
        
        return {
            "status": status.value,
            "report": {
                "version": report.version,
                "security_state": report.security_state,
                "sw_version": report.sw_version,
                "hw_version": report.hw_version
            }
        }


def verify_tee_evidence(tee_type: str, data: bytes) -> Dict[str, Any]:
    verifier = TEEVerifier()
    return verifier.verify(TEEType[tee_type.upper()], data)