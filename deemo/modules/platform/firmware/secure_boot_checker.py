#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""secure_boot_checker — verify boot chain integrity.

ARM Trusted Firmware / U-Boot / Linux boot stages:
  ROM -> SPL -> U-Boot -> Kernel

Each stage is verified against a stored hash or signature.
Reports tampering and matches bootloader versions against
a database of known CVE-impacted releases.

2026-07 新增: TCG 度量启动事件日志解析 + VFF 风格验证器函数 BB 模式检测。
参考: "VFF: Precise Identification of Firmware Validator Functions Based on
Basic Block Layout Patterns", Zenodo Jan 2026.
"""

import hashlib as _hl
import json as _json
import logging as _logging
import os as _os
import re as _re
import struct as _struct
from dataclasses import dataclass, field as _field
from datetime import datetime as _dt
from enum import Enum as _Enum
from typing import Any, Callable, Dict, List, Optional

_logger = _logging.getLogger(__name__)

class BootStage(_Enum):
    ROM = "rom"; SPL = "spl"; UBOOT = "uboot"
    KERNEL = "kernel"; DTREE = "dtree"; INITRD = "initrd"

class SignatureStatus(_Enum):
    VALID = "valid"; TAMPERED = "tampered"
    UNKNOWN = "unknown"; MISSING = "missing"

class HashAlgorithm:
    SHA256 = "sha256"; SHA384 = "sha384"; SHA512 = "sha512"; SM3 = "sm3"
    _MAP: Dict[str, Callable] = {"sha256": _hl.sha256, "sha384": _hl.sha384, "sha512": _hl.sha512}
    @classmethod
    def get_hasher(cls, algo: str) -> Callable:
        return cls._MAP.get(algo, _hl.sha256)


_VULN_BOOTLOADERS: Dict[str, Dict[str, List[str]]] = {
    "u-boot": {
        "2020.01": ["CVE-2020-8432", "CVE-2020-10648"], "2020.04": ["CVE-2020-8432"],
        "2020.07": ["CVE-2020-8432"], "2020.10": ["CVE-2021-27097", "CVE-2021-27138"],
        "2021.01": ["CVE-2021-27097"], "2021.04": ["CVE-2021-27097"],
        "2021.07": ["CVE-2021-27097", "CVE-2021-36147"],
        "2022.01": ["CVE-2022-30767", "CVE-2022-34835"], "2022.04": ["CVE-2022-30767"],
        "2022.07": ["CVE-2022-30790", "CVE-2022-34835"], "2023.01": ["CVE-2023-27426"],
        "2023.04": ["CVE-2023-27426"], "2023.07": ["CVE-2023-27426", "CVE-2023-31885"],
        "2023.10": ["CVE-2023-31885"], "2024.01": ["CVE-2024-25714"],
        "2024.04": ["CVE-2024-25714", "CVE-2024-28327"],
    },
    "grub": {
        "2.06": ["CVE-2022-2601", "CVE-2022-3775", "CVE-2023-4692", "CVE-2023-4693"],
        "2.04": ["CVE-2020-10713", "CVE-2020-14308", "CVE-2020-14309", "CVE-2020-14310",
                 "CVE-2020-14311", "CVE-2020-15705", "CVE-2020-15706", "CVE-2020-15707"],
        "2.12": ["CVE-2024-1048", "CVE-2024-2312"],
    },
    "arm-tf": {
        "2.7": ["CVE-2023-32253"], "2.8": ["CVE-2023-49100", "CVE-2023-32253"],
        "2.9": ["CVE-2024-3204"], "2.10": ["CVE-2024-3204"],
    },
}

_PCR_EVENT_MAP: Dict[int, str] = {
    0: "firmware_code", 1: "platform_config", 2: "external_rom",
    3: "external_config", 4: "boot_manager_code", 5: "boot_config",
    6: "platform_manufacturer", 7: "secure_boot_policy",
}

_EVT_TYPES = {
    0x00000000: "EV_PREBOOT_CERT", 0x00000001: "EV_POST_CODE",
    0x00000003: "EV_NO_ACTION", 0x00000004: "EV_SEPARATOR",
    0x00000005: "EV_ACTION", 0x80000000: "EV_EFI_EVENT_BASE",
    0x80000001: "EV_EFI_VARIABLE_DRIVER_CONFIG", 0x80000002: "EV_EFI_VARIABLE_BOOT",
    0x80000003: "EV_EFI_BOOT_SERVICES_APPLICATION", 0x80000004: "EV_EFI_BOOT_SERVICES_DRIVER",
    0x80000006: "EV_EFI_VARIABLE_AUTHORITY", 0x80000007: "EV_EFI_ACTION",
}

# VFF 风格: 启动验证器函数的 BB 布局模式 — 用于在固件中识别签名/哈希验证代码
_VALIDATOR_BB_SIGS = [
    (b'\x00\x28', "cmp_r0_zero", "ARM Thumb compare-zero pattern in validator return"),
    (b'\x00\xf0\x00\x80', "memcmp_branch", "memcmp result conditional in signature check"),
    (b'\x06\x03\x55\x1d', "x509_oid", "X.509 extension OID in certificate validator"),
    (b'\x00\x01\x00\x01', "rsa_f4", "RSA F4 public exponent in signature verifier"),
    (b'\x30\x82', "asn1_seq", "ASN.1 SEQUENCE tag in certificate parser"),
]


def _detect_validator_bb(data: bytes) -> list[dict]:
    """VFF 风格验证器基本块布局检测: 在二进制中定位签名校验函数"""
    found = []
    for sig_bytes, tag, desc in _VALIDATOR_BB_SIGS:
        off = 0
        while True:
            idx = data.find(sig_bytes, off)
            if idx == -1:
                break
            ctx = data[max(0, idx - 64):idx + len(sig_bytes) + 64]
            has_prologue = any(p in ctx[:64] for p in (b'\x80\xb5', b'\x2d\xe9', b'\x55\x48\x89'))
            found.append({"offset": idx, "tag": tag, "desc": desc, "near_prologue": has_prologue,
                          "ctx_hex": ctx[:32].hex()})
            off = idx + 1
    return found


@dataclass
class StageVerification:
    stage: BootStage; file_path: str; expected_sha256: str
    actual_sha256: str = ""; status: SignatureStatus = SignatureStatus.UNKNOWN
    size: int = 0; version: str = ""

    def verify(self) -> SignatureStatus:
        try:
            with open(self.file_path, "rb") as fh:
                blob = fh.read()
            self.size = len(blob)
            self.actual_sha256 = _hl.sha256(blob).hexdigest()
            self.status = (SignatureStatus.VALID
                           if self.actual_sha256 == self.expected_sha256
                           else SignatureStatus.TAMPERED)
        except OSError:
            self.status = SignatureStatus.MISSING
        return self.status


@dataclass
class PCRMeasurement:
    pcr_index: int; algorithm: str = "sha256"
    expected_digest: str = ""; description: str = ""
    def __post_init__(self):
        if not self.description:
            self.description = _PCR_EVENT_MAP.get(self.pcr_index, f"PCR{self.pcr_index}")


@dataclass
class BootChainReport:
    stages: List[StageVerification] = _field(default_factory=list)
    overall_valid: bool = True
    vulnerabilities: List[str] = _field(default_factory=list)
    checked_at: str = _field(default_factory=lambda: _dt.now().isoformat())
    pcr_measurements: List[PCRMeasurement] = _field(default_factory=list)
    pcr_valid: bool = True
    tcg_event_log: List[dict] = _field(default_factory=list)
    validators_detected: List[dict] = _field(default_factory=list)

    def add_stage(self, sv: StageVerification):
        self.stages.append(sv)
        if sv.status in (SignatureStatus.TAMPERED, SignatureStatus.MISSING):
            self.overall_valid = False


def _extract_uboot_version(blob: bytes) -> str:
    m = _re.search(rb"U-Boot\s+(\d{4}\.\d{2}(?:-rc\d+)?)", blob)
    return m.group(1).decode() if m else ""

def _extract_linux_version(blob: bytes) -> str:
    m = _re.search(rb"Linux\s+version\s+(\d+\.\d+\.\d+)", blob)
    return m.group(1).decode() if m else ""

def _extract_arm_tf_version(blob: bytes) -> str:
    m = _re.search(rb"TF-A\s+v?(\d+\.\d+)", blob)
    if not m:
        m = _re.search(rb"ARM\s+Trusted\s+Firmware\s+v?(\d+\.\d+)", blob)
    return m.group(1).decode() if m else ""


_VERSION_EXTRACTORS = {BootStage.UBOOT: _extract_uboot_version,
                       BootStage.KERNEL: _extract_linux_version,
                       BootStage.SPL: _extract_arm_tf_version}


def _validate_boot_policy(stages, baseline_ver="2022.01"):
    warnings = []
    for sv in stages:
        if sv.stage == BootStage.UBOOT and sv.version and sv.version < baseline_ver:
            warnings.append(f"U-Boot {sv.version} below baseline {baseline_ver}")
        if sv.size > 0 and sv.file_path:
            try:
                with open(sv.file_path, "rb") as fh:
                    chunk = fh.read(65536)
                if b"console=tty" in chunk and b"debug" in chunk.lower():
                    warnings.append(f"Debug UART in {sv.stage.value}")
            except OSError:
                pass
    return warnings


def _parse_tcg_event_log(raw: bytes) -> list[dict]:
    events = []; pos = 0; n = len(raw)
    while pos + 32 <= n:
        pcr_idx = _struct.unpack_from("<I", raw, pos)[0]
        evt_type = _struct.unpack_from("<I", raw, pos + 4)[0]
        digest = raw[pos + 8:pos + 28]
        evt_size = _struct.unpack_from("<I", raw, pos + 28)[0]
        if pos + 32 + evt_size > n:
            break
        evt_data = raw[pos + 32:pos + 32 + evt_size]
        events.append({"pcr": pcr_idx, "type": _EVT_TYPES.get(evt_type, f"0x{evt_type:08X}"),
                       "digest": digest.hex(), "event_size": evt_size,
                       "event_data_preview": evt_data[:64].decode('ascii', errors='replace')})
        pos += 32 + evt_size
    return events


class SecureBootChecker:
    """Verify a boot stage chain: hash validation, version detection, CVE matching."""

    def __init__(self, chain_file: Optional[str] = None):
        self._chain: List[Dict[str, str]] = []
        if chain_file:
            self.load_chain(chain_file)

    def load_chain(self, chain_file: str) -> None:
        with open(chain_file) as fh:
            raw = _json.load(fh)
        self._chain = raw if isinstance(raw, list) else raw.get("stages", [])

    def check(self, binary: str = "") -> Dict[str, Any]:
        report = BootChainReport()
        for entry in self._chain:
            try:
                stage = BootStage(entry.get("stage", "kernel"))
            except ValueError:
                _logger.warning("Unknown stage: %s", entry.get("stage")); continue
            sv = StageVerification(stage=stage, file_path=entry.get("path", ""),
                                   expected_sha256=entry.get("sha256", ""))
            sv.verify(); report.add_stage(sv)
            if sv.size > 0 and sv.file_path:
                try:
                    with open(sv.file_path, "rb") as fh:
                        sample = fh.read()
                    extractor = _VERSION_EXTRACTORS.get(stage)
                    if extractor:
                        sv.version = extractor(sample)
                        for cve in self._check_known_vulnerabilities(stage, sv.version):
                            if cve not in report.vulnerabilities:
                                report.vulnerabilities.append(cve)
                    # VFF 验证器检测: 对每个阶段扫描签名/哈希验证函数
                    report.validators_detected.extend(_detect_validator_bb(sample))
                except OSError:
                    pass

        evt_log_path = binary or ""
        if evt_log_path and _os.path.exists(evt_log_path):
            try:
                with open(evt_log_path, "rb") as fh:
                    report.tcg_event_log = _parse_tcg_event_log(fh.read())
            except OSError:
                pass

        policy_warns = _validate_boot_policy(report.stages)
        report.vulnerabilities.extend(f"POLICY: {w}" for w in policy_warns)

        return {"overall_valid": report.overall_valid,
                "stages": [{"stage": s.stage.value, "path": s.file_path,
                            "status": s.status.value, "expected_sha256": s.expected_sha256,
                            "actual_sha256": s.actual_sha256, "size": s.size,
                            "version": s.version} for s in report.stages],
                "vulnerabilities": report.vulnerabilities,
                "tcg_event_log": report.tcg_event_log,
                "validators_detected": report.validators_detected,
                "checked_at": report.checked_at}

    @staticmethod
    def _check_known_vulnerabilities(stage, version):
        cves = []
        if not version:
            return cves
        if stage == BootStage.UBOOT:
            db = _VULN_BOOTLOADERS.get("u-boot", {})
            for vrange, vulns in sorted(db.items()):
                if version <= vrange:
                    cves.extend(v for v in vulns if v not in cves)
        elif stage == BootStage.KERNEL:
            db = _VULN_BOOTLOADERS.get("grub", {})
            for vrange, vulns in sorted(db.items()):
                if version <= vrange:
                    cves.extend(v for v in vulns if v not in cves)
        elif stage in (BootStage.SPL, BootStage.ROM):
            db = _VULN_BOOTLOADERS.get("arm-tf", {})
            for vrange, vulns in sorted(db.items()):
                if version <= vrange:
                    cves.extend(v for v in vulns if v not in cves)
        return cves

    @staticmethod
    def compute_hash(file_path, algo="sha256"):
        hasher = HashAlgorithm.get_hasher(algo)
        with open(file_path, "rb") as fh:
            return hasher(fh.read()).hexdigest()

    @staticmethod
    def read_tpm_pcrs(algorithm="sha256"):
        pcrs = {}
        try:
            with open("/sys/class/tpm/tpm0/pcrs", "r") as fh:
                for line in fh:
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        pcrs[int(parts[0].lstrip("PCR-"))] = parts[2]
        except (OSError, ValueError):
            pass
        return pcrs

    @staticmethod
    def verify_pcr(pcr_measurements, current_pcrs=None):
        if current_pcrs is None:
            current_pcrs = SecureBootChecker.read_tpm_pcrs()
        if not current_pcrs:
            return True
        ok = True
        for pcr in pcr_measurements:
            cur = current_pcrs.get(pcr.pcr_index, "")
            if cur and pcr.expected_digest and cur.lower() != pcr.expected_digest.lower():
                _logger.warning("PCR%d mismatch: expected %s, got %s", pcr.pcr_index, pcr.expected_digest, cur)
                ok = False
        return ok


def check_secure_boot(chain_file):
    return SecureBootChecker(chain_file).check()

name = "secure_boot_checker"
module = "secure_boot_checker"
