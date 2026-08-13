#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""secure_boot_checker — verify boot chain integrity.

ARM Trusted Firmware / U-Boot / Linux boot stages:
  ROM -> SPL -> U-Boot -> Kernel

Each stage is verified against a stored hash or signature.
Reports tampering and matches bootloader versions against
a database of known CVE-impacted releases.
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

# Enums / constants

class BootStage(_Enum):
    ROM    = "rom"
    BL1    = "bl1"
    BL2    = "bl2"
    BL31   = "bl31"
    SPL    = "spl"
    UBOOT  = "uboot"
    KERNEL = "kernel"
    DTREE  = "dtree"       # device-tree blob
    INITRD = "initrd"

class SignatureStatus(_Enum):
    VALID     = "valid"
    TAMPERED  = "tampered"
    UNKNOWN   = "unknown"
    MISSING   = "missing"

class HashAlgorithm:
    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"
    SHA1   = "sha1"
    MD5    = "md5"
    SM3    = "sm3"

    _MAP: Dict[str, Callable] = {
        "sha256": _hl.sha256,
        "sha384": _hl.sha384,
        "sha512": _hl.sha512,
        "sha1":   _hl.sha1,
        "md5":    _hl.md5,
    }

    @classmethod
    def get_hasher(cls, algo: str) -> Callable:
        return cls._MAP.get(algo, _hl.sha256)


# Known-vulnerable bootloader version → CVE mapping

_VULN_BOOTLOADERS: Dict[str, Dict[str, List[str]]] = {
    "u-boot": {
        "2020.01": ["CVE-2020-8432", "CVE-2020-10648"],
        "2020.04": ["CVE-2020-8432"],
        "2020.07": ["CVE-2020-8432"],
        "2020.10": ["CVE-2021-27097", "CVE-2021-27138"],
        "2021.01": ["CVE-2021-27097"],
        "2021.04": ["CVE-2021-27097"],
        "2021.07": ["CVE-2021-27097", "CVE-2021-36147"],
        "2022.01": ["CVE-2022-30767", "CVE-2022-34835"],
        "2022.04": ["CVE-2022-30767"],
        "2022.07": ["CVE-2022-30790", "CVE-2022-34835"],
        "2023.01": ["CVE-2023-27426"],
    },
    "grub": {
        "2.06": ["CVE-2022-2601", "CVE-2022-3775", "CVE-2023-4692",
                 "CVE-2023-4693"],
        "2.04": ["CVE-2020-10713", "CVE-2020-14308", "CVE-2020-14309",
                 "CVE-2020-14310", "CVE-2020-14311", "CVE-2020-15705",
                 "CVE-2020-15706", "CVE-2020-15707"],
    },
}


# Data types

@dataclass
class StageVerification:
    stage: BootStage
    file_path: str
    expected_sha256: str
    actual_sha256: str = ""
    status: SignatureStatus = SignatureStatus.UNKNOWN
    size: int = 0
    version: str = ""

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
class BootChainReport:
    stages: List[StageVerification] = _field(default_factory=list)
    overall_valid: bool = True
    vulnerabilities: List[str] = _field(default_factory=list)
    checked_at: str = _field(default_factory=lambda: _dt.now().isoformat())

    def add_stage(self, sv: StageVerification):
        self.stages.append(sv)
        if sv.status in (SignatureStatus.TAMPERED, SignatureStatus.MISSING):
            self.overall_valid = False


# Version extraction

def _extract_uboot_version(blob: bytes) -> str:
    """Search for U-Boot version string in binary."""
    m = _re.search(rb"U-Boot\s+(\d{4}\.\d{2}(?:-rc\d+)?)", blob)
    return m.group(1).decode() if m else ""


def _extract_grub_version(blob: bytes) -> str:
    m = _re.search(rb"GRUB\s+(\d+\.\d+)", blob)
    return m.group(1).decode() if m else ""


def _extract_linux_version(blob: bytes) -> str:
    m = _re.search(rb"Linux\s+version\s+(\d+\.\d+\.\d+)", blob)
    return m.group(1).decode() if m else ""


_VERSION_EXTRACTORS: Dict[BootStage, Callable[[bytes], str]] = {
    BootStage.UBOOT:  _extract_uboot_version,
    BootStage.KERNEL: _extract_linux_version,
}


# Checker

class SecureBootChecker:
    """Verify a boot stage chain: hash validation, version detection, CVE matching."""

    def __init__(self, chain_file: Optional[str] = None):
        """chain_file: JSON with list of {stage, path, sha256}."""
        self._chain: List[Dict[str, str]] = []
        self.boot_components: List[Any] = []
        if chain_file:
            self.load_chain(chain_file)

    def load_chain(self, chain_file: str) -> None:
        with open(chain_file) as fh:
            raw = _json.load(fh)
        self._chain = raw if isinstance(raw, list) else raw.get("stages", [])

    @staticmethod
    def _guess_stage_from_name(name: str) -> BootStage:
        # 依据文件名子串推断启动阶段；ARM TF 的 BL1/BL2/BL31 按数字级别区分，
        # 其余按约定后缀匹配，未知名称回落 KERNEL 保持链式检查不中断。
        lowered = name.lower()
        if "bl31" in lowered:
            return BootStage.BL31
        if "bl2" in lowered:
            return BootStage.BL2
        if "bl1" in lowered:
            return BootStage.BL1
        if "spl" in lowered:
            return BootStage.SPL
        if "u-boot" in lowered or "uboot" in lowered:
            return BootStage.UBOOT
        if "kernel" in lowered:
            return BootStage.KERNEL
        return BootStage.KERNEL

    @staticmethod
    def _parse_hash_algorithm(algo: str) -> "HashAlgorithm":
        # 大小写不敏感解析算法标识，未知算法回落 SHA256，
        # 与 get_hasher 的默认策略保持一致。
        key = algo.strip().lower()
        for member in (HashAlgorithm.SHA256, HashAlgorithm.SHA384,
                       HashAlgorithm.SHA512, HashAlgorithm.SHA1,
                       HashAlgorithm.MD5):
            if member == key:
                return member
        return HashAlgorithm.SHA256

    def _calculate_coverage(self) -> float:
        # 签名覆盖率为已签名组件数占比；空链视为 0，避免除零。
        total = len(self.boot_components)
        if total == 0:
            return 0.0
        signed = sum(1 for c in self.boot_components if c.is_signed)
        return signed / total

    @staticmethod
    def _determine_overall_status(result: Any) -> str:
        # 按签名覆盖率分级：>=0.9 secure，>=0.5 partially_secure，
        # 否则 insecure；覆盖率指标是整体状态判定的唯一依据。
        coverage = getattr(result, "signature_coverage", 0.0)
        if coverage >= 0.9:
            return "secure"
        if coverage >= 0.5:
            return "partially_secure"
        return "insecure"

    def check(self, binary: str = "") -> Dict[str, Any]:
        """Execute verification across all stages in the loaded chain."""
        report = BootChainReport()

        for entry in self._chain:
            try:
                stage = BootStage(entry.get("stage", "kernel"))
            except ValueError:
                _logger.warning("Unknown stage: %s", entry.get("stage"))
                continue

            sv = StageVerification(
                stage=stage,
                file_path=entry.get("path", ""),
                expected_sha256=entry.get("sha256", ""),
            )
            sv.verify()
            report.add_stage(sv)

            # Extract embedded version string; cross-reference CVE database
            if sv.size > 0 and sv.file_path:
                try:
                    with open(sv.file_path, "rb") as fh:
                        sample = fh.read()
                    extractor = _VERSION_EXTRACTORS.get(stage)
                    if extractor:
                        ver = extractor(sample)
                        sv.version = ver
                        cves = self._check_known_vulnerabilities(stage, ver)
                        report.vulnerabilities.extend(cves)
                except OSError:
                    pass

        return {
            "overall_valid": report.overall_valid,
            "stages": [
                {
                    "stage": s.stage.value,
                    "path": s.file_path,
                    "status": s.status.value,
                    "expected_sha256": s.expected_sha256,
                    "actual_sha256": s.actual_sha256,
                    "size": s.size,
                    "version": s.version,
                }
                for s in report.stages
            ],
            "vulnerabilities": report.vulnerabilities,
            "checked_at": report.checked_at,
        }

    @staticmethod
    def _check_known_vulnerabilities(stage: BootStage, version: str) -> List[str]:
        cves: List[str] = []
        if stage == BootStage.UBOOT:
            db = _VULN_BOOTLOADERS.get("u-boot", {})
            for vrange, vulns in db.items():
                if version and version <= vrange:
                    cves.extend(v for v in vulns if v not in cves)
        elif stage == BootStage.KERNEL:
            # Stub: kernel-stage GRUB vulnerability cross-reference — deferred
            db = _VULN_BOOTLOADERS.get("grub", {})
            for vrange, vulns in db.items():
                if version and version <= vrange.partition(".")[0] + "." + \
                   vrange.partition(".")[2]:
                    pass
        return cves

    @staticmethod
    def compute_hash(file_path: str, algo: str = "sha256") -> str:
        hasher = HashAlgorithm.get_hasher(algo)
        with open(file_path, "rb") as fh:
            return hasher(fh.read()).hexdigest()


# Convenience

def check_secure_boot(chain_file: str) -> Dict[str, Any]:
    checker = SecureBootChecker(chain_file)
    return checker.check()


name = "secure_boot_checker"
module = "secure_boot_checker"
