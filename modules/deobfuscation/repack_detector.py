# repack_detector.py
# Detects APK repackaging by comparing original vs repackaged artifacts.
# Checks resource modifications, code injection, certificate changes, and
# AndroidManifest.xml tampering.

import hashlib as _hashlib
import logging
import os as _os
import re as _re
import struct as _struct
import zipfile as _zipfile
from dataclasses import dataclass as _dataclass, field as _field
from enum import Enum as _Enum
from io import BytesIO as _BytesIO
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# APK structure helpers

_ANDROIDMANIFEST = "AndroidManifest.xml"
_CLASSES_DEX     = "classes.dex"
_RESOURCES_ARSC  = "resources.arsc"
_META_DIR        = "META-INF/"
_CERT_EXTS       = {".RSA", ".DSA", ".EC"}
_SF_EXTS         = {".SF"}
_MF_FILE         = "MANIFEST.MF"


def _file_sha256(zf: _zipfile.ZipFile, name: str) -> str:
    try:
        return _hashlib.sha256(zf.read(name)).hexdigest()
    except (KeyError, _zipfile.BadZipFile):
        return ""


def _list_dex_classes(zf: _zipfile.ZipFile, dex_name: str) -> Set[str]:
    """Heuristic: extract class name strings from a DEX file."""
    try:
        raw = zf.read(dex_name)
    except (KeyError, _zipfile.BadZipFile):
        return set()
    classes = set()
    # Strings in DEX are at offset defined by string_ids.  For a lightweight
    # check we grep for L-prefixed internal form identifiers.
    for m in _re.finditer(rb"L[a-zA-Z0-9_/$]+;", raw):
        classes.add(m.group(0).decode("ascii", errors="replace"))
    return classes


def _parse_cert(zf: _zipfile.ZipFile) -> Optional[Dict[str, str]]:
    """Extract the first RSA/DSA cert fingerprint from META-INF."""
    for name in zf.namelist():
        if name.startswith(_META_DIR):
            _, ext = _os.path.splitext(name)
            if ext.upper() in (".RSA", ".DSA", ".EC"):
                raw = zf.read(name)
                sha = _hashlib.sha256(raw).hexdigest()
                return {"filename": name, "sha256": sha, "size": len(raw)}
    return None


def _parse_manifest_meta(zf: _zipfile.ZipFile) -> Dict[str, str]:
    """Return key attributes from AndroidManifest.xml (binary XML, so we
    do a string scan)."""
    meta: Dict[str, str] = {}
    try:
        raw = zf.read(_ANDROIDMANIFEST)
    except (KeyError, _zipfile.BadZipFile):
        return meta
    text = raw.decode("utf-8", errors="replace")
    # package
    m = _re.search(r"package=\"([^\"]+)\"", text)
    if m:
        meta["package"] = m.group(1)
    # versionCode
    m = _re.search(r"versionCode=\"([^\"]+)\"", text)
    if m:
        meta["version_code"] = m.group(1)
    # versionName
    m = _re.search(r"versionName=\"([^\"]+)\"", text)
    if m:
        meta["version_name"] = m.group(1)
    # permissions
    perms = _re.findall(r"uses-permission.*?android:name=\"([^\"]+)\"", text)
    if perms:
        meta["permissions"] = ",".join(sorted(perms))
    # activities / services / receivers
    for tag in ("activity", "service", "receiver"):
        items = _re.findall(rf"<{tag}.*?android:name=\"([^\"]+)\"", text)
        if items:
            meta[f"{tag}s"] = ",".join(sorted(items))
    return meta


# Detection result types

class Severity(_Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class RepackType(_Enum):
    NONE = "none"
    CODE_INJECTION = "code_injection"
    RESOURCE_MOD = "resource_modification"
    CERT_CHANGE = "certificate_change"
    MANIFEST_TAMPER = "manifest_tampering"
    LIB_INJECTION = "lib_injection"
    ASSET_INJECTION = "asset_injection"


@_dataclass
class Anomaly:
    repack_type: RepackType
    severity: Severity
    detail: str
    original_value: str = ""
    repackaged_value: str = ""


@_dataclass
class RepackResult:
    is_repacked: bool
    confidence: float   # 0..1
    anomalies: List[Anomaly] = _field(default_factory=list)
    original_hashes: Dict[str, str] = _field(default_factory=dict)
    repackaged_hashes: Dict[str, str] = _field(default_factory=dict)

    def summary(self) -> str:
        lines = [
            f"Repacked: {self.is_repacked} (confidence: {self.confidence:.0%})",
        ]
        for a in self.anomalies:
            lines.append(f"  [{a.severity.value.upper()}] {a.repack_type.value}: {a.detail}")
        return "\n".join(lines)


class SectionInfo:
    """APK section/entry descriptor."""
    def __init__(self, name: str = "", size: int = 0, crc: int = 0):
        self.name = name
        self.size = size
        self.crc = crc


# Config

@_dataclass
class RepackConfig:
    threshold: float = 0.8           # similarity threshold below which => repack
    check_code_injection: bool = True
    check_cert_changes: bool = True
    check_manifest_tamper: bool = True
    check_resource_mod: bool = True
    check_lib_injection: bool = True
    check_asset_injection: bool = True


# Detector

class RepackDetector:
    """Compare an original APK against a (suspected) repackaged one."""

    def __init__(self, config: Optional[RepackConfig] = None):
        self.config = config or RepackConfig()

    def detect(self, original_path: str, repackaged_path: str) -> RepackResult:
        anomalies: List[Anomaly] = []
        orig_hashes: Dict[str, str] = {}
        rep_hashes: Dict[str, str] = {}

        try:
            with _zipfile.ZipFile(original_path) as z_orig, \
                 _zipfile.ZipFile(repackaged_path) as z_rep:

                orig_names = set(z_orig.namelist())
                rep_names  = set(z_rep.namelist())

                # -- hash key files --
                for fname in (_ANDROIDMANIFEST, _CLASSES_DEX, _RESOURCES_ARSC):
                    orig_hashes[fname] = _file_sha256(z_orig, fname)
                    rep_hashes[fname]  = _file_sha256(z_rep, fname)

                # -- cert change --
                if self.config.check_cert_changes:
                    cert_orig = _parse_cert(z_orig)
                    cert_rep  = _parse_cert(z_rep)
                    if cert_orig and cert_rep and cert_orig["sha256"] != cert_rep["sha256"]:
                        anomalies.append(Anomaly(
                            repack_type=RepackType.CERT_CHANGE,
                            severity=Severity.HIGH,
                            detail="Certificate signature differs.",
                            original_value=cert_orig["filename"],
                            repackaged_value=cert_rep["filename"],
                        ))

                # -- manifest tampering --
                if self.config.check_manifest_tamper:
                    meta_orig = _parse_manifest_meta(z_orig)
                    meta_rep  = _parse_manifest_meta(z_rep)
                    for key in ("package", "version_code", "version_name"):
                        vo = meta_orig.get(key, "")
                        vr = meta_rep.get(key, "")
                        if vo != vr and vo and vr:
                            anomalies.append(Anomaly(
                                repack_type=RepackType.MANIFEST_TAMPER,
                                severity=Severity.MEDIUM,
                                detail=f"AndroidManifest {key} changed.",
                                original_value=vo, repackaged_value=vr,
                            ))
                    perms_orig = set(meta_orig.get("permissions", "").split(",")) - {""}
                    perms_rep  = set(meta_rep.get("permissions", "").split(",")) - {""}
                    new_perms = perms_rep - perms_orig
                    if new_perms:
                        anomalies.append(Anomaly(
                            repack_type=RepackType.MANIFEST_TAMPER,
                            severity=Severity.HIGH,
                            detail=f"New permissions: {sorted(new_perms)}",
                        ))

                # -- code injection (new/removed dex classes) --
                if self.config.check_code_injection:
                    for dex_name in ("classes.dex", "classes2.dex", "classes3.dex"):
                        if dex_name in orig_names or dex_name in rep_names:
                            orig_cls = _list_dex_classes(z_orig, dex_name) if dex_name in orig_names else set()
                            rep_cls  = _list_dex_classes(z_rep, dex_name) if dex_name in rep_names else set()
                            new_cls = rep_cls - orig_cls
                            if len(new_cls) > 3:
                                anomalies.append(Anomaly(
                                    repack_type=RepackType.CODE_INJECTION,
                                    severity=Severity.CRITICAL,
                                    detail=f"{dex_name}: {len(new_cls)} new class references.",
                                ))

                # -- new files --
                if self.config.check_lib_injection:
                    for prefix in ("lib/", "assets/"):
                        new_files = {n for n in rep_names - orig_names if n.startswith(prefix)}
                        if len(new_files) > 2:
                            rtype = RepackType.LIB_INJECTION if prefix == "lib/" else RepackType.ASSET_INJECTION
                            anomalies.append(Anomaly(
                                repack_type=rtype,
                                severity=Severity.MEDIUM,
                                detail=f"{len(new_files)} new files under {prefix}",
                            ))

                # -- resource modifications --
                if self.config.check_resource_mod:
                    d1 = set(z_orig.namelist())
                    d2 = set(z_rep.namelist())
                    removed = d1 - d2
                    added = d2 - d1
                    if removed or added:
                        anomalies.append(Anomaly(
                            repack_type=RepackType.RESOURCE_MOD,
                            severity=Severity.LOW,
                            detail=f"{len(removed)} removed, {len(added)} added files.",
                        ))

        except (_zipfile.BadZipFile, OSError) as exc:
            anomalies.append(Anomaly(
                repack_type=RepackType.NONE,
                severity=Severity.HIGH,
                detail=f"Error reading APK: {exc}",
            ))

        # confidence heuristic
        severity_weights = {
            Severity.CRITICAL: 0.40,
            Severity.HIGH: 0.25,
            Severity.MEDIUM: 0.15,
            Severity.LOW: 0.05,
        }
        confidence = sum(severity_weights.get(a.severity, 0) for a in anomalies)
        is_repacked = confidence >= (1.0 - self.config.threshold)

        return RepackResult(
            is_repacked=is_repacked,
            confidence=min(confidence, 1.0),
            anomalies=anomalies,
            original_hashes=orig_hashes,
            repackaged_hashes=rep_hashes,
        )

    def detect_single(self, binary: str) -> bool:
        """Trivial stub: single-argument check returns True if the
        APK shows signs of repacking (excess META-INF entries)."""
        try:
            with _zipfile.ZipFile(binary) as zf:
                meta_count = sum(1 for n in zf.namelist() if n.startswith(_META_DIR))
                return meta_count > 4  # more than MANIFEST.MF + *.SF + *.RSA
        except Exception:
            return False


def create_repack_detector(config: Optional[RepackConfig] = None) -> RepackDetector:
    return RepackDetector(config)


name = "repack_detector"
module = "repack_detector"
