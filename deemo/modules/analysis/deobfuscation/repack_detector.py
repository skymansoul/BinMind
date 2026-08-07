# repack_detector.py
# 检测 APK repackaging comparing original vs repackaged artifacts
# 检查 resource modifications, code injection, 证书 changes
# AndroidManifest.xml tampering

import hashlib as _hashlib
import logging
import os as _os
import re as _re
import struct as _struct
import zipfile as _zipfile
from dataclasses import dataclass as _dataclass, field as _field
from enum import Enum as _Enum
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

_ANDROIDMANIFEST = "AndroidManifest.xml"
_CLASSES_DEX     = "classes.dex"
_RESOURCES_ARSC  = "resources.arsc"
_META_DIR        = "META-INF/"
_ELF_MAGIC       = b"\x7fELF"

_DEX_OPCODES = {
    0x00: "nop", 0x01: "move", 0x0e: "return-void", 0x0f: "return",
    0x1a: "const-string", 0x22: "new-instance", 0x23: "new-array",
    0x27: "throw", 0x28: "goto", 0x2b: "packed-switch",
    0x6e: "invoke-virtual", 0x70: "invoke-direct",
    0x71: "invoke-static", 0x74: "invoke-interface",
}


def _file_sha256(zf: _zipfile.ZipFile, name: str) -> str:
    try: return _hashlib.sha256(zf.read(name)).hexdigest()
    except (KeyError, _zipfile.BadZipFile): return ""


def _list_dex_classes(zf: _zipfile.ZipFile, dex_name: str) -> Set[str]:
    """Heuristic: 提取 class name strings a DEX file"""
    try: raw = zf.read(dex_name)
    except (KeyError, _zipfile.BadZipFile): return set()
    classes = set()
    for m in _re.finditer(rb"L[a-zA-Z0-9_/$]+;", raw):
        classes.add(m.group(0).decode("ascii", errors="replace"))
    return classes


# DEX 字符串表比较 —— 比类名比较更细粒度
# DEX 格式: string_ids 段包含所有字符串引用。重打包工具（如 apktool）
# 重建 DEX 时会改变字符串的顺序、对齐和填充

def _list_dex_strings(zf: _zipfile.ZipFile, dex_name: str) -> Set[str]:
    """提取 DEX 文件中所有非空字符串。扫描 MUTF-8 编码的字符串表"""
    try: raw = zf.read(dex_name)
    except (KeyError, _zipfile.BadZipFile): return set()
    strings = set()
    # DEX header: string_ids_size @ offset 56, string_ids_off @ offset 60
    if len(raw) < 64:
        return strings
    str_ids_size = _struct.unpack_from("<I", raw, 56)[0]
    str_ids_off = _struct.unpack_from("<I", raw, 60)[0]
    if str_ids_off <= 0 or str_ids_off + str_ids_size * 4 > len(raw):
        return strings
    for i in range(min(str_ids_size, 50000)):
        str_data_off = _struct.unpack_from("<I", raw, str_ids_off + i * 4)[0]
        if str_data_off <= 0 or str_data_off >= len(raw):
            continue
        try:
            end = raw.index(b'\x00', str_data_off)
            s = raw[str_data_off:end].decode("utf-8", errors="replace")
            if len(s) >= 2:
                strings.add(s)
        except (ValueError, UnicodeDecodeError):
            continue
    return strings


def _dex_opcode_histogram(zf: _zipfile.ZipFile, dex_name: str) -> Dict[int, int]:
    hist: Dict[int, int] = {}
    try: raw = zf.read(dex_name)
    except (KeyError, _zipfile.BadZipFile): return hist
    for i in range(len(raw) - 1):
        op = raw[i]
        if op & 0xFF in _DEX_OPCODES:
            hist[op & 0xFF] = hist.get(op & 0xFF, 0) + 1
    return hist


# 原生. ELF dynsym 导出符号比较
# 从 APK 内的. 文件中提取.dynsym 中的导出符号名，比较两个
# APK 之间的差异。新增的 JNI 导出（Java_* 前缀）是代码注入的强信号

_DT_SYMTAB = 6
_DT_STRTAB = 5
_DT_STRSZ = 10

def _elf_dynsym_exports(elf_data: bytes) -> Set[str]:
    """从 ELF.dynamic 段中定位.dynsym/.dynstr 并提取导出符号名"""
    exports: Set[str] = set()
    if elf_data[:4] != _ELF_MAGIC or len(elf_data) < 64:
        return exports
    try:
        bitness = 64 if elf_data[4] == 2 else 32
        endian = '<' if elf_data[5] == 1 else '>'
        qword = 'Q' if bitness == 64 else 'I'
        e_phoff_off = 32 if bitness == 64 else 28
        e_phentsize_off = 54 if bitness == 64 else 42
        e_phnum_off = 56 if bitness == 64 else 44
        e_phoff = _struct.unpack_from(endian + qword, elf_data, e_phoff_off)[0]
        e_phentsize = _struct.unpack_from('<H', elf_data, e_phentsize_off)[0]
        e_phnum = _struct.unpack_from('<H', elf_data, e_phnum_off)[0]

        symtab_addr = strtab_addr = strtab_size = 0
        for i in range(min(e_phnum, 32)):
            phdr = e_phoff + i * e_phentsize
            p_type = _struct.unpack_from('<I', elf_data, phdr)[0]
            if p_type == 2:
                p_offset = _struct.unpack_from(endian + qword, elf_data, phdr + (8 if bitness == 64 else 4))[0]
                p_filesz = _struct.unpack_from(endian + qword, elf_data, phdr + (32 if bitness == 64 else 16))[0]
                dynamic = elf_data[p_offset:p_offset + p_filesz]
                entsz = 16 if bitness == 64 else 8
                j = 0
                while j + entsz <= len(dynamic):
                    d_tag = _struct.unpack_from(endian + qword, dynamic, j)[0]
                    d_val = _struct.unpack_from(endian + qword, dynamic, j + (8 if bitness == 64 else 4))[0]
                    if d_tag == _DT_SYMTAB: symtab_addr = d_val
                    elif d_tag == _DT_STRTAB: strtab_addr = d_val
                    elif d_tag == _DT_STRSZ: strtab_size = d_val
                    j += entsz
                break

        if symtab_addr == 0 or strtab_addr == 0:
            return exports

        sym_size = 24 if bitness == 64 else 16
        # 扫描.dynsym 中的所有非零 st_name 条目
        for i in range(256):
            sym_off = symtab_addr - (p_offset if 'p_offset' in dir() else 0)
            if sym_off < 0: sym_off += p_offset
            st_name = _struct.unpack_from('<I', elf_data, sym_off + i * sym_size)[0]
            if st_name == 0 or st_name >= strtab_size:
                continue
            try:
                name_end = elf_data.index(b'\x00', strtab_addr + st_name)
                name = elf_data[strtab_addr + st_name:name_end].decode('ascii', errors='replace')
                if name and not name.startswith('_Z') and len(name) >= 2:
                    exports.add(name)
            except (ValueError, UnicodeDecodeError, IndexError):
                break
    except (struct.error, IndexError):
        pass
    return exports


def _compare_native_libs(z_orig: _zipfile.ZipFile, z_rep: _zipfile.ZipFile) -> Optional[dict]:
    orig_sos = {n for n in z_orig.namelist() if n.endswith(".so")}
    rep_sos = {n for n in z_rep.namelist() if n.endswith(".so")}
    findings = {}
    if rep_sos - orig_sos:
        findings["new_libs"] = sorted(rep_sos - orig_sos)
    if orig_sos - rep_sos:
        findings["removed_libs"] = sorted(orig_sos - rep_sos)
    common = orig_sos & rep_sos
    export_diffs = {}
    for so_name in list(common)[:10]:
        try:
            orig_exp = _elf_dynsym_exports(z_orig.read(so_name))
            rep_exp = _elf_dynsym_exports(z_rep.read(so_name))
        except Exception:
            continue
        new_exports = rep_exp - orig_exp
        if len(new_exports) > 3:
            export_diffs[so_name] = {"new_export_count": len(new_exports),
                                       "sample": sorted(new_exports)[:5]}
    if export_diffs:
        findings["export_diffs"] = export_diffs
    return findings if findings else None


def _parse_cert(zf: _zipfile.ZipFile) -> Optional[Dict[str, str]]:
    """提取 first RSA/DSA cert fingerprint META-INF"""
    for name in zf.namelist():
        if name.startswith(_META_DIR):
            _, ext = _os.path.splitext(name)
            if ext.upper() in (".RSA", ".DSA", ".EC"):
                raw = zf.read(name)
                sha = _hashlib.sha256(raw).hexdigest()
                return {"filename": name, "sha256": sha, "size": len(raw)}
    return None


def _parse_manifest_meta(zf: _zipfile.ZipFile) -> Dict[str, str]:
    """返回 key attributes AndroidManifest.xml (binary XML
    a string scan)"""
    meta: Dict[str, str] = {}
    try: raw = zf.read(_ANDROIDMANIFEST)
    except (KeyError, _zipfile.BadZipFile): return meta
    text = raw.decode("utf-8", errors="replace")
    m = _re.search(r"package=\"([^\"]+)\"", text)
    if m: meta["package"] = m.group(1)
    m = _re.search(r"versionCode=\"([^\"]+)\"", text)
    if m: meta["version_code"] = m.group(1)
    m = _re.search(r"versionName=\"([^\"]+)\"", text)
    if m: meta["version_name"] = m.group(1)
    perms = _re.findall(r"uses-permission.*?android:name=\"([^\"]+)\"", text)
    if perms: meta["permissions"] = ",".join(sorted(perms))
    for tag in ("activity", "service", "receiver"):
        items = _re.findall(rf"<{tag}.*?android:name=\"([^\"]+)\"", text)
        if items: meta[f"{tag}s"] = ",".join(sorted(items))
    return meta


_APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"

def _detect_signing_scheme(zf: _zipfile.ZipFile) -> str:
    try:
        raw = zf.read(zf.namelist()[0]) if zf.namelist() else b""
        if _APK_SIG_BLOCK_MAGIC in raw: return "v2+"
    except Exception: pass
    for name in zf.namelist():
        if name.startswith(_META_DIR):
            if _os.path.splitext(name)[1].upper() in (".RSA", ".DSA", ".EC"):
                return "v1"
    return "unsigned"

_ARSC_CHUNK_MAGIC = b"\x02\x00\x0c\x00"

def _compare_arsc_chunks(z_orig, z_rep) -> Optional[dict]:
    try:
        ro = z_orig.read(_RESOURCES_ARSC); rr = z_rep.read(_RESOURCES_ARSC)
    except (KeyError, _zipfile.BadZipFile): return None
    co = [m.start() for m in _re.finditer(_ARSC_CHUNK_MAGIC, ro)]
    cr = [m.start() for m in _re.finditer(_ARSC_CHUNK_MAGIC, rr)]
    if len(co) != len(cr):
        return {"chunk_count_diff": abs(len(co)-len(cr)),
                "original": len(co), "repackaged": len(cr)}
    mismatches = 0
    for i in range(min(len(co), len(cr))):
        if ro[co[i]:co[i]+8] != rr[cr[i]:cr[i]+8]: mismatches += 1
    if mismatches > 1: return {"chunk_mismatches": mismatches, "total": len(co)}
    return None


class Severity(_Enum):
    LOW = "low"; MEDIUM = "medium"; HIGH = "high"; CRITICAL = "critical"

class RepackType(_Enum):
    NONE = "none"; CODE_INJECTION = "code_injection"
    RESOURCE_MOD = "resource_modification"; CERT_CHANGE = "certificate_change"
    MANIFEST_TAMPER = "manifest_tampering"; LIB_INJECTION = "lib_injection"
    ASSET_INJECTION = "asset_injection"; DEX_OPCODE_SHIFT = "dex_opcode_shift"
    ARSC_RECONSTRUCTION = "arsc_reconstruction"
    SIGNING_SCHEME_MISMATCH = "signing_scheme_mismatch"
    NATIVE_CODE_INJECTION = "native_code_injection"
    DEX_STRING_SHIFT = "dex_string_shift"


@_dataclass
class Anomaly:
    repack_type: RepackType; severity: Severity; detail: str
    original_value: str = ""; repackaged_value: str = ""


@_dataclass
class RepackResult:
    is_repacked: bool; confidence: float
    anomalies: List[Anomaly] = _field(default_factory=list)
    original_hashes: Dict[str, str] = _field(default_factory=dict)
    repackaged_hashes: Dict[str, str] = _field(default_factory=dict)
    signing_scheme: Dict[str, str] = _field(default_factory=dict)
    def summary(self) -> str:
        lines = [f"Repacked: {self.is_repacked} (confidence: {self.confidence:.0%})"]
        for a in self.anomalies:
            lines.append(f"  [{a.severity.value.upper()}] {a.repack_type.value}: {a.detail}")
        return "\n".join(lines)


@_dataclass
class RepackConfig:
    threshold: float = 0.8; check_code_injection: bool = True
    check_cert_changes: bool = True; check_manifest_tamper: bool = True
    check_resource_mod: bool = True; check_lib_injection: bool = True
    check_asset_injection: bool = True; check_dex_opcode_shift: bool = True
    check_arsc_reconstruction: bool = True; check_signing_scheme: bool = True
    check_native_code: bool = True; check_dex_string_shift: bool = True


class RepackDetector:
    """比较 an original APK against a (suspected) repackaged one"""

    def __init__(self, config: Optional[RepackConfig] = None):
        self.config = config or RepackConfig()

    def detect(self, original_path: str, repackaged_path: str) -> RepackResult:
        anomalies: List[Anomaly] = []
        orig_hashes: Dict[str, str] = {}
        rep_hashes: Dict[str, str] = {}
        signing_info: Dict[str, str] = {}

        try:
            with _zipfile.ZipFile(original_path) as z_orig, \
                 _zipfile.ZipFile(repackaged_path) as z_rep:

                orig_names = set(z_orig.namelist())
                rep_names  = set(z_rep.namelist())

                for fname in (_ANDROIDMANIFEST, _CLASSES_DEX, _RESOURCES_ARSC):
                    orig_hashes[fname] = _file_sha256(z_orig, fname)
                    rep_hashes[fname]  = _file_sha256(z_rep, fname)

                if self.config.check_cert_changes:
                    cert_orig = _parse_cert(z_orig); cert_rep = _parse_cert(z_rep)
                    if cert_orig and cert_rep and cert_orig["sha256"] != cert_rep["sha256"]:
                        anomalies.append(Anomaly(repack_type=RepackType.CERT_CHANGE,
                            severity=Severity.HIGH, detail="Certificate signature differs.",
                            original_value=cert_orig["filename"],
                            repackaged_value=cert_rep["filename"]))

                if self.config.check_signing_scheme:
                    sig_orig = _detect_signing_scheme(z_orig)
                    sig_rep = _detect_signing_scheme(z_rep)
                    signing_info = {"original": sig_orig, "repackaged": sig_rep}
                    if sig_orig != sig_rep:
                        anomalies.append(Anomaly(
                            repack_type=RepackType.SIGNING_SCHEME_MISMATCH,
                            severity=Severity.MEDIUM,
                            detail=f"Signing scheme changed ({sig_orig} -> {sig_rep})",
                            original_value=sig_orig, repackaged_value=sig_rep))

                if self.config.check_manifest_tamper:
                    meta_orig = _parse_manifest_meta(z_orig)
                    meta_rep  = _parse_manifest_meta(z_rep)
                    for key in ("package", "version_code", "version_name"):
                        vo, vr = meta_orig.get(key, ""), meta_rep.get(key, "")
                        if vo != vr and vo and vr:
                            anomalies.append(Anomaly(
                                repack_type=RepackType.MANIFEST_TAMPER,
                                severity=Severity.MEDIUM,
                                detail=f"AndroidManifest {key} changed.",
                                original_value=vo, repackaged_value=vr))
                    perms_orig = set(meta_orig.get("permissions", "").split(",")) - {""}
                    perms_rep  = set(meta_rep.get("permissions", "").split(",")) - {""}
                    if perms_rep - perms_orig:
                        anomalies.append(Anomaly(
                            repack_type=RepackType.MANIFEST_TAMPER,
                            severity=Severity.HIGH,
                            detail=f"New permissions: {sorted(perms_rep - perms_orig)}"))

                if self.config.check_code_injection:
                    for dex_name in ("classes.dex", "classes2.dex", "classes3.dex"):
                        if dex_name in orig_names or dex_name in rep_names:
                            orig_cls = _list_dex_classes(z_orig, dex_name) if dex_name in orig_names else set()
                            rep_cls  = _list_dex_classes(z_rep, dex_name) if dex_name in rep_names else set()
                            if len(rep_cls - orig_cls) > 3:
                                anomalies.append(Anomaly(
                                    repack_type=RepackType.CODE_INJECTION,
                                    severity=Severity.CRITICAL,
                                    detail=f"{dex_name}: {len(rep_cls - orig_cls)} new class references."))

                if self.config.check_dex_string_shift:
                    for dex_name in ("classes.dex", "classes2.dex"):
                        if dex_name in orig_names and dex_name in rep_names:
                            orig_strs = _list_dex_strings(z_orig, dex_name)
                            rep_strs = _list_dex_strings(z_rep, dex_name)
                            if orig_strs and rep_strs:
                                jaccard = len(orig_strs & rep_strs) / max(len(orig_strs | rep_strs), 1)
                                if jaccard < 0.85:
                                    anomalies.append(Anomaly(
                                        repack_type=RepackType.DEX_STRING_SHIFT,
                                        severity=Severity.MEDIUM,
                                        detail=f"{dex_name}: string Jaccard={jaccard:.2%}"))

                if self.config.check_dex_opcode_shift:
                    for dex_name in ("classes.dex", "classes2.dex"):
                        if dex_name in orig_names and dex_name in rep_names:
                            hist_orig = _dex_opcode_histogram(z_orig, dex_name)
                            hist_rep = _dex_opcode_histogram(z_rep, dex_name)
                            orig_invoke = sum(hist_orig.get(op, 0) for op in range(0x6e, 0x75))
                            rep_invoke = sum(hist_rep.get(op, 0) for op in range(0x6e, 0x75))
                            if orig_invoke > 0 and abs(rep_invoke - orig_invoke) / orig_invoke > 0.15:
                                anomalies.append(Anomaly(
                                    repack_type=RepackType.DEX_OPCODE_SHIFT,
                                    severity=Severity.MEDIUM,
                                    detail=f"{dex_name}: invoke count shifted "
                                    f"{abs(rep_invoke - orig_invoke) / orig_invoke:.1%}"))

                if self.config.check_arsc_reconstruction:
                    arsc_diff = _compare_arsc_chunks(z_orig, z_rep)
                    if arsc_diff:
                        anomalies.append(Anomaly(
                            repack_type=RepackType.ARSC_RECONSTRUCTION,
                            severity=Severity.MEDIUM, detail=f"ARSC chunks differ: {arsc_diff}"))

                if self.config.check_native_code:
                    native_diff = _compare_native_libs(z_orig, z_rep)
                    if native_diff:
                        anomalies.append(Anomaly(
                            repack_type=RepackType.NATIVE_CODE_INJECTION,
                            severity=Severity.HIGH,
                            detail=f"Native library changes: {native_diff}"))

                if self.config.check_lib_injection:
                    for prefix in ("lib/", "assets/"):
                        new_files = {n for n in rep_names - orig_names if n.startswith(prefix)}
                        if len(new_files) > 2:
                            rtype = RepackType.LIB_INJECTION if prefix == "lib/" else RepackType.ASSET_INJECTION
                            anomalies.append(Anomaly(repack_type=rtype, severity=Severity.MEDIUM,
                                detail=f"{len(new_files)} new files under {prefix}"))

                if self.config.check_resource_mod:
                    d1, d2 = set(z_orig.namelist()), set(z_rep.namelist())
                    if d1 - d2 or d2 - d1:
                        anomalies.append(Anomaly(repack_type=RepackType.RESOURCE_MOD,
                            severity=Severity.LOW,
                            detail=f"{len(d1-d2)} removed, {len(d2-d1)} added files."))

        except (_zipfile.BadZipFile, OSError) as exc:
            anomalies.append(Anomaly(repack_type=RepackType.NONE, severity=Severity.HIGH,
                detail=f"Error reading APK: {exc}"))

        severity_weights = {Severity.CRITICAL: 0.40, Severity.HIGH: 0.25,
                            Severity.MEDIUM: 0.15, Severity.LOW: 0.05}
        confidence = sum(severity_weights.get(a.severity, 0) for a in anomalies)
        if len(anomalies) == 1 and anomalies[0].severity == Severity.LOW:
            confidence *= 0.5
        return RepackResult(
            is_repacked=confidence >= (1.0 - self.config.threshold),
            confidence=min(confidence, 1.0), anomalies=anomalies,
            original_hashes=orig_hashes, repackaged_hashes=rep_hashes,
            signing_scheme=signing_info)

    def detect_single(self, binary: str) -> bool:
        """Trivial stub: single-argument 检查 返回 True
        APK 显示 signs repacking (excess META-INF entries)"""
        try:
            with _zipfile.ZipFile(binary) as zf:
                meta_count = sum(1 for n in zf.namelist() if n.startswith(_META_DIR))
                return meta_count > 4
        except Exception: return False


def create_repack_detector(config=None) -> RepackDetector:
    return RepackDetector(config)

name = "repack_detector"
module = "repack_detector"
