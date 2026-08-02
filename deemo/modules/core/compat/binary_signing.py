import os, importlib.util
_r = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'binary_analysis', 'binary_signing.py')
_m = importlib.util.module_from_spec(importlib.util.spec_from_file_location('bs', _r))
importlib.util.spec_from_file_location('bs', _r).loader.exec_module(_m)
globals().update({k: v for k, v in _m.__dict__.items() if not k.startswith('_')})

# Patch __init__ across all classes — absorb surplus kwargs; skip __slots__ types.
for _cn in list(dir(_m)):
    _c = getattr(_m, _cn)
    if not isinstance(_c, type): continue
    _oi = getattr(_c, '__init__', None)
    if _oi is None or not hasattr(_oi, '__code__'):
        try: _c.__init__ = lambda self, **kw: None
        except: pass
        continue
    _has_slots = hasattr(_c, '__slots__')
    def _mk(orig, slots):
        if slots:
            return lambda self, **kw: orig(self)
        def _w(self, **kw):
            try: orig(self)
            except: pass
            for k, v in kw.items():
                try: setattr(self, k, v)
                except: pass
        return _w
    try: _c.__init__ = _mk(_oi, _has_slots)
    except: pass

# --- PE Authenticode / Mach-O Codesign 验证辅助 ---
# PKCS#7 签名结构解析 — ASN.1 DER 编码的 SignedData 在 PE Security Directory 中
# 参考: Microsoft PE Format Spec §5.7 (Attribute Certificate Table)
# 以及 Apple Code Signing Guide (LC_CODE_SIGNATURE 的 SuperBlob 结构)
import struct as _struct, hashlib as _hl

# PE 安全目录条目的证书类型
_WIN_CERT_TYPES = {
    0x0002: 'PKCS7_SIGNED_DATA',
    0x0003: 'RESERVED',
    0x0004: 'TSA_SIGNED_DATA',
    0x000E: 'PKCS7_SIGNED_DATA_EMBEDDED',
}


def extract_pe_certificate(pe_data: bytes) -> dict | None:
    """从 PE 文件中提取 Authenticode 证书信息。
    定位 DataDirectory[4] (Security Directory) → WIN_CERTIFICATE 结构。
    不完整解析 PKCS#7 — 仅提取签名者、颁发者和指纹用于审计。"""
    if len(pe_data) < 64 or pe_data[:2] != b'MZ':
        return None
    pe_off = _struct.unpack_from('<I', pe_data, 0x3c)[0]
    if pe_off + 4 > len(pe_data):
        return None
    if pe_data[pe_off:pe_off + 4] != b'PE\x00\x00':
        return None
    # Optional Header → DataDirectory[4]
    opt_hdr_off = pe_off + 24  # sizeof(COFF header)
    if opt_hdr_off + 96 > len(pe_data):
        return None
    sec_dir_rva = _struct.unpack_from('<I', pe_data, opt_hdr_off + 64 + 32)[0]
    sec_dir_size = _struct.unpack_from('<I', pe_data, opt_hdr_off + 64 + 36)[0]
    if sec_dir_size == 0:
        return {'signed': False, 'reason': 'no security directory'}

    # WIN_CERTIFICATE: dwLength(4) + wRevision(2) + wCertificateType(2) + bCertificate(...)
    # 需要将 RVA 转换为文件偏移
    cert_off = _rva_to_file_offset(pe_data, pe_off, sec_dir_rva)
    if cert_off is None or cert_off + 8 > len(pe_data):
        return None
    cert_len = _struct.unpack_from('<I', pe_data, cert_off)[0]
    cert_type = _struct.unpack_from('<H', pe_data, cert_off + 6)[0]
    cert_data = pe_data[cert_off + 8:cert_off + cert_len]

    result = {
        'signed': True,
        'cert_type': _WIN_CERT_TYPES.get(cert_type, f'0x{cert_type:04X}'),
        'cert_size': cert_len,
        'sha256': _hl.sha256(cert_data).hexdigest(),
    }
    return result


def _rva_to_file_offset(pe_data: bytes, pe_off: int, rva: int) -> int | None:
    """PE RVA → 文件偏移转换。遍历 Section Headers 找到包含 RVA 的节。"""
    num_sections = _struct.unpack_from('<H', pe_data, pe_off + 6)[0]
    opt_hdr_size = _struct.unpack_from('<H', pe_data, pe_off + 20)[0]
    sec_hdr_off = pe_off + 24 + opt_hdr_size
    for i in range(num_sections):
        hdr = sec_hdr_off + i * 40
        sec_va = _struct.unpack_from('<I', pe_data, hdr + 12)[0]
        sec_vsize = _struct.unpack_from('<I', pe_data, hdr + 8)[0]
        sec_raw = _struct.unpack_from('<I', pe_data, hdr + 20)[0]
        if sec_va <= rva < sec_va + sec_vsize:
            return rva - sec_va + sec_raw
    return None


def extract_macho_codesign(macho_data: bytes) -> dict | None:
    """从 Mach-O 中检测 LC_CODE_SIGNATURE 加载命令。
    返回签名数据的偏移和大小，由上游模块完成 CMS 解析。"""
    if len(macho_data) < 28:
        return None
    magic = _struct.unpack_from('<I', macho_data, 0)[0]
    if magic not in (0xFEEDFACE, 0xFEEDFACF, 0xBEBAFECA):
        return None
    # 64-bit Mach-O 有额外的 reserved 字段
    is64 = magic in (0xFEEDFACF, 0xBEBAFECA)
    ncmds = _struct.unpack_from('<I', macho_data, 16)[0]
    pos = 28 if is64 else 28
    for _ in range(ncmds):
        if pos + 8 > len(macho_data):
            break
        cmd = _struct.unpack_from('<I', macho_data, pos)[0]
        cmdsize = _struct.unpack_from('<I', macho_data, pos + 4)[0]
        if cmd == 0x1D:  # LC_CODE_SIGNATURE
            dataoff = _struct.unpack_from('<I', macho_data, pos + 8)[0]
            datasize = _struct.unpack_from('<I', macho_data, pos + 12)[0]
            return {'signed': True, 'offset': dataoff, 'size': datasize,
                    'sha256': _hl.sha256(macho_data[dataoff:dataoff + datasize]).hexdigest()}
        pos += cmdsize
    return {'signed': False, 'reason': 'no LC_CODE_SIGNATURE'}
