# //// 隐写与隐藏数据检测 ////
# PE overlay — 文件尾部超出SizeOfImage的部分，加载器不映射，常见隐藏载体。
# section间隙(slack space): 节区文件占用 > 内存映射空间，可嵌入数据。
# 内嵌归档文件: 枚举MAGIC_DB魔数，在二进制中搜索，排除offset=0(主格式)。
# 高熵区滑动窗口: 加密/压缩数据熵>0.92, .text段熵<0.7, 天然区分。
# EOF尾部间隙(ZIP EOCD/PNG IEND/JPEG EOI后追加数据),
# LSB卡方隐写(Westfeld-Pfitzmann χ²检验, p>0.95标记可疑),
# BMP像素层LSB专用检测路径。

from dataclasses import dataclass
from typing import List, Optional, Tuple
import struct
import math
from .utils import shannon_entropy
# HiddenDataType导入顺序修复 2026-08-02 — 提升到模块顶部


@dataclass
class StegoFinding:
    offset: int
    format: str
    confidence: float
    description: str


# 归档文件魔数库
MAGIC_DB: List[Tuple[bytes, str, int]] = [
    (b'\x50\x4B\x03\x04', 'ZIP', 30),
    (b'\x50\x4B\x05\x06', 'ZIP_EOCD', 22),
    (b'\x50\x4B\x07\x08', 'ZIP64_EOCD', 56),
    (b'\x1F\x8B\x08', 'GZIP', 10),
    (b'\x1F\x9D', 'COMPRESS', 3),
    (b'\x42\x5A\x68', 'BZ2', 4),
    (b'\xFD\x37\x7A\x58\x5A\x00', 'XZ', 6),
    (b'\x37\x7A\xBC\xAF\x27\x1C', '7Z', 6),
    (b'\x52\x61\x72\x21\x1A\x07\x00', 'RAR4', 7),
    (b'\x52\x61\x72\x21\x1A\x07\x01\x00', 'RAR5', 8),
    (b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A', 'PNG', 8),
    (b'\xFF\xD8\xFF', 'JPEG', 3),
    (b'\x47\x49\x46\x38', 'GIF', 6),
    (b'\x25\x50\x44\x46', 'PDF', 5),
    (b'\xD0\xCF\x11\xE0', 'OLE_Office', 8),
    (b'\x00\x01\x00\x00\x00', 'TrueType', 12),
    (b'\x77\x4F\x46\x46', 'WOFF', 8),
    (b'\x77\x4F\x46\x32', 'WOFF2', 8),
    (b'\x49\x44\x33', 'MP3_ID3', 10),
    (b'\xFF\xFB', 'MP3_MPEG', 2),
    (b'\x52\x49\x46\x46', 'RIFF', 12),
    (b'\x1A\x45\xDF\xA3', 'Matroska', 8),
    (b'\x21\x3C\x61\x72\x63\x68\x3E', 'AR', 8),
    (b'\x1F\xA0', 'CPIO', 2),
    (b'\x4D\x53\x43\x46', 'CAB', 4),
    (b'\xED\xAB\xEE\xDB', 'RPM', 4),
    (b'\x4D\x5A', 'MZ_PE', 2),
    (b'\x7F\x45\x4C\x46', 'ELF', 4),
    (b'\xCF\xFA\xED\xFE', 'MachO_64', 4),
    (b'\xCE\xFA\xED\xFE', 'MachO_32', 4),
    (b'\x75\x73\x74\x61\x72', 'TAR', 5),
    (b'\x3C\x3F\x78\x6D\x6C', 'XML', 5),
    (b'\x1F\x8B', 'TAR_GZ', 2),
    (b'\x4C\x5A\x49\x50', 'LZIP', 4),
    (b'\x28\xB5\x2F\xFD', 'ZSTD', 4),
]

# 常见文件尾标记 — 检测EOF后追加的隐藏数据
_EOF_MARKERS = [
    (b'IEND\xae\x42\x60\x82', 'PNG_IEND', 12),
    (b'\xFF\xD9', 'JPEG_EOI', 2),
    (b'PK\x05\x06', 'ZIP_EOCD', 22),
]


# PE overlay检测
def detect_overlay_data(pe_data: bytes) -> Optional[StegoFinding]:
    _dl = len(pe_data)
    if _dl < 0x40 or pe_data[:2] != b'MZ':
        return None

    _e_lfanew = struct.unpack_from('<I', pe_data, 0x3C)[0]
    if _e_lfanew >= _dl - 4 or pe_data[_e_lfanew:_e_lfanew + 4] != b'PE\x00\x00':
        return None

    _opt_off = _e_lfanew + 4 + 20
    if _opt_off + 2 > _dl:
        return None
    _magic = struct.unpack_from('<H', pe_data, _opt_off)[0]
    if _magic == 0x10B:
        _soi_off = _opt_off + 56
    elif _magic == 0x20B:
        _soi_off = _opt_off + 72
    else:
        return None

    if _soi_off + 4 > _dl:
        return None
    _size_of_image = struct.unpack_from('<I', pe_data, _soi_off)[0]

    if _dl > _size_of_image:
        _overlay = pe_data[_size_of_image:]
        _sample = _overlay[:1024] if len(_overlay) > 1024 else _overlay
        _ent = shannon_entropy(_sample)
        return StegoFinding(
            offset=_size_of_image, format='PE_overlay',
            confidence=min(0.95, 0.5 + _ent),
            description='PE overlay {} bytes, H={:.3f}'.format(len(_overlay), _ent))
    return None


# EOF尾部间隙检测
def detect_eof_gaps(data: bytes) -> List[StegoFinding]:
    """检测文件格式EOF标记之后追加的隐藏数据。"""
    _out = []
    _dl = len(data)
    for _marker, _name, _trailer_len in _EOF_MARKERS:
        _idx = data.rfind(_marker)
        if _idx == -1:
            continue
        _eof_end = _idx + _trailer_len
        # ZIP EOCD含变长comment，精确计算尾部偏移
        if _name == 'ZIP_EOCD' and _eof_end + 2 <= _dl:
            _comment_len = struct.unpack_from('<H', data, _eof_end - 2)[0]
            _eof_end = _eof_end + _comment_len - 2
        _gap = _dl - _eof_end
        if _gap >= 256:
            _ent = shannon_entropy(data[_eof_end:_eof_end + min(_gap, 4096)])
            _out.append(StegoFinding(
                offset=_eof_end, format='EOF_gap_{}'.format(_name),
                confidence=0.6 + _ent * 0.3,
                description='EOF gap after {}: {} bytes, H={:.3f}'.format(_name, _gap, _ent)))
    return _out


# Section间隙
def detect_section_gaps(pe_data: bytes) -> List[StegoFinding]:
    _out = []
    _dl = len(pe_data)
    if _dl < 0x40 or pe_data[:2] != b'MZ':
        return _out

    _e_lfanew = struct.unpack_from('<I', pe_data, 0x3C)[0]
    if _e_lfanew + 4 > _dl or pe_data[_e_lfanew:_e_lfanew + 4] != b'PE\x00\x00':
        return _out

    _num_sec = struct.unpack_from('<H', pe_data, _e_lfanew + 4 + 2)[0]
    _opt_off = _e_lfanew + 4 + 20
    _magic = struct.unpack_from('<H', pe_data, _opt_off)[0]
    _opt_size = 96 if _magic == 0x10B else (112 if _magic == 0x20B else 0)
    if _opt_size == 0:
        return _out

    _sec_off = _opt_off + _opt_size
    _secs = []
    for _i in range(_num_sec):
        _so = _sec_off + _i * 40
        if _so + 40 > _dl:
            break
        _ptr_raw = struct.unpack_from('<I', pe_data, _so + 20)[0]
        _size_raw = struct.unpack_from('<I', pe_data, _so + 16)[0]
        _secs.append((_ptr_raw, _size_raw))

    for _i in range(len(_secs) - 1):
        _end = _secs[_i][0] + _secs[_i][1]
        _next_start = _secs[_i + 1][0]
        if _next_start > _end and _end > 0:
            _gap = _next_start - _end
            _gd = pe_data[_end:_next_start]
            _ent = shannon_entropy(_gd)
            if _ent > 0.5 or _gap > 256:
                _out.append(StegoFinding(
                    offset=_end, format='section_gap',
                    confidence=0.4 + _ent * 0.4,
                    description='Section gap {}B at 0x{:x}, H={:.3f}'.format(_gap, _end, _ent)))
    return _out


# 内嵌归档
def detect_embedded_archives(data: bytes) -> List[StegoFinding]:
    _out = []
    _dl = len(data)
    for _magic, _fmt, _min_len in MAGIC_DB:
        _pos = 0
        while True:
            _pos = data.find(_magic, _pos)
            if _pos == -1:
                break
            if _pos > 0 and _dl - _pos >= _min_len:
                _out.append(StegoFinding(
                    offset=_pos, format='embedded_{}'.format(_fmt),
                    confidence=0.7,
                    description='{} magic at 0x{:x}'.format(_fmt, _pos)))
            _pos += 1
    return _out


# 高熵区扫描
def scan_high_entropy_regions(data: bytes, window: int = 256) -> List[StegoFinding]:
    _out = []
    _dl = len(data)
    if _dl < window:
        return _out

    _regions = []
    for _pos in range(0, _dl - window, window // 4):
        _chunk = data[_pos:_pos + window]
        _ent = shannon_entropy(_chunk)
        if _ent > 0.92:
            _regions.append((_pos, _ent))

    if not _regions:
        return _out

    _merged = [_regions[0]]
    for _r in _regions[1:]:
        _last = _merged[-1]
        if _r[0] - _last[0] < window * 2:
            _merged[-1] = (_last[0], max(_last[1], _r[1]))
        else:
            _merged.append(_r)

    for _pos, _ent in _merged:
        _out.append(StegoFinding(
            offset=_pos, format='high_entropy',
            confidence=_ent,
            description='高熵区(H={:.3f}) at 0x{:x}'.format(_ent, _pos)))
    return _out


# LSB 卡方隐写分析
def _lsb_chi_square(data: bytes) -> Tuple[float, float]:
    """PoV (Pairs of Values) χ²检验。返回(chi_sq, p_value)。p > 0.95→LSB嵌入嫌疑。"""
    n = len(data)
    if n < 1024:
        return 0.0, 0.0
    hist = [0] * 256
    for b in data:
        hist[b] += 1

    # 128对: (0,1), (2,3), ..., (254,255)
    k = 0
    chi_sq = 0.0
    for i in range(128):
        even = hist[2 * i]
        odd = hist[2 * i + 1]
        expected = (even + odd) / 2.0
        if expected > 0:
            chi_sq += (even - expected) ** 2 / expected
            k += 1

    df = k - 1
    if df <= 0:
        return chi_sq, 0.0

    # Wilson-Hilferty χ²→正态近似
    t = (chi_sq / df) ** (1.0 / 3.0)
    z = (t - (1.0 - 2.0 / (9.0 * df))) / math.sqrt(2.0 / (9.0 * df))
    # 正态生存函数: P(Z > z)
    if z < -6:
        return chi_sq, 1.0
    if z > 6:
        return chi_sq, 0.0
    a1, a2, a3 = 0.4361836, -0.1201676, 0.9372980
    kv = 1.0 / (1.0 + 0.33267 * abs(z))
    phi = 1.0 - (1.0 / math.sqrt(2.0 * math.pi)) * math.exp(-z * z / 2.0) * (
        a1 * kv + a2 * kv * kv + a3 * kv * kv * kv)
    return chi_sq, phi if z >= 0 else 1.0 - phi

# LSB检测阈值
_LSB_P_THRESHOLD = 0.95


def detect_lsb_stego(data: bytes) -> List[StegoFinding]:
    """全局+分段LSB卡方扫描。"""
    _out = []
    _dl = len(data)
    if _dl < 1024:
        return _out

    # 全量扫描
    _chi, _p = _lsb_chi_square(data)
    if _p > _LSB_P_THRESHOLD:
        _out.append(StegoFinding(
            offset=0, format='LSB_stego',
            confidence=_p,
            description='LSB stego: χ²={:.1f}, p={:.4f}'.format(_chi, _p)))

    # 分段扫描 (64KB窗口)
    for _seg in range(0, _dl - 1024, 65536):
        _chunk = data[_seg:_seg + 65536]
        _chi2, _p2 = _lsb_chi_square(_chunk)
        if _p2 > _LSB_P_THRESHOLD:
            _out.append(StegoFinding(
                offset=_seg, format='LSB_stego_segment',
                confidence=_p2,
                description='LSB segment @ 0x{:x}: χ²={:.1f}, p={:.4f}'.format(_seg, _chi2, _p2)))

    return _out


def detect_bmp_lsb(data: bytes) -> List[StegoFinding]:
    """BMP像素层LSB专用检测 — 跳过54字节文件头，仅对像素数据做卡方检验。"""
    if len(data) < 1078 or data[:2] != b'BM':
        return []
    pixel_off = struct.unpack_from('<I', data, 10)[0]
    if pixel_off >= len(data):
        return []
    pixels = data[pixel_off:]
    if len(pixels) < 1024:
        return []
    _chi, _p = _lsb_chi_square(pixels)
    if _p > _LSB_P_THRESHOLD:
        return [StegoFinding(
            offset=pixel_off, format='BMP_LSB_stego',
            confidence=_p,
            description='BMP pixel LSB: χ²={:.1f}, p={:.4f}'.format(_chi, _p))]
    return []


# 主检测器
class SteganographyDetector:
    def __init__(self, data: bytes):
        self._data = data

    def run_all(self) -> List[StegoFinding]:
        _all = []
        _ov = detect_overlay_data(self._data)
        if _ov:
            _all.append(_ov)
        _all.extend(detect_eof_gaps(self._data))
        _all.extend(detect_section_gaps(self._data))
        _all.extend(detect_embedded_archives(self._data))
        _all.extend(scan_high_entropy_regions(self._data))
        _all.extend(detect_lsb_stego(self._data))
        _all.extend(detect_bmp_lsb(self._data))
        return sorted(_all, key=lambda f: -f.confidence)
