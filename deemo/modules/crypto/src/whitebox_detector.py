"""
白盒密码学检测 — 从二进制静态特征识别白盒密码实现(密钥嵌入+编码混淆的查表结构)。

修改记录:
  2025-08-12 09:15 — 初始实现: 编码S-box检测/外部编码指纹/T-box结构/Chow风格实现识别

设计意图:
  白盒密码学(WBC)将密钥嵌入到大量预计算的查找表中, 通过内部/外部编码混淆表内容,
  使攻击者即使完全控制执行环境也无法提取密钥。WBC在DRM/移动支付/软件保护中广泛使用。

  检测WBC实现具有双重安全价值:
    (a) 良性: 确认WBC保护是否到位 — 编码强度不足的实现可能被DCA攻破。
    (b) 恶意: 恶意软件使用WBC隐藏加密密钥 — 检测WBC模式可定位隐藏的C2通信密钥。

  现有WBC检测工具(Whiteboxgrind/Deadpool/DarkPhoenix)均依赖动态执行trace —
  需要运行二进制并捕获内存访问。本模块从以下静态信号识别WBC:
    1. 巨型查表结构: 单个表≥64KB, 多个编码表共现 → WBC的标记性特征。
    2. 编码S-box: 标准S-box经仿射变换后的高熵变体 — 256字节完美排列但非已知S-box。
    3. T-box结构: AES Chow风格实现中, T-box = 8→32bit映射 → 4个256-entry×4-byte表。
    4. XOR表: 对编码数据执行XOR操作的辅助表 → nibble-wise XOR查找。
    5. 外部编码字符串: "whitebox"/"wbc"/"wb_aes"/"encoded"等开发者留下的调试符号。

  - Chow et al.: "White-Box Cryptography and an AES Implementation" —
    WBC的原始论文, 定义了T-box/编码表/XOR表的结构模式。
  - Castelnovi & Houzelot: 证明小内部编码不能阻止DCA —
    本模块可辅助评估二进制中的WBC是否使用了足够强的编码。
  - Hu et al.: SM4白盒方案 — 使用4阶非线性编码+表访问重排,
    仅需1.44MB → 本模块可检测此类紧凑WBC的编码签名。

边界条件:
  - 编码S-box与随机256字节排列无法静态区分 → 编码S-box匹配为概率性(置信度0.65-0.78)。
  - WBC与普通大型查找表(如字体/图像数据)可能混淆 → 通过多信号共存提高置信度。
  - 部分WBC方案使用bit-sliced实现而非查表 → 此类实现无法通过本模块检测。
"""

import math
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .constants import AES_SBOX, SM4_SBOX
from .utils import shannon_entropy

@dataclass
class WBCFinding:
    algorithm: str = ""
    wb_type: str = ""              # CHOW / XIAO_LAI / KARROUMI / CUSTOM
    confidence: float = 0.0
    evidence: str = ""
    location: int = 0
    table_count: int = 0           # 检测到的编码表数量

# WBC特征阈值
_LARGE_TABLE_MIN_BYTES = 64 * 1024     # 单个大表≥64KB
_TBOX_ENTRY_SIZE = 4                     # T-box每项4字节(8→32bit)
_MIN_TBOX_ENTRIES = 256                  # 标准T-box有256项
_ENCODED_SBOX_ENTROPY_MIN = 0.98        # 编码S-box熵接近1.0(仍是排列)
_XOR_TABLE_MIN = 16 * 16                 # 最小XOR表: 16×16 nibble组合

# 已知标准S-box集合(用于编码S-box排除)
_KNOWN_SBOXES: Set[bytes] = {
    bytes(AES_SBOX), bytes(AES_SBOX),
    bytes(SM4_SBOX),
}

def _is_bytes_permutation(data: bytes, start: int, length: int = 256) -> bool:
    """检查data[start:start+length]是否为完美排列(每个字节值恰好出现一次)。"""
    if start + length > len(data):
        return False
    return len(set(data[start:start + length])) == length

def _detect_large_tables(data: bytes) -> List[Tuple[int, int, float]]:
    """
    检测大型查找表。返回[(偏移, 表大小, 熵), ...]。
    WBC表特征: ≥256字节, 高熵但非随机(因编码保持双射性)。
    """
    tables: List[Tuple[int, int, float]] = []
    min_size = 256
    i = 0
    n = len(data)

    while i < n - min_size:
        # 检查从i开始的256字节窗口
        window = data[i:i + 256]
        ent = shannon_entropy(window)
        # WBC表: 排列→熵≈1.0; 随机→熵≈1.0。区分的要点是排列结构。
        if ent > 0.97 and _is_bytes_permutation(data, i):
            # 扩大到最大表尺寸: 找连续的排列块
            table_end = i + 256
            chunk_size = 256
            while table_end + 256 <= n and table_end - i < 256 * 1024:
                next_chunk = data[table_end:table_end + 256]
                if shannon_entropy(next_chunk) > 0.96:
                    if _is_bytes_permutation(data, table_end):
                        chunk_size += 256
                        table_end += 256
                        continue
                break
            if chunk_size >= 256:
                # 整表的平均熵
                tbl_data = data[i:i + chunk_size]
                avg_ent = shannon_entropy(tbl_data)
                tables.append((i, chunk_size, avg_ent))
            i = table_end
        else:
            i += 64

    return tables

def _detect_encoded_sbox(data: bytes, offset: int) -> Tuple[bool, float, str]:
    """
    检测是否为编码S-box(经仿射变换的AES/SM4 S-box)。
    策略: 检查256字节是否为排列、不在已知S-box集合中、具有特定的差分特征。
    编码S-box保持双射性但改变了差分分布 → 部分偏离参考S-box的差分均匀度。
    """
    if not _is_bytes_permutation(data, offset):
        return False, 0.0, ""

    region = data[offset:offset + 256]
    ref_box = bytes(region)

    # 排除标准S-box
    if ref_box in _KNOWN_SBOXES:
        return False, 0.0, ""

    # 检查非线性度近似: 编码S-box的非线性度通常保持在较高水平(≥100)
    # 简化为: 检查Walsh-Hadamard变换的max绝对值不超过某个边界
    # 此处使用近似: 与AES S-box的逐字节差异分布
    diffs = [ref_box[i] ^ AES_SBOX[i] for i in range(256)]
    unique_diffs = len(set(diffs))

    # 编码S-box: 差异分布较均匀(unique_diffs > 200)
    # 随机排列: 差异分布也均匀 → 无法仅凭此区分
    # 附加信号: 编码S-box常以连续块形式出现, 且伴随XOR表
    if unique_diffs > 128:
        wb_conf = 0.65  # 概率性判定
        if unique_diffs > 200:
            wb_conf = 0.78
        return True, wb_conf, f'encoded permutation, unique XOR diffs vs AES={unique_diffs}'

    return False, 0.0, ""

def _detect_tbox_structure(data: bytes, offset: int) -> Tuple[bool, int, float]:
    """
    检测Chow风格T-box结构: 4个256-entry的32-bit表。
    T-box = 8→32bit映射 → 每项4字节, 256项=1024字节/表, 4表=4096字节。
    表内容为32-bit值, 表现为每4字节组具有一致的内部结构。
    """
    if offset + 4096 > len(data):
        return False, 0, 0.0

    # 检查4个候选T-box的熵
    tbox_ents = []
    for t in range(4):
        tbl = data[offset + t * 1024:offset + (t + 1) * 1024]
        tbox_ents.append(shannon_entropy(tbl))

    # T-box具有高熵(接近1.0)但结构规律(每4字节组为一个word)
    avg_ent = sum(tbox_ents) / 4.0
    if avg_ent < 0.92:
        return False, 0, 0.0

    # 检查4字节对齐: 每4字节组的第4字节(高位)是否有零填充模式
    zero_high_bytes = 0
    for t in range(4):
        for i in range(t * 1024 + 3, (t + 1) * 1024, 4):
            if data[offset + i] == 0x00:
                zero_high_bytes += 1

    expected = 256
    zero_ratio = zero_high_bytes / (4 * expected) if expected > 0 else 0

    # T-box的高位字节约有25-50%的零(取决于编码)
    if 0.15 <= zero_ratio <= 0.60:
        return True, 4, avg_ent

    return False, 0, 0.0

def _detect_xor_tables(data: bytes, start_offset: int, search_radius: int = 8192
                       ) -> Tuple[int, float]:
    """
    在指定区域搜索XOR辅助表。
    XOR表 = 对两个nibble输入做XOR后经编码输出的查找表。
    典型尺寸: 16×16=256字节(nibble XOR)或256×256=65536字节(byte XOR)。
    """
    end = min(start_offset + search_radius, len(data))
    xor_count = 0
    best_conf = 0.0

    for off in range(start_offset, end - 256, 64):
        if not _is_bytes_permutation(data, off):
            continue
        # 检查XOR表特征: 表[i]与表[0]的差异分布
        tbl = data[off:off + 256]
        # nibble XOR表: 每16字节段的第一个元素是该段的基础值
        segment_starts = [tbl[i * 16] for i in range(16)]
        if len(set(segment_starts)) > 12:  # 段首值几乎唯一 → XOR表特征
            xor_count += 1
            best_conf = max(best_conf, 0.75)

    return xor_count, best_conf

# WBC字符串指纹
_WBC_STRING_PATTERNS: List[Tuple[bytes, str, float]] = [
    (b'whitebox', 'whitebox', 0.85),
    (b'white-box', 'whitebox', 0.85),
    (b'wb_aes', 'WBC-AES', 0.90),
    (b'wbaes', 'WBC-AES', 0.88),
    (b'wb_AES', 'WBC-AES', 0.88),
    (b'wb_sm4', 'WBC-SM4', 0.90),
    (b'encoded_sbox', 'encoded-Sbox', 0.82),
    (b'external_encoding', 'ext-encoding', 0.85),
    (b'internal_encoding', 'int-encoding', 0.82),
    (b'chow_aes', 'Chow-AES', 0.92),
    (b'TBox', 'T-box', 0.88),
    (b'TyTable', 'Ty-table', 0.85),
    (b'XorTable', 'XOR-table', 0.85),
    (b'lookup_table_encode', 'encoded-lookup', 0.80),
]

class WhiteBoxDetector:
    """白盒密码学静态检测器。"""

    def __init__(self, data: bytes, strings: Optional[List[str]] = None):
        self._data = data
        self._strs = strings or []

    def run_all(self) -> List[WBCFinding]:
        findings: List[WBCFinding] = []

        # 1. 大型查表检测
        large_tables = _detect_large_tables(self._data)
        for offset, size, ent in large_tables:
            # 检查是否为WBC表(多信号共存提高置信度)
            tbox_found, tbox_count, tbox_ent = _detect_tbox_structure(self._data, offset)
            xor_count, xor_conf = _detect_xor_tables(self._data, offset)

            if tbox_found and size >= 4096:
                findings.append(WBCFinding(
                    algorithm='AES (Chow-style)', wb_type='CHOW',
                    confidence=min(0.92, 0.70 + tbox_ent * 0.2),
                    evidence=f'{tbox_count} T-boxes + {xor_count} XOR tables, total {size}B at 0x{offset:x}',
                    location=offset, table_count=tbox_count + xor_count))
            elif size >= _LARGE_TABLE_MIN_BYTES and xor_count >= 1:
                findings.append(WBCFinding(
                    algorithm='AES/SM4', wb_type='CUSTOM',
                    confidence=0.72,
                    evidence=f'Large encoded table ({size}B) + {xor_count} XOR tables at 0x{offset:x}',
                    location=offset, table_count=1 + xor_count))

        # 2. 编码S-box检测
        for offset in range(0, min(len(self._data), 0x100000), 64):
            is_encoded, conf, detail = _detect_encoded_sbox(self._data, offset)
            if is_encoded:
                # 只在非大表区报告(避免重复)
                too_close = any(abs(offset - f.location) < 4096 for f in findings)
                if not too_close:
                    findings.append(WBCFinding(
                        algorithm='AES/SM4', wb_type='CUSTOM',
                        confidence=conf,
                        evidence=f'{detail} at 0x{offset:x}',
                        location=offset, table_count=1))

        # 3. 字符串指纹
        for s in self._strs:
            sb = s.encode('ascii', errors='replace') if isinstance(s, str) else s
            for pat, algo, conf in _WBC_STRING_PATTERNS:
                if pat in sb:
                    findings.append(WBCFinding(
                        algorithm=algo, wb_type='CHOW',
                        confidence=conf,
                        evidence=f'WBC string: "{s[:50]}"',
                        location=0, table_count=0))
                    break

        return sorted(findings, key=lambda f: -f.confidence)
