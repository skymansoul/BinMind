"""
二进制级密钥扩展重构与验证 — 对已检测到的密码实现进行密钥编排校验。

修改记录:
  2025-08-01 10:41 — 补充SM4 CK常量完整匹配, 增加轮常量变异标志
  2025-08-04 16:28 — 拆分评分逻辑为独立函数, 输出KSReconstructionReport

设计意图:
  crypto_detector通过S-box/IV魔数识别算法, 但无法判断密钥扩展例程是否正确实现。
  本模块对已检测到的密码学结构搜索邻近密钥编排数据(轮常量序列/密钥扩展表),
  与已知参考实现比对, 检测:
    (a) 轮常量被篡改 — 可能为故意弱化或后门;
    (b) 轮数异常 — 低于标准轮数(如AES-256实际只做8轮);
    (c) 轮常量缺失 — 代码存在但数据被strip或不完整。

  - NIST FIPS 197 (AES): §5.2 Key Expansion, Rcon[i] = {02}^{i-1} in GF(2^8)
  - GB/T 32907-2016 (SM4): §7.2 密钥扩展算法, FK/CK常量定义
  - Biham & Shamir, "Differential Fault Analysis of Secret Key Cryptosystems":
    密钥扩展中微小修改可导致灾难性降级
  - US11431484B2: 检测修改过的密码实现的方法 — 轮常量比对是最直接判据
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .constants import AES_RCON

# 轮常量数据库
# 每个条目: (算法名, 轮数, 密钥长度(bit), 轮常量序列(bytes))
# 轮常量序列为连续字节串 — 如AES-128的Rcon为10字节。

_AES_RCON_128: bytes = bytes(AES_RCON)                       # 10 bytes
_AES_RCON_192: bytes = bytes(AES_RCON[:12])                  # 12 bytes
_AES_RCON_256: bytes = bytes(AES_RCON[:14])                  # 14 bytes

# SM4 CK常量 (32×32bit, 固定值, 从π小数部分导出)
# GB/T 32907-2016 §7.2.2: CK[i] = (ck_{i,0}, ck_{i,1}, ck_{i,2}, ck_{i,3})
# ck_{i,j} = (4*i + j) * 7 mod 256
_SM4_CK: bytes = bytes([
    0x00, 0x07, 0x0E, 0x15, 0x1C, 0x23, 0x2A, 0x31,
    0x38, 0x3F, 0x46, 0x4D, 0x54, 0x5B, 0x62, 0x69,
    0x70, 0x77, 0x7E, 0x85, 0x8C, 0x93, 0x9A, 0xA1,
    0xA8, 0xAF, 0xB6, 0xBD, 0xC4, 0xCB, 0xD2, 0xD9,
    0xE0, 0xE7, 0xEE, 0xF5, 0xFC, 0x03, 0x0A, 0x11,
    0x18, 0x1F, 0x26, 0x2D, 0x34, 0x3B, 0x42, 0x49,
    0x50, 0x57, 0x5E, 0x65, 0x6C, 0x73, 0x7A, 0x81,
    0x88, 0x8F, 0x96, 0x9D, 0xA4, 0xAB, 0xB2, 0xB9,
    0xC0, 0xC7, 0xCE, 0xD5, 0xDC, 0xE3, 0xEA, 0xF1,
    0xF8, 0xFF, 0x06, 0x0D, 0x14, 0x1B, 0x22, 0x29,
    0x30, 0x37, 0x3E, 0x45, 0x4C, 0x53, 0x5A, 0x61,
    0x68, 0x6F, 0x76, 0x7D, 0x84, 0x8B, 0x92, 0x99,
    0xA0, 0xA7, 0xAE, 0xB5, 0xBC, 0xC3, 0xCA, 0xD1,
    0xD8, 0xDF, 0xE6, 0xED, 0xF4, 0xFB, 0x02, 0x09,
    0x10, 0x17, 0x1E, 0x25, 0x2C, 0x33, 0x3A, 0x41,
    0x48, 0x4F, 0x56, 0x5D, 0x64, 0x6B, 0x72, 0x79,
])

# SM4 FK常量 (4×32bit, 从π小数部分导出)
_SM4_FK: bytes = bytes([
    0xA3, 0xB1, 0xBA, 0xC6, 0x56, 0xAA, 0x33, 0x50,
    0x67, 0x7D, 0x91, 0x97, 0xB2, 0x70, 0x22, 0xDC,
])

# Camellia轮常量 (Sigma值, RFC 3713) — 6×64bit
_CAMELLIA_SIGMA: bytes = bytes([
    0xA0, 0x9E, 0x66, 0x7F, 0x3B, 0xCC, 0x90, 0x8B,
    0xB6, 0x7A, 0xE8, 0x58, 0x4C, 0xAA, 0x73, 0xB2,
    0xC6, 0xEF, 0x37, 0x2F, 0xE9, 0x4F, 0x82, 0xBE,
    0x54, 0xFF, 0x53, 0xA5, 0xF1, 0xD3, 0x6F, 0x1C,
    0x10, 0xE5, 0x27, 0xFA, 0xDE, 0x68, 0x2D, 0x1D,
    0xB0, 0x56, 0x88, 0xC2, 0xB3, 0xE6, 0xC1, 0xFD,
])

# 实现数据库
_KS_REFERENCE: Dict[str, List[Tuple[str, bytes]]] = {
    'AES': [
        ('AES-128 Rcon', _AES_RCON_128),
        ('AES-192 Rcon', _AES_RCON_192),
        ('AES-256 Rcon', _AES_RCON_256),
    ],
    'SM4': [
        ('SM4 CK', _SM4_CK),
        ('SM4 FK', _SM4_FK),
    ],
    'Camellia': [
        ('Camellia Sigma', _CAMELLIA_SIGMA),
    ],
}

# 核心数据结构

@dataclass
class KeyScheduleMatch:
    """密钥扩展表匹配结果."""
    name: str                                  # 参考表名称, 如 'AES-128 Rcon'
    ref_data: bytes                            # 参考数据
    found_offset: int                          # 二进制中的位置
    match_length: int                          # 匹配字节数
    is_exact: bool                             # 是否精确匹配
    modifications: List[Tuple[int, int, int]]  # (偏移, 期望值, 实际值)差异列表

@dataclass
class KSReconstructionReport:
    """密钥扩展重构报告 — 汇总密钥编排完整性与异常."""
    algorithm: str = ""
    found_round_constants: List[KeyScheduleMatch] = field(default_factory=list)
    inferred_round_count: int = 0
    expected_round_count: int = 0
    is_complete: bool = False
    is_consistent: bool = False
    anomaly_flags: List[str] = field(default_factory=list)

    def is_suspicious(self) -> bool:
        return len(self.anomaly_flags) > 0

# 轮常量搜索
# Boyer-Moore-Horspool搜索已知轮常量序列; 允许部分匹配以捕获被strip或混淆的变体。

def _bmh_find_all(data: bytes, pattern: bytes) -> List[int]:
    """BMH搜索 — 返回pattern在data中的所有起始位置."""
    dl, pl = len(data), len(pattern)
    if pl == 0 or dl < pl:
        return []
    skip = {pattern[i]: pl - 1 - i for i in range(pl - 1)}
    positions: List[int] = []
    pos = 0
    while pos <= dl - pl:
        j = pl - 1
        while j >= 0 and data[pos + j] == pattern[j]:
            j -= 1
        if j < 0:
            positions.append(pos)
            pos += 1
        else:
            bc = data[pos + pl - 1]
            pos += skip.get(bc, pl)
    return positions

def search_round_constants(data: bytes,
                           algo: str,
                           search_radius: int = 65536,
                           anchor_offset: int = 0) -> List[KeyScheduleMatch]:
    """在二进制中搜索指定算法的密钥扩展常量.

    search_radius: 从锚点(如S-box位置)出发的搜索半径(默认64KB).
    anchor_offset: 锚定偏移 — 搜索限定在[anchor-radius, anchor+radius].
    """
    if algo not in _KS_REFERENCE:
        return []

    search_start = max(0, anchor_offset - search_radius)
    search_end = min(len(data), anchor_offset + search_radius)
    region = data[search_start:search_end]

    results: List[KeyScheduleMatch] = []
    seen_positions: Set[int] = set()

    for ref_name, ref_data in _KS_REFERENCE[algo]:
        # 用前4字节做初始锚定搜索
        prefix = ref_data[:4] if len(ref_data) >= 4 else ref_data
        candidates = _bmh_find_all(region, prefix)
        for cand_rel in candidates:
            cand_abs = search_start + cand_rel
            if cand_abs in seen_positions:
                continue
            seen_positions.add(cand_abs)

            # 验证完整匹配
            match_len = 0
            mods: List[Tuple[int, int, int]] = []
            for i in range(len(ref_data)):
                if cand_abs + i >= len(data):
                    break
                actual = data[cand_abs + i]
                if actual == ref_data[i]:
                    match_len += 1
                else:
                    mods.append((i, ref_data[i], actual))
            is_exact = len(mods) == 0 and match_len == len(ref_data)

            results.append(KeyScheduleMatch(
                name=ref_name,
                ref_data=ref_data,
                found_offset=cand_abs,
                match_length=match_len,
                is_exact=is_exact,
                modifications=mods,
            ))
    return results

# 轮常量变异分析
# 精确匹配≠安全; 微小偏离(1-2字节)可能为编译优化或端序问题。
# >2字节偏离且排除端序 → 标记为可疑。

def _is_endian_swap(orig: bytes, found: bytes) -> bool:
    """检查差异是否可由端序翻转解释."""
    if len(orig) != len(found) or len(orig) % 4 != 0:
        return False
    swapped = b''.join(orig[i:i + 4][::-1] for i in range(0, len(orig), 4))
    return swapped == found

def score_key_schedule(matches: List[KeyScheduleMatch]) -> KSReconstructionReport:
    """对密钥扩展匹配结果综合评价.

    判据:
      - 精确匹配全部轮常量 → 高置信度无问题
      - 匹配但非精确 → 评估偏离程度与端序翻转
      - 完全无匹配 → 可能被strip/混淆/自定义算法
    """
    if not matches:
        return KSReconstructionReport(
            anomaly_flags=['未找到密钥扩展常量 — 可能被strip或为自定义算法'])

    first_match = matches[0]
    # 从参考名推导算法名
    algo_name = first_match.name.split(' ')[0] if ' ' in first_match.name else first_match.name

    report = KSReconstructionReport(algorithm=algo_name)
    report.found_round_constants = matches

    # 最佳匹配: 选匹配长度最长者
    best = max(matches, key=lambda m: m.match_length)
    ref_len = len(best.ref_data)

    if best.is_exact:
        report.is_complete = True
        report.is_consistent = True
        report.match_length = ref_len
        # 从参考长度推轮数: AES-128 Rcon=10B→10轮, AES-192→12轮, AES-256→14轮
        report.inferred_round_count = ref_len
        report.expected_round_count = ref_len
    else:
        # 部分匹配 — 分析偏离
        n_mods = len(best.modifications)
        if n_mods <= 2:
            # 检查端序解释
            found_bytes = bytes(data[best.found_offset + i]
                                if best.found_offset + i < 2**32 else 0
                                for i in range(ref_len))
            found_bytes = data[best.found_offset:best.found_offset + ref_len] \
                if best.found_offset + ref_len <= len(data) else b''
            if found_bytes and _is_endian_swap(best.ref_data, found_bytes):
                report.anomaly_flags.append(
                    f'{best.name}: 端序差异 (big vs little endian), 非安全问题')
                report.is_consistent = True
            else:
                report.anomaly_flags.append(
                    f'{best.name}: {n_mods}字节偏离参考值 — 可能为编译优化变异')
                report.is_consistent = True   # 仍标记为一致, 降置信
        elif n_mods <= ref_len // 4:
            report.anomaly_flags.append(
                f'{best.name}: {n_mods}字节偏离 ({n_mods/ref_len:.0%}) — '
                '非编译器可解释的差异, 疑似被修改')
        else:
            report.anomaly_flags.append(
                f'{best.name}: 大量偏离 ({n_mods}字节/{ref_len}) — '
                '匹配可能为巧合或非标准实现')

        report.inferred_round_count = best.match_length
        report.expected_round_count = ref_len
        if best.match_length < ref_len:
            report.anomaly_flags.append(
                f'轮常量不足: 找到{best.match_length}B 期望{ref_len}B → '
                f'轮数可能不足')

    return report

# 便捷函数

def reconstruct(data: bytes, algo: str,
                anchor: int = 0,
                radius: int = 65536) -> KSReconstructionReport:
    """一站式密钥扩展重构 — 搜索+评估."""
    matches = search_round_constants(data, algo, radius, anchor)
    return score_key_schedule(matches)

__all__ = [
    'KeyScheduleMatch', 'KSReconstructionReport',
    'search_round_constants', 'score_key_schedule', 'reconstruct',
]
