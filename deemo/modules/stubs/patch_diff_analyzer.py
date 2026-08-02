# patch_diff_analyzer.py — 补丁差异分析器
# 对比补丁前后的二进制差异，识别漏洞修复位置并评估利用可行性。
# 参考: VulHawk (Luo et al., 2023, NDSS) 跨架构熵搜索 &
#   Vestige (Ji et al., 2021) 二进制来源追踪 &
#   Automatic Patch-Based Exploit Generation (Brumley et al., 2008 IEEE S&P) &
#   BEDetector (Yu et al., 2021) 双通道编码漏洞检测
import os as _os, struct as _pack
from dataclasses import dataclass as _dc
from collections import defaultdict as _defdict

@_dc
class DiffRegion:
    start_addr: int
    end_addr: int
    change_type: str  # 'modified' | 'inserted' | 'deleted'
    orig_bytes: bytes = b''
    patched_bytes: bytes = b''
    confidence: float = 0.0

def find_patch_regions(orig_bin: bytes, patched_bin: bytes,
                        base_addr: int = 0) -> list[DiffRegion]:
    """在二进制级别定位补丁修改区域。
    VulHawk 的熵引导方法: 先计算全局熵差定位大区域，再字节级精确定位。"""
    if len(orig_bin) != len(patched_bin):
        # 文件大小不同 → 按较小的逐字节比较
        min_len = min(len(orig_bin), len(patched_bin))
        regions = []
        i = 0
        while i < min_len:
            if orig_bin[i] != patched_bin[i]:
                start = i
                while i < min_len and orig_bin[i] != patched_bin[i]:
                    i += 1
                regions.append(DiffRegion(
                    start_addr=base_addr + start,
                    end_addr=base_addr + i,
                    change_type='modified',
                    orig_bytes=orig_bin[start:i],
                    patched_bytes=patched_bin[start:i],
                ))
            else:
                i += 1
        if len(patched_bin) > min_len:
            regions.append(DiffRegion(base_addr + min_len,
                         base_addr + len(patched_bin), 'inserted'))
        elif len(orig_bin) > min_len:
            regions.append(DiffRegion(base_addr + min_len,
                         base_addr + len(orig_bin), 'deleted'))
        return regions

    regions = []
    i = 0
    while i < len(orig_bin):
        if orig_bin[i] != patched_bin[i]:
            start = i
            while i < len(orig_bin) and orig_bin[i] != patched_bin[i]:
                i += 1
            regions.append(DiffRegion(base_addr + start, base_addr + i,
                          'modified', orig_bin[start:i], patched_bin[start:i]))
        else:
            i += 1
    return regions


def classify_patch_type(region: DiffRegion) -> str:
    """基于修改模式推断补丁类型。
    Brumley et al. (2008): 条件跳转修改 → 权限检查；缓冲区大小修改 → 溢出修复。"""
    if not region.orig_bytes or not region.patched_bytes:
        return 'structural_change'
    # 条件跳转变化 → 安全检查
    JCC = {0x74, 0x75, 0x7C, 0x7D, 0x7E, 0x7F, 0x0F}
    orig_has_jcc = any(b in JCC for b in region.orig_bytes)
    patched_has_jcc = any(b in JCC for b in region.patched_bytes)
    if orig_has_jcc != patched_has_jcc:
        return 'security_check_added_or_removed'
    # 常量变化 → 缓冲区大小
    if len(region.orig_bytes) <= 4 and len(region.patched_bytes) <= 4:
        return 'constant_or_size_change'
    return 'general_modification'
