# ASLR熵分析器: 有效熵量化 / 部分覆写窗口 / 去随机化概率
# 技术问题: 64-bit Linux ASLR名义上有28-bit熵 (约2.68亿种布局),
#   但实际有效熵常因以下原因大幅降低:
#   (a) 页对齐: 低12-bit固定为0→实际熵仅16-bit/区域
#   (b) 部分覆写: 若已知高n字节, 仅需爆破低(8-n)字节
#   (c) 库加载顺序: 某些发行版中libc基址与ld.so基址间距固定
#   (d) 堆实现: glibc的mmap基址在特定版本中有偏置
#   现有工具仅报告"ASLR enabled/disabled", 不量化可利用的熵
# 解决手段: 对每个内存区域(PIE/libc/stack/heap/vdso)计算:
#   1. 名义熵: 架构/OS提供的理论随机比特数
#   2. 有效熵: 减去固定位(页对齐)+已知偏置后的剩余熵
#   3. 部分覆写窗口: 已知高位→仅需爆破产的低位比特数
#   4. 去随机化概率: 给定爆破尝试次数N, 一次成功的概率
# 技术效果: 精确识别可利用的部分覆写窗口,
#   将"ASLR绕过"从二元是/否变为概率化评估
#
#   Binarly US Patent 12,287,885 — 二进制可达性分析,
#     本项目互补: 量化ASLR对可达路径的影响
import logging
import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

log = logging.getLogger(__name__)


@dataclass
class RegionEntropy:
    """单个内存区域的ASLR熵分析."""
    region_name: str          # 'pie' | 'libc' | 'stack' | 'heap' | 'vdso'
    nominal_bits: int = 0     # 理论随机比特数
    fixed_bits: int = 0       # 固定比特数 (页对齐/架构约束)
    known_offset_bits: int = 0  # 已知偏置 (泄漏获取)
    side_channel_bits: int = 0  # 侧信道可缩减的比特数
    effective_bits: int = 0    # 有效熵 = nominal - fixed - known - side_channel
    partial_overwrite_mask: int = 0  # 部分覆写掩码: 哪些位需改变
    brute_force_2pow: int = 0   # 爆破复杂度: 2^N次尝试


@dataclass
class ASLRAnalysis:
    """完整的ASLR分析结果."""
    regions: List[RegionEntropy]
    overall_effective_bits: int
    partial_overwrite_viable: bool
    recommended_attack: str
    brute_force_time_estimate: str  # 在典型爆破速率下的时间


class ASLREntropyAnalyzer:
    """ASLR熵分析器.

    分析目标环境中的有效ASLR熵, 识别部分覆写攻击面.
    """

    # 各架构/区域的ASLR熵基准 (bits)
    _NOMINAL_ENTROPY = {
        "linux_x86_64": {
            "pie":   28, "libc":  28, "stack": 22,
            "heap":  13, "vdso":  11, "ld":    28},
        "linux_i386": {
            "pie":    8, "libc":   8, "stack": 19,
            "heap":  13, "vdso":  11, "ld":     8},
        "linux_arm64": {
            "pie":   28, "libc":  28, "stack": 22,
            "heap":  13, "vdso":  11, "ld":    28},
    }
    _PAGE_BITS = 12     # 4KB页固定低12-bit

    def analyze(self, arch: str = "linux_x86_64",
                leaked_regions: Optional[Dict[str, int]] = None,
                side_channel_info: Optional[Dict[str, int]] = None
                ) -> ASLRAnalysis:
        """完整ASLR分析."""
        leaks = leaked_regions or {}
        side = side_channel_info or {}
        nominal = self._NOMINAL_ENTROPY.get(arch,
                   self._NOMINAL_ENTROPY["linux_x86_64"])
        regions = []
        for name, nom_bits in nominal.items():
            fixed = self._PAGE_BITS
            known_offset = 0
            if name in leaks:
                known_offset = nom_bits  # 完全泄漏→该区域熵为0
            sc_bits = side.get(name, 0)
            effective = max(0, nom_bits - fixed - known_offset - sc_bits)
            # 部分覆写分析: 64-bit值中哪些位已确定
            known_byte_count = (known_offset + fixed) // 8
            # 需要改的字节数 = 8 - known_byte_count (若高字节已知)
            overwrite_bytes = 8 - known_byte_count if known_byte_count > 0 else 8
            overwrite_bits = effective
            pow2 = min(overwrite_bits, 28)  # 上限2^28≈268M

            regions.append(RegionEntropy(
                region_name=name, nominal_bits=nom_bits,
                fixed_bits=fixed, known_offset_bits=known_offset,
                side_channel_bits=sc_bits,
                effective_bits=effective,
                partial_overwrite_mask=(1 << (overwrite_bytes * 8)) - 1,
                brute_force_2pow=pow2))
        # 整体有效熵: 取非泄漏区域的最小有效熵×区域数
        unleaked = [r for r in regions if r.effective_bits > 0]
        overall = min((r.effective_bits for r in unleaked),
                     default=0) if unleaked else 0
        # 部分覆写可行性
        partial_viable = any(
            r.effective_bits > 0 and r.effective_bits <= 16
            for r in regions if r.region_name in ("pie", "libc"))
        # 推荐攻击方式
        attack = self._recommend_attack(regions, arch)
        time_est = self._brute_force_time(overall)
        return ASLRAnalysis(
            regions=regions,
            overall_effective_bits=overall,
            partial_overwrite_viable=partial_viable,
            recommended_attack=attack,
            brute_force_time_estimate=time_est)

    def _recommend_attack(self, regions: List[RegionEntropy],
                          arch: str) -> str:
        """根据ASLR分析推荐攻击策略."""
        by_name = {r.region_name: r for r in regions}
        pie = by_name.get("pie")
        libc = by_name.get("libc")
        stack = by_name.get("stack")
        # 策略1: 无ASLR→直接固定地址利用
        if all(r.effective_bits == 0 for r in regions):
            return "直接使用硬编码地址 (所有区域已去随机化)"
        # 策略2: libc已知→ret2libc
        if libc and libc.effective_bits == 0:
            return "ret2libc/ROP: libc基址已知, 使用libc中的gadget和函数"
        # 策略3: PIE部分覆写
        if pie and 0 < pie.effective_bits <= 16:
            return (f"PIE部分覆写: 爆破低{pie.effective_bits}bit "
                   f"(2^{pie.effective_bits}={1<<pie.effective_bits}次)")
        # 策略4: 栈已知→ROP on stack
        if stack and stack.effective_bits == 0:
            return "栈地址已知: 栈上ROP或ret2stack"
        # 策略5: 高熵→需信息泄漏
        return f"需要信息泄漏: 有效熵{self._summary_bits(regions)}bit, 盲爆破不可行"

    def _brute_force_time(self, effective_bits: int) -> str:
        if effective_bits == 0:
            return "无需爆破"
        ops = 1 << effective_bits
        rate = 1000  # 每秒约1000次尝试 (网络/本地)
        seconds = ops / rate
        if seconds < 1:
            return "<1秒"
        if seconds < 60:
            return f"{seconds:.0f}秒"
        if seconds < 3600:
            return f"{seconds/60:.1f}分钟"
        if seconds < 86400:
            return f"{seconds/3600:.1f}小时"
        days = seconds / 86400
        if days < 365:
            return f"{days:.1f}天"
        return f"{days/365:.1f}年 (不可行)"

    def _summary_bits(self, regions: List[RegionEntropy]) -> int:
        unleaked = [r.effective_bits for r in regions if r.effective_bits > 0]
        return sum(unleaked) if unleaked else 0

    def partial_overwrite_opportunities(self, target_addr: int,
                                         known_high_bytes: int,
                                         target_value: int
                                         ) -> Dict[str, any]:
        """分析特定地址的部分覆写机会.

        known_high_bytes: 已知不变的地址高位字节数.
        返回需要爆破的比特数和预期成功率.
        """
        changed_bytes = 8 - known_high_bytes
        bits_to_brute = changed_bytes * 8
        mask = (1 << (changed_bytes * 8)) - 1
        old_low = target_addr & mask
        new_low = target_value & mask
        return {
            "known_high_bytes": known_high_bytes,
            "bytes_to_overwrite": changed_bytes,
            "bits_to_brute": bits_to_brute,
            "brute_force_space": 1 << bits_to_brute,
            "old_low_bits": hex(old_low),
            "target_low_bits": hex(new_low),
            "recommended_write_size": ("byte" if changed_bytes <= 1 else
                                       "short" if changed_bytes <= 2 else
                                       "int" if changed_bytes <= 4 else "full"),
            "viable": bits_to_brute <= 16,
        }
