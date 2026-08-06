# 创建: 2025-08-16 12:40
# 修改: 2025-08-16 — 22 项指标库 x 加权可靠性 x 多样性奖励
"""
反分析技术检测器 — 多指标加权风险评分。

现有反混淆模块 (anti_analysis.py, anti_vm_bypass.py) 检测特定的单一
反分析技术。本模块提供系统化的枚举 + 加权评分:

检测维度:
  1. 反调试: IsDebuggerPresent/ptrace/timing checks/self-debugging
  2. 反虚拟机: VMEXIT side-channel/CPUID/RDTSC/registry artifacts
  3. 反插桩: Frida detection/Pin detection/procfs 检查
  4. 完整性检查: 代码段 CRC/反篡改/import hook 检测

加权评分:
  每个指标的可靠性不同——ptrace 检查可靠 (99%), 而 timing-based
  检查有噪声 (可能只是性能测量)。最终风险分数 = Σ(检测到 × 权重),
  归一化到 [0, 100]。

为什么选择加权而非二值判定:
  商用保护器 (VMProtect/Themida) 使用 10+ 层反分析——权重评分
  反映"对抗强度"。单一反调试可能是误报 (调试版编译残留),
  但 5+ 个指标同时命中几乎是确定的反分析意图。

ref: LibIHT (arXiv:2510.16251, 2025) — hardware-assisted evasion-
     resistant DBI, 本项目取其反检测思路的反面——检测反分析技术
ref: Sabri (ETASR 2026) — adaptive anti-debugging framework,
     本项目将其多指标加权模型改编为检测器而非保护器
ref: Norby et al. (IEEE Access 2025) — measurement of anti-debugging
     techniques, 本项目引用其 Windows/Linux 双平台技术枚举
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class DetectionCategory(Enum):
    ANTI_DEBUG = 'anti_debug'
    ANTI_VM = 'anti_vm'
    ANTI_INSTRUMENT = 'anti_instrument'
    INTEGRITY = 'integrity_check'
    TIMING = 'timing_check'


@dataclass
class DetectionIndicator:
    """单个检测指标——一种反分析技术的签名。"""
    name: str
    category: DetectionCategory
    pattern: str              # 字节/字符串/API名 的检测模式
    weight: float = 0.5       # [0,1] 可靠性权重——越高越确定
    platform: str = 'all'     # 'windows' | 'linux' | 'all'


@dataclass
class AntiAnalysisReport:
    """反分析技术检测报告。"""
    binary_name: str = ''
    total_indicators: int = 0
    detected: list[DetectionIndicator] = field(default_factory=list)
    risk_score: float = 0.0       # [0, 100]
    risk_level: str = 'NONE'      # 'NONE'|'LOW'|'MEDIUM'|'HIGH'|'CRITICAL'
    category_breakdown: dict = field(default_factory=dict)


# --- 检测指标库 ---
# 基于 IEEE Access 2025 的测量研究 + 社区经验整理。
# 每个指标: (名称, 类别, 检测模式, 权重, 平台)

_INDICATOR_LIBRARY: list[DetectionIndicator] = [
    # 反调试 — Windows
    DetectionIndicator('IsDebuggerPresent', DetectionCategory.ANTI_DEBUG,
                       'IsDebuggerPresent', 0.85, 'windows'),
    DetectionIndicator('NtQueryInformationProcess', DetectionCategory.ANTI_DEBUG,
                       'NtQueryInformationProcess', 0.90, 'windows'),
    DetectionIndicator('CheckRemoteDebuggerPresent', DetectionCategory.ANTI_DEBUG,
                       'CheckRemoteDebuggerPresent', 0.80, 'windows'),
    DetectionIndicator('NtSetInformationThread(HideFromDebugger)',
                       DetectionCategory.ANTI_DEBUG,
                       'NtSetInformationThread', 0.70, 'windows'),
    DetectionIndicator('OutputDebugString exploit',
                       DetectionCategory.ANTI_DEBUG,
                       'OutputDebugString', 0.40, 'windows'),
    # 反调试 — Linux
    DetectionIndicator('ptrace(PTRACE_TRACEME)', DetectionCategory.ANTI_DEBUG,
                       'ptrace', 0.85, 'linux'),
    DetectionIndicator('/proc/self/status', DetectionCategory.ANTI_DEBUG,
                       '/proc/self/status', 0.90, 'linux'),
    DetectionIndicator('prctl(PR_SET_DUMPABLE)', DetectionCategory.ANTI_DEBUG,
                       'prctl', 0.50, 'linux'),
    # 反虚拟机
    DetectionIndicator('CPUID hypervisor leaf', DetectionCategory.ANTI_VM,
                       'cpuid.*0x40000000|cpuid.*0x1', 0.95, 'all'),
    DetectionIndicator('RDTSC timing delta', DetectionCategory.ANTI_VM,
                       'rdtsc', 0.35, 'all'),
    DetectionIndicator('VMWare backdoor I/O', DetectionCategory.ANTI_VM,
                       '0x5658|VMXh|in.*0x5658', 0.90, 'all'),
    DetectionIndicator('VirtualBox Guest Additions', DetectionCategory.ANTI_VM,
                       'VBoxGuest|VBoxService|VirtualBox', 0.85, 'all'),
    DetectionIndicator('Red Pill (sidt/sgdt)', DetectionCategory.ANTI_VM,
                       'sidt|sgdt|sldt|str', 0.80, 'all'),
    # 反插桩
    DetectionIndicator('Frida detection (port check)',
                       DetectionCategory.ANTI_INSTRUMENT,
                       'frida|gum-js-loop|linjector', 0.90, 'all'),
    DetectionIndicator('Pin detection (pin/.dll)', DetectionCategory.ANTI_INSTRUMENT,
                       'pin\\.dll|pinbin|pin.*client', 0.85, 'all'),
    DetectionIndicator('/proc/self/maps inspection',
                       DetectionCategory.ANTI_INSTRUMENT,
                       '/proc/self/maps', 0.50, 'linux'),
    # 完整性检查
    DetectionIndicator('Code section CRC', DetectionCategory.INTEGRITY,
                       'crc32|adler32|checksum', 0.45, 'all'),
    DetectionIndicator('Import hook detection', DetectionCategory.INTEGRITY,
                       'GetProcAddress.*VirtualProtect|mprotect.*dlopen',
                       0.55, 'all'),
    DetectionIndicator('Hardware breakpoint check', DetectionCategory.INTEGRITY,
                       'GetThreadContext|DR0|DR7', 0.70, 'all'),
    # timing
    DetectionIndicator('timeGetTime delta', DetectionCategory.TIMING,
                       'timeGetTime|GetTickCount', 0.25, 'windows'),
    DetectionIndicator('clock_gettime delta', DetectionCategory.TIMING,
                       'clock_gettime', 0.25, 'linux'),
]


# --- 检测引擎 ---

class AntiAnalysisDetector:
    """多指标反分析技术检测器。

    在二进制中搜索反调试/反VM/反插桩/完整性检查的 API/字符串模式,
    按加权可靠性评分, 综合判定风险等级。"""

    __slots__ = ('_indicators',)

    def __init__(self):
        self._indicators = list(_INDICATOR_LIBRARY)

    def scan(self, binary_data: bytes,
             imports: list[str],
             strings: list[str],
             binary_name: str = '') -> AntiAnalysisReport:
        """扫描二进制文件中的反分析技术。"""
        report = AntiAnalysisReport(binary_name=binary_name)
        report.total_indicators = len(self._indicators)

        data_hex = binary_data.hex()
        data_str = binary_data.decode('ascii', errors='ignore').lower()
        all_imports = ' '.join(imports).lower()
        all_strings = ' '.join(strings).lower()

        for ind in self._indicators:
            detected = False
            pattern_lower = ind.pattern.lower()

            # 检测策略: imports 精确匹配 > strings 模糊匹配 > hex data
            if pattern_lower in all_imports:
                detected = True
            elif any(kw in all_strings for kw in pattern_lower.split('|')):
                detected = True
            elif _pattern_in_hex(pattern_lower, data_hex):
                detected = True

            if detected:
                report.detected.append(ind)

        # 计算加权风险分
        report.risk_score = self._compute_risk(report.detected)
        report.risk_level = self._classify_risk(report.risk_score)

        # 类别分布
        cats = {}
        for ind in report.detected:
            cats[ind.category.value] = cats.get(ind.category.value, 0) + 1
        report.category_breakdown = cats

        return report

    def _compute_risk(self, detected: list[DetectionIndicator]) -> float:
        """加权风险评分 [0, 100]。权重总和归一化。"""
        if not detected:
            return 0.0
        total_weight = sum(d.weight for d in detected)
        max_weight = sum(d.weight for d in self._indicators)
        # 基础分: 检测到的权重和 / 最大权重和
        base = total_weight / max(1e-9, max_weight)
        # 多样性奖励: 2+ 类别 → 1.2x, 3+ 类别 → 1.5x
        categories = set(d.category for d in detected)
        diversity_bonus = 1.0
        if len(categories) >= 3:
            diversity_bonus = 1.5
        elif len(categories) >= 2:
            diversity_bonus = 1.2
        return min(100.0, base * 100.0 * diversity_bonus)

    def _classify_risk(self, score: float) -> str:
        if score >= 80:
            return 'CRITICAL'
        if score >= 50:
            return 'HIGH'
        if score >= 25:
            return 'MEDIUM'
        if score >= 5:
            return 'LOW'
        return 'NONE'

    def stats(self) -> dict:
        return {'indicator_library_size': len(self._indicators)}


def _pattern_in_hex(pattern: str, hex_data: str) -> bool:
    """在 hex 数据中搜索模式——处理 | 分隔的多模式。"""
    import re
    for alt in pattern.split('|'):
        alt_hex = alt.encode().hex()
        if alt_hex in hex_data:
            return True
        # 正则模式保留原始形式
        if '0x' in alt:
            try:
                if re.search(alt, hex_data, re.IGNORECASE):
                    return True
            except re.error:
                pass
    return False


__all__ = [
    'AntiAnalysisDetector', 'AntiAnalysisReport',
    'DetectionIndicator', 'DetectionCategory',
]
