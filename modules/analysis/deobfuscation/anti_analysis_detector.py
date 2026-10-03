from __future__ import annotations

import re
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
    name: str
    category: DetectionCategory
    pattern: str
    weight: float = 0.5
    platform: str = 'all'


@dataclass
class AntiAnalysisReport:
    binary_name: str = ''
    total_indicators: int = 0
    detected: list[DetectionIndicator] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = 'NONE'
    category_breakdown: dict = field(default_factory=dict)


_INDICATOR_LIBRARY: list[DetectionIndicator] = [
    # 反调试 - Windows
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
    # 反调试 - Linux
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


class AntiAnalysisDetector:

    __slots__ = ('_indicators',)

    def __init__(self):
        self._indicators = list(_INDICATOR_LIBRARY)

    def scan(self, binary_data: bytes,
             imports: list[str],
             strings: list[str],
             binary_name: str = '') -> AntiAnalysisReport:
        report = AntiAnalysisReport(binary_name=binary_name)
        report.total_indicators = len(self._indicators)

        data_hex = binary_data.hex()
        data_str = binary_data.decode('ascii', errors='ignore').lower()
        all_imports = ' '.join(imports).lower()
        all_strings = ' '.join(strings).lower()

        for ind in self._indicators:
            detected = False
            pattern_lower = ind.pattern.lower()

            if pattern_lower in all_imports:
                detected = True
            elif any(kw in all_strings for kw in pattern_lower.split('|')):
                detected = True
            elif _pattern_in_hex(pattern_lower, data_hex):
                detected = True

            if detected:
                report.detected.append(ind)

        report.risk_score = self._compute_risk(report.detected)
        report.risk_level = self._classify_risk(report.risk_score)

        cats = {}
        for ind in report.detected:
            cats[ind.category.value] = cats.get(ind.category.value, 0) + 1
        report.category_breakdown = cats

        return report

    def _compute_risk(self, detected: list[DetectionIndicator]) -> float:
        if not detected:
            return 0.0
        total_weight = sum(d.weight for d in detected)
        max_weight = sum(d.weight for d in self._indicators)
        base = total_weight / max(1e-9, max_weight)
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
    for alt in pattern.split('|'):
        alt_hex = alt.encode().hex()
        if alt_hex in hex_data:
            return True
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
