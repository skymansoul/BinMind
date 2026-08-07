# 修改记录:
# 2025-09-14 15:33 — 初始实现：补丁中随机值的熵质量评估
# 2025-09-15 08:47 — 增加 NIST SP 800-22 简化测试套件

"""Patch Entropy Quality Analyzer — 补丁中随机值的密码学质量检测。

搜索结果显示栈 canary 和 ASLR 的弱点广为人知（null byte 前缀、
fork 继承、低熵），但无自动化工具检查补丁中使用的随机值的熵质量。

本模块自动检测补丁中随机值的密码学弱点：
  1. Canary 质量：是否使用弱随机源（如 rand() 而非 /dev/urandom）
  2. 常量随机值：补丁中的立即数是否有可预测的模式
  3. 熵源识别：从汇编模式推断随机值来源
  4. NIST 简化测试：对 canary 字节序列做频率/游程/块内频次检验

检测规则（基于汇编模式）：
  - call rand → 弱随机（libc rand() 仅有 31-bit 状态）
  - rdtsc → 中等（时间戳可被攻击者估算）
  - rdrand → 强随机（Intel 硬件随机数）
  - fs:0x28 → 标准栈 canary（内核提供，强随机）
  - 无可见随机源 → 标记为"未知熵源"
"""

import re
import math
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from collections import Counter

_log = logging.getLogger(__name__)


class EntropySource(str):
    WEAK = "weak"           # rand(), random(), 时间戳
    MEDIUM = "medium"       # rdtsc, getpid()
    STRONG = "strong"       # rdrand, /dev/urandom, fs:0x28
    UNKNOWN = "unknown"


@dataclass
class EntropyFinding:
    """单条熵质量发现。"""
    location: str = ""               # 代码位置描述
    source: str = EntropySource.UNKNOWN
    description: str = ""
    # 熵估计
    estimated_entropy_bits: int = 0
    recommended_entropy_bits: int = 64
    is_adequate: bool = False


@dataclass
class EntropyReport:
    """补丁熵质量报告。"""
    patch_id: str = ""
    findings: List[EntropyFinding] = field(default_factory=list)
    # 统计
    weak_sources: int = 0
    adequate_sources: int = 0
    # 综合
    overall_entropy_adequate: bool = True
    recommendation: str = ""

    def to_dict(self) -> Dict:
        return {
            'patch_id': self.patch_id,
            'weak_sources': self.weak_sources,
            'adequate': self.adequate_sources,
            'overall_ok': self.overall_entropy_adequate,
            'findings': [
                {'loc': f.location, 'source': f.source,
                 'entropy_bits': f.estimated_entropy_bits, 'ok': f.is_adequate}
                for f in self.findings[:8]
            ],
            'recommendation': self.recommendation,
        }


# 熵源识别

class EntropySourceIdentifier:
    """从汇编模式推断随机值来源。"""

    # (模式, 源类型, 估计熵位数, 描述)
    _SOURCE_PATTERNS = [
        (re.compile(r'\bcall\s+rand\b', re.I), EntropySource.WEAK, 31,
         "libc rand() — 31-bit LCG，可预测"),
        (re.compile(r'\bcall\s+random\b', re.I), EntropySource.WEAK, 31,
         "libc random() — 31-bit 状态"),
        (re.compile(r'\bcall\s+srand\b', re.I), EntropySource.WEAK, 31,
         "srand() — 显式种子，可能为常量"),
        (re.compile(r'\brdtsc\b', re.I), EntropySource.MEDIUM, 40,
         "RDTSC 时间戳 — 可被攻击者估算范围"),
        (re.compile(r'\bcall\s+time\b', re.I), EntropySource.MEDIUM, 32,
         "time() — 秒级精度，可预测"),
        (re.compile(r'\bcall\s+getpid\b', re.I), EntropySource.MEDIUM, 15,
         "getpid() — PID 空间有限 (≤32768)"),
        (re.compile(r'\brdrand\b', re.I), EntropySource.STRONG, 64,
         "RDRAND — Intel 硬件随机数"),
        (re.compile(r'\brdseed\b', re.I), EntropySource.STRONG, 64,
         "RDSEED — Intel 硬件熵源"),
        (re.compile(r'fs:0x28|gs:0x28|fs:0x14', re.I), EntropySource.STRONG, 56,
         "线程局部 canary — 内核提供 (56 effective bits after null byte)"),
        (re.compile(r'\bcall\s+getrandom\b', re.I), EntropySource.STRONG, 128,
         "getrandom() — 内核 CSPRNG"),
        (re.compile(r'\/dev\/urandom|RAND_bytes|RAND_priv_bytes', re.I),
         EntropySource.STRONG, 128, "OpenSSL/内核 CSPRNG"),
    ]

    def identify(self, asm_lines: List[str]) -> List[EntropyFinding]:
        """识别汇编中的所有随机源。"""
        findings = []
        for line in asm_lines:
            stripped = line.strip()
            for pattern, source, bits, desc in self._SOURCE_PATTERNS:
                if pattern.search(stripped):
                    findings.append(EntropyFinding(
                        location=stripped[:60],
                        source=source,
                        description=desc,
                        estimated_entropy_bits=bits,
                        is_adequate=(bits >= 56 and source == EntropySource.STRONG),
                    ))
                    break  # 一行只匹配第一个模式
        return findings


# NIST 简化测试

class NISTSimplifiedTests:
    """NIST SP 800-22 的简化实现（频率/游程/块内频次）。

    对补丁中提取的随机字节序列执行基本随机性检验。
    不替代完整的 NIST 套件——作为第一道快速筛选。
    """

    def test_sequence(self, data: bytes) -> Dict[str, Tuple[float, bool]]:
        """对字节序列做简化检验。返回 {(test_name, (p_value, passed))}。"""
        results = {}
        if len(data) < 8:
            return results

        # 1. 频率检验 (Frequency / Monobit)
        results['frequency'] = self._frequency_test(data)

        # 2. 游程检验 (Runs)
        results['runs'] = self._runs_test(data)

        # 3. 块内频次 (Block Frequency, block_size=8)
        results['block_freq'] = self._block_frequency_test(data)

        return results

    def _frequency_test(self, data: bytes) -> Tuple[float, bool]:
        """单比特频率检验。"""
        bits = self._to_bits(data)
        n = len(bits)
        if n == 0:
            return 0.0, False
        s = sum(1 if b == '1' else -1 for b in bits)
        s_obs = abs(s) / math.sqrt(n)
        p = math.erfc(s_obs / math.sqrt(2))
        return p, p >= 0.01

    def _runs_test(self, data: bytes) -> Tuple[float, bool]:
        """游程检验。"""
        bits = self._to_bits(data)
        n = len(bits)
        if n == 0:
            return 0.0, False
        ones = sum(1 for b in bits if b == '1')
        pi = ones / n
        if abs(pi - 0.5) >= 2.0 / math.sqrt(n):
            return 0.0, False  # 前提条件不满足
        runs = 1
        for i in range(1, n):
            if bits[i] != bits[i-1]:
                runs += 1
        num = abs(runs - 2 * n * pi * (1 - pi))
        den = 2 * math.sqrt(2 * n) * pi * (1 - pi)
        p = math.erfc(num / den) if den > 0 else 0.0
        return p, p >= 0.01

    def _block_frequency_test(self, data: bytes) -> Tuple[float, bool]:
        """块内频次检验。"""
        bits = self._to_bits(data)
        n = len(bits)
        M = max(n // 8, 4)
        N = n // M
        if N == 0:
            return 0.0, False
        chi_sq = 0.0
        for i in range(N):
            block = bits[i*M:(i+1)*M]
            ones = sum(1 for b in block if b == '1')
            pi_i = ones / M
            chi_sq += (pi_i - 0.5) ** 2
        chi_sq *= 4 * M
        # 不完全 gamma 函数的简化近似
        p = math.exp(-chi_sq / 2.0) if chi_sq < 20 else 0.0
        return max(0.0, min(1.0, p)), p >= 0.01

    @staticmethod
    def _to_bits(data: bytes) -> str:
        return ''.join(format(b, '08b') for b in data)


# 分析器

class EntropyQualityAnalyzer:
    """补丁熵质量分析器。"""

    def __init__(self):
        self._identifier = EntropySourceIdentifier()
        self._nist = NISTSimplifiedTests()

    def analyze(self, patched_asm: List[str],
                canary_bytes: bytes = b"",
                patch_id: str = "") -> EntropyReport:
        """分析补丁的熵质量。"""
        report = EntropyReport(patch_id=patch_id)
        findings = self._identifier.identify(patched_asm)
        report.findings = findings

        report.weak_sources = sum(1 for f in findings
                                  if f.source == EntropySource.WEAK)
        report.adequate_sources = sum(1 for f in findings if f.is_adequate)

        # 若提供了 canary 字节，做 NIST 检验
        if canary_bytes and len(canary_bytes) >= 8:
            nist_results = self._nist.test_sequence(canary_bytes)
            passed = sum(1 for _, ok in nist_results.values() if ok)
            total = len(nist_results)
            if passed < total:
                report.findings.append(EntropyFinding(
                    location="canary_bytes",
                    source=EntropySource.WEAK,
                    description="NIST 检验: %d/%d 通过——canary 值可能非随机" % (passed, total),
                    estimated_entropy_bits=passed * 20,
                    is_adequate=False))

        # 综合判定
        report.weak_sources = sum(1 for f in findings
                                  if f.source == EntropySource.WEAK)
        report.overall_entropy_adequate = (
            report.weak_sources == 0 and
            all(f.is_adequate for f in findings))

        if not report.overall_entropy_adequate:
            report.recommendation = "补丁使用了弱随机源——canary/ASLR 保护可能被绕过"
        else:
            report.recommendation = "补丁的随机值熵质量充分"

        return report
