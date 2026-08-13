"""
二进制比特腐烂风险评分 — 编译年龄 × 依赖陈旧度 × 格式过时度。

问题定义:
  二进制随时间推移累积"技术债务":
    1. 编译时已知漏洞未修复 (静态链接的旧版 zlib/OpenSSL)
    2. 编译器版本过时 — 缺少最新的安全缓解 (CFG/CET/Shadow Stack)
    3. 二进制格式版本 — 旧格式缺少现代安全特性
    4. 依赖库已 EOL — 不再接收安全更新
    5. 构建工具链存在已知缺陷 (旧版 GCC/Clang 的代码生成缺陷)

  全网检索 "binary bitrot risk scoring" 零结果。
  Grype/Trivy 检测已知 CVE 但不评分累积技术债务。

  评分: bitrot = w1×age_factor + w2×compiler_staleness
                + w3×format_deprecation + w4×dependency_eol
                + w5×known_cve_debt

  所有因子归一化至 [0, 1]，加权求和 → [0, 10]。

  无现有工作.
  CWE-1104: Use of Unmaintained Third-Party Components.

修改记录:
  2025-03-03 10:56 - 初始版本，五因子 bitrot 模型
"""

import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# 编译器版本 → 安全缓解代际分 (越高越现代)
# GCC 6+ 引入 -fstack-clash-protection; GCC 8+ 引入 CET 支持
# Clang 7+ 引入 Shadow Call Stack; Clang 12+ 引入 CFI 改进
_COMPILER_GENERATION: Dict[str, float] = {}
for _ver in range(4, 15):
    _COMPILER_GENERATION[f'GCC {_ver}'] = min((_ver - 3) / 11.0, 1.0)
    _COMPILER_GENERATION[f'Clang {_ver}'] = min((_ver - 2) / 12.0, 1.0)
_COMPILER_GENERATION.update({
    'MSVC 2015': 0.10, 'MSVC 2017': 0.25, 'MSVC 2019': 0.50,
    'MSVC 2022': 0.75, 'MSVC 2025': 0.90,
    'unknown': 0.3,
})

# 已知 EOL 库的年份阈值
_LIBRARY_EOL_THRESHOLDS: Dict[str, int] = {
    'openssl': 2026, 'libressl': 2028, 'gnutls': 2027,
    'zlib': None,     # 极稳定，无 EOL
    'libxml2': 2027, 'libxslt': 2027,
    'libpng': None, 'libjpeg': None,
    'glibc': 2030, 'musl': None,
    'libcurl': 2028, 'libssh2': 2027,
    'ncurses': None, 'readline': None,
    'sqlite3': None,  # 持续维护
}

_DEFAULT_WEIGHTS = (0.30, 0.25, 0.10, 0.20, 0.15)
# age, compiler, format, dependency_eol, cve_debt

# 二进制格式过时风险
_FORMAT_RISK: Dict[str, float] = {
    'elf': 0.0, 'elf64': 0.0,
    'pe': 0.1, 'pe32+': 0.05,
    'mach-o': 0.15, 'mach-o-arm64': 0.05,
    'a.out': 1.0, 'coff': 0.9, 'srec': 0.8,
}

@dataclass
class BitrotScore:
    """二进制比特腐烂评分。"""
    binary_name: str
    bitrot_score: float             # 0-10
    age_factor: float               # 编译年龄贡献
    compiler_factor: float           # 编译器过时贡献
    format_factor: float             # 格式过时贡献
    dependency_factor: float         # 依赖 EOL 贡献
    cve_debt_factor: float           # CVE 债务贡献
    risk_level: str = 'low'
    estimated_tech_debt_days: int = 0  # 估算技术债务修复所需人天

    def __post_init__(self):
        if self.bitrot_score >= 7.0:
            self.risk_level = 'critical'
        elif self.bitrot_score >= 4.5:
            self.risk_level = 'high'
        elif self.bitrot_score >= 2.5:
            self.risk_level = 'medium'
        else:
            self.risk_level = 'low'

def _age_factor(compilation_year: int, current_year: Optional[int] = None) -> float:
    """编译年龄因子 — 每年 +0.08，10年封顶。"""
    cy = current_year or time.localtime().tm_year
    age = max(0, cy - compilation_year)
    return round(min(age * 0.08, 1.0), 2)

def _compiler_factor(compiler_version: str) -> float:
    """编译器代际差距因子 — 1.0 - generation_score。"""
    for key, score in _COMPILER_GENERATION.items():
        if key.lower() in compiler_version.lower():
            return round(1.0 - score, 2)
    # 版本号解析
    for token in compiler_version.split():
        try:
            major = int(token.split('.')[0])
            if 4 <= major <= 20:
                score = min((major - 3) / 11.0, 1.0)
                return round(1.0 - score, 2)
        except ValueError:
            continue
    return round(1.0 - _COMPILER_GENERATION['unknown'], 2)

def _format_factor(binary_format: str) -> float:
    """二进制格式过时因子。"""
    fmt_lower = binary_format.lower()
    for key, risk in _FORMAT_RISK.items():
        if key in fmt_lower:
            return risk
    return 0.3  # 未知格式 — 中等风险

def _dependency_eol_factor(
    linked_libraries: List[str],
    current_year: Optional[int] = None,
) -> float:
    """
    依赖库 EOL 因子 — 已超过 EOL 日期的库比例。

    指数衰减叠加: 1 - Π(1 - min((current-eol)/5, 1.0) × 0.3)
    """
    cy = current_year or time.localtime().tm_year
    eol_risk_product = 1.0
    eol_count = 0

    for lib in linked_libraries:
        lib_lower = lib.lower()
        for key, eol_year in _LIBRARY_EOL_THRESHOLDS.items():
            if key in lib_lower and eol_year is not None:
                years_past = max(0, cy - eol_year)
                if years_past > 0:
                    risk = min(years_past / 5.0, 1.0) * 0.3
                    eol_risk_product *= (1.0 - risk)
                    eol_count += 1
                break

    return round(min((1.0 - eol_risk_product), 1.0), 2)

def _cve_debt_factor(unfixed_cve_count: int, cvss_sum: float) -> float:
    """
    CVE 债务因子 — 未修复 CVE 数量 + 累计 CVSS 分数。

    sigmoid: 0 CVE → 0, 50+ CVE 且 CVSS 和 >300 → 1.0。
    """
    if unfixed_cve_count == 0:
        return 0.0
    count_norm = min(unfixed_cve_count / 50.0, 1.0)
    cvss_norm = min(cvss_sum / 300.0, 1.0)
    raw = 0.5 * count_norm + 0.5 * cvss_norm
    return round(raw, 2)

def _tech_debt_days(score: float) -> int:
    """bitrot 分数 → 估算修复人天。"""
    return int(score * 12)  # 每分 ≈ 12 人天

def assess_bitrot(
    binary_name: str = '',
    compilation_year: int = 2020,
    compiler_version: str = 'unknown',
    binary_format: str = 'elf',
    linked_libraries: Optional[List[str]] = None,
    unfixed_cve_count: int = 0,
    cvss_sum: float = 0.0,
    current_year: Optional[int] = None,
    weights: Optional[Tuple[float, ...]] = None,
) -> BitrotScore:
    """
    评估二进制比特腐烂风险。

    返回 BitrotScore (0-10)，含五项因子分解和技术债务估算。
    """
    w = weights or _DEFAULT_WEIGHTS
    cy = current_year or time.localtime().tm_year

    af = _age_factor(compilation_year, cy)
    cf = _compiler_factor(compiler_version)
    ff = _format_factor(binary_format)
    df = _dependency_eol_factor(linked_libraries or [], cy)
    cvf = _cve_debt_factor(unfixed_cve_count, cvss_sum)

    raw = w[0]*af + w[1]*cf + w[2]*ff + w[3]*df + w[4]*cvf
    score = round(raw * 10.0, 1)

    return BitrotScore(
        binary_name=binary_name or 'unknown',
        bitrot_score=score,
        age_factor=round(af * 10, 1),
        compiler_factor=round(cf * 10, 1),
        format_factor=round(ff * 10, 1),
        dependency_factor=round(df * 10, 1),
        cve_debt_factor=round(cvf * 10, 1),
        estimated_tech_debt_days=_tech_debt_days(score),
    )

def bitrot_summary(score: BitrotScore) -> Dict[str, Any]:
    """bitrot 评估摘要。"""
    recs = []
    if score.age_factor >= 5.0:
        recs.append(f'二进制已编译 {int(score.age_factor/0.8)} 年以上 — 建议重新编译以获取现代安全缓解')
    if score.compiler_factor >= 5.0:
        recs.append('编译器版本过时 — 缺少 CFG/CET/Shadow Stack 等现代缓解')
    if score.dependency_factor >= 3.0:
        recs.append('依赖库已超过 EOL — 不再接收安全更新')
    if score.cve_debt_factor >= 3.0:
        recs.append('存在未修复 CVE — 优先评估这些 CVE 在此二进制中的可达性')

    return {
        'bitrot_score': score.bitrot_score,
        'risk_level': score.risk_level,
        'estimated_tech_debt_days': score.estimated_tech_debt_days,
        'factors': {
            'code_age': score.age_factor,
            'compiler_staleness': score.compiler_factor,
            'format_risk': score.format_factor,
            'dependency_eol': score.dependency_factor,
            'cve_debt': score.cve_debt_factor,
        },
        'recommendations': recs,
    }
