"""
密码学熵源审计 — 识别二进制中使用的随机数生成机制并评估其密码学质量。

设计意图:
  密码学安全性最终归结为密钥的不可预测性 — 而密钥的不可预测性取决于熵源质量。
  一个完美的AES-256实现, 若用time()做种子, 其安全性降至零。
  既有rng_tester统计检验RNG输出, entropy_analyzer区分密钥/压缩/加密数据,
  但两者都不回答"此二进制如何获取随机数"这一根本问题。

  本模块从静态二进制分析识别和审计熵源:
    1. 硬件熵源: RDRAND/RDSEED(x86), ARM TRNG, TPM/HSM随机数。
    2. 内核熵源: /dev/random, /dev/urandom, getrandom()系统调用。
    3. 软件熵源: jitterentropy, haveged, OpenSSL PRNG。
    4. 弱熵源: time(NULL), getpid(), rand(), 硬编码种子。
    5. 熵源组合: 多源混合策略(如RDRAND⊕/dev/urandom⊕计数器)。

  质量分级基于NIST SP 800-90B和BSI AIS-31标准。

  - NIST SP 800-90B: 熵源评估标准 — 独立同分布检验/健康测试/熵估计。
  - BSI AIS-31: 物理随机数生成器评估标准 — PTG.2/PTG.3功能等级。
  - Kicksecure Dev/Entropy: Linux内核熵源信任模型 — RDRAND争议和urandom启动问题。

边界条件:
  - 静态熵源分析无法评估运行时的熵质量(无实际输出可统计检验)。
  - 多熵源混合策略的识别受限于字符串匹配 — 自定义混合算法可能漏检。
  - 熵源审计标记的是"设计级别"的强度, 而非运行时的实际熵。
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

class EntropyGrade(Enum):
    HIGH = 0       # 硬件TRNG或内核CSPRNG(≥128-bit熵)
    MEDIUM = 1     # 软件CSPRNG或内核urandom(有启动期弱熵风险)
    LOW = 2        # 弱种子(pid/time)经哈希 → 可预测空间有限
    CRITICAL = 3   # 无熵源/硬编码种子 → 密钥可被完全预测

@dataclass
class EntropySourceReport:
    source_type: str = ""           # HARDWARE / KERNEL / SOFTWARE / WEAK / NONE
    source_name: str = ""           # RDRAND / getrandom / OpenSSL / time() ...
    grade: EntropyGrade = EntropyGrade.CRITICAL
    confidence: float = 0.0
    evidence: str = ""
    location: int = 0
    has_health_check: bool = False   # 是否有熵源健康监测(如FIPS 140-2连续测试)
    has_debiasing: bool = False      # 是否有去偏处理(如Von Neumann矫正)
    flags: List[str] = field(default_factory=list)

# 熵源分类规则
# 每条规则: (字节模式, 类型, 名称, 等级, 权重)
_ENTROPY_PATTERNS: List[Tuple[bytes, str, str, EntropyGrade, float]] = [
    # 硬件熵源 — 最高质量
    (b'RDRAND', 'HARDWARE', 'RDRAND', EntropyGrade.HIGH, 0.95),
    (b'RDSEED', 'HARDWARE', 'RDSEED', EntropyGrade.HIGH, 0.95),
    (b'_rdrand', 'HARDWARE', 'RDRAND (intrinsic)', EntropyGrade.HIGH, 0.92),
    (b'_rdseed', 'HARDWARE', 'RDSEED (intrinsic)', EntropyGrade.HIGH, 0.92),
    (b'TRNG', 'HARDWARE', 'TRNG peripheral', EntropyGrade.HIGH, 0.78),
    (b'trng_', 'HARDWARE', 'TRNG', EntropyGrade.HIGH, 0.75),
    # 内核CSPRNG — 高质量
    (b'getrandom', 'KERNEL', 'getrandom(2)', EntropyGrade.HIGH, 0.90),
    (b'getentropy', 'KERNEL', 'getentropy(2)', EntropyGrade.HIGH, 0.90),
    (b'/dev/random', 'KERNEL', '/dev/random', EntropyGrade.HIGH, 0.85),
    (b'/dev/urandom', 'KERNEL', '/dev/urandom', EntropyGrade.MEDIUM, 0.85),
    (b'CryptGenRandom', 'KERNEL', 'Windows CSPRNG', EntropyGrade.HIGH, 0.88),
    (b'BCryptGenRandom', 'KERNEL', 'Windows BCryptGenRandom', EntropyGrade.HIGH, 0.92),
    # 软件CSPRNG — 中高质量
    (b'RAND_bytes', 'SOFTWARE', 'OpenSSL RAND', EntropyGrade.MEDIUM, 0.82),
    (b'RAND_priv_bytes', 'SOFTWARE', 'OpenSSL RAND (private)', EntropyGrade.HIGH, 0.85),
    (b'arc4random', 'SOFTWARE', 'arc4random', EntropyGrade.MEDIUM, 0.80),
    (b'randombytes_', 'SOFTWARE', 'libsodium randombytes', EntropyGrade.HIGH, 0.85),
    (b'jitterentropy', 'SOFTWARE', 'jitterentropy', EntropyGrade.MEDIUM, 0.78),
    # 弱熵源 — 密码学不充分
    (b'time(NULL)', 'WEAK', 'time(NULL)', EntropyGrade.CRITICAL, 0.95),
    (b'gettimeofday', 'WEAK', 'gettimeofday()', EntropyGrade.CRITICAL, 0.90),
    (b'getpid()', 'WEAK', 'getpid()', EntropyGrade.CRITICAL, 0.92),
    (b'rand()', 'WEAK', 'libc rand()', EntropyGrade.CRITICAL, 0.95),
    (b'srand(', 'WEAK', 'srand() with seed', EntropyGrade.CRITICAL, 0.90),
    (b'random(', 'WEAK', 'libc random()', EntropyGrade.LOW, 0.88),
    # 种子相关
    (b'seed=', 'WEAK', 'hardcoded seed assignment', EntropyGrade.CRITICAL, 0.80),
    (b'SEED', 'WEAK', 'seed constant', EntropyGrade.LOW, 0.60),
    (b'0xDEAD', 'WEAK', 'magic debug seed', EntropyGrade.CRITICAL, 0.85),
    (b'0xDEADBEEF', 'WEAK', 'magic debug seed', EntropyGrade.CRITICAL, 0.92),
]

# 健康监测检测
_HEALTH_CHECK_PATTERNS: List[bytes] = [
    b'FIPS_continuous_test', b'continuous_random', b'health_test',
    b'stuck_test', b'adaptive_proportion', b'repetition_count',
    b'entropy_health', b'drbg_health', b'df_health',
]

# 去偏处理检测
_DEBIASING_PATTERNS: List[bytes] = [
    b'von_neumann', b'debiasing', b'whitening', b'extractor',
    b'HKDF_extract', b'SHA256_', b'blake2b_', b'conditioning',
    b'hash_df', b'block cipher df',
]

def audit_entropy_sources(data: bytes, strings: Optional[List[str]] = None
                          ) -> List[EntropySourceReport]:
    reports: List[EntropySourceReport] = []

    # 检测熵源类型
    seen_sources: Dict[str, EntropySourceReport] = {}
    for pat, stype, sname, grade, conf in _ENTROPY_PATTERNS:
        positions = []
        pos = 0
        while True:
            pos = data.find(pat, pos)
            if pos == -1:
                break
            positions.append(pos)
            pos += len(pat)

        if positions:
            key = f"{stype}:{sname}"
            if key in seen_sources:
                seen_sources[key].confidence = max(seen_sources[key].confidence, conf)
                # 更新为最严重等级
                if grade.value > seen_sources[key].grade.value:
                    seen_sources[key].grade = grade
            else:
                seen_sources[key] = EntropySourceReport(
                    source_type=stype, source_name=sname,
                    grade=grade, confidence=conf,
                    evidence=f'found at {len(positions)} location(s)',
                    location=positions[0])

    # 从字符串列表补充
    if strings:
        for s in strings:
            sb = s.encode('ascii', errors='replace') if isinstance(s, str) else s
            for pat, stype, sname, grade, conf in _ENTROPY_PATTERNS:
                if pat in sb:
                    key = f"{stype}:{sname}"
                    if key not in seen_sources:
                        seen_sources[key] = EntropySourceReport(
                            source_type=stype, source_name=sname,
                            grade=grade, confidence=conf * 0.85,
                            evidence=f'string: "{s[:50]}"',
                            location=0)

    # 检测健康监测
    has_health = any(pat in data for pat in _HEALTH_CHECK_PATTERNS)
    has_debias = any(pat in data for pat in _DEBIASING_PATTERNS)

    # 组装最终报告
    for key, report in seen_sources.items():
        report.has_health_check = has_health and report.source_type in ('HARDWARE', 'KERNEL')
        report.has_debiasing = has_debias

        if report.grade == EntropyGrade.CRITICAL:
            report.flags.append('CRITICAL: 密钥可预测 — 熵源不适用于密码学用途')
        elif report.grade == EntropyGrade.LOW:
            report.flags.append('LOW: 弱熵源 — 仅适用于非安全关键的随机数')
        if report.source_type == 'WEAK' and not has_debias:
            report.flags.append('缺少去偏/白化处理 — 原始弱熵源直接用于密码学')
        if not has_health:
            report.flags.append('未检测到熵源健康监测 — 可能无法检测熵源失效')

        reports.append(report)

    # 按严重度排序(最差的在前)
    reports.sort(key=lambda r: (-r.grade.value, -r.confidence))
    return reports

def classify_overall_entropy_quality(reports: List[EntropySourceReport]) -> Tuple[EntropyGrade, str]:
    """
    基于检测到的所有熵源综合评定整体质量。
    策略: 取最佳熵源的等级作为可信上限, 但若同时存在弱源→降一级(混合退化风险)。
    """
    if not reports:
        return EntropyGrade.CRITICAL, '未检测到任何熵源 — 假定无随机数生成'

    best_grade = min(r.grade.value for r in reports)  # 最小枚举值=最好
    worst_grade = max(r.grade.value for r in reports)

    # 存在WEAK源 → 降级(即使用强源混合, 弱源可能被误用为唯一源)
    adjusted = best_grade
    if worst_grade >= EntropyGrade.LOW.value and len(reports) >= 2:
        adjusted = min(adjusted + 1, EntropyGrade.CRITICAL.value)

    final_grade = EntropyGrade(adjusted)
    desc = {
        EntropyGrade.HIGH: '强熵源(HW TRNG或内核CSPRNG) — 密码学密钥生成级别',
        EntropyGrade.MEDIUM: '中等熵源(软件CSPRNG或urandom) — 一般密码学用途可接受',
        EntropyGrade.LOW: '弱熵源 — 建议替换为getrandom()或硬件TRNG',
        EntropyGrade.CRITICAL: '无可靠熵源或使用可预测种子 — 密钥不安全',
    }

    return final_grade, desc.get(final_grade, '')
