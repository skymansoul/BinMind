"""
密码学失效模式与影响分析(Crypto-FMEA) — 系统化枚举二进制加密实现的潜在失效模式。

修改记录:
  2025-08-28 11:23 — 初始实现: 7类失效模式/严重度-可检测性-发生概率三维评分/RPN风险优先级

设计意图:
  传统FMEA (Failure Mode and Effects Analysis) 是工程可靠性分析的基石方法,
  已在汽车(ISO 26262)/医疗(FDA)/航空(DO-178C)等安全关键领域强制使用。
  但FMEA从未被系统化地应用于密码学实现的安全分析。

  本模块将FMEA方法论移植到二进制密码学审计:
    (a) 失效模式(Failure Mode): 密钥泄漏、认证绕过、随机数可预测等7大类。
    (b) 影响(Effect): 从"密钥完全暴露"到"时序信息微量泄漏"的严重度分级。
    (c) 原因(Cause): 从二进制指标(无清零/弱熵源/ECB模式)追溯到失效根因。
    (d) RPN (Risk Priority Number) = 严重度 × 发生概率 × 可检测性。

  与既有模块的差异: crypto_misuse检测具体误用模式, crypto_backdoor_analyzer
  检测故意弱化, 但都不提供系统化的"故障树"视角 — 什么可能出错, 影响是什么,
  如何排序修复优先级。

参考:
  - ISO 26262-3:2018 (汽车功能安全): FMEA方法论标准。
  - SAE J1739 (2021): FMEA实施指南。
  - NIST SP 800-53 Rev.5 (2020): SA-11(8)要求对关键系统做失效模式分析。
  - CWE (Common Weakness Enumeration): 映射到密码学相关CWE编号。

边界条件:
  - FMEA基于静态检测信号 — 运行时失效模式(如竞争条件)无法检测。
  - 发生概率和可检测性评分是启发式估计, 需专家根据实际部署环境校准。
  - 某些失效模式之间存在关联(如熵源弱→密钥可预测→加密失效) — 当前不建模因果链。
"""

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Tuple


class Severity(IntEnum):
    """失效影响的严重度 — 参考ISO 26262 ASIL分级。"""
    S10 = 10  # 密钥完全暴露 / 任意密文解密
    S8 = 8    # 认证绕过 / 签名伪造
    S6 = 6    # 密钥可预测 / 加密可逆
    S4 = 4    # 侧信道信息泄漏 / 部分密钥恢复
    S2 = 2    # 降级攻击可行 / 弱参数
    S1 = 1    # 信息性: 未来风险 / 标准不符合


class Occurrence(IntEnum):
    """失效发生概率 — 基于二进制审计信号的频率。"""
    O10 = 10  # 几乎确定: 硬编码密钥 / 无熵源
    O8 = 8    # 很高: 弱熵源(time/pid) / 已知弱算法(DES)
    O6 = 6    # 中等: 软件CSPRNG / 过渡期算法(RSA-2048)
    O4 = 4    # 较低: 硬件TRNG但无健康监测 / AES-128
    O2 = 2    # 很低: 硬件TRNG+健康监测 / 现代算法
    O1 = 1    # 极低: 最高安全级别实现


class Detection(IntEnum):
    """失效可检测性 — 静态分析可以多容易地发现此失效。"""
    D10 = 10  # 几乎不可能静态检测
    D8 = 8    # 极难: 需完整逆向+运行时验证
    D6 = 6    # 难: 需多信号组合推断
    D4 = 4    # 中等: 字符串+结构分析可检测
    D2 = 2    # 容易: 魔数匹配或字符串直接检测
    D1 = 1    # 极容易: 标准检测即可发现


@dataclass
class FailureMode:
    fm_id: str = ""
    category: str = ""            # KEY_MGMT / RNG / CIPHER / HASH / SIGNATURE / PROTOCOL / OTHER
    description: str = ""
    severity: Severity = Severity.S4
    occurrence: Occurrence = Occurrence.O6
    detection: Detection = Detection.D4
    rpn: int = 0                  # = severity × occurrence × detection
    cwe_id: str = ""              # 映射的CWE编号
    binary_indicators: List[str] = field(default_factory=list)
    recommended_mitigation: str = ""


# ── 密码学失效模式知识库 ──

def _build_failure_mode_kb() -> List[FailureMode]:
    """构建密码学实现的失效模式库。基于CWE和实际CVE统计。"""
    kb: List[FailureMode] = []

    # KEY_MGMT 类别
    kb.append(FailureMode('FM-KEY-01', 'KEY_MGMT',
        '硬编码/嵌入密钥 — 反向工程后可完全恢复密钥',
        Severity.S10, Occurrence.O8, Detection.D2,
        cwe_id='CWE-321/CWE-798',
        binary_indicators=['hardcoded_key', 'static_key_in_rodata',
                          'key_material_in_strings'],
        recommended_mitigation='使用KDF从外部密钥源派生或使用HSM/TPM'))
    kb.append(FailureMode('FM-KEY-02', 'KEY_MGMT',
        '密钥使用后未清零 — 残留在栈/堆/core dump中',
        Severity.S8, Occurrence.O10, Detection.D4,
        cwe_id='CWE-226/CWE-244',
        binary_indicators=['missing_explicit_bzero', 'no_secure_cleanup'],
        recommended_mitigation='在所有密钥路径添加explicit_bzero/SecureZeroMemory'))
    kb.append(FailureMode('FM-KEY-03', 'KEY_MGMT',
        '密钥导出函数(KDF)迭代次数不足 — 暴力破解可行',
        Severity.S6, Occurrence.O6, Detection.D8,
        cwe_id='CWE-916 (insufficient iteration count)',
        binary_indicators=['PBKDF2_iter_lt_100000', 'bcrypt_cost_lt_10'],
        recommended_mitigation='PBKDF2≥600000轮; bcrypt≥12; Argon2id t≥3'))

    # RNG 类别
    kb.append(FailureMode('FM-RNG-01', 'RNG',
        '使用非密码学随机源 — 输出可被预测',
        Severity.S10, Occurrence.O8, Detection.D2,
        cwe_id='CWE-338',
        binary_indicators=['weak_rng', 'time_based_seed', 'rand()', 'srand()'],
        recommended_mitigation='替换为getrandom(2)/RDRAND/libsodium randombytes'))
    kb.append(FailureMode('FM-RNG-02', 'RNG',
        '缺少熵源健康监测 — 熵源故障时静默降级',
        Severity.S8, Occurrence.O6, Detection.D8,
        cwe_id='CWE-1240',
        binary_indicators=['missing_health_tests', 'no_continuous_rng_test'],
        recommended_mitigation='实现NIST SP 800-90B健康测试(重复计数/自适应比例)'))

    # CIPHER 类别
    kb.append(FailureMode('FM-CIPHER-01', 'CIPHER',
        'ECB模式使用 — 明文模式泄漏',
        Severity.S6, Occurrence.O8, Detection.D2,
        cwe_id='CWE-327 (broken algorithm)',
        binary_indicators=['ECB_block_repetition', 'ECB_mode_string'],
        recommended_mitigation='迁移到GCM/CCM/ChaCha20-Poly1305 AEAD'))
    kb.append(FailureMode('FM-CIPHER-02', 'CIPHER',
        'IV/Nonce复用 — 密钥流恢复攻击',
        Severity.S10, Occurrence.O6, Detection.D8,
        cwe_id='CWE-329 (nonce reuse)',
        binary_indicators=['static_iv', 'constant_nonce', 'zero_iv'],
        recommended_mitigation='每次加密生成随机IV; 使用96-bit随机nonce(GCM)'))

    # HASH 类别
    kb.append(FailureMode('FM-HASH-01', 'HASH',
        '弱哈希用于安全目的 — 碰撞攻击可行',
        Severity.S6, Occurrence.O6, Detection.D2,
        cwe_id='CWE-328 (weak hash)',
        binary_indicators=['MD5_detection', 'SHA1_detection'],
        recommended_mitigation='替换为SHA-384/SHA-512或BLAKE2b'))

    # SIGNATURE 类别
    kb.append(FailureMode('FM-SIG-01', 'SIGNATURE',
        '签名验证不完整 — 认证绕过',
        Severity.S10, Occurrence.O4, Detection.D10,
        cwe_id='CWE-347 (improper verification)',
        binary_indicators=['missing_signature_check', 'truncated_hash_verify'],
        recommended_mitigation='验证返回码; 检查所有验证步骤; 使用固定时间比较'))

    # PROTOCOL 类别
    kb.append(FailureMode('FM-PROTO-01', 'PROTOCOL',
        '协议版本协商可降级 — 中间人降级攻击',
        Severity.S8, Occurrence.O8, Detection.D6,
        cwe_id='CWE-757',
        binary_indicators=['downgrade_path', 'fallback_to_weak'],
        recommended_mitigation='禁用弱协议版本; 实现降级保护(TLS 1.3)'))

    return kb


# ── FMEA分析器 ──

class CryptoFMEA:
    """密码学FMEA — 评估失效模式在当前二进制中的适用性和风险。"""

    def __init__(self):
        self._kb = _build_failure_mode_kb()

    def analyze(self,
                crypto_findings: Optional[List] = None,
                misuse_findings: Optional[List] = None,
                entropy_reports: Optional[List] = None,
                key_lifecycle_reports: Optional[List] = None) -> List[FailureMode]:
        """
        评估所有已知失效模式在当前二进制中的适用性。
        基于检测到的信号调整发生概率和可检测性。
        """
        results: List[FailureMode] = []
        findings = crypto_findings or []

        # 收集二进制指标
        indicators = set()
        for f in findings:
            try:
                algo = getattr(f, 'algorithm', '')
                if 'DES' in algo or 'MD5' in algo or 'SHA-1' in algo:
                    indicators.add('weak_algorithm')
                if 'ECB' in algo or 'CBC' in algo:
                    indicators.add('ECB_mode_string' if 'ECB' in algo else 'CBC_mode')
            except Exception:
                pass

        for mf in misuse_findings or []:
            try:
                mtype = getattr(mf, 'misuse_type', '')
                if 'HARDCODED' in mtype or 'CONSTANT' in mtype:
                    indicators.add('hardcoded_key')
                if 'WEAK_IV' in mtype or 'STATIC' in mtype:
                    indicators.add('static_iv')
            except Exception:
                pass

        for er in entropy_reports or []:
            try:
                if getattr(er, 'grade', None):
                    grade_name = er.grade.name
                    if grade_name in ('LOW', 'CRITICAL'):
                        indicators.add('weak_rng')
                if getattr(er, 'source_name', '') in ('time(NULL)', 'rand()', 'getpid()'):
                    indicators.add('time_based_seed')
                if not getattr(er, 'has_health_check', True):
                    indicators.add('missing_health_tests')
            except Exception:
                pass

        for kl in key_lifecycle_reports or []:
            try:
                if not getattr(kl, 'is_zeroized', True):
                    indicators.add('missing_explicit_bzero')
            except Exception:
                pass

        # 评估每个失效模式的RPN
        for fm in self._kb:
            matched = set(fm.binary_indicators) & indicators
            occ = fm.occurrence
            det = fm.detection

            if matched:
                # 信号匹配 → 失效概率更高, 更容易检测
                occ = Occurrence(min(10, occ.value + 2))
                det = Detection(max(1, det.value - 1))

            rpn = fm.severity.value * occ.value * det.value
            fm.occurrence = occ
            fm.detection = det
            fm.rpn = rpn
            results.append(fm)

        results.sort(key=lambda f: -f.rpn)
        return results

    @staticmethod
    def top_risks(fmea_results: List[FailureMode], top_n: int = 5) -> List[FailureMode]:
        """返回RPN最高的N个失效模式。"""
        return sorted(fmea_results, key=lambda f: -f.rpn)[:top_n]
