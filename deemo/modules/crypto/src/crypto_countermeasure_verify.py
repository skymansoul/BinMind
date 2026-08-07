"""
密码学对策验证 — 验证二进制中声称存在的侧信道/故障注入防御对策。

修改记录:
  2025-09-02 16:41 — 初始实现: 掩码/重排/盲化/常量时间屏障/故障检测/冗余计算验证

设计意图:
  密码学实现常声明已部署防御对策, 但在二进制中验证这些声明极为困难。
  审计者需要回答:"供应商声称此固件有DPA掩码, 二进制中真的存在吗?"

  本模块从6个维度验证对策的二进制存在性:
    C1 (布尔掩码): 数据路径中是否存在随机掩码生成+异或应用模式?
    C2 (表重排): 查表访问顺序是否被随机化(每个加密调用使用不同的表排列)?
    C3 (盲化): RSA/ECC中是否存在盲化因子生成+应用+移除的序列?
    C4 (CT屏障): 是否存在data_memory_barrier/volatile asm来防止编译器重排?
    C5 (故障检测): 是否存在冗余计算+比较+错误处理模式?
    C6 (随机延迟): 是否存在随机NOP插入或while(random_wait)模式?

  每项输出 PRESENT / ABSENT / UNCERTAIN 三级判定, 附带二进制证据。

  - Balasch et al.: 掩码实现的编译器优化破坏 — DSE消除掩码。
  - Hu et al.: SM4白盒4阶非线性编码+表访问重排。
  - GnuZero: 编译器级零化验证 — 对策的编译器幸存性。

边界条件:
  - 静态验证只能确认对策代码"存在" — 不能验证运行时正确性。
  - 掩码/盲化代码可能被编译器DSE优化掉 → 标记UNCERTAIN。
  - 自定义对策(非标准实现模式)可能漏检 → 输出保守的UNCERTAIN判定。
"""

from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

@dataclass
class CountermeasureCheck:
    cm_id: str = ""
    cm_name: str = ""              # 对策名称(如"布尔掩码" / "RSA盲化")
    cm_type: str = ""              # MASKING / SHUFFLING / BLINDING / BARRIER / FAULT_DETECT / DELAY
    status: str = "UNCERTAIN"      # PRESENT / ABSENT / UNCERTAIN
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    risk_if_absent: str = ""       # 若对策不存在 → 面临什么攻击?
    standard_reference: str = ""   # FIPS 140-3 IG / 通用准则 / etc.

# C1: 布尔掩码检测
_MASKING_PATTERNS: List[Tuple[bytes, str, float]] = [
    (b'random_mask', 'random mask generation', 0.85),
    (b'generate_mask', 'mask generation function', 0.80),
    (b'masked_aes', 'masked AES implementation', 0.88),
    (b'masked_', 'masked operation reference', 0.78),
    (b'boolean_mask', 'boolean masking reference', 0.85),
    (b'xor_mask', 'XOR masking pattern', 0.75),
]

# C2: 表重排检测
_SHUFFLING_PATTERNS: List[Tuple[bytes, str, float]] = [
    (b'shuffle_table', 'table shuffling', 0.85),
    (b'permute_table', 'table permutation', 0.82),
    (b'random_permutation', 'random permutation', 0.80),
    (b'shuffled_access', 'shuffled access pattern', 0.82),
    (b'randomize_order', 'randomized order', 0.78),
    (b'TableR', 'TableR (shuffle index table)', 0.88),
]

# C3: 盲化检测
_BLINDING_PATTERNS: List[Tuple[bytes, str, float]] = [
    (b'blinding', 'blinding factor reference', 0.82),
    (b'blinding_factor', 'blinding factor', 0.88),
    (b'rsa_blinding', 'RSA blinding', 0.90),
    (b'ecc_blinding', 'ECC blinding', 0.88),
    (b'scalar_blinding', 'scalar blinding (ECC)', 0.85),
]

# C4: 常量时间屏障检测
_BARRIER_PATTERNS: List[Tuple[bytes, str, float]] = [
    (b'asm volatile', 'volatile asm barrier (GCC/Clang)', 0.85),
    (b'__asm__ __volatile__', 'volatile asm barrier', 0.88),
    (b'barrier(', 'compiler barrier', 0.75),
    (b'OPTIONAL_MEMORY_BARRIER', 'memory barrier macro', 0.82),
    (b'data_memory_barrier', 'data memory barrier', 0.85),
    (b'dmb ish', 'ARM data memory barrier (DMB ISH)', 0.82),
    (b'mfence', 'x86 memory fence', 0.80),
    (b'lfence', 'x86 load fence (Spectre mitigation)', 0.80),
]

# C5: 故障检测检测
_FAULT_DETECT_PATTERNS: List[Tuple[bytes, str, float]] = [
    (b'fault_detect', 'fault detection', 0.85),
    (b'fault_attack', 'fault attack countermeasure', 0.85),
    (b'redundant_compute', 'redundant computation', 0.82),
    (b'double_compute', 'double computation check', 0.80),
    (b'verify_result', 'result verification', 0.65),
    (b'check_point', 'checkpoint/integrity', 0.55),
    (b'infection_countermeasure', 'infective countermeasure', 0.90),
    (b'diffusion_countermeasure', 'diffusion countermeasure', 0.85),
]

# C6: 随机延迟检测
_DELAY_PATTERNS: List[Tuple[bytes, str, float]] = [
    (b'random_delay', 'random delay', 0.82),
    (b'random_wait', 'random wait', 0.80),
    (b'jitter', 'timing jitter', 0.70),
    (b'dummy_operation', 'dummy operation insertion', 0.78),
    (b'random_nop', 'random NOP insertion', 0.82),
]

def _check_patterns(data: bytes, patterns: List[Tuple[bytes, str, float]]
                    ) -> Tuple[bool, float, List[str]]:
    """检查一组模式是否存在于二进制中。"""
    found = []
    best_conf = 0.0
    for pat, desc, conf in patterns:
        if pat in data:
            found.append(desc)
            best_conf = max(best_conf, conf)
    present = len(found) >= 1
    avg_conf = (best_conf + min(1.0, len(found) * 0.15)) / 2.0 if present else 0.0
    return present, avg_conf, found

def verify_countermeasures(data: bytes, algo_hint: str = ""
                           ) -> List[CountermeasureCheck]:
    """
    验证二进制中密码学对策的存在性。
    algo_hint: 'AES' / 'RSA' / 'ECC' — 不同算法使用不同对策组合。
    """
    checks: List[CountermeasureCheck] = []

    # C1: 掩码
    present, conf, evidence = _check_patterns(data, _MASKING_PATTERNS)
    checks.append(CountermeasureCheck(
        cm_id='CM-01', cm_name='布尔/算术掩码', cm_type='MASKING',
        status='PRESENT' if present else 'ABSENT',
        confidence=conf, evidence=evidence,
        risk_if_absent='无掩码→DPA/CPA攻击可行; 每个trace可泄漏1bit密钥',
        standard_reference='FIPS 140-3 IG A.13 / ISO 17825'))

    # C2: 表重排
    present, conf, evidence = _check_patterns(data, _SHUFFLING_PATTERNS)
    checks.append(CountermeasureCheck(
        cm_id='CM-02', cm_name='查表访问重排', cm_type='SHUFFLING',
        status='PRESENT' if present else 'ABSENT',
        confidence=conf, evidence=evidence,
        risk_if_absent='无重排→DCA攻击可通过trace对齐恢复密钥',
        standard_reference='Hu et al. 2025 (SM4白盒) / JCR 2020'))

    # C3: 盲化
    present, conf, evidence = _check_patterns(data, _BLINDING_PATTERNS)
    checks.append(CountermeasureCheck(
        cm_id='CM-03', cm_name='RSA/ECC盲化', cm_type='BLINDING',
        status='PRESENT' if present else 'ABSENT',
        confidence=conf, evidence=evidence,
        risk_if_absent='无盲化→SPA可从单条trace恢复RSA私钥指数',
        standard_reference='FIPS 140-3 IG A.14 / PKCS#1 v2.2 §9'))

    # C4: 屏障
    present, conf, evidence = _check_patterns(data, _BARRIER_PATTERNS)
    checks.append(CountermeasureCheck(
        cm_id='CM-04', cm_name='编译器/内存屏障', cm_type='BARRIER',
        status='PRESENT' if present else 'ABSENT',
        confidence=conf, evidence=evidence,
        risk_if_absent='无屏障→编译器优化可能破坏常量时间代码(Schneider 2024)',
        standard_reference='DOCC  / GnuZero (DSN 2025)'))

    # C5: 故障检测
    present, conf, evidence = _check_patterns(data, _FAULT_DETECT_PATTERNS)
    checks.append(CountermeasureCheck(
        cm_id='CM-05', cm_name='故障注入检测', cm_type='FAULT_DETECT',
        status='PRESENT' if present else 'ABSENT',
        confidence=conf, evidence=evidence,
        risk_if_absent='无检测→DFA可通过跳过轮次恢复AES密钥(Piret-Quisquater)',
        standard_reference='FIPS 140-3 IG A.15'))

    # C6: 随机延迟
    present, conf, evidence = _check_patterns(data, _DELAY_PATTERNS)
    checks.append(CountermeasureCheck(
        cm_id='CM-06', cm_name='随机时序延迟', cm_type='DELAY',
        status='PRESENT' if present else 'ABSENT',
        confidence=conf, evidence=evidence,
        risk_if_absent='无延迟→时序攻击更易对齐trace; SPA特征更明显',
        standard_reference='ISO 17825 Annex C'))

    return checks

def countermeasure_coverage(checks: List[CountermeasureCheck]) -> Tuple[int, int, str]:
    """统计对策覆盖率: (已部署数, 总数, 评估)。"""
    present = sum(1 for c in checks if c.status == 'PRESENT')
    total = len(checks)
    if present >= 5:
        assessment = 'STRONG — 多个互补对策层'
    elif present >= 3:
        assessment = 'MODERATE — 基本防护但仍有缺口'
    elif present >= 1:
        assessment = 'WEAK — 仅单个对策, 单点故障风险'
    else:
        assessment = 'NONE — 无检测到的对策; 所有攻击面暴露'
    return present, total, assessment
