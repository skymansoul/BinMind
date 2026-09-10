"""
密码学实现老化评估 — 对照当前安全标准评估检测到的密码学实现的合规性和退役状态。

设计意图:
  密码学算法的安全性随时间衰减 — 今天安全的算法明天可能是"允许但建议迁移",
  后天是"禁止使用"。组织级CBOM工具(SCANOSS)在依赖/源码层追踪算法状态,
  但无工具在二进制层面对已编译的密码学实现做老化评估。

  本模块从二进制检测结果出发, 对照三个权威标准的当前状态矩阵,
  输出每个检测到的算法的:
    - 合规状态 (COMPLIANT / TRANSITIONING / DEPRECATED / PROHIBITED)
    - 退役截止日期 (基于NIST SP 800-131Ar2 / CNSA 2.0 / BSI TR-02102-1)
    - 老化评分 (0=刚标准化, 1=已禁止; 反映紧迫性)
    - 推荐的替代算法和迁移优先级

  多标准覆盖确保评估适用于不同监管域(美国联邦/国家安全系统/欧盟/通用)。

  - NIST SP 800-131Ar2: 密码学算法和密钥长度的过渡计划。
  - CNSA 2.0: 国家安全系统密码学算法要求, 含PQC迁移时间线。
  - BSI TR-02102-1: 德国BSI密码学算法推荐和使用期限。
  - ANSSI RGS v2.0: 法国密码学安全指南。
  - NIST FIPS 203/204/205: PQC标准, 定义正式退役前的最短过渡期。

边界条件:
  - 评估基于算法名匹配 → 不检测同一算法的不同参数。
    需要额外的参数推断(来自key_schedule或密钥大小模式)以细化评估。
  - 标准状态矩阵需要定期更新(各标准机构每1-2年更新) → 矩阵硬编码, 需维护。
  - 自定义/私有算法不在标准覆盖范围内 → 标记为UNASSESSED, 提示审计。
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

class ComplianceStatus(Enum):
    COMPLIANT = 0       # 符合所有主要标准, 推荐使用
    ACCEPTABLE = 1      # 标准允许但非首选(如AES-128在CNSA中仍可接受)
    TRANSITIONING = 2   # 已宣布退役计划, 应在截止日期前迁移
    DEPRECATED = 3      # 已正式弃用, 仅遗留系统可用
    PROHIBITED = 4      # 明确禁止使用
    UNASSESSED = 5      # 不在已知标准覆盖范围内

@dataclass
class AgingReport:
    algorithm: str = ""
    location: int = 0
    status: ComplianceStatus = ComplianceStatus.UNASSESSED
    deprecation_deadline: str = ""     # 退役截止日期, 如 "2030-12-31"
    aging_score: float = 0.0           # 0=现代, 1=应立即替换
    governing_standard: str = ""       # 适用的最严格标准
    rationale: str = ""
    recommended_replacement: str = ""
    migration_priority: str = ""       # IMMEDIATE / PLANNED / OPTIONAL / NONE

# 密码学算法老化矩阵
# 格式: (状态, 截止日期, 适用标准, 评分, 理由, 替换建议)
# 评分: 0.0=现代安全, 0.3=可接受, 0.5=过渡期, 0.8=已弃用, 1.0=禁止

_AGING_MATRIX: Dict[str, Tuple[ComplianceStatus, str, str, float, str, str]] = {
# 对称加密
    'AES-256': (ComplianceStatus.COMPLIANT, '', 'CNSA 2.0/NIST/BSI', 0.0,
                '量子安全级别≥128-bit; CNSA 2.0批准用于所有分类级别', ''),
    'AES-128': (ComplianceStatus.ACCEPTABLE, '2030-12-31', 'NIST SP 800-131Ar2', 0.20,
                'Grover算法将安全级别降至~64bit; NIST要求2030前迁移到AES-256',
                'AES-256'),
    'AES': (ComplianceStatus.ACCEPTABLE, '2030-12-31', 'NIST SP 800-131Ar2', 0.20,
            '未指定密钥长度; 若为AES-128则需在2030前迁移', 'AES-256'),
    'DES': (ComplianceStatus.PROHIBITED, '2014-01-01', 'NIST SP 800-131Ar2', 1.0,
            '56-bit密钥可暴力破解; 自2014年起NIST禁止使用', 'AES-256'),
    '3DES': (ComplianceStatus.DEPRECATED, '2023-12-31', 'NIST SP 800-131Ar2', 0.85,
             'Sweet32攻击; 64-bit分组不足; NIST自2024年起禁用', 'AES-256'),
    'ChaCha20': (ComplianceStatus.COMPLIANT, '', 'NIST/BSI', 0.05,
                 '256-bit密钥, 量子安全级别~128-bit, 无已知实际攻击', ''),
    'SM4': (ComplianceStatus.UNASSESSED, '', '', 0.30,
            '中国国家标准; 128-bit分组+密钥; 国际标准未评估', 'AES-256 (国际兼容)'),
# 哈希
    'SHA-256': (ComplianceStatus.COMPLIANT, '', 'CNSA 2.0/NIST', 0.05,
                '≥128-bit量子抗碰撞; CNSA批准用于所有分类', ''),
    'SHA-512': (ComplianceStatus.COMPLIANT, '', 'CNSA 2.0/NIST', 0.0,
               '256-bit量子抗碰撞; 优于SHA-256', ''),
    'SHA-384': (ComplianceStatus.COMPLIANT, '', 'CNSA 2.0/NIST', 0.0, '', ''),
    'SHA-1': (ComplianceStatus.PROHIBITED, '2014-01-01', 'NIST SP 800-131Ar2', 1.0,
              'SHAttered碰撞攻击(PDF); 自2014年NIST禁止数字签名使用', 'SHA-256/SHA-512'),
    'MD5': (ComplianceStatus.PROHIBITED, '2010-01-01', 'NIST SP 800-131Ar2', 1.0,
            '选择前缀碰撞; 完全破解; 禁止所有密码学用途', 'SHA-256/SHA-512'),
    'SM3': (ComplianceStatus.UNASSESSED, '', '', 0.25,
            '中国国家标准哈希; 国际标准未评估', 'SHA-256 (国际兼容)'),
# 非对称/签名
    'RSA': (ComplianceStatus.TRANSITIONING, '2030-12-31', 'CNSA 2.0/NIST', 0.55,
            'Shor算法破解; <2048-bit已禁止; ≥2048-bit在2030前可接受',
            'ML-DSA-65 (FIPS 204)'),
    'ECDSA': (ComplianceStatus.TRANSITIONING, '2030-12-31', 'CNSA 2.0/NIST', 0.50,
              'Shor算法破解; P-256在2030前可接受; P-384/521过渡期中',
              'ML-DSA-44/65 (FIPS 204)'),
    'Ed25519': (ComplianceStatus.TRANSITIONING, '2035-12-31', 'CNSA 2.0', 0.35,
                '曲线安全但Shor-vulnerable; CNSA允许到2035(因128-bit经典安全)',
                'ML-DSA-87 (FIPS 204)或SLH-DSA'),
    'EdDSA': (ComplianceStatus.TRANSITIONING, '2035-12-31', 'CNSA 2.0', 0.35,
              '与Ed25519同族; 2035前迁移', 'ML-DSA'),
    'DSA': (ComplianceStatus.PROHIBITED, '2014-01-01', 'NIST SP 800-131Ar2', 1.0,
            '自2014年NIST禁止; 仅遗留验证', 'ML-DSA-65'),
# 密钥协商
    'ECDH': (ComplianceStatus.TRANSITIONING, '2030-12-31', 'CNSA 2.0/NIST', 0.55,
             'Shor算法破解; 2030前迁移到ML-KEM', 'ML-KEM-768 (FIPS 203)'),
    'DH': (ComplianceStatus.DEPRECATED, '2025-12-31', 'CNSA 2.0/NIST', 0.75,
           'Shor破解+Logjam; <2048-bit已禁止; CNSA要求2025前迁移', 'ML-KEM-768'),
    'X25519': (ComplianceStatus.TRANSITIONING, '2035-12-31', 'CNSA 2.0', 0.35,
               'Curve25519安全但Shor-vulnerable; CNSA允许到2035', 'ML-KEM-1024'),
    'Curve25519': (ComplianceStatus.TRANSITIONING, '2035-12-31', 'CNSA 2.0', 0.35,
                   '与X25519同族', 'ML-KEM-768/1024'),
# 后量子(现代)
    'ML-KEM': (ComplianceStatus.COMPLIANT, '', 'FIPS 203/CNSA 2.0', 0.0,
               'NIST PQC标准; CNSA批准; 量子安全', ''),
    'ML-DSA': (ComplianceStatus.COMPLIANT, '', 'FIPS 204/CNSA 2.0', 0.0, '', ''),
    'SLH-DSA': (ComplianceStatus.COMPLIANT, '', 'FIPS 205/CNSA 2.0', 0.0, '', ''),
# LWC
    'ASCON': (ComplianceStatus.COMPLIANT, '', 'NIST SP 800-232', 0.0,
              'NIST LWC标准(2024); 物联网轻量级首选', ''),
    'ASCON-128': (ComplianceStatus.COMPLIANT, '', 'NIST SP 800-232', 0.0, '', ''),
    'ASCON-128a': (ComplianceStatus.COMPLIANT, '', 'NIST SP 800-232', 0.0, '', ''),
}

def assess_aging(algorithm: str, location: int = 0) -> AgingReport:
    """评估单个密码学算法的老化状态。"""
    entry = _AGING_MATRIX.get(algorithm)
    if entry:
        status, deadline, standard, score, rationale, replacement = entry
        priority = 'NONE'
        if status == ComplianceStatus.PROHIBITED:
            priority = 'IMMEDIATE'
        elif status == ComplianceStatus.DEPRECATED:
            priority = 'IMMEDIATE'
        elif status == ComplianceStatus.TRANSITIONING:
            priority = 'PLANNED'
            # 距截止日期<2年→升级为IMMEDIATE
            if deadline and deadline < '2027':
                priority = 'IMMEDIATE'
        return AgingReport(
            algorithm=algorithm, location=location,
            status=status, deprecation_deadline=deadline,
            aging_score=score, governing_standard=standard,
            rationale=rationale, recommended_replacement=replacement,
            migration_priority=priority)
    else:
        # 未知算法 → 模糊匹配
        for known in sorted(_AGING_MATRIX.keys(), key=len, reverse=True):
            if known in algorithm or algorithm in known:
                return assess_aging(known, location)

        return AgingReport(
            algorithm=algorithm, location=location,
            status=ComplianceStatus.UNASSESSED,
            deprecation_deadline='', aging_score=0.40,
            governing_standard='',
            rationale='不在已知标准覆盖范围内 — 需人工审计',
            recommended_replacement='', migration_priority='OPTIONAL')

def assess_batch(findings: List) -> List[AgingReport]:
    """批量评估 — 输入crypto_detector的CryptoFinding列表。"""
    reports = []
    for f in findings:
        try:
            algo = getattr(f, 'algorithm', 'unknown')
            loc = getattr(f, 'location', 0)
            reports.append(assess_aging(algo, loc))
        except Exception:
            pass
    reports.sort(key=lambda r: (-r.aging_score, r.algorithm))
    return reports

def compute_aging_summary(reports: List[AgingReport]) -> Dict[str, int]:
    """汇总老化状态统计。"""
    summary = {'COMPLIANT': 0, 'ACCEPTABLE': 0, 'TRANSITIONING': 0,
               'DEPRECATED': 0, 'PROHIBITED': 0, 'UNASSESSED': 0}
    for r in reports:
        summary[r.status.name] += 1
    return summary
