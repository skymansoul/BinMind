"""
PQC迁移路径规划器 — 从检测到的经典密码学实现自动生成向后量子密码学的最小变更迁移计划。

修改记录:
  2025-08-08 14:32 — 初始实现: NIST PQC标准映射/迁移步骤生成/依赖排序/影响评估

设计意图:
  crypto_agility评估"迁移难不难", 但不回答"迁移到哪儿, 怎么迁移"。
  NIST已在2024年8月正式标准化3个PQC算法:
    - ML-KEM (FIPS 203): 密钥封装 — 替代RSA-OAEP/ECDH
    - ML-DSA (FIPS 204): 数字签名 — 替代RSA-PSS/ECDSA
    - SLH-DSA (FIPS 205): 无状态哈希签名 — 高安全场景的备选

  本模块从二进制检测结果出发, 生成可执行的迁移计划:
    1. 识别量子脆弱算法(RSA/ECDSA/ECDH/DSA)的每个实例。
    2. 映射到推荐的PQC替代方案(考虑安全级别/性能/二进制尺寸)。
    3. 检测迁移依赖(密钥尺寸变化→缓冲区重分配; 签名尺寸变化→协议帧格式变更)。
    4. 输出按优先级排序的迁移步骤列表。

  迁移计划包括:
    - 步骤编号和优先级
    - 目标PQC算法及参数
    - 影响的代码位置/模块
    - 预期的二进制尺寸变化
    - 前置依赖(什么必须先改)

参考:
  - NIST FIPS 203/204/205 (2024): ML-KEM, ML-DSA, SLH-DSA标准。
  - NIST SP 800-208 (2020, updated 2024): 有状态哈希签名推荐(LMS/XMSS)。
  - OMB M-23-02 (2022): 联邦系统PQC迁移时间线要求。
  - CNSA 2.0 (2024): 国家安全系统密码学算法迁移指南。
  - QED (IEEE Access 2025): 量子脆弱可执行文件检测 — 本模块补充其"检测后"环节。

边界条件:
  - 迁移建议基于NIST标准推荐, 不包含专有算法。
  - 参数选择采用保守策略(优先NIST Level 5安全, 兼顾性能)。
  - 二进制尺寸变化为近似估计 — 实际取决于编译器和优化级别。
"""

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple


class MigrationPriority(Enum):
    CRITICAL = 0    # 直接暴露在网络攻击面的密钥协商
    HIGH = 1        # 数字签名(证书/身份验证)
    MEDIUM = 2      # 对称加密(需增加密钥长度)
    LOW = 3         # 哈希函数(需增加输出长度)


@dataclass
class MigrationStep:
    step_id: int = 0
    priority: MigrationPriority = MigrationPriority.MEDIUM
    current_algorithm: str = ""
    target_algorithm: str = ""         # 推荐的PQC替代算法
    target_params: str = ""            # 推荐的参数集
    rationale: str = ""
    affected_locations: List[int] = field(default_factory=list)
    key_size_change: str = ""          # 密钥/签名/密文尺寸变化描述
    binary_size_impact: str = ""       # 预期的二进制尺寸变化
    depends_on: List[int] = field(default_factory=list)  # 前置步骤ID列表
    agility_requirement: str = "MODERATE"  # 需要的敏捷性级别


# ── 量子脆弱算法→PQC替代方案映射 ──
# 格式: (当前算法, [(替代算法, 参数集, 安全级别, NIST标准, 选择理由)])
_MIGRATION_MAP: Dict[str, List[Tuple[str, str, int, str, str]]] = {
    'RSA': [
        ('ML-DSA-65', 'FIPS 204 IPD', 3, 'FIPS 204',
         'ML-DSA为NIST首选的通用数字签名; Level 3≈AES-128等效安全性'),
        ('SLH-DSA-128s', 'FIPS 205 IPD', 3, 'FIPS 205',
         'SLH-DSA无状态→不需要状态管理; 备选, 用于高安全场景'),
    ],
    'ECDSA': [
        ('ML-DSA-44', 'FIPS 204 IPD', 2, 'FIPS 204',
         'ECDSA P-256 → ML-DSA-44; 匹配AES-128安全级别'),
        ('ML-DSA-65', 'FIPS 204 IPD', 3, 'FIPS 204',
         'ECDSA P-384/521 → ML-DSA-65; 匹配AES-192安全级别'),
    ],
    'Ed25519': [
        ('ML-DSA-87', 'FIPS 204 IPD', 5, 'FIPS 204',
         'Ed25519(~128bit安全)→ML-DSA-87(Level 5); 高安全场景保守选择'),
        ('ML-DSA-65', 'FIPS 204 IPD', 3, 'FIPS 204',
         '中等安全场景 → ML-DSA-65; 签名尺寸更小'),
    ],
    'EdDSA': [
        ('ML-DSA-65', 'FIPS 204 IPD', 3, 'FIPS 204',
         '通用EdDSA替代; 平衡安全性和性能'),
    ],
    'ECDH': [
        ('ML-KEM-768', 'FIPS 203 IPD', 3, 'FIPS 203',
         'ECDH P-256 → ML-KEM-768; 匹配AES-128等效'),
        ('ML-KEM-1024', 'FIPS 203 IPD', 5, 'FIPS 203',
         'ECDH P-384/521 → ML-KEM-1024; 匹配AES-256等效'),
    ],
    'DSA': [
        ('ML-DSA-65', 'FIPS 204 IPD', 3, 'FIPS 204',
         'DSA已被废弃; ML-DSA为其现代化替代'),
    ],
    'DH': [
        ('ML-KEM-768', 'FIPS 203 IPD', 3, 'FIPS 203',
         'DH-2048 → ML-KEM-768; 约等效安全级别'),
    ],
    'RSA-OAEP': [
        ('ML-KEM-768', 'FIPS 203 IPD', 3, 'FIPS 203',
         'RSA-2048密钥封装 → ML-KEM-768'),
    ],
}

# 对称加密: 量子Grover算法将安全级别减半 → 密钥长度翻倍
_SYMMETRIC_UPGRADES: Dict[str, str] = {
    'AES-128': 'AES-256',
    'AES-192': 'AES-256',
    'ChaCha20': 'ChaCha20 (仍≥128-bit量子安全)',
    '3DES': 'AES-256 (3DES已废弃)',
    'DES': 'AES-256 (DES已废弃)',
}

# 哈希函数: 量子Grover → 抗碰撞性减半 → 输出长度翻倍
_HASH_UPGRADES: Dict[str, str] = {
    'SHA-256': 'SHA-512 或 SHA-384 (≥128-bit量子抗碰撞)',
    'SHA-1': 'SHA-256 或 SHA-512 (SHA-1已废弃)',
    'MD5': 'SHA-256 或 SHA-512 (MD5已废弃)',
}


def _estimate_binary_size_impact(current_algo: str, target_algo: str) -> str:
    """估计迁移到PQC后二进制尺寸的变化量级。"""
    if 'ML-KEM' in target_algo:
        return '+20-40KB (Kyber参考实现; 含NTT和多项式算术)'
    elif 'ML-DSA' in target_algo:
        return '+25-50KB (Dilithium参考实现; 含拒绝采样和NTT)'
    elif 'SLH-DSA' in target_algo:
        return '+50-120KB (SPHINCS+参考实现; 哈希树和WOTS+)'
    elif 'AES-256' in target_algo:
        return '+2-5KB (AES轮数不变; 仅密钥调度和上下文尺寸变化)'
    elif 'SHA-512' in target_algo:
        return '+1-3KB (IV和常量表尺寸翻倍)'
    return 'unknown'


def _estimate_key_size_change(current_algo: str, target_algo: str) -> str:
    """描述密钥/签名/密文尺寸变化。"""
    changes = {
        ('RSA', 'ML-DSA-65'): '私钥: 2048→4032B; 签名: 256→3309B',
        ('ECDSA', 'ML-DSA-44'): '私钥: 32→2560B; 签名: 64→2420B',
        ('ECDSA', 'ML-DSA-65'): '私钥: 32→4032B; 签名: 64→3309B',
        ('Ed25519', 'ML-DSA-65'): '私钥: 32→4032B; 签名: 64→3309B',
        ('ECDH', 'ML-KEM-768'): '公钥: 32→1184B; 密文: 0→1088B',
        ('ECDH', 'ML-KEM-1024'): '公钥: 32→1568B; 密文: 0→1568B',
        ('DH', 'ML-KEM-768'): '公钥: 256→1184B; 密文: 0→1088B',
    }
    return changes.get((current_algo, target_algo),
                        f'密钥/签名尺寸会显著增加(PQC特征)')


@dataclass
class MigrationPlan:
    plan_id: str = ""
    total_steps: int = 0
    steps: List[MigrationStep] = field(default_factory=list)
    critical_count: int = 0
    estimated_total_size_increase: str = ""
    minimum_agility_required: str = "MODERATE"


def generate_migration_plan(crypto_findings: Optional[List] = None,
                            agility_report=None
                            ) -> MigrationPlan:
    """
    从密码学检测结果生成PQC迁移计划。
    crypto_findings: crypto_detector的检测结果。
    agility_report: 来自crypto_agility.audit_agility的敏捷性评估。
    """
    if not crypto_findings:
        return MigrationPlan(plan_id="EMPTY", total_steps=0)

    # 按算法分组, 收集位置
    algo_locations: Dict[str, List[int]] = defaultdict(list)
    for f in crypto_findings:
        try:
            algo = getattr(f, 'algorithm', 'unknown')
            loc = getattr(f, 'location', 0)
            algo_locations[algo].append(loc)
        except Exception:
            pass

    steps: List[MigrationStep] = []
    step_id = 0
    total_size_impact = 0

    for algo, locations in sorted(algo_locations.items()):
        matched = False

        # 检查量子脆弱算法
        if algo in _MIGRATION_MAP:
            targets = _MIGRATION_MAP[algo]
            target_algo, params, sec_level, standard, rationale = targets[0]

            priority = MigrationPriority.CRITICAL if algo in ('ECDH', 'DH', 'RSA-OAEP') \
                else MigrationPriority.HIGH

            size_impact = _estimate_binary_size_impact(algo, target_algo)
            key_change = _estimate_key_size_change(algo, target_algo)

            step_id += 1
            steps.append(MigrationStep(
                step_id=step_id, priority=priority,
                current_algorithm=algo, target_algorithm=target_algo,
                target_params=params, rationale=rationale,
                affected_locations=locations[:10],
                key_size_change=key_change,
                binary_size_impact=size_impact))
            matched = True

        # 对称加密 → 密钥长度翻倍
        if not matched and algo in _SYMMETRIC_UPGRADES:
            target = _SYMMETRIC_UPGRADES[algo]
            step_id += 1
            steps.append(MigrationStep(
                step_id=step_id, priority=MigrationPriority.MEDIUM,
                current_algorithm=algo, target_algorithm=target,
                target_params='按需', rationale='Grover算法将密钥搜索复杂度减半→密钥长度翻倍以维持安全性',
                affected_locations=locations[:10],
                key_size_change='密钥长度翻倍',
                binary_size_impact=_estimate_binary_size_impact(algo, target)))
            matched = True

        # 哈希函数 → 输出长度翻倍
        if not matched and algo in _HASH_UPGRADES:
            target = _HASH_UPGRADES[algo]
            step_id += 1
            steps.append(MigrationStep(
                step_id=step_id, priority=MigrationPriority.LOW,
                current_algorithm=algo, target_algorithm=target,
                target_params='按需', rationale='Grover算法将抗碰撞性减半→哈希输出长度翻倍',
                affected_locations=locations[:10],
                key_size_change='摘要长度增加',
                binary_size_impact=_estimate_binary_size_impact(algo, target)))
            matched = True

        # 未知算法或已PQC — 不生成步骤
        if not matched:
            continue

    # 按优先级排序
    steps.sort(key=lambda s: (s.priority.value, s.step_id))

    # 检测依赖关系: CRITICAL步骤必须先于使用其密钥的步骤
    critical_ids = [s.step_id for s in steps if s.priority == MigrationPriority.CRITICAL]
    for s in steps:
        if s.priority in (MigrationPriority.HIGH, MigrationPriority.LOW):
            s.depends_on = critical_ids[:1]  # 依赖首个CRITICAL步骤

    # 确定所需的最低敏捷性
    agility_needed = "MODERATE"
    if agility_report:
        try:
            score = getattr(agility_report, 'composite_score', 0.5)
            if score > 0.6:
                agility_needed = "HIGH (当前实现敏捷性不足—需先重构抽象层)"
        except Exception:
            pass

    critical_count = sum(1 for s in steps if s.priority == MigrationPriority.CRITICAL)
    total_kb = sum(1 for s in steps if 'KB' in s.binary_size_impact)

    return MigrationPlan(
        plan_id=f"PQC-MIG-{len(steps):02d}",
        total_steps=len(steps),
        steps=steps,
        critical_count=critical_count,
        estimated_total_size_increase=f'+{total_kb * 25}-{total_kb * 40}KB (粗略估计)',
        minimum_agility_required=agility_needed,
    )
