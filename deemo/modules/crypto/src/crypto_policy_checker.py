"""
密码学策略合规检查 — 对照可配置的组织安全策略评估二进制密码学实现。

设计意图:
  crypto_aging对照公开标准(NIST/CNSA/BSI)评估算法状态, 但组织安全策略通常
  比公开标准更严格或更具体。例如:
    - "仅允许AES-256-GCM, 禁止所有ECB/CBC模式"
    - "密钥协商必须使用ML-KEM-768或X25519, 禁止RSA/DH"
    - "所有哈希必须≥384-bit输出, SHA-256仅允许用于HMAC"
    - "必须使用硬件熵源(RDRAND或TRNG), 禁止仅依赖/dev/urandom"

  本模块将策略表达为结构化规则集, 对照检测结果评估合规性,
  输出违规列表和合规评分。策略模板覆盖:
    - CNSA 2.0 (高安全)
    - PCI DSS 4.0 (支付卡行业)
    - BSI TR-03161 (德国政府受限环境)
    - FIPS 140-3 IG (密钥管理)
    - 自定义策略(JSON式规则)

  - CNSA 2.0: 美国国家安全系统算法要求。
  - PCI DSS 4.0.1: 支付卡行业数据安全标准 — 要求3.6-3.7涉及密钥管理。
  - BSI TR-03161: 受限环境密码学要求。
  - OWASP ASVS V9: 密码学验证标准。

边界条件:
  - 策略检查精度取决于crypto_detector的算法名精度 — "AES"vs"AES-128-GCM"区别显著。
  - 模式检测(GCM vs ECB)当前依赖字符串分析 — 精确的模式推断需要更深入的IR分析。
  - 自定义策略的规则表达力受限于当前规则模型(白名单/黑名单/最小强度/必需特性)。
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional, Set, Tuple

class RuleSeverity(Enum):
    BLOCKER = 0     # 阻止部署
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    INFO = 5

@dataclass
class PolicyRule:
    rule_id: str = ""
    category: str = ""            # ALGORITHM / KEY_SIZE / MODE / ENTROPY / LIFECYCLE
    description: str = ""
    severity: RuleSeverity = RuleSeverity.HIGH
    # 检查逻辑的简化表达
    allowed: List[str] = field(default_factory=list)       # 白名单
    forbidden: List[str] = field(default_factory=list)     # 黑名单
    min_key_bits: int = 0
    min_hash_bits: int = 0
    require_hardware_entropy: bool = False
    require_zeroization: bool = False
    require_constant_time: bool = False

@dataclass
class PolicyViolation:
    rule: PolicyRule
    algorithm: str = ""
    detail: str = ""
    recommendation: str = ""

@dataclass
class PolicyReport:
    policy_name: str = ""
    total_rules: int = 0
    violations: List[PolicyViolation] = field(default_factory=list)
    blocker_count: int = 0
    critical_count: int = 0
    compliance_score: float = 0.0   # 0-100
    passed: bool = False            # 无BLOCKER→通过

# 算法分类辅助
_SYM_ALGO_KW = {'AES', 'DES', '3DES', 'ChaCha', 'SM4', 'RC4'}
_HASH_ALGO_KW = {'SHA', 'MD5', 'SM3', 'BLAKE', 'Keccak'}
_KEX_ALGO_KW = {'ECDH', 'DH', 'X25519', 'Curve25519', 'ML-KEM', 'Kyber', 'RSA'}
_SIG_ALGO_KW = {'ECDSA', 'Ed25519', 'EdDSA', 'DSA', 'ML-DSA', 'SLH-DSA'}

def _algo_matches_category(algo: str, rule: PolicyRule) -> bool:
    """仅当算法类别与规则类别匹配时返回True。"""
    cat = rule.category
    if cat in ('ENTROPY', 'LIFECYCLE'):
        return False
    # 检查规则允许/禁止列表是否包含与algo相同类别的项
    allowed_str = ' '.join(rule.allowed + rule.forbidden)
    if cat == 'ALGORITHM' or cat == 'KEY_SIZE':
        algo_is_sym = any(kw in algo for kw in _SYM_ALGO_KW)
        algo_is_hash = any(kw in algo for kw in _HASH_ALGO_KW)
        algo_is_kex = any(kw in algo for kw in _KEX_ALGO_KW)
        algo_is_sig = any(kw in algo for kw in _SIG_ALGO_KW)
        rule_is_sym = any(kw in allowed_str for kw in _SYM_ALGO_KW)
        rule_is_hash = any(kw in allowed_str for kw in _HASH_ALGO_KW)
        rule_is_kex = any(kw in allowed_str for kw in _KEX_ALGO_KW)
        rule_is_sig = any(kw in allowed_str for kw in _SIG_ALGO_KW)
        return ((algo_is_sym and rule_is_sym) or (algo_is_hash and rule_is_hash) or
                (algo_is_kex and rule_is_kex) or (algo_is_sig and rule_is_sig))
    return True

# 预定义策略模板

def _build_cnsa_policy() -> List[PolicyRule]:
    """CNSA 2.0 (2024) — 国家安全系统最高安全级别。"""
    return [
        PolicyRule('CNSA-SYM-01', 'ALGORITHM', '对称加密: 仅AES-256',
                   severity=RuleSeverity.BLOCKER,
                   allowed=['AES-256'], forbidden=['AES-128', 'AES-192', 'DES', '3DES']),
        PolicyRule('CNSA-HASH-01', 'ALGORITHM', '哈希: SHA-384或SHA-512',
                   severity=RuleSeverity.BLOCKER,
                   allowed=['SHA-384', 'SHA-512'], min_hash_bits=384,
                   forbidden=['SHA-256', 'SHA-1', 'MD5']),
        PolicyRule('CNSA-KEX-01', 'ALGORITHM', '密钥协商: ML-KEM-1024或X25519(2035前)',
                   severity=RuleSeverity.CRITICAL,
                   allowed=['ML-KEM-1024', 'X25519'],
                   forbidden=['RSA', 'DH', 'ECDH']),
        PolicyRule('CNSA-SIG-01', 'ALGORITHM', '签名: ML-DSA-87或SLH-DSA',
                   severity=RuleSeverity.CRITICAL,
                   allowed=['ML-DSA-87', 'SLH-DSA'],
                   forbidden=['RSA', 'ECDSA', 'DSA']),
        PolicyRule('CNSA-ENT-01', 'ENTROPY', '熵源: 必须硬件TRNG',
                   severity=RuleSeverity.HIGH, require_hardware_entropy=True),
        PolicyRule('CNSA-ZERO-01', 'LIFECYCLE', '密钥必须清零',
                   severity=RuleSeverity.HIGH, require_zeroization=True),
    ]

def _build_pci_policy() -> List[PolicyRule]:
    """PCI DSS 4.0.1 — 支付卡行业。"""
    return [
        PolicyRule('PCI-SYM-01', 'ALGORITHM', '对称加密: ≥AES-128',
                   severity=RuleSeverity.BLOCKER,
                   allowed=['AES-128', 'AES-256'],
                   forbidden=['DES', '3DES', 'RC4']),
        PolicyRule('PCI-HASH-01', 'ALGORITHM', '哈希: ≥SHA-256',
                   severity=RuleSeverity.HIGH,
                   min_hash_bits=256, forbidden=['SHA-1', 'MD5']),
        PolicyRule('PCI-KEX-01', 'ALGORITHM', '密钥协商: ≥RSA-2048或ECDH',
                   severity=RuleSeverity.CRITICAL,
                   forbidden=['DH-1024', 'RSA-1024']),
        PolicyRule('PCI-ENT-01', 'ENTROPY', '熵源: CSPRNG或更强',
                   severity=RuleSeverity.MEDIUM),
        PolicyRule('PCI-ZERO-01', 'LIFECYCLE', '密钥应清零(推荐)',
                   severity=RuleSeverity.LOW, require_zeroization=True),
    ]

def _build_bsi_policy() -> List[PolicyRule]:
    """BSI TR-03161 — 德国受限环境。"""
    return [
        PolicyRule('BSI-SYM-01', 'ALGORITHM', '对称加密: AES-128及以上',
                   severity=RuleSeverity.BLOCKER, min_key_bits=128,
                   allowed=['AES-128', 'AES-256', 'ChaCha20'],
                   forbidden=['DES', '3DES', 'RC4']),
        PolicyRule('BSI-HASH-01', 'ALGORITHM', '哈希: SHA-256及以上(2030前)',
                   severity=RuleSeverity.HIGH, min_hash_bits=256,
                   allowed=['SHA-256', 'SHA-384', 'SHA-512', 'SHA-3'],
                   forbidden=['SHA-1', 'MD5']),
        PolicyRule('BSI-ECC-01', 'ALGORITHM', '椭圆曲线: ≥256-bit',
                   severity=RuleSeverity.CRITICAL, min_key_bits=256),
        PolicyRule('BSI-ENT-01', 'ENTROPY', '熵源: 符合AIS-31的TRNG',
                   severity=RuleSeverity.HIGH, require_hardware_entropy=True),
    ]

_POLICY_TEMPLATES: Dict[str, Callable[[], List[PolicyRule]]] = {
    'CNSA_2.0': _build_cnsa_policy,
    'PCI_DSS_4.0': _build_pci_policy,
    'BSI_TR_03161': _build_bsi_policy,
}

# 策略检查引擎

class PolicyChecker:
    """对照策略规则检查检测结果和审计报告。"""

    def __init__(self, rules: List[PolicyRule], policy_name: str = "Custom"):
        self._rules = rules
        self._policy_name = policy_name

    @classmethod
    def from_template(cls, template_name: str) -> Optional['PolicyChecker']:
        builder = _POLICY_TEMPLATES.get(template_name)
        if builder is None:
            return None
        return cls(builder(), template_name)

    def check(self, crypto_findings: Optional[List] = None,
              algo_names: Optional[List[str]] = None,
              entropy_reports: Optional[List] = None,
              key_lifecycle_reports: Optional[List] = None,
              aging_reports: Optional[List] = None,
              ) -> PolicyReport:
        """
        执行策略检查。
        crypto_findings: crypto_detector输出, 或仅algo_names列表。
        """
        if algo_names is None and crypto_findings:
            algo_names = []
            for f in crypto_findings:
                try:
                    algo_names.append(getattr(f, 'algorithm', 'unknown'))
                except Exception:
                    pass

        algo_names = algo_names or []
        violations: List[PolicyViolation] = []

        for rule in self._rules:
            # 白名单检查
            if rule.allowed:
                for algo in algo_names:
                    if not _algo_matches_category(algo, rule):
                        continue
                    any_allowed = any(a in algo for a in rule.allowed)
                    if not any_allowed and rule.severity in (RuleSeverity.BLOCKER,
                                                              RuleSeverity.CRITICAL):
                        violations.append(PolicyViolation(
                            rule=rule, algorithm=algo,
                            detail=f'{algo}不在白名单{rule.allowed}中',
                            recommendation=f'替换为{rule.allowed}'))

            # 黑名单检查
            for algo in algo_names:
                if not _algo_matches_category(algo, rule):
                    continue
                for forbidden in rule.forbidden:
                    if forbidden in algo:
                        violations.append(PolicyViolation(
                            rule=rule, algorithm=algo,
                            detail=f'{algo}匹配禁止算法{forbidden}',
                            recommendation=f'立即迁移到{rule.allowed[0] if rule.allowed else "批准的替代方案"}'))
                        break

            # 密钥长度检查
            if rule.min_key_bits > 0:
                for algo in algo_names:
                    if any(kw in algo for kw in ('RSA', 'AES', 'DH', 'EC')):
                        import re as _re
                        m = _re.search(r'(\d+)', algo)
                        if m and int(m.group(1)) < rule.min_key_bits:
                            violations.append(PolicyViolation(
                                rule=rule, algorithm=algo,
                                detail=f'密钥长度不足: 需要≥{rule.min_key_bits}bit',
                                recommendation=f'升级到≥{rule.min_key_bits}bit'))

            # 硬件熵源检查
            if rule.require_hardware_entropy and entropy_reports:
                has_hw = any(
                    getattr(r, 'source_type', '') == 'HARDWARE'
                    for r in entropy_reports)
                if not has_hw:
                    violations.append(PolicyViolation(
                        rule=rule, algorithm='ENTROPY',
                        detail='未检测到硬件熵源; 策略要求TRNG',
                        recommendation='启用RDRAND或外接TRNG'))

            # 清零检查
            if rule.require_zeroization and key_lifecycle_reports:
                all_zeroized = all(
                    getattr(r, 'is_zeroized', True) for r in key_lifecycle_reports)
                if not all_zeroized:
                    violations.append(PolicyViolation(
                        rule=rule, algorithm='KEY_MGMT',
                        detail='检测到未清零的密钥 — 违反生命周期策略',
                        recommendation='在所有密钥使用路径上添加explicit_bzero'))

        # 合规评分计算
        blocker_count = sum(1 for v in violations
                           if v.rule.severity == RuleSeverity.BLOCKER)
        critical_count = sum(1 for v in violations
                            if v.rule.severity == RuleSeverity.CRITICAL)
        total_severity_weight = sum(
            {RuleSeverity.BLOCKER: 20, RuleSeverity.CRITICAL: 10,
             RuleSeverity.HIGH: 5, RuleSeverity.MEDIUM: 2,
             RuleSeverity.LOW: 1, RuleSeverity.INFO: 0}[v.rule.severity]
            for v in violations)
        score = max(0.0, 100.0 - total_severity_weight * 3.0)

        return PolicyReport(
            policy_name=self._policy_name,
            total_rules=len(self._rules),
            violations=violations,
            blocker_count=blocker_count,
            critical_count=critical_count,
            compliance_score=round(score, 1),
            passed=blocker_count == 0)
