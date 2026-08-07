#!/usr/bin/env python3
"""
后量子密码检测与迁移评估器

检测二进制文件中的密码学原语，评估其后量子安全性
并根据 NIST PQC 标准化进程给出迁移

参考标准：
- NIST SP 800-208 (Stateful Hash-Based 签名s)
- NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)
- BSI TR-02102-1 (Cryptographic Mechanisms: Recommendations Key Lengths)
- 的密码学审计框架
"""

import logging
import re
import math
import hashlib
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from collections import defaultdict
from enum import Enum

logger = logging.getLogger(__name__)


class SecurityLevel(Enum):
    """NIST 安全等级"""
    LEVEL1 = 1   # ≥ AES-128 (128-bit classical)
    LEVEL2 = 2   # ≥ SHA256 collision
    LEVEL3 = 3   # ≥ AES-192
    LEVEL4 = 4   # ≥ AES-256
    LEVEL5 = 5   # ≥ AES-256 (256-bit classical + Grover-resistant)
    UNKNOWN = 0


class PQThreat(str, Enum):
    """量子威胁级别"""
    VULNERABLE = "vulnerable"        # Shor/Simon 算法可完全破解
    WEAKENED = "weakened"             # Grover 算法平方根加速
    RESISTANT = "resistant"           # 已知量子算法无明显优势
    UNKNOWN = "unknown"


@dataclass
class CryptoPrimitive:
    """检测到的密码学原语"""
    name: str
    category: str  # 'asymmetric', 'symmetric', 'hash', '签名', 'kem', 'rng'
    algorithm: str  # 标准化名称
    detected_in: str  # 检测来源: 'import', 'string', 'constant', 'code_pattern'
    location: str = ""
    key_size: Optional[int] = None
    curve: Optional[str] = None  # 椭圆曲线名称

    def pq_threat(self) -> PQThreat:
        return evaluate_pq_threat(self)


@dataclass
class PQAssessment:
    """后量子安全评估结果"""
    primitive: CryptoPrimitive
    pq_threat: PQThreat
    nist_security_level: SecurityLevel
    recommended_replacement: Optional[str] = None
    migration_urgency: str = "none"  # 'critical', 'high', 'medium', 'low', 'none'
    notes: str = ""


class CryptoFingerprintDB:
    """
    密码学指纹数据库
    
    维护已知密码学实现的特征签名
    用于二进制文件中的原语识别
    """

    # 非对称密码的量子脆弱性 (Shor 算法可破解)
    _QUANTUM_VULNERABLE = {
        'RSA': {
            'categories': ['asymmetric', 'signature', 'kem'],
            'signatures': [
                'RSA_public_decrypt', 'RSA_private_encrypt',
                'RSA_generate_key', 'RSA_generate_key_ex',
                'RSA_PKCS1', 'RSA_OAEP', 'RSA_PSS',
                'rsa_public_key', 'rsa_private_key',
            ],
            'nist_level': lambda ks: (
                SecurityLevel.LEVEL1 if ks < 2048 else
                SecurityLevel.LEVEL2 if ks < 3072 else
                SecurityLevel.LEVEL3 if ks < 7680 else
                SecurityLevel.LEVEL4
            ),
            'pq_migration': 'ML-DSA (FIPS 204) / ML-KEM (FIPS 203)',
        },
        'ECDSA': {
            'categories': ['asymmetric', 'signature'],
            'signatures': [
                'ECDSA_do_sign', 'ECDSA_sign', 'ECDSA_verify',
                'EC_KEY_generate_key', 'EC_GROUP_new_by_curve_name',
                'ECDSA_sign_setup', 'ecdsa_sign', 'ecdsa_verify',
            ],
            'nist_level': lambda ks: (
                SecurityLevel.LEVEL2 if ks and ks <= 256 else
                SecurityLevel.LEVEL3 if ks and ks <= 384 else
                SecurityLevel.LEVEL5
            ),
            'pq_migration': 'ML-DSA (FIPS 204) / SLH-DSA (FIPS 205)',
        },
        'ECDH': {
            'categories': ['asymmetric', 'kem', 'key_exchange'],
            'signatures': [
                'ECDH_compute_key', 'EC_POINT_mul',
                'ecdh', 'X25519', 'x25519_scalar_mul',
                'curve25519', 'ED25519',
            ],
            'nist_level': lambda ks: (
                SecurityLevel.LEVEL2 if ks and ks <= 255 else
                SecurityLevel.LEVEL3 if ks and ks <= 384 else
                SecurityLevel.LEVEL5
            ),
            'pq_migration': 'ML-KEM (FIPS 203)',
        },
        'DSA': {
            'categories': ['asymmetric', 'signature'],
            'signatures': ['DSA_sign', 'DSA_verify', 'DSA_generate_key'],
            'nist_level': lambda ks: SecurityLevel.LEVEL1,
            'pq_migration': 'ML-DSA (FIPS 204)',
        },
        'DiffieHellman': {
            'categories': ['asymmetric', 'key_exchange'],
            'signatures': [
                'DH_compute_key', 'DH_generate_key',
                'DH_generate_parameters', 'dh_',
            ],
            'nist_level': lambda ks: (
                SecurityLevel.LEVEL1 if ks and ks < 2048 else
                SecurityLevel.LEVEL3 if ks and ks < 3072 else
                SecurityLevel.LEVEL4
            ),
            'pq_migration': 'ML-KEM (FIPS 203)',
        },
    }

    # 对称密码和哈希的量子抗性 (Grover 加速但不可破解)
    _QUANTUM_WEAKENED = {
        'AES': {
            'signatures': [
                'AES_encrypt', 'AES_decrypt', 'AES_set_encrypt_key',
                'AES_set_decrypt_key', 'aesni_', 'rijndael',
            ],
            'nist_level': lambda ks: (
                SecurityLevel.LEVEL1 if ks == 128 else
                SecurityLevel.LEVEL3 if ks == 192 else
                SecurityLevel.LEVEL5 if ks == 256 else
                SecurityLevel.UNKNOWN
            ),
        },
        'SHA2': {
            'signatures': [
                'SHA256_Init', 'SHA256_Update', 'SHA256_Final',
                'SHA512_Init', 'SHA384_Init',
                'SHA256_Transform', 'sha256_', 'sha512_',
            ],
            'nist_level': lambda ks: SecurityLevel.LEVEL2,
        },
        'SHA3': {
            'signatures': [
                'SHA3_256', 'SHA3_512', 'Keccak', 'sha3_',
                'FIPS202', 'SHAKE128', 'SHAKE256',
            ],
            'nist_level': lambda ks: (
                SecurityLevel.LEVEL2 if '256' in str(ks) else
                SecurityLevel.LEVEL4 if '512' in str(ks) else
                SecurityLevel.LEVEL2
            ),
        },
        'ChaCha20': {
            'signatures': ['ChaCha20', 'chacha20', 'chacha_'],
            'nist_level': lambda ks: SecurityLevel.LEVEL5,
        },
    }

    # 已知后量子实现
    _QUANTUM_RESISTANT = {
        'Kyber': {
            'signatures': ['pqcrystals_kyber', 'kyber', 'ML-KEM'],
            'nist_level': lambda ks: SecurityLevel.LEVEL1,
        },
        'Dilithium': {
            'signatures': ['pqcrystals_dilithium', 'dilithium', 'ML-DSA'],
            'nist_level': lambda ks: SecurityLevel.LEVEL1,
        },
        'SPHINCS+': {
            'signatures': ['sphincs', 'SLH-DSA', 'SPHINCS+'],
            'nist_level': lambda ks: SecurityLevel.LEVEL5,
        },
        'Falcon': {
            'signatures': ['falcon_sign', 'falcon_keygen', 'Falcon'],
            'nist_level': lambda ks: SecurityLevel.LEVEL5,
        },
        'XMSS': {
            'signatures': ['xmss_sign', 'xmss_keygen'],
            'nist_level': lambda ks: SecurityLevel.LEVEL2,
        },
        'LMS': {
            'signatures': ['lms_sign', 'lms_verify', 'HSS_'],
            'nist_level': lambda ks: SecurityLevel.LEVEL2,
        },
        'McEliece': {
            'signatures': ['mceliece', 'Classic McEliece'],
            'nist_level': lambda ks: SecurityLevel.LEVEL5,
        },
        'BIKE': {
            'signatures': ['bike_kem', 'BIKE_'],
            'nist_level': lambda ks: SecurityLevel.LEVEL1,
        },
        'HQC': {
            'signatures': ['hqc_kem', 'HQC_'],
            'nist_level': lambda ks: SecurityLevel.LEVEL3,
        },
    }

    # 弱密码学原语（已弃用）
    _WEAK_CRYPTO = {
        'DES': {'sig': ['DES_', 'des_encrypt', 'des_decrypt'],
                'issue': '56-bit 密钥可暴力破解'},
        'RC4': {'sig': ['RC4_', 'rc4_', 'ArcFour'],
                'issue': '流密码偏差攻击已成熟'},
        'MD5': {'sig': ['MD5_', 'md5_'],
                'issue': '碰撞攻击可在秒级完成'},
        'SHA1': {'sig': ['SHA1_', 'sha1_', 'SHA_1'],
                 'issue': 'SHAttered 碰撞攻击已公开'},
        'RC2': {'sig': ['RC2_'], 'issue': '已废弃的传统密码'},
        'Blowfish': {'sig': ['Blowfish_', 'bf_encrypt'],
                     'issue': '64-bit 块大小导致 Sweet32 攻击'},
        '3DES': {'sig': ['3DES', 'triple_des', 'DES_ede3'],
                 'issue': '64-bit 块大小 + Sweet32'},
    }


def evaluate_pq_threat(primitive: CryptoPrimitive) -> PQThreat:
    """评估单个原语的后量子威胁级别"""
    category = primitive.category.lower()
    name_upper = primitive.algorithm.upper()

    if category in ('asymmetric', 'kem', 'key_exchange', 'signature'):
        if any(pq in name_upper for pq in ['KYBER', 'DILITHIUM', 'SPHINCS',
                                              'FALCON', 'XMSS', 'LMS', 'MCELIECE',
                                              'BIKE', 'HQC']):
            return PQThreat.RESISTANT
        if any(vuln in name_upper for vuln in ['RSA', 'EC', 'DH', 'DSA', 'X25519',
                                                  'ED25519', 'CURVE25519']):
            return PQThreat.VULNERABLE
        return PQThreat.VULNERABLE  # 默认：非对称密码假定量子脆弱

    if category in ('symmetric', 'hash', 'rng'):
        return PQThreat.WEAKENED  # Grover 平方根加速

    return PQThreat.UNKNOWN


class PostQuantumDetector:
    """
    后量子密码检测器
    
    扫描二进制中的密码学原语，评估其后量子安全性
    融合 [SoK 2026] 的系统化分类框架
    """

    def __init__(self):
        self.db = CryptoFingerprintDB()
        self._findings: List[CryptoPrimitive] = []
        self._assessments: List[PQAssessment] = []

    def analyze(
        self,
        strings: List[str],
        imports: Optional[Dict[str, List[str]]] = None,
        binary_data: Optional[bytes] = None
    ) -> Dict[str, Any]:
        """
        执行后量子安全评估
        
        Args:
        strings: 二进制中提取的字符串列表
        imports: 导入函数表 {module: [func_names]}
        binary_data: 原始二进制数据
        
        返回:
        评估结果字典
        """
        primitives = []

        # 1. 从字符串检测
        primitives.extend(self._from_strings(strings))

        # 2. 从导入表检测
        if imports:
            primitives.extend(self._from_imports(imports))

        # 3. 从二进制常量检测
        if binary_data:
            primitives.extend(self._from_constants(binary_data))

        # 去重
        unique = self._deduplicate(primitives)

        # 评估每个原语
        assessments = []
        for p in unique:
            assessment = self._assess_primitive(p)
            assessments.append(assessment)

        # 计算综合评分
        risk = self._compute_risk(assessments)

        return {
            'total_primitives': len(unique),
            'vulnerable_count': sum(1 for a in assessments
                                   if a.pq_threat == PQThreat.VULNERABLE),
            'weakened_count': sum(1 for a in assessments
                                 if a.pq_threat == PQThreat.WEAKENED),
            'resistant_count': sum(1 for a in assessments
                                  if a.pq_threat == PQThreat.RESISTANT),
            'risk_score': risk['score'],
            'risk_level': risk['level'],
            'primitives': [
                {
                    'algorithm': p.algorithm,
                    'category': p.category,
                    'key_size': p.key_size,
                    'pq_threat': a.pq_threat.value,
                    'nist_level': a.nist_security_level.name,
                    'migration': a.recommended_replacement,
                    'urgency': a.migration_urgency,
                    'notes': a.notes,
                }
                for p, a in zip(unique, assessments)
            ],
            'migration_plan': self._build_migration_plan(assessments),
        }

    def _from_strings(self, strings: List[str]) -> List[CryptoPrimitive]:
        """从字符串中检测密码学原语"""
        found = []

        for db, pq_category in [
            (self.db._QUANTUM_VULNERABLE, 'vulnerable_db'),
            (self.db._QUANTUM_WEAKENED, 'weakened_db'),
            (self.db._QUANTUM_RESISTANT, 'resistant_db'),
        ]:
            for algo_name, info in db.items():
                for sig in info.get('signatures', []):
                    for s in strings:
                        if sig.lower() in s.lower():
                            found.append(CryptoPrimitive(
                                name=s,
                                category=info.get('categories', ['unknown'])[0],
                                algorithm=algo_name,
                                detected_in='string',
                                location=s[:100]
                            ))
                            break

        return found

    def _from_imports(self, imports: Dict[str, List[str]]) -> List[CryptoPrimitive]:
        """从导入表中检测"""
        found = []

        all_funcs = []
        for module, funcs in imports.items():
            for func in funcs:
                all_funcs.append((module, func))

        for db, _ in [
            (self.db._QUANTUM_VULNERABLE, None),
            (self.db._QUANTUM_WEAKENED, None),
            (self.db._QUANTUM_RESISTANT, None),
        ]:
            for algo_name, info in db.items():
                for sig in info.get('signatures', []):
                    for module, func in all_funcs:
                        if sig.lower() in func.lower():
                            found.append(CryptoPrimitive(
                                name=func,
                                category=info.get('categories', ['unknown'])[0],
                                algorithm=algo_name,
                                detected_in='import',
                                location=f"{module}.{func}"
                            ))

        return found

    def _from_constants(self, data: bytes) -> List[CryptoPrimitive]:
        """从二进制常量中检测（大整数、曲线参数）"""
        found = []

        # RSA 常见公钥指数
        rsa_exponents = {
            b'\x01\x00\x01\x00': 'RSA_F4 (65537)',
        }

        # NIST P-256 曲线参数 (a = -3)
        p256_params = bytes.fromhex(
            'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF'
        )

        text = data
        for needle, desc in rsa_exponents.items():
            if needle in text:
                found.append(CryptoPrimitive(
                    name=desc,
                    category='asymmetric',
                    algorithm='RSA',
                    detected_in='constant',
                    location=f"offset {text.find(needle)}"
                ))

        if p256_params in text:
            found.append(CryptoPrimitive(
                name='NIST P-256',
                category='asymmetric',
                algorithm='ECDSA/ECDH',
                detected_in='constant',
                curve='P-256'
            ))

        return found

    def _deduplicate(self, primitives: List[CryptoPrimitive]) -> List[CryptoPrimitive]:
        """去重：保留首次出现的原语"""
        seen = set()
        unique = []
        for p in primitives:
            key = (p.algorithm.lower(), p.category)
            if key not in seen:
                seen.add(key)
                unique.append(p)
        return unique

    def _assess_primitive(self, p: CryptoPrimitive) -> PQAssessment:
        """评估单个原语的后量子安全性"""
        threat = evaluate_pq_threat(p)
        nist_level = SecurityLevel.UNKNOWN

        # 查找迁移
        migration = None
        for db_group in [
            self.db._QUANTUM_VULNERABLE,
            self.db._QUANTUM_WEAKENED,
            self.db._QUANTUM_RESISTANT,
        ]:
            for algo_name, info in db_group.items():
                if algo_name.upper() == p.algorithm.upper():
                    nist_level_func = info.get('nist_level')
                    if nist_level_func:
                        nist_level = nist_level_func(p.key_size)
                    migration = info.get('pq_migration')
                    break

        urgency = 'none'
        if threat == PQThreat.VULNERABLE:
            urgency = 'critical'
        elif threat == PQThreat.WEAKENED and p.algorithm.upper() in ('MD5', 'SHA1', 'DES', 'RC4'):
            urgency = 'high'
        elif threat == PQThreat.WEAKENED:
            urgency = 'low'

        notes = ""
        if threat == PQThreat.VULNERABLE:
            notes = "Shor 算法在足够大的量子计算机上可高效破解此原语"
        elif threat == PQThreat.WEAKENED:
            notes = "Grover 算法将该原语的安全强度降低一半（平方根加速）"

        return PQAssessment(
            primitive=p,
            pq_threat=threat,
            nist_security_level=nist_level,
            recommended_replacement=migration,
            migration_urgency=urgency,
            notes=notes,
        )

    def _compute_risk(self, assessments: List[PQAssessment]) -> Dict[str, Any]:
        """计算综合风险评分"""
        if not assessments:
            return {'score': 0, 'level': 'none'}

        critical = sum(1 for a in assessments if a.migration_urgency == 'critical')
        high = sum(1 for a in assessments if a.migration_urgency == 'high')
        medium = sum(1 for a in assessments if a.migration_urgency == 'medium')

        score = critical * 25 + high * 10 + medium * 5
        score = min(score, 100)

        if score >= 75:
            level = 'critical'
        elif score >= 50:
            level = 'high'
        elif score >= 25:
            level = 'medium'
        elif score > 0:
            level = 'low'
        else:
            level = 'acceptable'

        return {'score': score, 'level': level}

    def _build_migration_plan(self, assessments: List[PQAssessment]) -> List[Dict[str, Any]]:
        """构建迁移计划（按紧急程度排序）"""
        ordered = sorted(
            assessments,
            key=lambda a: (
                {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'none': 4}
                .get(a.migration_urgency, 4)
            )
        )

        plan = []
        for a in ordered:
            if a.migration_urgency == 'none':
                continue

            plan.append({
                'current': a.primitive.algorithm,
                'category': a.primitive.category,
                'urgency': a.migration_urgency,
                'recommended': a.recommended_replacement or '需手动评估',
                'action': self._suggest_action(a),
            })

        return plan

    def _suggest_action(self, a: PQAssessment) -> str:
        if a.migration_urgency == 'critical':
            return f"立即将 {a.primitive.algorithm} 替换为 {a.recommended_replacement or 'PQC 方案'}"
        if a.migration_urgency == 'high':
            return f"制定迁移时间表，在下一版本中替换 {a.primitive.algorithm}"
        if a.migration_urgency == 'low':
            return f"持续监控 {a.primitive.algorithm} 的量子威胁进展"
        return "无需立即行动"


def audit_pq_readiness(
    strings: List[str],
    imports: Optional[Dict[str, List[str]]] = None,
    data: Optional[bytes] = None
) -> Dict[str, Any]:
    """
    便捷函数：后量子密码就绪审计
    
    参考 NIST PQC 标准化进程和 BSI 迁移
    """
    detector = PostQuantumDetector()
    return detector.analyze(strings=strings, imports=imports, binary_data=data)
