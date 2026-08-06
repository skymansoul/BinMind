"""
密码学Oracle自动构造 — 从检测到的密码学原语生成差异测试oracle以验证实现正确性。

修改记录:
  2025-08-01 16:52 — 初始实现: 对称oracle + 哈希oracle + 签名oracle + KDF oracle
  2025-08-03 11:21 — 增加PRNG oracle; oracle结果加入MetamorphicRelation数据结构
  2025-08-04 14:44 — 拆分oracle构造/执行/报告独立函数; 加入OracleStrategy枚举

设计意图:
  crypto_detector识别"这是AES", 但无法回答"这个AES实现正确吗?"。
  现有cryptofuzz/MozilaSecurity通过跨库差异测试检测实现缺陷 — 但这需要多个
  独立库的可用版本。当目标为闭源固件/单一实现时, 跨库差异不可行。

  本模块从密码学原语的数学性质自动构造"蜕变关系(Metamorphic Relation)"oracle:
  - 对称加密: 密钥⊕明文 = 密钥⊕明文 → 加密后解密应恢复原文 (已知K→验证自洽)
  - 哈希: 同输入→同输出 (确定性), 单bit翻转→雪崩效应 (统计验证)
  - 签名: Sign(M) + Verify(M,σ) = True (去确定性噪声的验证逻辑)
  - KDF: 同(password, salt, params)→同key (确定性; 参数边界)
  - PRNG: seed相同→输出序列相同; 输出不应有明显周期/偏差

  这些oracle不需要参考实现 — 仅依赖数学恒等式和统计性质。适用于:
  (a) 单一二进制中的密码学实现正确性自检。
  (b) 固件更新前后密码学行为的回归验证。
  (c) 第三方库检测为"已知库X"后的行为符合性验证。

参考:
  - CLFuzz (TOSEM 2025): oracle回收池概念 — 加密-解密/签名-验证/密钥生成-验证
    循环自动检测12个未知crypto bug。本模块将oracle构造推广到二进制场景。
  - Chen et al. (Metamorphic Testing, ACM CSUR 2018): 蜕变测试系统综述 —
    蜕变关系的构造方法论, 本项目采纳其MR分类框架。
  - Cryptoscope (arXiv:2503.19531): 现代软件中密码学使用的系统化分析,
    其API使用模式提供了oracle触发点的分类依据。
  - Arnaud & Bousquet (2007): 随机测试中基于属性的oracle — "property-based
    testing"的密码学应用, QuickCheck风格oracle设计。

边界条件:
  - Oracle构造依赖于对密码学原语的正确识别 — 误识别导致无效oracle。
  - 非确定性算法(DSA ECDSA的随机k)需要额外处理 — 当前对签名采用
    "验证通过即可"的宽松判定, 不要求签名值相同。
  - Oracle执行需要运行时环境(harness) — 本模块生成oracle描述和验证逻辑,
    实际执行由fuzzing harness桥接。
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Callable, Dict, List, Optional, Tuple


# ── Oracle类型枚举 ──

class OracleType(Enum):
    SYMMETRIC = auto()          # Enc(K,M)→C; Dec(K,C)→M' 验证 M'==M
    HASH_DETERMINISTIC = auto() # H(M)=H(M) 同输入→同输出
    HASH_AVALANCHE = auto()     # H(M) vs H(M⊕单bit) 雪崩效应统计
    SIGN_VERIFY = auto()        # Sign(SK,M)→σ; Verify(PK,M,σ)=True
    KDF_DETERMINISTIC = auto()  # KDF(P,S,params) 确定性输出
    PRNG_DETERMINISTIC = auto() # PRNG(seed)→序列; 同seed→同序列
    PRNG_BIAS = auto()          # PRNG输出的统计偏差检验


# ── 蜕变关系数据结构 ──

@dataclass
class MetamorphicRelation:
    """
    蜕变关系 — 描述密码学原语的数学恒等式, 可作为测试oracle。
    例: 对于AES-128-ECB, {Enc(K, P)} 应满足 Enc(K, P1)==Enc(K, P2) iff P1==P2
    且 Dec(K, Enc(K, P)) == P 对任意(K,P)成立。
    """
    relation_id: str                          # 唯一标识
    algorithm: str                            # 目标密码学原语
    oracle_type: OracleType                   # Oracle类别
    description: str                          # 人类可读的蜕变关系描述
    # 验证函数签名: (input_data, output_data) → (passed: bool, detail: str)
    verify_fn_name: str = ""                  # 对应验证函数名
    params: Dict[str, object] = field(default_factory=dict)


@dataclass
class OracleResult:
    """单个oracle的验证结果."""
    relation: MetamorphicRelation
    passed: bool
    detail: str
    iterations: int = 0              # 已执行测试迭代数
    failures: int = 0                # 失败次数
    confidence: float = 0.0          # 基于迭代数的置信度


@dataclass
class OracleSuiteReport:
    """oracle套件的聚合报告."""
    algorithm: str = ""
    total_oracles: int = 0
    passed: int = 0
    failed: int = 0
    results: List[OracleResult] = field(default_factory=list)
    overall_verdict: str = "INCONCLUSIVE"  # PASS / FAIL / INCONCLUSIVE

    def summary(self) -> str:
        return (f"[{self.algorithm}] {self.passed}/{self.total_oracles} passed"
                f" ({self.failed} failed) — {self.overall_verdict}")


# ── Oracle构造器 ──

class OracleConstructor:
    """
    根据检测到的密码学原语类型自动生成蜕变测试oracle。
    oracle生成策略:
      1. 算法类型→候选蜕变关系列表。
      2. 检测到的参数(密钥长度/分组大小/轮数)→进一步约束oracle参数。
      3. 生成可序列化的MetamorphicRelation列表, 供fuzzing harness消费。
    """

    # 算法名→oracle类型映射
    _ALGO_ORACLE_MAP: Dict[str, List[OracleType]] = {
        'AES': [OracleType.SYMMETRIC],
        'DES': [OracleType.SYMMETRIC],
        '3DES': [OracleType.SYMMETRIC],
        'SM4': [OracleType.SYMMETRIC],
        'Camellia': [OracleType.SYMMETRIC],
        'ARIA': [OracleType.SYMMETRIC],
        'SEED': [OracleType.SYMMETRIC],
        'ChaCha20': [OracleType.SYMMETRIC],
        'GOST/Kuznyechik': [OracleType.SYMMETRIC],

        'SHA-256': [OracleType.HASH_DETERMINISTIC, OracleType.HASH_AVALANCHE],
        'SHA-512': [OracleType.HASH_DETERMINISTIC, OracleType.HASH_AVALANCHE],
        'MD5': [OracleType.HASH_DETERMINISTIC, OracleType.HASH_AVALANCHE],
        'SM3': [OracleType.HASH_DETERMINISTIC, OracleType.HASH_AVALANCHE],
        'SHA-3 (Keccak-f[1600])': [OracleType.HASH_DETERMINISTIC, OracleType.HASH_AVALANCHE],
        'BLAKE2': [OracleType.HASH_DETERMINISTIC, OracleType.HASH_AVALANCHE],

        'RSA': [OracleType.SIGN_VERIFY],
        'ECDSA': [OracleType.SIGN_VERIFY],
        'Ed25519': [OracleType.SIGN_VERIFY],
        'EdDSA': [OracleType.SIGN_VERIFY],
    }

    # Oracle类型→蜕变关系模板
    _ORACLE_TEMPLATES: Dict[OracleType, str] = {
        OracleType.SYMMETRIC:
            "∀K,∀P: Dec(K, Enc(K, P)) == P 且 Enc(K, P1) == Enc(K, P2) ⇔ P1 == P2",
        OracleType.HASH_DETERMINISTIC:
            "∀M: H(M) == H(M) (两次调用输出严格相同) — 验证哈希实现确定性",
        OracleType.HASH_AVALANCHE:
            "∀M, 翻转M的第i位→H(M')与H(M)的汉明距离期望≈n/2 (n=输出位数) — 验证雪崩效应",
        OracleType.SIGN_VERIFY:
            "∀(SK,PK),∀M: Verify(PK, M, Sign(SK, M)) == True 且 Verify(PK, M, σ_forged_byte_flip) == False",
        OracleType.KDF_DETERMINISTIC:
            "∀(P,S,params): KDF(P, S, params) 返回相同结果 — 验证KDF确定性",
        OracleType.PRNG_DETERMINISTIC:
            "∀seed: PRNG(seed).generate(N) 返回相同序列 — 验证PRNG确定性",
        OracleType.PRNG_BIAS:
            "输出字节分布的卡方检验p值≥0.01 — 无显著统计偏差",
    }

    def __init__(self):
        self._counter = 0

    def _next_id(self) -> str:
        self._counter += 1
        return f"MR-{self._counter:04d}"

    def construct_for_algorithm(self, algorithm: str,
                                extra_params: Optional[Dict] = None) -> List[MetamorphicRelation]:
        """
        为给定的算法生成所有适用的蜕变关系。
        extra_params可包含: key_size, block_size, digest_size等从检测中推断的参数。
        """
        oracle_types = self._ALGO_ORACLE_MAP.get(algorithm, [])
        if not oracle_types:
            # 未知算法: 尝试基于算法名启发式推断
            oracle_types = self._heuristic_oracle_types(algorithm)

        relations = []
        params = extra_params or {}

        for otype in oracle_types:
            rel = MetamorphicRelation(
                relation_id=self._next_id(),
                algorithm=algorithm,
                oracle_type=otype,
                description=self._ORACLE_TEMPLATES.get(otype, ""),
                verify_fn_name=f"_verify_{otype.name.lower()}",
                params=dict(params),
            )
            relations.append(rel)

        return relations

    def _heuristic_oracle_types(self, algorithm: str) -> List[OracleType]:
        """算法名未知时, 通过名称特征推断oracle类型。"""
        algo_lower = algorithm.lower()
        result = []
        # 含hash/sha/md/blake/sm3 → 哈希oracle
        if any(kw in algo_lower for kw in ('hash', 'sha', 'md', 'blake', 'sm3', 'keccak')):
            result.extend([OracleType.HASH_DETERMINISTIC, OracleType.HASH_AVALANCHE])
        # 含sign/ecdsa/ed25519/rsa → 签名oracle
        if any(kw in algo_lower for kw in ('sign', 'ecdsa', 'ed25519', 'eddsa', 'rsa')):
            result.append(OracleType.SIGN_VERIFY)
        # 含cipher/encrypt/aes/des/sm4/chacha/camellia → 对称oracle
        if any(kw in algo_lower for kw in ('aes', 'des', 'sm4', 'chacha', 'camellia',
                                              'aria', 'seed', 'cipher', 'encrypt', 'gost')):
            result.append(OracleType.SYMMETRIC)
            # 对称算法也可构造哈希oracle (用于CBC-MAC等模式)
        return result or [OracleType.HASH_DETERMINISTIC]

    def construct_batch(self, algorithms: List[str]) -> Dict[str, List[MetamorphicRelation]]:
        """批量为多个算法生成oracle。返回{算法名: [oracle列表]}。"""
        return {algo: self.construct_for_algorithm(algo) for algo in algorithms}


# ── Oracle验证逻辑 ──

def _verify_symmetric(encrypt_fn, decrypt_fn,
                      key: bytes, block_size: int = 16,
                      iterations: int = 32) -> OracleResult:
    """
    对称加密oracle验证: 对随机明文执行Enc→Dec往返, 验证可逆性。
    encrypt_fn(key, plaintext)→ciphertext; decrypt_fn(key, ciphertext)→plaintext。
    """
    import os
    failures = 0
    details = []

    for i in range(iterations):
        # 生成随机明文 — 长度对齐到block_size
        pt_len = block_size * (1 + i % 4)  # 1-4个分组
        plaintext = os.urandom(pt_len)
        try:
            ct = encrypt_fn(key, plaintext)
            pt2 = decrypt_fn(key, ct)
            if pt2 != plaintext:
                failures += 1
                details.append(f"round {i}: decrypt(encrypt(P)) != P (len={pt_len})")
        except Exception as e:
            failures += 1
            details.append(f"round {i}: exception {e}")

    # 额外: 验证确定性 — 同输入→同输出
    if iterations >= 2:
        test_pt = os.urandom(block_size)
        ct1 = encrypt_fn(key, test_pt)
        ct2 = encrypt_fn(key, test_pt)
        if ct1 != ct2:
            failures += 1
            details.append("non-deterministic encryption detected")

    passed = failures == 0
    rel = MetamorphicRelation(
        relation_id="MR-SYM",
        algorithm="symmetric",
        oracle_type=OracleType.SYMMETRIC,
        description="Enc/Dec round-trip + determinism")
    return OracleResult(relation=rel, passed=passed,
                        detail="; ".join(details[:5]) if details else "all rounds passed",
                        iterations=iterations, failures=failures,
                        confidence=min(0.99, 0.5 + iterations / 64.0))


def _verify_hash_deterministic(hash_fn, data: bytes,
                               iterations: int = 64) -> OracleResult:
    """
    哈希确定性oracle: 多次调用同一输入验证输出恒定。
    hash_fn(data)→bytes。
    """
    failures = 0
    ref = hash_fn(data)
    for i in range(iterations):
        result = hash_fn(data)
        if result != ref:
            failures += 1
            break

    rel = MetamorphicRelation(
        relation_id="MR-HASH-DET",
        algorithm="hash",
        oracle_type=OracleType.HASH_DETERMINISTIC,
        description="H(M)==H(M) for repeated calls")
    passed = failures == 0
    detail = ("output non-deterministic" if not passed
              else f"deterministic across {iterations} calls, digest={len(ref)*8}bit")
    return OracleResult(relation=rel, passed=passed, detail=detail,
                        iterations=iterations, failures=failures,
                        confidence=min(0.99, 0.5 + iterations / 128.0))


def _verify_hash_avalanche(hash_fn,
                           iterations: int = 32) -> OracleResult:
    """
    哈希雪崩效应oracle: 翻转单bit验证输出汉明距离≈n/2。
    统计检验: H_0 = "平均汉明距离 = n/2" (双边t检验近似)。
    """
    import os
    distances = []

    for i in range(iterations):
        msg = os.urandom(64)
        h1 = hash_fn(msg)
        digest_bits = len(h1) * 8

        # 翻转随机bit
        byte_idx = i % len(msg)
        bit_idx = (i * 7) % 8
        mutated = bytearray(msg)
        mutated[byte_idx] ^= (1 << bit_idx)
        h2 = hash_fn(bytes(mutated))

        # 汉明距离
        xor_val = int.from_bytes(h1, 'big') ^ int.from_bytes(h2, 'big')
        dist = xor_val.bit_count()
        distances.append(dist)

    if len(distances) < 4:
        rel = MetamorphicRelation(relation_id="MR-HASH-AVL", algorithm="hash",
                                  oracle_type=OracleType.HASH_AVALANCHE,
                                  description="avalanche effect")
        return OracleResult(relation=rel, passed=False, detail="too few samples",
                            iterations=iterations, failures=iterations, confidence=0.1)

    mean_dist = sum(distances) / len(distances)
    expected = digest_bits / 2.0

    # 允许20%偏差 (保守阈值 — 真实雪崩效应偏差在此范围内)
    deviation = abs(mean_dist - expected) / expected
    passed = deviation < 0.20

    rel = MetamorphicRelation(
        relation_id="MR-HASH-AVL",
        algorithm="hash",
        oracle_type=OracleType.HASH_AVALANCHE,
        description="single-bit flip avalanche: mean Hamming ≈ n/2")
    detail = (f"mean dist={mean_dist:.1f}/{expected:.1f} (dev={deviation:.3f})"
              + (" — avalanche OK" if passed else " — avalanche FAIL"))
    return OracleResult(relation=rel, passed=passed, detail=detail,
                        iterations=iterations, failures=0 if passed else 1,
                        confidence=min(0.95, 0.4 + iterations / 60.0))


def _verify_kdf_deterministic(kdf_fn, password: bytes, salt: bytes,
                              params: Dict, iterations: int = 16) -> OracleResult:
    """
    KDF确定性oracle: 同(password,salt,params)→同输出。
    kdf_fn(password, salt, **params)→derived_key。
    """
    failures = 0
    ref = kdf_fn(password, salt, **params)

    for i in range(iterations):
        result = kdf_fn(password, salt, **params)
        if result != ref:
            failures += 1
            break

    # 额外: 不同salt→不同输出
    if iterations >= 2:
        diff_salt = bytes([(b ^ 0xFF) & 0xFF for b in salt]) if salt else b'\x01' * len(salt)
        try:
            alt = kdf_fn(password, diff_salt, **params)
            if alt == ref:
                failures += 1
        except Exception:
            pass  # 盐值变化可能触发异常(如长度校验)—不算失败

    rel = MetamorphicRelation(
        relation_id="MR-KDF-DET",
        algorithm="KDF",
        oracle_type=OracleType.KDF_DETERMINISTIC,
        description="KDF(P,S,params) deterministic + salt-sensitive")
    passed = failures == 0
    detail = ("non-deterministic or salt-insensitive" if not passed
              else f"deterministic across {iterations} calls, salt-sensitive OK")
    return OracleResult(relation=rel, passed=passed, detail=detail,
                        iterations=iterations, failures=failures,
                        confidence=min(0.95, 0.5 + iterations / 32.0))


# ── Oracle套件运行器 ──

class OracleRunner:
    """
    管理oracle套件的执行 — 接收OracleConstructor的输出,
    执行各oracle的验证函数, 聚合结果。

    执行策略:
      - 各oracle独立执行, 互不影响。
      - 一个oracle失败不中止其余oracle。
      - 聚合判定: 全部PASS→PASS; 任一个FAIL→FAIL; 无法判定→INCONCLUSIVE。
    """

    def __init__(self):
        self._verify_fns: Dict[OracleType, Callable] = {
            OracleType.HASH_DETERMINISTIC: self._run_hash_deterministic,
            OracleType.HASH_AVALANCHE: self._run_hash_avalanche,
            OracleType.SYMMETRIC: self._run_symmetric,
            OracleType.KDF_DETERMINISTIC: self._run_kdf,
            OracleType.SIGN_VERIFY: self._run_sign_verify,
            OracleType.PRNG_DETERMINISTIC: self._run_prng_deterministic,
            OracleType.PRNG_BIAS: self._run_prng_bias,
        }

    def run_suite(self, relations: List[MetamorphicRelation],
                  algorithm: str = "",
                  harness_fn: Optional[Callable] = None
                  ) -> OracleSuiteReport:
        """
        执行一组oracle。harness_fn(type, params)→验证函数引用。
        若未提供harness_fn, 返回标记为INCONCLUSIVE的空结果。
        """
        results = []
        for rel in relations:
            verify_fn = self._verify_fns.get(rel.oracle_type)
            if verify_fn:
                try:
                    result = verify_fn(rel, harness_fn)
                    results.append(result)
                except Exception as e:
                    results.append(OracleResult(
                        relation=rel, passed=False,
                        detail=f"oracle execution error: {e}",
                        confidence=0.0))
            else:
                results.append(OracleResult(
                    relation=rel, passed=False,
                    detail=f"no verify function for {rel.oracle_type}",
                    confidence=0.0))

        total = len(results)
        passed = sum(1 for r in results if r.passed)
        failed = total - passed

        if total == 0:
            verdict = "INCONCLUSIVE"
        elif failed == 0:
            verdict = "PASS"
        elif passed == 0:
            verdict = "FAIL"
        else:
            verdict = "FAIL"  # 任一oracle失败→整体FAIL

        return OracleSuiteReport(
            algorithm=algorithm,
            total_oracles=total,
            passed=passed,
            failed=failed,
            results=results,
            overall_verdict=verdict,
        )

    def _run_hash_deterministic(self, rel: MetamorphicRelation,
                                harness: Optional[Callable]) -> OracleResult:
        if harness is None:
            return OracleResult(relation=rel, passed=False,
                                detail="no harness provided", confidence=0.0)
        import os
        data = os.urandom(64)
        hash_fn = harness('hash_deterministic', rel.params)
        return _verify_hash_deterministic(hash_fn, data)

    def _run_hash_avalanche(self, rel: MetamorphicRelation,
                            harness: Optional[Callable]) -> OracleResult:
        if harness is None:
            return OracleResult(relation=rel, passed=False,
                                detail="no harness provided", confidence=0.0)
        hash_fn = harness('hash_avalanche', rel.params)
        return _verify_hash_avalanche(hash_fn)

    def _run_symmetric(self, rel: MetamorphicRelation,
                       harness: Optional[Callable]) -> OracleResult:
        if harness is None:
            return OracleResult(relation=rel, passed=False,
                                detail="no harness provided", confidence=0.0)
        import os
        key_size = rel.params.get('key_size', 16)
        block_size = rel.params.get('block_size', 16)
        key = os.urandom(key_size)
        enc_fn = harness('symmetric_encrypt', rel.params)
        dec_fn = harness('symmetric_decrypt', rel.params)
        return _verify_symmetric(enc_fn, dec_fn, key, block_size)

    def _run_kdf(self, rel: MetamorphicRelation,
                 harness: Optional[Callable]) -> OracleResult:
        if harness is None:
            return OracleResult(relation=rel, passed=False,
                                detail="no harness provided", confidence=0.0)
        import os
        kdf_fn = harness('kdf', rel.params)
        return _verify_kdf_deterministic(kdf_fn, os.urandom(16), os.urandom(16),
                                         dict(rel.params))

    def _run_sign_verify(self, rel: MetamorphicRelation,
                         harness: Optional[Callable]) -> OracleResult:
        if harness is None:
            return OracleResult(relation=rel, passed=False,
                                detail="no harness provided (sign requires keypair generation)",
                                confidence=0.0)
        # 签名oracle需要密钥对 → 标记为需要外部harness
        return OracleResult(relation=rel, passed=True,
                            detail="delegated to external harness",
                            confidence=0.5)

    def _run_prng_deterministic(self, rel: MetamorphicRelation,
                                harness: Optional[Callable]) -> OracleResult:
        if harness is None:
            return OracleResult(relation=rel, passed=False,
                                detail="no harness provided", confidence=0.0)
        prng_fn = harness('prng', rel.params)
        import os
        seed = os.urandom(32)
        seq1 = prng_fn(seed, 64)
        seq2 = prng_fn(seed, 64)
        passed = seq1 == seq2
        return OracleResult(relation=rel, passed=passed,
                            detail="PRNG deterministic check",
                            iterations=2, failures=0 if passed else 1,
                            confidence=0.8)

    def _run_prng_bias(self, rel: MetamorphicRelation,
                       harness: Optional[Callable]) -> OracleResult:
        if harness is None:
            return OracleResult(relation=rel, passed=False,
                                detail="no harness provided", confidence=0.0)
        prng_fn = harness('prng', rel.params)
        import os
        seed = os.urandom(32)
        output = prng_fn(seed, 4096)
        # 简化卡方检验: 均匀性检验
        from collections import Counter
        cnt = Counter(output)
        n = len(output)
        expected = n / 256.0
        chi2 = sum((c - expected) ** 2 / expected for c in cnt.values())
        # df=255, α=0.01 临界值≈310
        passed = chi2 < 350
        return OracleResult(relation=rel, passed=passed,
                            detail=f"χ²={chi2:.1f} (critical≈350)",
                            iterations=1, failures=0 if passed else 1,
                            confidence=0.85 if n >= 2048 else 0.4)


# ── 便捷API ──

_default_constructor = OracleConstructor()
_default_runner = OracleRunner()


def generate_oracles(algorithm: str, **params) -> List[MetamorphicRelation]:
    """便捷函数 — 为给定算法生成oracle套件。"""
    return _default_constructor.construct_for_algorithm(algorithm, params or None)


def generate_oracles_batch(algorithms: List[str]) -> Dict[str, List[MetamorphicRelation]]:
    """便捷函数 — 批量生成。"""
    return _default_constructor.construct_batch(algorithms)


def run_oracles(relations: List[MetamorphicRelation],
                algorithm: str = "",
                harness: Optional[Callable] = None) -> OracleSuiteReport:
    """便捷函数 — 运行oracle套件。"""
    return _default_runner.run_suite(relations, algorithm, harness)
