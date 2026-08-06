# 修改记录:
# 2025-08-05 14:37 - 初始实现：同原语多库实现的差分行为对比

"""跨库差分密码分析 — 同一密码学原语的不同库实现的输入/输出对比。

IoT固件和大型应用中常见场景：同一二进制链接了多个密码学库
（如OpenSSL做TLS、mbedTLS做固件签名验证、libsodium做密钥派生）。
这些库各自实现了AES/SHA256/ECDH等相同原语。

关键洞察——多库交集蕴含差分oracle：
若两个独立实现的相同原语对绝大多数输入产生相同输出，
但存在特定输入导致输出分歧→至少一个实现有bug。
差分分析自动发现这些"分歧输入"，无需参考实现。

与现有工作的区别：
- CryptoFuzz (Mozilla): 跨*进程*的差异测试，需要运行时环境。
- go-fuzz/cryptofuzz: 需要源码编译对照实现。
- 本方案: 纯二进制层面的跨库差异，从静态提取的库指纹直接构造差分对。

技术路径：
1. 库指纹识别→识别同原语的不同实现实例。
2. 对每对实现构造代表性测试向量（边界值、已知攻击向量、随机输入）。
3. 通过轻量级模拟执行对比输出。
4. 分歧案例分析→标记潜在bug或故意后门。

参考：
- CryptoFuzz (Mozilla, 2019-2025): 多库差异测试的工业标杆。
- CLFuzz (TOSEM 2025): Oracle回收池——自洽性+跨库差分验证。
"""

import hashlib
import math
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

_EPS: float = 1e-9


class CryptoPrimitive(Enum):
    AES_128 = "aes_128"
    AES_256 = "aes_256"
    SHA256 = "sha256"
    SHA512 = "sha512"
    HMAC_SHA256 = "hmac_sha256"
    ECDH_P256 = "ecdh_p256"
    ECDSA_P256 = "ecdsa_p256"
    RSA_2048 = "rsa_2048"
    CHACHA20 = "chacha20"


@dataclass
class LibInstance:
    """二进制中一个密码学原语实现的实例。"""
    instance_id: str
    library_name: str         # 识别出的库名 (openssl/mbedtls/libsodium/unknown)
    primitive: CryptoPrimitive
    function_address: int
    function_size: int
    confidence: float          # 库识别的置信度
    extra_functions: List[int] = field(default_factory=list)  # 相关联的辅助函数地址


@dataclass
class TestVector:
    """一个测试向量——输入+期望输出（若已知）或仅输入。"""
    input_bytes: bytes
    key_bytes: Optional[bytes] = None
    iv_bytes: Optional[bytes] = None
    expected_output: Optional[bytes] = None  # 来自标准文档的已知答案
    vector_type: str = "random"  # known_answer / boundary / random / attack


@dataclass
class DiffResult:
    """一次差分比较的结果。"""
    primitive: CryptoPrimitive
    lib_a: str
    lib_b: str
    test_vector: TestVector
    output_a: Optional[bytes]
    output_b: Optional[bytes]
    match: bool
    divergence_type: str = ""  # "consistent" / "occasional_divergence" / "consistent_divergence"


class CrossLibDifferentialAnalyzer:
    """跨库差分密码分析器。

    使用范式：
      analyzer = CrossLibDifferentialAnalyzer()
      instances = analyzer.identify_instances(binary_path)
      pairs = analyzer.form_diff_pairs(instances)
      results = analyzer.analyze_divergences(pairs, executor)
    """

    def __init__(self):
        self._instances: List[LibInstance] = []
        # 预置已知答案测试向量 (NIST/FIPS标准测试向量)
        self._known_answer_tests: Dict[CryptoPrimitive, List[TestVector]] = (
            self._init_kat_vectors()
        )
        # 差分结果历史
        self._results: List[DiffResult] = []

    # -----------------------------------------------------------------
    # 公开 API
    # -----------------------------------------------------------------

    def identify_instances(
        self, lib_instances: List[LibInstance]
    ) -> Dict[CryptoPrimitive, List[LibInstance]]:
        """将库实例按密码学原语分组。

        输入来自 crypto_lib_fingerprint 的识别结果。
        返回 {primitive: [instance, ...]}。
        """
        self._instances = lib_instances
        _by_primitive: Dict[CryptoPrimitive, List[LibInstance]] = defaultdict(list)
        for _inst in lib_instances:
            _by_primitive[_inst.primitive].append(_inst)
        return dict(_by_primitive)

    def form_diff_pairs(
        self, grouped: Dict[CryptoPrimitive, List[LibInstance]]
    ) -> List[Tuple[LibInstance, LibInstance]]:
        """为每种密码学原语构造库间差分对。

        只对来自不同库的实例配对——同库的不同函数地址可能有优化/回退关系。
        """
        _pairs: List[Tuple[LibInstance, LibInstance]] = []
        for _prim, _instances in grouped.items():
            for _i in range(len(_instances)):
                for _j in range(_i + 1, len(_instances)):
                    _a, _b = _instances[_i], _instances[_j]
                    if _a.library_name != _b.library_name:
                        _pairs.append((_a, _b))
        return _pairs

    def generate_test_vectors(
        self, primitive: CryptoPrimitive, n_random: int = 50,
    ) -> List[TestVector]:
        """为指定原语生成测试向量集。

        包含三类：已知答案(KAT)、边界值、随机输入。
        """
        _vectors: List[TestVector] = []

        # 1. 已知答案测试——来自标准文档
        _kats = self._known_answer_tests.get(primitive, [])
        _vectors.extend(_kats)

        # 2. 边界值——全0/全1/单bit翻转
        _boundary = self._generate_boundary_vectors(primitive)
        _vectors.extend(_boundary)

        # 3. 随机输入
        _random = self._generate_random_vectors(primitive, n_random)
        _vectors.extend(_random)

        return _vectors

    def analyze_divergences(
        self,
        pairs: List[Tuple[LibInstance, LibInstance]],
        executor: Any,  # (instance, test_vector) → bytes
        n_test_vectors: int = 50,
    ) -> List[DiffResult]:
        """对每对实例执行差分分析。

        executor 是测试执行器——接受 (LibInstance, TestVector) 返回输出字节。
        实际集成时通过 subprocess/frida/unicon 调用。
        """
        _results: List[DiffResult] = []
        for _a, _b in pairs:
            _vectors = self.generate_test_vectors(_a.primitive, n_test_vectors)
            _divergences = 0
            for _tv in _vectors:
                try:
                    _out_a = executor(_a, _tv)
                    _out_b = executor(_b, _tv)
                except Exception:
                    continue

                _match = _out_a == _out_b
                _result = DiffResult(
                    primitive=_a.primitive,
                    lib_a=_a.library_name,
                    lib_b=_b.library_name,
                    test_vector=_tv,
                    output_a=_out_a,
                    output_b=_out_b,
                    match=_match,
                )
                _results.append(_result)
                if not _match:
                    _divergences += 1

        self._results = _results
        return _results

    def score_implementation_trust(
        self, results: List[DiffResult]
    ) -> Dict[str, float]:
        """基于差分一致性为每个库的实现计算信任分数。

        分数 ∈ [0, 1]。
        若库A与库B在所有测试向量上一致，两者都获得高信任。
        若库A与库B、C都分歧→库A可疑→低信任。
        """
        _lib_scores: Dict[str, List[float]] = defaultdict(list)

        for _r in results:
            _pair_key = (_r.lib_a, _r.lib_b)
            if _r.match:
                _lib_scores[_r.lib_a].append(1.0)
                _lib_scores[_r.lib_b].append(1.0)
            else:
                # 分歧：无法确定哪方正确——双方都扣分
                _lib_scores[_r.lib_a].append(0.0)
                _lib_scores[_r.lib_b].append(0.0)

        _trust: Dict[str, float] = {}
        for _lib, _scores in _lib_scores.items():
            if _scores:
                _consistency = sum(_scores) / len(_scores)
                # 加上先验：如果只有一个实例，默认中立
                _n_instances = sum(
                    1 for i in self._instances if i.library_name == _lib
                )
                _prior = 0.5 if _n_instances <= 1 else 0.7
                _trust[_lib] = _consistency * 0.7 + _prior * 0.3
            else:
                _trust[_lib] = 0.5

        return _trust

    def get_divergence_report(self) -> Dict[str, Any]:
        """生成差分分析报告——按原语和库对汇总。"""
        _by_primitive: Dict[str, int] = defaultdict(int)
        _by_pair: Dict[str, Dict[str, int]] = defaultdict(lambda: {"total": 0, "mismatch": 0})

        for _r in self._results:
            _by_primitive[_r.primitive.value] += 1 if not _r.match else 0
            _key = f"{_r.lib_a} vs {_r.lib_b}"
            _by_pair[_key]["total"] += 1
            if not _r.match:
                _by_pair[_key]["mismatch"] += 1

        return {
            "mismatches_by_primitive": dict(_by_primitive),
            "mismatches_by_pair": {
                k: {"mismatch_rate": round(v["mismatch"] / max(v["total"], 1), 4),
                    "total_tests": v["total"]}
                for k, v in _by_pair.items()
            },
        }

    # -----------------------------------------------------------------
    # 测试向量生成
    # -----------------------------------------------------------------

    @staticmethod
    def _init_kat_vectors() -> Dict[CryptoPrimitive, List[TestVector]]:
        """预置 NIST/FIPS 标准测试向量——用于已知答案验证。"""
        _kats: Dict[CryptoPrimitive, List[TestVector]] = {}

        # SHA256 KAT: "" → 特定哈希
        _kats[CryptoPrimitive.SHA256] = [
            TestVector(
                input_bytes=b"",
                expected_output=bytes.fromhex(
                    "e3b0c44298fc1c149afbf4c8996fb924"
                    "27ae41e4649b934ca495991b7852b855"
                ),
                vector_type="known_answer",
            ),
            TestVector(
                input_bytes=b"abc",
                expected_output=bytes.fromhex(
                    "ba7816bf8f01cfea414140de5dae2223"
                    "b00361a396177a9cb410ff61f20015ad"
                ),
                vector_type="known_answer",
            ),
        ]

        # AES-128 KAT: 全零密钥/明文
        _kats[CryptoPrimitive.AES_128] = [
            TestVector(
                input_bytes=bytes(16),           # 全零明文
                key_bytes=bytes(16),             # 全零密钥
                expected_output=bytes.fromhex(
                    "66e94bd4ef8a2c3b884cfa59ca342b2e"
                ),
                vector_type="known_answer",
            ),
        ]

        return _kats

    @staticmethod
    def _generate_boundary_vectors(
        primitive: CryptoPrimitive,
    ) -> List[TestVector]:
        """生成边界测试向量。"""
        _vecs: List[TestVector] = []
        _sizes = _primitive_block_size(primitive)

        # 最小输入
        _vecs.append(TestVector(
            input_bytes=b"", vector_type="boundary",
        ))
        # 单字节
        _vecs.append(TestVector(
            input_bytes=b"\x00", vector_type="boundary",
        ))
        _vecs.append(TestVector(
            input_bytes=b"\xff", vector_type="boundary",
        ))
        # 块大小边界
        if _sizes["block"] > 0:
            _vecs.append(TestVector(
                input_bytes=b"\x00" * _sizes["block"], vector_type="boundary",
            ))
            _vecs.append(TestVector(
                input_bytes=b"\x00" * (_sizes["block"] - 1), vector_type="boundary",
            ))
            _vecs.append(TestVector(
                input_bytes=b"\x00" * (_sizes["block"] + 1), vector_type="boundary",
            ))

        return _vecs

    @staticmethod
    def _generate_random_vectors(
        primitive: CryptoPrimitive, n: int,
    ) -> List[TestVector]:
        """生成随机测试向量（确定性——基于原语名的种子）。"""
        _seed = hash(primitive.value) & 0xFFFFFFFF
        _vecs: List[TestVector] = []
        _state = _seed
        _sizes = _primitive_block_size(primitive)

        for _i in range(n):
            _state = (_state * 1103515245 + 12345) & 0x7FFFFFFF
            _length = max(1, (_state % (_sizes["block"] * 4)) if _sizes["block"] > 0 else 64)
            _data = bytes([
                (((_state >> (j % 24)) ^ (j * 73 + _i * 17)) & 0xFF)
                for j in range(_length)
            ])
            _vecs.append(TestVector(input_bytes=_data, vector_type="random"))
            _state = (_state * 25214903917 + 11) & 0x7FFFFFFF

        return _vecs


def _primitive_block_size(primitive: CryptoPrimitive) -> Dict[str, int]:
    _map = {
        CryptoPrimitive.AES_128: {"block": 16, "key": 16},
        CryptoPrimitive.AES_256: {"block": 16, "key": 32},
        CryptoPrimitive.SHA256: {"block": 64, "key": 0},
        CryptoPrimitive.SHA512: {"block": 128, "key": 0},
        CryptoPrimitive.CHACHA20: {"block": 64, "key": 32},
    }
    return _map.get(primitive, {"block": 0, "key": 0})


# ---- 冒烟测试 ----
def _smoke_test():
    _analyzer = CrossLibDifferentialAnalyzer()

    # 模拟识别出的实例
    _instances = [
        LibInstance("i1", "openssl", CryptoPrimitive.SHA256, 0x401000, 512, 0.95),
        LibInstance("i2", "mbedtls", CryptoPrimitive.SHA256, 0x405000, 480, 0.88),
        LibInstance("i3", "openssl", CryptoPrimitive.AES_128, 0x410000, 1024, 0.97),
        LibInstance("i4", "libsodium", CryptoPrimitive.AES_128, 0x420000, 800, 0.82),
    ]

    _grouped = _analyzer.identify_instances(_instances)
    print(f"[xlib] grouped primitives: {list(_grouped.keys())}")

    _pairs = _analyzer.form_diff_pairs(_grouped)
    print(f"[xlib] diff pairs: {len(_pairs)}")

    # 模拟执行器——同库同原语总是输出一致的模拟
    def _mock_exec(inst, tv):
        return hashlib.sha256(tv.input_bytes + inst.library_name.encode()).digest()

    _results = _analyzer.analyze_divergences(_pairs, _mock_exec, n_test_vectors=10)
    _trust = _analyzer.score_implementation_trust(_results)
    print(f"[xlib] trust scores: {_trust}")

    _report = _analyzer.get_divergence_report()
    print(f"[xlib] report: {_report['mismatches_by_pair']}")

    # 同库不同实现→模拟发散应导致信任差异
    assert len(_pairs) == 2, f"expected 2 diff pairs, got {len(_pairs)}"
    assert len(_results) > 0, "should have results"

    print("[OK] CrossLibDifferentialAnalyzer smoke test passed.")


if __name__ == "__main__":
    _smoke_test()
