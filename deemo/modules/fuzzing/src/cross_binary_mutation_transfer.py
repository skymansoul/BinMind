# 初始实现：基于语义特征映射的跨二进制变异策略迁移

"""跨二进制变异迁移 - 将变异策略效能从已知二进制迁移到新目标。

现有变异策略（字节翻转、算术运算、字典替换等）对每个二进制独立学习-
经历数小时的冷启动期才收敛到有效策略。对新的二进制目标，
学到的策略知识全部丢弃，从零开始。

语义特征桥接 (Semantic Feature Bridge, SFB)：
1. 对每个字节偏移量提取语义特征向量（上下文指令类型、所在基本块属性、
   距函数入口距离、数据流角色等），而非仅记录偏移量数值。
2. 训练一个轻量级回归模型，输入语义特征向量，输出该偏移量的变异效能预估。
3. 对新的二进制目标，提取其各偏移量的语义特征向量，
   用已有模型预估变异效能，直接给出高潜力变异位置的初始热图。
4. 新目标的在线反馈持续微调模型（在线迁移学习）。

区别于现有所有方案的要点：
- 不是策略迁移（像迁移强化学习那样搬 policy），
  而是将"什么样的字节位置对变异敏感"这一知识跨二进制泛化。
- 冷启动时间从数小时压缩到数分钟-模型预热后立即可生成变异热图。

技术依据：
- 同一编译器产出的二进制中，"函数序言中的立即数"、
  "跳转表偏移量"、"字符串常量"等语义角色具有跨二进制的结构同源性。
- 语义特征向量捕获这些结构角色，使模型可以泛化。

- "Transfer Learning for Fuzzing" — 迁移种子调度器到新目标。
  与本方案的差异：我们迁移的是变异位置知识，粒度更细。
"""

import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

_TOLERANCE = 1e-9

@dataclass
class ByteOffsetProfile:
    """一个字节偏移量的语义特征画像。"""
    offset: int
    # 上下文语义特征
    instr_type: int = 0          # 所属指令类型编码
    bb_size: int = 0             # 所在基本块指令数
    bb_in_degree: int = 0        # 基本块入度
    bb_out_degree: int = 0       # 基本块出度
    dist_from_entry: int = 0     # 距函数入口距离（指令数）
    is_immediate: bool = False   # 是否是立即数字节
    is_displacement: bool = False  # 是否是地址偏移字节
    is_string_byte: bool = False # 是否是字符串常量字节
    data_ref_count: int = 0      # 被多少条指令引用
    entropy_local: float = 0.0   # 局部字节熵

    def to_feature_vector(self) -> List[float]:
        """转为 10 维归一化特征向量。"""
        return [
            self.instr_type / 256.0,
            min(1.0, self.bb_size / 64.0),
            min(1.0, self.bb_in_degree / 10.0),
            min(1.0, self.bb_out_degree / 10.0),
            min(1.0, self.dist_from_entry / 500.0),
            1.0 if self.is_immediate else 0.0,
            1.0 if self.is_displacement else 0.0,
            1.0 if self.is_string_byte else 0.0,
            min(1.0, self.data_ref_count / 20.0),
            self.entropy_local,
        ]

@dataclass
class OffsetFeedback:
    """一个字节偏移的变异效能反馈。"""
    offset: int
    profile: ByteOffsetProfile
    mutation_attempts: int = 0
    coverage_gains: int = 0      # 累计新边数
    crash_triggers: int = 0
    efficacy_score: float = 0.0  # [0, 1] 变异效能

class SemanticFeatureBridge:
    """语义特征桥接器-字节偏移的语义画像提取。

    将二进制中的每个字节位置映射到语义特征空间，
    使不同二进制的"相似角色"字节在特征空间中相邻。
    """

    def profile_offset(
        self,
        offset: int,
        section_info: Optional[Dict[str, Any]] = None,
    ) -> ByteOffsetProfile:
        """为单个字节偏移量构建语义画像。

        实际集成需要反汇编器（如 capstone）来获取指令类型、
        基本块属性等。此处提供推断逻辑的参考实现。
        """
        _info = section_info or {}
        _bb = _info.get("basic_block", {})
        _instr = _info.get("instruction", {})

        _local_bytes = _info.get("local_context", b"")
        _entropy = _byte_entropy(_local_bytes) if _local_bytes else 0.0

        return ByteOffsetProfile(
            offset=offset,
            instr_type=_instr.get("type_id", 0),
            bb_size=_bb.get("size", 0),
            bb_in_degree=_bb.get("in_degree", 0),
            bb_out_degree=_bb.get("out_degree", 0),
            dist_from_entry=_instr.get("dist_from_entry", 0),
            is_immediate=_instr.get("has_immediate", False),
            is_displacement=_instr.get("has_displacement", False),
            is_string_byte=_info.get("in_string_section", False),
            data_ref_count=_info.get("data_xref_count", 0),
            entropy_local=_entropy,
        )

class CrossBinaryMutationTransfer:
    """跨二进制变异效能迁移器。

    使用范式：
      cbm = CrossBinaryMutationTransfer()
      cbm.learn_from_binary("binary_A", offset_profiles, feedbacks)
      # 对新目标生成变异热图
      hotmap = cbm.predict_hotmap(new_binary_profiles)
    """

    def __init__(
        self,
        feature_dim: int = 10,
        learning_rate: float = 0.05,
        regularization: float = 0.01,
    ):
        self.feature_dim = feature_dim
        self.learning_rate = learning_rate
        self.regularization = regularization

        # 线性回归权重：w^T · x -> efficacy_score
        self._weights: List[float] = [0.0] * feature_dim
        self._bias: float = 0.0
        # 在线学习统计
        self._total_updates: int = 0
        # 已学习过的二进制标识
        self._learned_binaries: Set[str] = set()
        # 全局反馈池
        self._global_feedbacks: List[OffsetFeedback] = []

    def learn_from_binary(
        self,
        binary_id: str,
        profiles: Dict[int, ByteOffsetProfile],
        feedbacks: List[OffsetFeedback],
    ):
        """从一个二进制的变异反馈中在线学习。

        更新模型参数使得预测效能逼近真实效能。
        """
        if binary_id in self._learned_binaries:
            return  # 避免重复学习
        self._learned_binaries.add(binary_id)

        for _fb in feedbacks:
            self._global_feedbacks.append(_fb)
            self._online_update(_fb)

    def predict_hotmap(
        self, profiles: Dict[int, ByteOffsetProfile]
    ) -> Dict[int, float]:
        """对新目标二进制生成变异热图。

        返回：{offset: predicted_efficacy_score}。
        score 越高 -> 该位置被预测为变异高潜力点。
        """
        _hotmap: Dict[int, float] = {}
        for _offset, _profile in profiles.items():
            _feat = _profile.to_feature_vector()
            _score = self._predict_single(_feat)
            _hotmap[_offset] = max(0.0, min(1.0, _score))
        return _hotmap

    def transfer_knowledge(
        self,
        target_profiles: Dict[int, ByteOffsetProfile],
        top_k: int = 100,
    ) -> List[int]:
        """将学到的知识迁移到新目标-返回 top-k 推荐变异偏移量。

        这些偏移量是预估变异效能最高的位置，
        可在 fuzzing 初期直接作为变异热区。
        """
        _hotmap = self.predict_hotmap(target_profiles)
        _sorted = sorted(_hotmap.items(), key=lambda x: x[1], reverse=True)
        return [offset for offset, _ in _sorted[:top_k]]

    def get_feature_importance(self) -> Dict[str, float]:
        """返回各语义特征的相对重要性。

        可用于解释模型为何推荐某些偏移量-
        例如"立即数字节对变异的敏感性权重最高"。
        """
        _names = [
            "instr_type", "bb_size", "bb_in_degree", "bb_out_degree",
            "dist_from_entry", "is_immediate", "is_displacement",
            "is_string_byte", "data_ref_count", "entropy_local",
        ]
        _abs_w = [abs(w) for w in self._weights]
        _total = sum(_abs_w) + _TOLERANCE
        return {_names[i]: _abs_w[i] / _total for i in range(len(_names))}

    # 内部

    def _predict_single(self, features: List[float]) -> float:
        """线性预测 + sigmoid 激活。"""
        _z = self._bias
        for _i in range(min(len(features), len(self._weights))):
            _z += self._weights[_i] * features[_i]
        return 1.0 / (1.0 + math.exp(-_z))

    def _online_update(self, feedback: OffsetFeedback):
        """SGD 在线更新-对新目标的反馈持续微调模型。"""
        _feat = feedback.profile.to_feature_vector()
        _pred = self._predict_single(_feat)
        _target = feedback.efficacy_score
        _error = _pred - _target

        # SGD with L2 regularization
        for _i in range(min(len(_feat), len(self._weights))):
            _grad = _error * _feat[_i] + self.regularization * self._weights[_i]
            self._weights[_i] -= self.learning_rate * _grad

        self._bias -= self.learning_rate * _error
        self._total_updates += 1

    @property
    def is_warm(self) -> bool:
        """模型是否已预热到可迁移状态。"""
        return self._total_updates >= 50 and len(self._learned_binaries) >= 1

class GaussianProcessTransfer(CrossBinaryMutationTransfer):
    """GP增强的跨二进制迁移-用非参数贝叶斯回归替代线性模型。

    在CrossBinaryMutationTransfer的线性回归之上叠加GP层：
    1. 保留线性回归作为均值函数（先验趋势）。
    2. GP核建模残差的局部相关性-相似的字节偏移产生相似的残差。
    3. 对新二进制，GP输出预测均值+方差-方差高=高不确定性->优先探索。
    4. Expected Improvement (EI) 采集函数指导主动采样：
       自动选择"高预测效能+高不确定性"的字节偏移进行优先变异。

    复杂度: 训练O(N³)来自GP矩阵求逆。N<200时可在<10ms内完成。
    对更大的N，采用诱导点稀疏近似（N_inducing=50）。
    """

    def __init__(self, feature_dim=10, learning_rate=0.05, gp_lengthscale=0.5,
                 gp_noise=0.01, n_inducing=50):
        super().__init__(feature_dim, learning_rate)
        self.gp_lengthscale = gp_lengthscale
        self.gp_noise = gp_noise
        self.n_inducing = n_inducing
        # GP训练数据
        self._gp_X: List[List[float]] = []  # 特征向量
        self._gp_y: List[float] = []        # 残差 = 实际效能 - 线性预测
        self._K_inv: Optional[List[List[float]]] = None  # 核矩阵的逆

    def predict_with_uncertainty(
        self, profile: ByteOffsetProfile,
    ) -> Tuple[float, float]:
        """GP预测-返回(均值, 标准差)。

        均值 = 线性预测 + GP残差修正。
        方差来自GP后验-邻近训练点->低方差，远离->高方差。
        """
        _feat = profile.to_feature_vector()
        _linear_pred = self._predict_single(_feat)

        if not self._gp_X or self._K_inv is None:
            return max(0.0, min(1.0, _linear_pred)), 0.3  # 无GP数据时默认高不确定

        # 核向量 k_* = K(X_train, x_test)
        _k_star = [self._rbf_kernel(_feat, _xi) for _xi in self._gp_X]

        # GP后验均值修正
        _correction = sum(
            _k_star[_i] * sum(
                self._K_inv[_i][_j] * (self._gp_y[_j])
                for _j in range(len(self._gp_y))
            )
            for _i in range(len(self._gp_X))
        )
        _mean = max(0.0, min(1.0, _linear_pred + _correction))

        # GP后验方差
        _k_ss = self._rbf_kernel(_feat, _feat) + self.gp_noise
        _var = _k_ss - sum(
            _k_star[_i] * sum(
                self._K_inv[_i][_j] * _k_star[_j]
                for _j in range(len(self._gp_X))
            )
            for _i in range(len(self._gp_X))
        )
        _std = math.sqrt(max(0.0, _var))

        return _mean, _std

    def expected_improvement(
        self, profile: ByteOffsetProfile, best_observed: float = 0.0,
    ) -> float:
        """Expected Improvement (EI) 采集函数。

        EI(x) = E[max(0, f(x) - best_observed)]
        高EI值意味着该点可能显著超越当前最优-应优先变异。
        """
        _mean, _std = self.predict_with_uncertainty(profile)
        if _std < _TOLERANCE:
            return 0.0

        _improvement = _mean - best_observed
        _z = _improvement / _std
        # EI = σ * (z*Φ(z) + φ(z))
        _cdf = 0.5 * (1.0 + math.erf(_z / math.sqrt(2.0))) if abs(_z) < 6.0 else (1.0 if _z > 0 else 0.0)
        _pdf = math.exp(-0.5 * _z * _z) / math.sqrt(2.0 * math.pi)
        return _std * (_z * _cdf + _pdf)

    def update_gp(self, profile: ByteOffsetProfile, true_efficacy: float):
        """用新的观测更新GP训练数据。"""
        _feat = profile.to_feature_vector()
        _linear_pred = self._predict_single(_feat)
        _residual = true_efficacy - _linear_pred

        self._gp_X.append(_feat)
        self._gp_y.append(_residual)

        # 稀疏化：若超过n_inducing，用最远点采样保留代表性子集
        if len(self._gp_X) > self.n_inducing:
            self._sparsify_gp()

        # 重新计算核矩阵逆
        self._K_inv = self._compute_K_inv()

    def _rbf_kernel(self, a: List[float], b: List[float]) -> float:
        """平方指数核-k(a,b) = exp(-||a-b||² / (2ℓ²))。"""
        _sq_dist = sum((ai - bi) ** 2 for ai, bi in zip(a, b))
        return math.exp(-_sq_dist / (2.0 * self.gp_lengthscale ** 2))

    def _compute_K_inv(self) -> Optional[List[List[float]]]:
        """计算 (K + σ²I)⁻¹ -Cholesky分解求逆。"""
        _n = len(self._gp_X)
        if _n == 0:
            return None

        # 构建K + σ²I
        _K = [[0.0] * _n for _ in range(_n)]
        for _i in range(_n):
            for _j in range(_n):
                _K[_i][_j] = self._rbf_kernel(self._gp_X[_i], self._gp_X[_j])
                if _i == _j:
                    _K[_i][_j] += self.gp_noise

        # Cholesky分解: K = L @ L^T
        _L = [[0.0] * _n for _ in range(_n)]
        for _i in range(_n):
            for _j in range(_i + 1):
                _sum = sum(_L[_i][_k] * _L[_j][_k] for _k in range(_j))
                if _i == _j:
                    _L[_i][_j] = math.sqrt(max(_TOLERANCE, _K[_i][_i] - _sum))
                else:
                    _L[_i][_j] = (_K[_i][_j] - _sum) / max(_L[_j][_j], _TOLERANCE)

        # 求逆: 先用前代后代解 L@L^T @ K_inv = I
        _n = len(_L)
        _inv = [[1.0 if i == j else 0.0 for j in range(_n)] for i in range(_n)]
        # 前代 L @ Y = I -> Y
        for _col in range(_n):
            for _i in range(_n):
                _sum = sum(_L[_i][_k] * _inv[_k][_col] for _k in range(_i))
                _inv[_i][_col] = (_inv[_i][_col] - _sum) / max(_L[_i][_i], _TOLERANCE)
        # 后代 L^T @ K_inv = Y -> K_inv
        for _col in range(_n):
            for _i in range(_n - 1, -1, -1):
                _sum = sum(_L[_k][_i] * _inv[_k][_col] for _k in range(_i + 1, _n))
                _inv[_i][_col] = (_inv[_i][_col] - _sum) / max(_L[_i][_i], _TOLERANCE)

        return _inv

    def _sparsify_gp(self):
        """最远点采样-保留最具代表性的诱导点子集。"""
        if len(self._gp_X) <= self.n_inducing:
            return
        _selected = [0]
        _distances = [float('inf')] * len(self._gp_X)
        while len(_selected) < self.n_inducing:
            _last = _selected[-1]
            for _i in range(len(self._gp_X)):
                _d = sum((a - b) ** 2 for a, b in zip(self._gp_X[_i], self._gp_X[_last]))
                _distances[_i] = min(_distances[_i], _d)
            _next = max(
                (i for i in range(len(self._gp_X)) if i not in _selected),
                key=lambda i: _distances[i],
            )
            _selected.append(_next)
        self._gp_X = [self._gp_X[i] for i in _selected]
        self._gp_y = [self._gp_y[i] for i in _selected]

def _byte_entropy(data: bytes) -> float:
    """计算字节序列的 Shannon 熵（归一化到 [0, 1]）。"""
    if not data:
        return 0.0
    _counts: Dict[int, int] = defaultdict(int)
    for _b in data:
        _counts[_b] += 1
    _n = len(data)
    _h = 0.0
    for _c in _counts.values():
        _p = _c / _n
        _h -= _p * math.log2(_p)
    return _h / 8.0  # 归一化到 [0,1]

# 冒烟测试
def _smoke_test():
    import random
    random.seed(42)

    _sfb = SemanticFeatureBridge()
    _cbm = CrossBinaryMutationTransfer()

    # 模拟二进制 A 的变异反馈
    _profiles_a: Dict[int, ByteOffsetProfile] = {}
    _feedbacks_a: List[OffsetFeedback] = []
    for _off in range(200):
        _info = {
            "instruction": {
                "type_id": _off % 50,
                "dist_from_entry": _off * 4,
                "has_immediate": (_off % 7 == 0),
                "has_displacement": (_off % 11 == 0),
            },
            "basic_block": {
                "size": 3 + (_off % 20),
                "in_degree": _off % 5,
                "out_degree": 1 + (_off % 3),
            },
            "in_string_section": (_off > 150),
            "data_xref_count": _off % 8,
            "local_context": bytes([random.randint(0, 255) for _ in range(16)]),
        }
        _prof = _sfb.profile_offset(_off, _info)
        _profiles_a[_off] = _prof

        # 模拟效能：立即数字节和字符串字节的变异效能更高
        _true_efficacy = 0.1
        if _prof.is_immediate:
            _true_efficacy = 0.7 + random.random() * 0.2
        elif _prof.is_string_byte:
            _true_efficacy = 0.5 + random.random() * 0.3
        elif _prof.is_displacement:
            _true_efficacy = 0.4 + random.random() * 0.3

        _fb = OffsetFeedback(
            offset=_off, profile=_prof,
            mutation_attempts=10, coverage_gains=int(_true_efficacy * 5),
            efficacy_score=_true_efficacy,
        )
        _feedbacks_a.append(_fb)

    _cbm.learn_from_binary("binary_A", _profiles_a, _feedbacks_a)
    assert _cbm.is_warm, "should be warm after learning"

    # 对新目标 binary_B 生成热图
    _profiles_b: Dict[int, ByteOffsetProfile] = {}
    for _off in range(100):
        _info = {
            "instruction": {
                "type_id": (_off * 3) % 50,
                "dist_from_entry": _off * 4 + 16,
                "has_immediate": (_off % 7 == 0),
                "has_displacement": (_off % 11 == 1),
            },
            "basic_block": {"size": 4 + (_off % 15), "in_degree": _off % 4, "out_degree": _off % 3},
            "in_string_section": (_off > 80),
            "data_xref_count": (_off * 2) % 8,
            "local_context": bytes([random.randint(0, 255) for _ in range(16)]),
        }
        _profiles_b[_off] = _sfb.profile_offset(_off, _info)

    _hotmap = _cbm.predict_hotmap(_profiles_b)
    _top_k = _cbm.transfer_knowledge(_profiles_b, top_k=20)

    print(f"[xfer] predicted hotmap for binary_B: {len(_hotmap)} offsets")
    print(f"[xfer] top-5 recommended offsets: {_top_k[:5]}")
    # 立即数字节应出现在 top-k 中
    _imm_offsets = [o for o in _profiles_b if _profiles_b[o].is_immediate]
    _top_set = set(_top_k)
    _imm_in_top = len([o for o in _imm_offsets if o in _top_set])
    print(f"[xfer] immediate offsets in top-20: {_imm_in_top}/{len(_imm_offsets)}")

    _importance = _cbm.get_feature_importance()
    print(f"[xfer] top-3 feature importance: {sorted(_importance.items(), key=lambda x: x[1], reverse=True)[:3]}")

    assert _cbm._total_updates > 0, "should have performed updates"
    assert len(_top_k) == 20, "should return exactly top_k offsets"
    print("[OK] CrossBinaryMutationTransfer smoke test passed.")

    # GP增强测试
    _gp = GaussianProcessTransfer(feature_dim=10, n_inducing=15)
    _gp.learn_from_binary("binary_A", _profiles_a, _feedbacks_a)

    # 用GP预测+不确定性
    _test_off = 0
    _test_prof = _profiles_b.get(0)
    if _test_prof:
        _mean, _std = _gp.predict_with_uncertainty(_test_prof)
        _ei = _gp.expected_improvement(_test_prof, best_observed=0.5)
        print(f"[gp_xfer] GP prediction: mean={_mean:.3f} std={_std:.3f} EI={_ei:.3f}")
        assert _std > 0, "GP should provide uncertainty estimate"

        # 更新GP后重新预测
        _gp.update_gp(_test_prof, 0.65)
        _mean2, _std2 = _gp.predict_with_uncertainty(_test_prof)
        print(f"[gp_xfer] after update: mean={_mean2:.3f} std={_std2:.3f}")
        assert _std2 < _std, "uncertainty should decrease after observation"

    print("[OK] GaussianProcessTransfer smoke test passed.")

if __name__ == "__main__":
    _smoke_test()
