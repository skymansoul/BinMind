# RedunFuse — 冗余性感知 + 模态缺失鲁棒对比融合
# 设计意图: 模块内现有融合（multi_modal_fusion.py 的静态加权、multi_modal_attention.py 的
#           固定门控）在某一模态缺失或含噪时，融合表征退化、下游置信度骤降。
#           本文件将每个模态特征分解为"冗余部分（跨模态共享信息）"与"模态特异部分（独有
#           信息）"，以可学习门控系数按冗余度动态分配权重；对缺失模态用其余模态的冗余
#           部分做条件重建；融合表征与各单模态表征之间施加跨模态对比正则；融合置信度
#           依据可用模态数与冗余一致性校准，并衔接 multi_modal_confidence.py。
# 参考论文（实现时对应关系见各节注释）:
#   [1] Robult — arXiv:2509.03477  冗余/特异特征分解 + 门控加权融合
#   [2] FedMAC — arXiv:2410.03070  跨模态聚合重建缺失模态 + 对比正则化
#   [3] Incomplete Modality Misinfo Recognition — arXiv:2510.05839  融合置信度校准
# 设计权衡: 纯 Python 实现，与模块内其余文件一致，不依赖 torch/numpy；
#           投影权重以正弦确定性初始化，保证跨进程可复现；门控系数以启发式接口更新，
#           完整反向传播可在 torch 中直接复用本文件的分解-重建-融合结构。

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ==== 数值与默认超参 ====
_EPS: float = 1e-9           # 除零/对数保护
_DEFAULT_TEMP: float = 0.07  # 对比损失温度，与 multi_modal_alignment.py 的 NTXent 对齐
_DEFAULT_LATENT: int = 64    # 冗余共享子空间维度


# ============================================================================
# 缺失模态掩码 — 以 0/1 显式建模各模态是否可用
# 缺失的定义: 键存在但值为 None / 空表，或输入字典缺键。
# 掩码的下游用途: (a) 融合时跳过缺失模态；(b) 确定重建目标集合；
#                 (c) 置信度校准中的 coverage 因子。
# ============================================================================

def build_modality_mask(
        modalities: Dict[str, Optional[List[List[float]]]]
) -> Tuple[List[str], List[float]]:
    """构建 0/1 可用性掩码，返回 (模态名列表, 掩码列表)。

    与多模态分析管线约定一致: 特征非空即视为可用。
    掩码长度 = 输入字典键数；缺失模态在融合中被显式重建而非忽略。
    """
    _names = list(modalities.keys())
    _mask: List[float] = []
    for _n in _names:
        _feat = modalities[_n]
        if _feat is not None and len(_feat) > 0 and len(_feat[0]) > 0:
            _mask.append(1.0)
        else:
            _mask.append(0.0)
    return _names, _mask


# ============================================================================
# 冗余-特异特征分解器 [1] (Robult)
# 将每个模态特征 X_m 投影到共享冗余子空间 R_m 与模态特异子空间 S_m:
#     R_m = tanh(X_m · W_red_m)      // 冗余部分，跨模态共享信息
#     S_m = tanh(X_m · W_spec_m)     // 特异部分，模态独有信息
# 冗余度 r_m[n] = ||R_m[n]|| / (||R_m[n]|| + ||S_m[n]||) ∈ (0,1)，
# 表示该样本信息中共享分量的占比——作为动态门控与置信度校准的依据。
# W_red_m 按同一结构种子初始化 → 冗余部分在 D 维共享子空间中对齐，
# 使 [2] 的跨模态聚合在几何上成立（同一坐标系内加权）。
# ============================================================================

class RedundantSpecificDecomposer:
    """冗余-特异分解器: 维护每模态冗余/特异投影、可学习门控系数与重建查询向量。"""

    def __init__(self, modality_dims: Dict[str, int],
                 latent_dim: int = _DEFAULT_LATENT):
        self.latent_dim = latent_dim
        self.modality_dims = dict(modality_dims)
        _items = list(modality_dims.items())
        # 冗余投影: 共享结构种子，输出到同一 D 维子空间
        self._W_red: Dict[str, List[List[float]]] = {
            _m: self._init_proj(_d, latent_dim, seed=1.17 + _mi * 0.37)
            for _mi, (_m, _d) in enumerate(_items)
        }
        # 特异投影: 模态专属种子，降低与冗余子空间的相关性
        self._W_spec: Dict[str, List[List[float]]] = {
            _m: self._init_proj(_d, latent_dim, seed=0.53 + _mi * 1.73)
            for _mi, (_m, _d) in enumerate(_items)
        }
        # 可学习门控系数 alpha_m ∈ [0,1]: 该模态融合时冗余部分的贡献权重
        self._alpha: Dict[str, float] = {_m: 0.5 for _m in modality_dims}
        # 每模态可学习重建查询向量 q_m* (D,): [2] 条件重建的 attention query
        self._query: Dict[str, List[float]] = {
            _m: [math.sin(_mi * 0.91 + _j * 0.29) * 0.1
                 for _j in range(latent_dim)]
            for _mi, _m in enumerate(_items)
        }

    @staticmethod
    def _init_proj(in_dim: int, out_dim: int, seed: float) -> List[List[float]]:
        """正弦确定性初始化: 幅值 1/sqrt(in_dim)，保持输入方差量级（类 Xavier）。"""
        _scale = 1.0 / math.sqrt(max(in_dim, 1))
        return [[math.sin(seed + _i * 0.73 + _j * 1.17) * _scale
                 for _j in range(out_dim)] for _i in range(in_dim)]

    @staticmethod
    def _tanh(x: float) -> float:
        # clamp 防 exp 溢出；|x| 超过 20 时 tanh 已饱和
        return math.tanh(min(max(x, -20.0), 20.0))

    def _project(self, X: List[List[float]],
                 W: List[List[float]]) -> List[List[float]]:
        """线性投影 + tanh 非线性: X (N×d) · W (d×D) → (N×D)。"""
        _N = len(X)
        _D = len(W[0])
        _out = [[0.0] * _D for _ in range(_N)]
        for _i in range(_N):
            _row = X[_i]
            for _j in range(_D):
                _acc = 0.0
                for _k in range(min(len(_row), len(W))):
                    _acc += _row[_k] * W[_k][_j]
                _out[_i][_j] = self._tanh(_acc)
        return _out

    def decompose(self, X: List[List[float]], name: str
                  ) -> Tuple[List[List[float]], List[List[float]], List[float]]:
        """分解一个模态的特征矩阵。

        返回 (冗余部分 R [N,D], 特异部分 S [N,D], 冗余度 r [N])。
        冗余度为逐样本标量，能量占比形式，闭区间 (0,1)。
        """
        _R = self._project(X, self._W_red[name])
        _S = self._project(X, self._W_spec[name])
        _N = len(X)
        _r: List[float] = [0.5] * _N
        for _i in range(_N):
            _nr = math.sqrt(sum(_v * _v for _v in _R[_i])) + _EPS
            _ns = math.sqrt(sum(_v * _v for _v in _S[_i])) + _EPS
            _r[_i] = _nr / (_nr + _ns)
        return _R, _S, _r

    def contribution(self, R: List[List[float]], S: List[List[float]],
                     name: str) -> List[List[float]]:
        """门控加权贡献向量: alpha·R + (1-alpha)·S，alpha 为该模态可学习系数。

        alpha→1 时融合表征主要由跨模态共享的冗余信息构成（模态缺失情形下更稳）；
        alpha→0 时主要由模态特异信息构成（保独有判别力）。
        """
        _a = self._alpha.get(name, 0.5)
        _N = len(R)
        _D = len(R[0]) if R else 0
        _out = [[0.0] * _D for _ in range(_N)]
        for _i in range(_N):
            for _j in range(_D):
                _out[_i][_j] = _a * R[_i][_j] + (1.0 - _a) * S[_i][_j]
        return _out

    def set_alpha(self, name: str, alpha: float) -> None:
        """更新可学习门控系数（启发式训练接口；torch 场景直接替换张量即可）。"""
        self._alpha[name] = min(1.0, max(0.0, alpha))

    def get_alpha(self) -> Dict[str, float]:
        """返回当前门控系数副本，供审计/可视化。"""
        return dict(self._alpha)

    def query(self, name: str) -> List[float]:
        """返回某模态的重建查询向量副本。"""
        return list(self._query.get(name, [0.0] * self.latent_dim))


# ============================================================================
# 跨模态条件重建器 [2] (FedMAC cross-modal aggregation)
# 对缺失模态 m*: 用可用模态的冗余部分 R_k 依注意力加权聚合出 R_hat_m*:
#     w_k ∝ exp( cos(q_m*, R_k) / τ )
#     R_hat_m* = Σ_k w_k · R_k / Σ_k w_k
# q_m* 是可学习查询向量，表达"m* 的冗余信息应在共享子空间中何处"。
# 特异部分无法跨模态重建（模态独有），故重建仅覆盖冗余部分——与 [1] 的
# 冗余性建模一致: 冗余信息在缺失时可恢复，特异信息缺失不可逆。
# ============================================================================

class CrossModalReconstructor:
    """跨模态重建器: 用可用模态冗余部分重建缺失模态的冗余表征。"""

    def __init__(self, latent_dim: int = _DEFAULT_LATENT, temperature: float = 1.0):
        self.latent_dim = latent_dim
        self.temperature = temperature  # attention 温度: 越小越集中

    def reconstruct(self, R_available: Dict[str, List[List[float]]],
                    queries: Dict[str, List[float]],
                    missing_names: List[str]
                    ) -> Tuple[Dict[str, List[List[float]]],
                               Dict[str, List[float]]]:
        """为缺失模态重建冗余部分 R_hat_m*（与 R 同形 [N,D]）。

        返回 (重建冗余部分 {name: [N,D]}, 重建置信度 {name: [N]})。
        重建置信度 = 注意力集中度（最大 softmax 权重 ∈ [1/K, 1]）:
        集中度越高 → query 与某个可用模态的冗余部分强匹配 → 重建越可信；
        近似均匀（≈1/K）→ 各可用模态冗余信号彼此冲突 → 重建置信度低，
        在融合阶段据此降权（对应 [3] 的缺失不确定性建模）。
        边界条件: 无可用模态时返回零矩阵且置信度为 0（交由置信度校准降权）。
        """
        _avail = list(R_available.keys())
        _D = self.latent_dim
        _N = len(R_available[_avail[0]]) if _avail else 0
        _out: Dict[str, List[List[float]]] = {}
        _conf: Dict[str, List[float]] = {}
        for _m in missing_names:
            _q = queries.get(_m, [0.0] * _D)
            if not _avail or _N == 0:
                _out[_m] = [[0.0] * _D for _ in range(_N)]
                _conf[_m] = [0.0] * _N
                continue
            _recon = [[0.0] * _D for _ in range(_N)]
            _mconf: List[float] = [0.0] * _N
            _nq = math.sqrt(sum(_v * _v for _v in _q)) + _EPS
            for _i in range(_N):
                # 计算 query 与各可用冗余部分的余弦注意力权重
                _sims: List[float] = []
                for _k in _avail:
                    _row = R_available[_k][_i]
                    _dot = sum(_q[_j] * _row[_j] for _j in range(_D))
                    _nk = math.sqrt(sum(_v * _v for _v in _row)) + _EPS
                    _sims.append(_dot / (_nq * _nk))
                _mx = max(_sims) if _sims else 0.0
                _exps = [math.exp((_s - _mx) / max(self.temperature, _EPS))
                         for _s in _sims]
                _sum_e = sum(_exps) + _EPS
                _max_w = 0.0
                for _idx, _k in enumerate(_avail):
                    _w = _exps[_idx] / _sum_e
                    _max_w = max(_max_w, _w)
                    _row = R_available[_k][_i]
                    for _j in range(_D):
                        _recon[_i][_j] += _w * _row[_j]
                _mconf[_i] = _max_w
            _out[_m] = _recon
            _conf[_m] = _mconf
        return _out, _conf


# ============================================================================
# 跨模态对比正则 [2] (FedMAC contrastive regularization)
# 融合表征 F 与各单模态联合表征 Z_m 在批次内做 NT-Xent:
# 同一样本的 (F[n], Z_m[n]) 为正样本对，其余样本为负样本。
# 缺失模态不参与（mask=0 → 跳过），避免对空表征产生噪声梯度。
# 该项使 F 在部分模态缺失情形下仍与可用模态表征保持一致——融合不被某个
# 强模态劫持，缺失鲁棒性提升。温度与 multi_modal_alignment.NTXentLoss 对齐。
# ============================================================================

class CrossModalContrastiveLoss:
    """融合表征 ↔ 单模态表征的 NT-Xent 对比损失。"""

    def __init__(self, temperature: float = _DEFAULT_TEMP):
        self.temperature = temperature

    @staticmethod
    def _cosine_sim(A: List[List[float]], B: List[List[float]]) -> List[List[float]]:
        """成对余弦相似度矩阵 [len(A) × len(B)]。"""
        _n, _m = len(A), len(B)
        _d = len(A[0]) if A else 0
        _norm_a = [math.sqrt(sum(_v * _v for _v in _row)) + _EPS for _row in A]
        _norm_b = [math.sqrt(sum(_v * _v for _v in _row)) + _EPS for _row in B]
        _S = [[0.0] * _m for _ in range(_n)]
        for _i in range(_n):
            for _j in range(_m):
                _dot = sum(A[_i][_k] * B[_j][_k]
                           for _k in range(min(_d, len(B[_j]))))
                _S[_i][_j] = _dot / (_norm_a[_i] * _norm_b[_j])
        return _S

    def forward(self, fused: List[List[float]],
                modality_reprs: Dict[str, List[List[float]]],
                mask: List[float],
                names: List[str]) -> float:
        """融合表征与各可用模态表征的 NT-Xent 平均损失。

        fused: 融合表征 [N,D]；modality_reprs: 单模态联合表征 {name: [N,D]}。
        仅遍历 mask>0 的模态；N<2 时返回 0（单样本无法构成负样本对）。
        """
        _N = len(fused)
        if _N < 2:
            return 0.0
        _loss = 0.0
        _count = 0
        for _idx, _m in enumerate(names):
            if _idx >= len(mask) or mask[_idx] <= 0.0:
                continue
            _Z = modality_reprs.get(_m)
            if _Z is None or len(_Z) < 2:
                continue
            _sim = self._cosine_sim(fused, _Z)
            for _i in range(_N):
                for _j in range(_N):
                    _sim[_i][_j] /= self.temperature
            # 方向 F→Z: 对角线为正样本，log-sum-exp 稳定计算
            for _i in range(_N):
                _row = _sim[_i]
                _pos = _row[_i]
                _mx = max(_row)
                _sum_e = sum(math.exp(_v - _mx) for _v in _row)
                _loss += -(_pos - _mx - math.log(_sum_e + _EPS))
                _count += 1
        return _loss / max(_count, 1)


# ============================================================================
# 融合置信度校准 [3]（衔接 multi_modal_confidence.py）
# 校准置信度由三因子修正原始置信度 raw:
#     coverage     = 可用模态数 / 总模态数            // 缺失越多，信息越不完整
#     consistency  = 冗余部分两两余弦相似度均值        // 共享信息冲突 → 不可信
#     blend_w      = sample_count/(sample_count+K)    // 样本量加权，沿用 WeightedBlender
# 设计权衡: coverage 以 sqrt 压缩，避免单一模态缺失时置信度被过度压制；
#           consistency<1 表示冗余信号冲突，直接线性压制；
#           sample_count=0 时不做样本量混合（纯结构校准）。
# ============================================================================

class RedunFuseConfidence:
    """冗余感知的融合置信度校准器。"""

    def __init__(self, blend_K: float = 10.0):
        self.blend_K = blend_K

    def consistency(self, R: Dict[str, List[List[float]]]) -> float:
        """可用模态冗余部分之间的平均两两余弦相似度。

        单模态无参照，视为完全一致返回 1.0；多模态冲突时值 <1。
        """
        _names = list(R.keys())
        if len(_names) < 2:
            return 1.0
        _N = len(R[_names[0]])
        if _N == 0:
            return 1.0
        _total = 0.0
        _pairs = 0
        for _a in range(len(_names)):
            for _b in range(_a + 1, len(_names)):
                _A = R[_names[_a]]
                _B = R[_names[_b]]
                for _i in range(_N):
                    _dot = sum(_A[_i][_j] * _B[_i][_j]
                               for _j in range(min(len(_A[_i]), len(_B[_i]))))
                    _na = math.sqrt(sum(_v * _v for _v in _A[_i])) + _EPS
                    _nb = math.sqrt(sum(_v * _v for _v in _B[_i])) + _EPS
                    _total += _dot / (_na * _nb)
                _pairs += _N
        return _total / max(_pairs, 1)

    def calibrate(self, raw_confidence: float, mask: List[float],
                  consistency: float, sample_count: int = 0) -> float:
        """依据可用模态数与冗余一致性校准原始置信度。

        raw_confidence: 融合模型输出的原始置信度（未校准）。
        返回值 clamp 到 [0.01, 0.99]，避免极端值破坏下游阈值判定。
        """
        _M = max(len(mask), 1)
        _coverage = sum(1.0 for _m in mask if _m > 0.0) / _M
        _cov_factor = math.sqrt(max(_coverage, _EPS))
        _cons_factor = max(0.0, min(1.0, consistency))
        # 缺失鲁棒修正: 信任度 = 覆盖因子 × 一致性
        _robust = _cov_factor * _cons_factor
        _calibrated = raw_confidence * _robust
        # 样本量混合: 样本充足时信任结构校准，不足时向原始分回退
        if sample_count > 0:
            _blend_w = min(sample_count / (sample_count + self.blend_K), 0.95)
            _calibrated = (1.0 - _blend_w) * raw_confidence + _blend_w * _calibrated
        return max(0.01, min(0.99, _calibrated))

    def calibrate_with_beta(self, raw_confidence: float, mask: List[float],
                            consistency: float, success_count: int,
                            sample_count: int) -> float:
        """与 multi_modal_confidence.py 衔接: 先做 Beta-Binomial 后验校准，
        再叠加缺失鲁棒修正。

        Beta 后验均值作为结构化校准的输入，使历史观测统计与当前模态结构
        共同决定最终置信度。
        """
        from .multi_modal_confidence import BetaCalibration, WeightedBlender
        _cal = BetaCalibration()
        _cal.update(success_count, sample_count)
        _beta_conf = _cal.get_confidence()
        _blender = WeightedBlender()
        _blended = _blender.blend(raw_confidence, _beta_conf, sample_count)
        return self.calibrate(_blended, mask, consistency, sample_count)


# ============================================================================
# RedunFuse 融合器 — 分解 → 重建 → 门控融合 → 对比正则 → 置信度校准
# 融合公式（逐样本）:
#     F[n] = Σ_m w_m[n]·C_m[n] / Σ_m w_m[n]
#     可用模态: C_m = alpha_m·R_m + (1-alpha_m)·S_m，w_m = 0.5+0.5·r_m
#     缺失模态: C_m = R_hat_m（重建冗余部分），w_m = 0.5+0.5·注意力集中度
# 相比 multi_modal_fusion.py 的静态/固定门控:
#     权重 w_m 由冗余度逐样本动态分配；缺失模态不再被静默忽略，而是显式重建。
# ============================================================================

class RedunFuse:
    """RedunFuse 端到端融合器。"""

    def __init__(self, modality_dims: Dict[str, int],
                 latent_dim: int = _DEFAULT_LATENT,
                 temperature: float = _DEFAULT_TEMP,
                 contrastive_lambda: float = 0.1):
        self.latent_dim = latent_dim
        self.contrastive_lambda = contrastive_lambda  # 对比正则权重（训练时用）
        self.decomposer = RedundantSpecificDecomposer(modality_dims, latent_dim)
        self.reconstructor = CrossModalReconstructor(latent_dim, temperature=1.0)
        self.contrastive = CrossModalContrastiveLoss(temperature)
        self.confidence = RedunFuseConfidence()

    def forward(self, modalities: Dict[str, Optional[List[List[float]]]],
                sample_count: int = 0) -> Dict[str, object]:
        """执行完整融合流程。

        modalities: {模态名: 特征矩阵 [N,d_m] 或 None/空表(缺失)}。
        sample_count: 观测样本量，>0 时参与置信度样本量混合。
        返回 dict 含 fused/redundant/specific/reconstructed/
              reconstruction_confidence/mask/weights/redundancy/
              consistency/contrastive_loss/confidence。
        """
        _names, _mask = build_modality_mask(modalities)
        _avail_names = [_n for _n, _m in zip(_names, _mask) if _m > 0.0]
        _missing = [_n for _n, _m in zip(_names, _mask) if _m <= 0.0]

        # 1) 分解: 冗余 + 特异 + 冗余度
        _R: Dict[str, List[List[float]]] = {}
        _S: Dict[str, List[List[float]]] = {}
        _r: Dict[str, List[float]] = {}
        for _n in _avail_names:
            _R[_n], _S[_n], _r[_n] = self.decomposer.decompose(modalities[_n], _n)

        _D = self.latent_dim
        _N = len(_R[_avail_names[0]]) if _avail_names else 0

        # 2) 跨模态重建缺失模态的冗余部分（[2] cross-modal aggregation）
        _R_hat, _recon_conf = self.reconstructor.reconstruct(
            _R, {_n: self.decomposer.query(_n) for _n in _names}, _missing)

        # 3) 门控融合（可用 + 重建）
        _fused = [[0.0] * _D for _ in range(_N)]
        _w_sum = [0.0] * _N
        _weights: Dict[str, List[float]] = {}
        for _n in _avail_names:
            _cont = self.decomposer.contribution(_R[_n], _S[_n], _n)
            _w = [0.5 + 0.5 * _rr for _rr in _r[_n]]  # 冗余度越高 → 权重越大
            _weights[_n] = _w
            for _i in range(_N):
                _w_sum[_i] += _w[_i]
                for _j in range(_D):
                    _fused[_i][_j] += _w[_i] * _cont[_i][_j]
        for _n in _missing:
            _R_hat_n = _R_hat[_n]
            # 重建权重 = 0.5 + 0.5·注意力集中度；集中度∈[1/K,1] → 权重∈[0.5,1]
            _c = _recon_conf.get(_n, [0.0] * _N)
            _w = [0.5 + 0.5 * _ci for _ci in _c]
            _weights[_n] = _w
            for _i in range(_N):
                _w_sum[_i] += _w[_i]
                for _j in range(_D):
                    _fused[_i][_j] += _w[_i] * _R_hat_n[_i][_j]
        for _i in range(_N):
            _inv = 1.0 / max(_w_sum[_i], _EPS)
            for _j in range(_D):
                _fused[_i][_j] *= _inv

        # 4) 对比正则损失（仅计算，训练时叠加到总损失）
        _reprs = {_n: self.decomposer.contribution(_R[_n], _S[_n], _n)
                  for _n in _avail_names}
        _loss = self.contrastive.forward(_fused, _reprs, _mask, _names)

        # 5) 置信度校准（[3]，衔接 multi_modal_confidence.py）
        _cons = self.confidence.consistency(_R)
        _conf = self.confidence.calibrate(0.5, _mask, _cons, sample_count)

        return {
            'fused': _fused,
            'redundant': _R,
            'specific': _S,
            'reconstructed': _R_hat,
            'reconstruction_confidence': _recon_conf,
            'mask': _mask,
            'weights': _weights,
            'redundancy': _r,
            'consistency': _cons,
            'contrastive_loss': _loss,
            'confidence': _conf,
        }


# ============================================================================
# 便捷函数 — 与 multi_modal_fusion.adaptive_fusion 同层级的单点入口
# 自动推断各模态输入维度，缺失模态以 None/空表传入即可。
# ============================================================================

def redunfuse(modalities: Dict[str, Optional[List[List[float]]]],
              latent_dim: int = _DEFAULT_LATENT,
              contrastive_lambda: float = 0.1,
              sample_count: int = 0) -> Dict[str, object]:
    """RedunFuse 便捷入口: 自动推断模态维度并执行完整融合。

    示例:
        fused = redunfuse({'text': text_feat, 'image': None, 'audio': audio_feat})
        # image 模态缺失，由 text/audio 的冗余部分条件重建。
    """
    _dims: Dict[str, int] = {}
    for _n, _feat in modalities.items():
        if _feat is not None and len(_feat) > 0 and len(_feat[0]) > 0:
            _dims[_n] = len(_feat[0])
        else:
            _dims[_n] = 1  # 缺失模态占位维度，分解时不会真正执行
    _fuser = RedunFuse(_dims, latent_dim=latent_dim,
                       contrastive_lambda=contrastive_lambda)
    return _fuser.forward(modalities, sample_count=sample_count)


__all__ = [
    "build_modality_mask",
    "RedundantSpecificDecomposer",
    "CrossModalReconstructor",
    "CrossModalContrastiveLoss",
    "RedunFuseConfidence",
    "RedunFuse",
    "redunfuse",
]
