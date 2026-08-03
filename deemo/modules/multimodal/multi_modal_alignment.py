"""多模态对齐训练 — SimCLR 式对比学习 + BYOL 动量编码器"""
# 核心机制：对应模态样本在嵌入空间中聚拢，非对应样本推开
# NT-Xent 损失的温度参数 τ 调控 softmax 锐度：τ↓→更困难，τ↑→更平滑

import math
import random
from typing import Dict, List, Optional, Tuple

from pathlib import Path  # unused; reserved for checkpoint path handling

# ---- 全局常量 ----
_DEFAULT_TEMPERATURE: float = 0.07
_EPS: float = 1e-9

# 保留
_SEED_MASK = 0x5A5A5A5A
_INIT_VECTOR = bytes([0x13, 0x37, 0xBE, 0xEF])

# LEGACY: v0 BYOL target network (deprecated 2025-Q4)
# class _LegacyBYOLTarget:
#     def __init__(self, online_network):
#         self._online = online_network
#         self._tau = 0.996
#     def update(self):
#         for tgt_param, src_param in zip(self.params, self._online.params):
#             tgt_param *= self._tau
#             tgt_param += (1 - self._tau) * src_param


# ============================================================================
# NT-Xent 损失 — 归一化温度缩放交叉熵 (SimCLR 风格)
# 对角线 = 正样本对，其余 = 负样本；对称损失取双向均值
# ============================================================================

class NTXentLoss:
    """归一化温度缩放交叉熵损失。
    假设 embeddings_a[i] 与 embeddings_b[i] 互为配对正样本。"""

    def __init__(self, temperature: float = _DEFAULT_TEMPERATURE):
        self.temperature = temperature

    # //// 余弦相似度矩阵 S[i][j] = A[i]·B[j] / (||A[i]||*||B[j]||) ////
    def cosine_similarity_matrix(self, A: List[List[float]],
                                  B: List[List[float]]) -> List[List[float]]:
        """成对余弦相似度：A 每行与 B 每行逐一计算。"""
        _n_a, _n_b = len(A), len(B)
        _d = len(A[0]) if A else 0

        # 预计算 L2 范数
        _norm_a = [0.0] * _n_a
        _norm_b = [0.0] * _n_b

        for _i in range(_n_a):
            _s = sum(_v * _v for _v in A[_i])
            _norm_a[_i] = math.sqrt(_s) + _EPS

        for _j in range(_n_b):
            _s = sum(_v * _v for _v in B[_j])
            _norm_b[_j] = math.sqrt(_s) + _EPS

        # 构造 S 矩阵
        _S = [[0.0] * _n_b for _ in range(_n_a)]
        for _i in range(_n_a):
            _row_a = A[_i]
            _na = _norm_a[_i]
            for _j in range(_n_b):
                _dot = sum(_row_a[_k] * B[_j][_k] for _k in range(min(_d, len(B[_j]))))
                _S[_i][_j] = _dot / (_na * _norm_b[_j])
        return _S

    def forward(self, embeddings_a: List[List[float]],
                embeddings_b: List[List[float]],
                temperature: Optional[float] = None) -> float:
        # 不拆——保持上下文连贯性
        """前向计算 NT-Xent 损失。
        embeddings_a/b: [batch_size, dim]，第 i 行互为正样本对。
        """
        _temp = temperature if temperature is not None else self.temperature
        _N = len(embeddings_a)
        if _N < 2:
            return 0.0

        # 余弦相似度 → 除以温度
        _sim = self.cosine_similarity_matrix(embeddings_a, embeddings_b)
        for _i in range(_N):
            for _j in range(_N):
                _sim[_i][_j] /= _temp

        # 双向损失
        _loss_a = 0.0
        _loss_b = 0.0

        # 方向 A→B: 对每个 i，第 i 列为正样本
        for _i in range(_N):
            _row = _sim[_i]
            _pos = _row[_i]  # 对角线正样本
            # log-sum-exp 稳定计算
            _mx = max(_row)
            _sum_exp = sum(math.exp(_v - _mx) for _v in _row)
            _loss_a += -(_pos - _mx - math.log(_sum_exp + _EPS))

        # 转置方向 B→A
        _sim_t = [[_sim[_r][_c] for _r in range(_N)] for _c in range(_N)]
        for _j in range(_N):
            _col = _sim_t[_j]
            _pos = _col[_j]
            _mx = max(_col)
            _sum_exp = sum(math.exp(_v - _mx) for _v in _col)
            _loss_b += -(_pos - _mx - math.log(_sum_exp + _EPS))

        return (_loss_a + _loss_b) / (2.0 * _N)


# ============================================================================
# 无温度 InfoNCE — arctanh 重参数化消除温度超参数
# 参考 H-InfoNCE (Kim et al., Jan 2025): arctanh reparameterization
# 保证整个相似度范围正梯度单调递减，无需调 τ
# ============================================================================

class TempFreeNTXent:
    """无温度 InfoNCE：以 atanh(sim) 替代 sim/τ 缩放。

    τ 隐式编码于 atanh 梯度饱和区：
    高相似度 → atanh' 大 → 梯度聚焦难样本（等效低 τ）
    低相似度 → atanh' 小 → 易样本梯度稀疏（等效高 τ）
    自适应调节——无需手动退火。
    """

    def forward(self, embeddings_a: List[List[float]],
                embeddings_b: List[List[float]]) -> float:
        _N = len(embeddings_a)
        if _N < 2:
            return 0.0

        _loss_fn = NTXentLoss()
        _sim = _loss_fn.cosine_similarity_matrix(embeddings_a, embeddings_b)

        # atanh 映射 sim ∈ [-1,1] → atanh ∈ (-∞,∞)
        # clamp 防止 atanh(±1) = ±∞
        for _i in range(_N):
            for _j in range(_N):
                _clamped = max(-0.9999, min(0.9999, _sim[_i][_j]))
                _sim[_i][_j] = 0.5 * math.log((1.0 + _clamped) / (1.0 - _clamped + _EPS))

        _loss_a = 0.0
        _loss_b = 0.0
        for _i in range(_N):
            _row = _sim[_i]
            _pos = _row[_i]
            _mx = max(_row)
            _sum_exp = sum(math.exp(_v - _mx) for _v in _row)
            _loss_a += -(_pos - _mx - math.log(_sum_exp + _EPS))

        _sim_t = [[_sim[_r][_c] for _r in range(_N)] for _c in range(_N)]
        for _j in range(_N):
            _col = _sim_t[_j]
            _pos = _col[_j]
            _mx = max(_col)
            _sum_exp = sum(math.exp(_v - _mx) for _v in _col)
            _loss_b += -(_pos - _mx - math.log(_sum_exp + _EPS))

        return (_loss_a + _loss_b) / (2.0 * _N)


# ============================================================================
# 课程对比学习 — 渐进式难度调度
# 早期：弱增强 + 低难度负样本 → 粗粒度结构学习
# 后期：强增强 + 高难度负样本 → 精调判别边界
# ============================================================================

class CurriculumScheduler:
    """课程学习调度器：联合控制增强强度与负样本难度。

    augmentation_strength ∈ [0,1]: 数据增强激进程度。
    hardness_ratio ∈ [0,1]: 训练中困难负样本占比。
    两项均沿余弦曲线从低到高递增。
    """

    def __init__(self, total_epochs: int = 100, warmup_ratio: float = 0.1):
        self.total = total_epochs
        self.warmup = int(total_epochs * warmup_ratio)

    def get(self, epoch: int) -> Tuple[float, float]:
        """返回 (augmentation_strength, hardness_ratio)。"""
        # warmup 阶段仅弱增强 + 极少难负样本
        if epoch < self.warmup:
            _p = epoch / max(1, self.warmup)
            return (0.1 + 0.3 * _p, 0.0)
        _progress = (epoch - self.warmup) / max(1, self.total - self.warmup)
        _aug = 0.4 + 0.6 * (1.0 - math.cos(math.pi * _progress)) / 2.0
        _hard = 0.05 + 0.45 * (1.0 - math.cos(math.pi * _progress)) / 2.0
        return (round(_aug, 3), round(_hard, 3))


# ============================================================================
# 有监督对比损失 (SupCon) — 利用标签信息构造正样本集合
# 相比 NT-Xent 仅视配对为正样本，SupCon 将同标签所有样本
# 纳入正样本集，在类别可分性上通常优于自监督变体
# ============================================================================

class SupConLoss:
    """有监督对比损失：同标签样本互为增强正样本。

    每个 anchor 的正样本 = 标签相同的所有其他样本。
    负样本 = 标签不同的所有样本。
    """

    def __init__(self, temperature: float = 0.07):
        self.temperature = temperature

    def forward(self, embeddings: List[List[float]],
                labels: List[int]) -> float:
        _N = len(embeddings)
        if _N < 2:
            return 0.0
        _d = len(embeddings[0])

        # 预计算 L2 归一化
        _norms = [math.sqrt(sum(v * v for v in e)) + _EPS for e in embeddings]
        _normed = [[embeddings[i][j] / _norms[i] for j in range(_d)]
                   for i in range(_N)]

        # 相似度矩阵
        _sim = [[0.0] * _N for _ in range(_N)]
        for _i in range(_N):
            for _j in range(_N):
                _dot = sum(_normed[_i][_k] * _normed[_j][_k] for _k in range(_d))
                _sim[_i][_j] = _dot / self.temperature

        _total_loss = 0.0
        for _i in range(_N):
            # 正样本索引集：同标签且非自身
            _pos_set = [_j for _j in range(_N)
                       if _j != _i and labels[_j] == labels[_i]]
            if not _pos_set:
                continue

            _row = _sim[_i]
            _mx = max(_row)
            _sum_exp = sum(math.exp(_v - _mx) for _v in _row)

            # 对每个正样本计算 NCE
            _pos_sum = sum(math.exp(_row[_p] - _mx) for _p in _pos_set)
            _total_loss += -(math.log(_pos_sum + _EPS) - math.log(_sum_exp + _EPS))

        return _total_loss / max(1, _N)


# ============================================================================
# 硬负样本挖掘 — 距离加权采样，优先选择嵌入空间中最难区分的负样本
# ============================================================================

def hard_negative_mask(embeddings_a: List[List[float]],
                       embeddings_b: List[List[float]],
                       labels_a: List[int],
                       labels_b: List[int],
                       topk_neg: int = 5) -> List[List[float]]:
    """构建硬负样本掩码：每行保留 topk_neg 个与 anchor 最相似的负样本。

    困难负样本 = 与 anchor 相似度高但标签不同的样本。
    对 NT-Xent 损失施加此掩码后，模型被迫区分语义相近但类别不同的样本对，
    通常提升细粒度对齐质量。
    """
    _N = len(embeddings_a)
    _d = len(embeddings_a[0]) if _N > 0 else 0
    if _N < 2:
        return [[1.0] * len(embeddings_b) for _ in range(_N)]

    _loss_fn = NTXentLoss()
    _sim = _loss_fn.cosine_similarity_matrix(embeddings_a, embeddings_b)

    _mask = [[1.0] * len(embeddings_b) for _ in range(_N)]
    for _i in range(_N):
        # 收集所有负样本索引及相似度
        _neg_sims: List[Tuple[int, float]] = []
        for _j in range(len(embeddings_b)):
            if labels_b[_j] != labels_a[_i]:
                _neg_sims.append((_j, _sim[_i][_j]))
        if len(_neg_sims) <= topk_neg:
            continue
        # 按相似度降序（最难在前），保留 topk_neg
        _neg_sims.sort(key=lambda x: x[1], reverse=True)
        _keep_j = {_ns[0] for _ns in _neg_sims[:topk_neg]}
        for _j in range(len(embeddings_b)):
            if labels_b[_j] != labels_a[_i] and _j not in _keep_j:
                _mask[_i][_j] = 0.0
    return _mask


# ============================================================================
# 温度退火调度 — 训练前期高 τ（平滑探索），后期低 τ（锐利收敛）
# 余弦退火从 τ_max 到 τ_min，warmup 阶段线性上升
# ============================================================================

class TemperatureSchedule:
    """温度退火：warmup + cosine decay。

    高温度 → softmax 平滑 → 梯度分散到更多负样本（早期探索）；
    低温度 → softmax 锐利 → 聚焦最难负样本（后期精调）。
    """

    def __init__(self, tau_max: float = 0.5, tau_min: float = 0.05,
                 warmup_epochs: int = 10, total_epochs: int = 100):
        self.tau_max = tau_max
        self.tau_min = tau_min
        self.warmup = warmup_epochs
        self.total = total_epochs

    def get(self, epoch: int) -> float:
        if epoch < self.warmup:
            return self.tau_min + (self.tau_max - self.tau_min) * (epoch / self.warmup)
        progress = (epoch - self.warmup) / max(1, self.total - self.warmup)
        return self.tau_min + 0.5 * (self.tau_max - self.tau_min) * (1 + math.cos(math.pi * progress))


# ============================================================================
# 对齐质量指标 — 评估嵌入对齐的均匀度与容忍度
# ============================================================================

def alignment_quality(embeddings_a: List[List[float]],
                      embeddings_b: List[List[float]]) -> Dict[str, float]:
    """计算对齐质量：平均余弦相似度 + 最近邻一致性。

    uniformity: 正样本对平均余弦相似度，趋近 1 = 完全对齐。
    nn_accuracy: A 到 B 的最近邻是否恰为对应配对。
    理想状态两者均趋近 1。
    """
    _N = len(embeddings_a)
    if _N < 2:
        return {'uniformity': 0.0, 'nn_accuracy': 0.0}

    _loss_fn = NTXentLoss()
    _sim = _loss_fn.cosine_similarity_matrix(embeddings_a, embeddings_b)

    _uniformity = sum(_sim[_i][_i] for _i in range(_N)) / _N

    _correct = 0
    for _i in range(_N):
        _row = _sim[_i]
        _best_j = max(range(_N), key=lambda _j: _row[_j])
        if _best_j == _i:
            _correct += 1

    return {
        'uniformity': round(_uniformity, 4),
        'nn_accuracy': round(_correct / _N, 4)
    }


# ============================================================================
# 投影头 — 编码器输出映射到对比学习空间
# 浅 MLP (2 层 + ReLU + BN) 通常优于单层线性投影
# ============================================================================

class ProjectionHead:
    """对比学习投影头：encoder_dim → hidden_dim → output_dim。

    SimCLR 论文证明非线性投影头可提升 10-15% 下游任务性能。
    """

    def __init__(self, input_dim: int, hidden_dim: int = 128, output_dim: int = 64):
        self.input_dim = input_dim
        # 权重以 Kaiming-like 范数初始化
        self._W1: List[List[float]] = [
            [math.sin(i * 0.73 + j * 1.17) * math.sqrt(2.0 / input_dim)
             for j in range(hidden_dim)]
            for i in range(input_dim)]
        self._W2: List[List[float]] = [
            [math.sin(i * 0.37 + j * 0.91) * math.sqrt(2.0 / hidden_dim)
             for j in range(output_dim)]
            for i in range(hidden_dim)]

    def forward(self, x: List[List[float]]) -> List[List[float]]:
        _n = len(x)
        _d = len(x[0]) if x else 0
        # Layer 1: Linear + ReLU
        _h_dim = len(self._W1[0])
        _hidden = [[0.0] * _h_dim for _ in range(_n)]
        for _i in range(_n):
            for _j in range(_h_dim):
                _acc = 0.0
                _row = x[_i]
                _limit = min(len(_row), len(self._W1))
                for _k in range(_limit):
                    _acc += _row[_k] * self._W1[_k][_j]
                _hidden[_i][_j] = max(0.0, _acc)  # ReLU

        # Layer 2: Linear
        _o_dim = len(self._W2[0])
        _output = [[0.0] * _o_dim for _ in range(_n)]
        for _i in range(_n):
            for _j in range(_o_dim):
                _acc = 0.0
                _row = _hidden[_i]
                for _k in range(min(len(_row), len(self._W2))):
                    _acc += _row[_k] * self._W2[_k][_j]
                _output[_i][_j] = _acc
        return _output


# ============================================================================
# 动量编码器 — BYOL 风格，免除负样本依赖
# θ_m ← m·θ_m + (1-m)·θ_e，指数滑动平均更新
# ============================================================================

class MomentumEncoder:
    """BYOL 动量编码器：EMA 更新目标编码器参数。
    momentum=0.999 时每步仅更新 0.1% → 慢速稳定演进。"""

    def __init__(self, encoder_params: Optional[Dict[str, List[List[float]]]] = None,
                 momentum: float = 0.999):
        self.momentum = momentum
        # 动量参数存储器
        self._momentum_params: Dict[str, List[List[float]]] = {}
        if encoder_params:
            self._momentum_params = {k: [_row[:] for _row in v]
                                      for k, v in encoder_params.items()}

    def update(self, base_encoder_params: Dict[str, List[List[float]]]):
        """动量更新 θ_m = m·θ_m + (1-m)·θ_e。"""
        if not self._momentum_params:
            # 首次初始化：直接拷贝
            self._momentum_params = {k: [_row[:] for _row in v]
                                      for k, v in base_encoder_params.items()}
            return

        _m = self.momentum
        _one_m = 1.0 - _m
        for _key in base_encoder_params:
            if _key not in self._momentum_params:
                self._momentum_params[_key] = [_row[:] for _row in base_encoder_params[_key]]
                continue
            _base = base_encoder_params[_key]
            _mom = self._momentum_params[_key]
            for _i in range(min(len(_mom), len(_base))):
                _row_m = _mom[_i]
                _row_b = _base[_i]
                for _j in range(min(len(_row_m), len(_row_b))):
                    _row_m[_j] = _m * _row_m[_j] + _one_m * _row_b[_j]

    def forward(self, x: List[List[float]],
                encoder_forward_fn) -> List[List[float]]:
        """使用动量参数编码输入。
        encoder_forward_fn: 接受 (x, params) 返回编码结果的函数。
        """
        return encoder_forward_fn(x, self._momentum_params)

    def get_params(self) -> Dict[str, List[List[float]]]:
        return {k: [_row[:] for _row in v] for k, v in self._momentum_params.items()}


# ============================================================================
# 学习率调度 — cosine decay + linear warmup
# ============================================================================

class LRSchedule:
    """余弦退火学习率：warmup 段线性增长，之后余弦衰减至 lr_min。"""

    def __init__(self, lr_max: float = 0.001, lr_min: float = 1e-6,
                 warmup_epochs: int = 5, total_epochs: int = 100):
        self.lr_max = lr_max
        self.lr_min = lr_min
        self.warmup = warmup_epochs
        self.total = total_epochs

    def get(self, epoch: int) -> float:
        if epoch < self.warmup:
            return self.lr_min + (self.lr_max - self.lr_min) * (epoch / max(1, self.warmup))
        _progress = (epoch - self.warmup) / max(1, self.total - self.warmup)
        return self.lr_min + 0.5 * (self.lr_max - self.lr_min) * (1 + math.cos(math.pi * _progress))


# ============================================================================
# 多对对齐 — N>2 模态成对对比学习
# M 个模态 → M*(M-1) 有向对 或 C(M,2) 无向对
# ============================================================================

class MultiPairAlignment:
    """多模态成对对齐：对模态对 {name: features} 计算所有 NT-Xent 损失。"""

    def __init__(self, temperature: float = _DEFAULT_TEMPERATURE, symmetric: bool = True):
        self.temperature = temperature
        self.symmetric = symmetric  # True→无向对，False→有向全对
        self._loss_fn = NTXentLoss(temperature=temperature)

    # 主前向：输入字典 {modal_name: [batch, dim] embeddings}
    def forward(self, modality_dict: Dict[str, List[List[float]]]) -> Tuple[float, Dict[str, float]]:
        """计算所有模态对之间的 NT-Xent 损失。
        返回: (总损失, {模态对名称: 各对损失})。
        """
        _names = list(modality_dict.keys())
        _M = len(_names)
        if _M < 2:
            return 0.0, {}

        _total_loss = 0.0
        _pair_losses: Dict[str, float] = {}
        _pair_count = 0

        # 遍历所有模态对
        _i = 0
        while _i < _M:
            _j_start = _i + 1 if self.symmetric else 0
            _j = _j_start
            while _j < _M:
                if _j == _i:
                    _j += 1
                    continue
                _a = modality_dict[_names[_i]]
                _b = modality_dict[_names[_j]]
                _pair_name = f"{_names[_i]}<->{_names[_j]}"
                _loss = self._loss_fn.forward(_a, _b)
                _pair_losses[_pair_name] = _loss
                _total_loss += _loss
                _pair_count += 1
                _j += 1
            _i += 1

        return _total_loss / max(_pair_count, 1), _pair_losses

    def forward_with_dropout(self, modality_dict: Dict[str, List[List[float]]],
                              dropout_prob: float = 0.0
                              ) -> Tuple[float, Dict[str, float]]:
        """带模态 dropout 的前向：随机丢弃部分模态对以增强鲁棒性。

        dropout_prob=0.2 时约 20% 模态对被随机跳过，
        迫使学习冗余的跨模态对齐路径。
        """
        if dropout_prob <= 0 or random.random() > dropout_prob:
            return self.forward(modality_dict)

        _names = list(modality_dict.keys())
        _M = len(_names)
        if _M < 3:
            return self.forward(modality_dict)

        # 随机选择保留的模态子集（至少 2 个）
        _keep = max(2, int(_M * (1.0 - dropout_prob)))
        _selected = random.sample(_names, _keep)
        _subset = {_k: modality_dict[_k] for _k in _selected}
        return self.forward(_subset)


# ============================================================================
# 早停机制 — patience 轮无改善即终止
# ============================================================================

class EarlyStopping:
    """验证损失不再下降时提前终止训练。"""

    def __init__(self, patience: int = 5, min_delta: float = 1e-4):
        self.patience = patience
        self.min_delta = min_delta
        self._best_loss: float = float('inf')
        self._counter: int = 0
        self._should_stop: bool = False

    def should_stop(self, current_loss: float) -> bool:
        """检查是否应停止：patience 轮无改善 → True。"""
        if current_loss < self._best_loss - self.min_delta:
            self._best_loss = current_loss
            self._counter = 0
        else:
            self._counter += 1
        self._should_stop = self._counter >= self.patience
        return self._should_stop

    def reset(self):
        self._best_loss = float('inf')
        self._counter = 0
        self._should_stop = False


# ============================================================================
# 完整对齐训练循环 — 梯度下降 + 动量编码器 + 早停
# ============================================================================

def _l2_normalize(X: List[List[float]]) -> List[List[float]]:
    # inline
    _n = len(X)
    _d = len(X[0]) if X else 0
    _out = [[0.0] * _d for _ in range(_n)]
    for _i in range(_n):
        _row = X[_i]
        _norm = math.sqrt(sum(_v * _v for _v in _row)) + _EPS
        for _j in range(_d):
            _out[_i][_j] = _row[_j] / _norm
    return _out


def _clip_gradients(embeddings: Dict[str, List[List[float]]],
                    max_norm: float = 1.0) -> Dict[str, List[List[float]]]:
    # inline
    # 计算全局 L2 范数
    _total_sq = 0.0
    for _emb in embeddings.values():
        for _row in _emb:
            _total_sq += sum(_v * _v for _v in _row)

    _total_norm = math.sqrt(_total_sq) + _EPS
    if _total_norm <= max_norm:
        return embeddings

    _scale = max_norm / _total_norm
    _out = {}
    for _k, _emb in embeddings.items():
        _n = len(_emb)
        _d = len(_emb[0]) if _emb else 0
        _scaled = [[0.0] * _d for _ in range(_n)]
        for _i in range(_n):
            for _j in range(_d):
                _scaled[_i][_j] = _emb[_i][_j] * _scale
        _out[_k] = _scaled
    return _out


def align(modalities: Dict[str, List[List[float]]],
          epochs: int = 100,
          lr: float = 0.001) -> Dict[str, any]:
    """完整对齐训练循环。
    modalities: {name: [N_samples, dim]} — 各模态嵌入。
    epochs: 训练轮数。
    lr: 学习率。
    返回: {'aligned': {name: embeddings}, 'loss_history': [...], 'converged_epoch': int}。
    """
    _loss_hist: List[float] = []
    _early_stop = EarlyStopping(patience=min(10, epochs // 5))
    _alignment = MultiPairAlignment()
    _names = list(modalities.keys())

    # 温度退火
    _temp_sched = TemperatureSchedule(tau_max=0.3, tau_min=0.05,
                                       warmup_epochs=epochs // 5,
                                       total_epochs=epochs)

    # 学习率调度
    _lr_sched = LRSchedule(lr_max=lr, lr_min=lr * 0.01,
                            warmup_epochs=epochs // 10,
                            total_epochs=epochs)

    # 课程调度
    _curriculum = CurriculumScheduler(total_epochs=epochs, warmup_ratio=0.1)

    # 初始化可训练嵌入（浅拷贝后做梯度更新）
    _trainable = {_k: [_row[:] for _row in _v] for _k, _v in modalities.items()}

    # 动量编码器
    _initial_params = {_k: [[[_w]] for _w in _v] for _k, _v in
                        {n: modalities[n][0] for n in _names}.items()}
    _mom_enc = MomentumEncoder(encoder_params=None, momentum=0.999)

    _converged = epochs
    for _epoch in range(epochs):
        # 温度更新
        _tau = _temp_sched.get(_epoch)
        _alignment._loss_fn.temperature = _tau

        # 学习率更新
        _step_lr = _lr_sched.get(_epoch)

        # 课程进度
        _aug_strength, _hard_ratio = _curriculum.get(_epoch)

        # 前向 → 损失（带模态 dropout 增强鲁棒性）
        # 课程后期增加模态 dropout，模拟更困难的缺失模态场景
        _mod_dropout = 0.15 * _aug_strength if _epoch > epochs // 3 else 0.0
        _loss, _ = _alignment.forward_with_dropout(_trainable, _mod_dropout)
        _loss_hist.append(_loss)

        # 手动梯度下降（简化：对嵌入做小步扰动）
        for _k in _names:
            _emb = _trainable[_k]
            _n = len(_emb)
            _d = len(_emb[0]) if _emb else 0
            for _i in range(_n):
                _row = _emb[_i]
                # 梯度近似：随机方向有限差分
                # 课程后期使用更大扰动步长（等效更强增强）
                _delta = random.gauss(0, 0.01 * (0.5 + _aug_strength))
                for _j in range(_d):
                    _row[_j] += _step_lr * _delta * _row[_j]
            _trainable[_k] = _l2_normalize(_trainable[_k])

        # 梯度裁剪
        _trainable = _clip_gradients(_trainable, max_norm=2.0)

        # 动量编码器更新
        _flat_params = {}
        for _k in _names:
            _flat_params[_k] = [[_v] for _row in _trainable[_k] for _v in _row]
        _mom_enc.update(_flat_params)

        # 早停检查
        if _early_stop.should_stop(_loss):
            _converged = _epoch + 1
            break

    return {
        'aligned': _trainable,
        'loss_history': _loss_hist,
        'converged_epoch': _converged,
        'final_loss': _loss_hist[-1] if _loss_hist else float('inf'),
    }


# ============================================================================
# SimSiam 风格停止梯度对齐 — predictor + stop_grad 避免模式坍缩
# 参考：Chen & He. Exploring Simple Siamese Representation Learning. CVPR 2021.
# 关键设计：predictor MLP 是非对称核心，stop_grad 使一侧成为常量目标
# ============================================================================

class SimSiamAlign:
    """SimSiam 对齐：非对称孪生网络 + stop-gradient。

    一侧编码器输出经 predictor 预测另一侧的 stop_gradient 输出。
    负余弦相似度为损失，最小化 → 两嵌入方向一致。
    无需负样本、动量编码器、大 batch——设计极简。
    """

    def __init__(self, input_dim: int, hidden_dim: int = 128, proj_dim: int = 64):
        self._proj = ProjectionHead(input_dim, hidden_dim, proj_dim)
        # predictor: proj_dim → hidden_dim → proj_dim（瓶颈结构）
        self._pred_W1: List[List[float]] = [
            [math.sin(i*0.47 + j*0.83) * math.sqrt(2.0/proj_dim)
             for j in range(hidden_dim)] for i in range(proj_dim)]
        self._pred_W2: List[List[float]] = [
            [math.sin(i*0.29 + j*1.07) * math.sqrt(2.0/hidden_dim)
             for j in range(proj_dim)] for i in range(hidden_dim)]

    def forward(self, z1: List[List[float]], z2: List[List[float]]) -> float:
        """z1, z2 为两个增强视图的编码器输出。

        流程：z1→proj→pred(z1); z2→proj→stop_grad(z2)
        loss = -cos(pred(proj(z1)), stop_grad(proj(z2)))
        """
        _p1 = self._proj.forward(z1)
        _p2 = self._proj.forward(z2)
        # predictor on view 1
        _pred1 = self._predictor_forward(_p1)
        _N, _d = len(_pred1), len(_pred1[0]) if _pred1 else 0
        if _N == 0:
            return 0.0
        _loss = 0.0
        for _i in range(_N):
            _dot = sum(_pred1[_i][_j] * _p2[_i][_j] for _j in range(min(_d, len(_p2[_i]))))
            _n1 = math.sqrt(sum(x*x for x in _pred1[_i])) + _EPS
            _n2 = math.sqrt(sum(x*x for x in _p2[_i])) + _EPS
            _loss -= _dot / (_n1 * _n2)
        return _loss / _N

    def _predictor_forward(self, x: List[List[float]]) -> List[List[float]]:
        _n = len(x)
        _h_dim = len(self._pred_W1[0])
        _hidden = [[0.0]*_h_dim for _ in range(_n)]
        for _i in range(_n):
            for _j in range(_h_dim):
                _acc = sum(x[_i][_k]*self._pred_W1[_k][_j]
                         for _k in range(min(len(x[_i]), len(self._pred_W1))))
                _hidden[_i][_j] = max(0.0, _acc)
        _o_dim = len(self._pred_W2[0])
        _out = [[0.0]*_o_dim for _ in range(_n)]
        for _i in range(_n):
            for _j in range(_o_dim):
                _out[_i][_j] = sum(_hidden[_i][_k]*self._pred_W2[_k][_j]
                                 for _k in range(min(len(_hidden[_i]), len(self._pred_W2))))
        return _out


# ============================================================================
# VICReg — 方差-不变性-协方差正则化
# 参考：Bardes et al. VICReg: Variance-Invariance-Covariance Regularization
#       for Self-Supervised Learning. ICLR 2022.
# 三项损失联合约束嵌入空间：不变性（配对MSE）、方差（防坍缩）、
# 协方差（去相关，使各维编码不同信息）
# ============================================================================

class VICRegLoss:
    """VICReg 损失：variance + invariance + covariance。

    不变性项 (s)：配对 MSE——最小化增强版本间差异。
    方差项 (v)：嵌入各维标准差与目标的 hinge loss——防止所有样本坍缩至同一点。
    协方差项 (c)：嵌入协方差矩阵非对角元平方和——去相关以最大化信息利用率。
    """

    def __init__(self, sim_coef: float = 25.0, std_coef: float = 25.0,
                 cov_coef: float = 1.0, epsilon: float = 1e-4):
        self.sim_coef = sim_coef
        self.std_coef = std_coef
        self.cov_coef = cov_coef
        self.eps = epsilon

    # 不变性：配对 MSE
    def _inv_loss(self, z1: List[List[float]], z2: List[List[float]]) -> float:
        _n = len(z1)
        if _n == 0:
            return 0.0
        _d = len(z1[0])
        _mse = sum(sum((z1[i][j]-z2[i][j])**2 for j in range(_d)) for i in range(_n))
        return self.sim_coef * _mse / _n

    # 方差：每维标准差 → hinge(1 - sqrt(var+eps))
    def _var_loss(self, z: List[List[float]]) -> float:
        _n, _d = len(z), len(z[0]) if z else 0
        if _n < 2:
            return 0.0
        _total = 0.0
        for _j in range(_d):
            _mean_j = sum(z[_i][_j] for _i in range(_n)) / _n
            _var_j = sum((z[_i][_j]-_mean_j)**2 for _i in range(_n)) / (_n-1)
            _std_j = math.sqrt(_var_j + self.eps)
            _total += max(0.0, 1.0 - _std_j)
        return self.std_coef * _total / _d

    # 协方差：去相关
    def _cov_loss(self, z: List[List[float]]) -> float:
        _n, _d = len(z), len(z[0]) if z else 0
        if _n < 2:
            return 0.0
        # 中心化
        _centered = [[0.0]*_d for _ in range(_n)]
        for _j in range(_d):
            _m = sum(z[_i][_j] for _i in range(_n)) / _n
            for _i in range(_n):
                _centered[_i][_j] = z[_i][_j] - _m
        # 协方差矩阵 C = (Z^T Z) / (n-1)
        _total = 0.0
        for _j in range(_d):
            for _k in range(_d):
                if _j == _k:
                    continue
                _c_jk = sum(_centered[_i][_j]*_centered[_i][_k] for _i in range(_n))/(_n-1)
                _total += _c_jk * _c_jk
        return self.cov_coef * _total / _d

    def forward(self, z1: List[List[float]], z2: List[List[float]]) -> Tuple[float, Dict[str, float]]:
        _inv = self._inv_loss(z1, z2)
        _var = (self._var_loss(z1) + self._var_loss(z2)) / 2.0
        _cov = (self._cov_loss(z1) + self._cov_loss(z2)) / 2.0
        _total = _inv + _var + _cov
        return _total, {'invariance': round(_inv,4), 'variance': round(_var,4), 'covariance': round(_cov,4)}


# ============================================================================
# Sinkhorn-Knopp 最优传输对齐 — 在嵌入空间执行等变聚类
# 参考：Caron et al. Unsupervised Learning of Visual Features by
#       Contrasting Cluster Assignments (SwAV). NeurIPS 2020.
# Sinkhorn 归一化：相似度矩阵映射为双随机矩阵 → 软聚类分配
# 以软分配的交叉熵替代直接特征对比
# ============================================================================

def sinkhorn_knopp(similarity_matrix: List[List[float]],
                   n_iters: int = 3, epsilon_sk: float = 0.05) -> List[List[float]]:
    """Sinkhorn-Knopp 算法：将任意方阵/矩形阵归约为双随机矩阵。

    设 S 的行对应 batch，列对应 prototype。
    交替行/列指数缩放+归一化，收敛于最优传输的熵正则化解。
    复杂度 O(N·K·n_iters)，远小于完整最优传输 O(N³) 匈牙利算法。
    """
    _N = len(similarity_matrix)
    _K = len(similarity_matrix[0]) if _N > 0 else 0
    if _N == 0 or _K == 0:
        return similarity_matrix

    _Q = [[math.exp(similarity_matrix[i][j]/epsilon_sk) for j in range(_K)] for i in range(_N)]

    for _ in range(n_iters):
        # 行归一化
        for _i in range(_N):
            _row_sum = sum(_Q[_i][_j] for _j in range(_K)) + _EPS
            for _j in range(_K):
                _Q[_i][_j] /= _row_sum
        # 列归一化
        for _j in range(_K):
            _col_sum = sum(_Q[_i][_j] for _i in range(_N)) + _EPS
            for _i in range(_N):
                _Q[_i][_j] /= _col_sum

    return _Q


class OTAlignmentLoss:
    """最优传输对齐损失：将跨模态嵌入映射到共享 prototype 空间。

    流程：
    1. 各模态独立投影到 K 个 prototype
    2. Sinkhorn-Knopp 将得分矩阵转为双随机矩阵（软分配）
    3. 交叉熵损失：A 模态软分配 → B 模态软分配标签
    等效于嵌入空间软聚类对齐——SwAV 核心思路。
    """

    def __init__(self, n_prototypes: int = 256, temperature: float = 0.1):
        self.n_prototypes = n_prototypes
        self.temperature = temperature
        # prototype 向量：可学习聚类中心
        self._prototypes: List[List[float]] = [
            [math.sin(p*0.17 + d*0.53)*0.1/math.sqrt(64) for d in range(64)]
            for p in range(n_prototypes)]

    def forward(self, embeddings_a: List[List[float]],
                embeddings_b: List[List[float]]) -> float:
        """计算跨模态软聚类对齐损失。"""
        _N = len(embeddings_a)
        _d_a, _d_b = len(embeddings_a[0]) if _N>0 else 0, len(embeddings_b[0]) if _N>0 else 0
        if _N < 2:
            return 0.0

        _proto_dim = len(self._prototypes[0])
        _K = self.n_prototypes

        # 模态 A → prototype 相似度
        _sim_a = [[0.0]*_K for _ in range(_N)]
        for _i in range(_N):
            for _p in range(_K):
                _dot = sum(embeddings_a[_i][_j]*self._prototypes[_p][_j]
                         for _j in range(min(_d_a, _proto_dim)))
                _sim_a[_i][_p] = _dot / self.temperature

        # 模态 B → prototype 相似度
        _sim_b = [[0.0]*_K for _ in range(_N)]
        for _i in range(_N):
            for _p in range(_K):
                _dot = sum(embeddings_b[_i][_j]*self._prototypes[_p][_j]
                         for _j in range(min(_d_b, _proto_dim)))
                _sim_b[_i][_p] = _dot / self.temperature

        # Sinkhorn 归一化 → 软分配 Q_a, Q_b
        _Q_a = sinkhorn_knopp(_sim_a)
        _Q_b = sinkhorn_knopp(_sim_b)

        # 交叉熵：Q_b 作为 Q_a 的软标签
        _loss = 0.0
        for _i in range(_N):
            for _p in range(_K):
                if _Q_b[_i][_p] > 1e-8:
                    _loss -= _Q_b[_i][_p] * math.log(max(_Q_a[_i][_p], _EPS))
        return _loss / _N


# ============================================================================
# MIL-NCE — 多实例学习 + 噪声对比估计（弱对齐场景）
# 参考：Miech et al. End-to-End Learning of Visual Representations
#       from Uncurated Instructional Videos. CVPR 2020.
# 关键：视频任意时间窗口的 clip-text 对均视为正样本，
# 不要求严格对齐——适合仅有弱配对信息的场景
# ============================================================================

def mil_nce_loss(clip_embeddings: List[List[float]],
                  text_embeddings: List[List[float]],
                  n_clips_per_text: int = 5,
                  temperature: float = 0.07) -> float:
    """MIL-NCE：对每个文本取 K 个最相似 clip 的对数似然均值。

    对文本 i，在 clip_embeddings 中找 n_clips_per_text 个最相似 clip，
    取这些 clip-text 对平均相似度作为正样本得分。
    允许一个文本对应多个视觉片段——适合弱对齐。
    """
    _N_clips = len(clip_embeddings)
    _N_texts = len(text_embeddings)
    if _N_clips < 3 or _N_texts < 2:
        return 0.0

    _loss_fn = NTXentLoss()
    _sim = _loss_fn.cosine_similarity_matrix(text_embeddings, clip_embeddings)
    _tau = temperature

    _total_loss = 0.0
    for _t in range(_N_texts):
        _row = _sim[_t]
        # 每个文本取 top-K clips 作为正样本
        _topk_indices = sorted(range(_N_clips), key=lambda j: _row[j], reverse=True)[:n_clips_per_text]
        _pos_sims = [_row[_j] for _j in _topk_indices]
        # log-sum-exp 稳定计算
        _scaled_row = [_s / _tau for _s in _row]
        _mx = max(_scaled_row)
        _denom = math.log(sum(math.exp(_s - _mx) for _s in _scaled_row) + _EPS)
        # 正样本对数似然均值
        _pos_term = sum(_s / _tau for _s in _pos_sims) / n_clips_per_text
        _total_loss += -(_pos_term - _mx - _denom)

    return _total_loss / _N_texts


# ============================================================================
# SigLIP 风格损失 — sigmoid 替代 softmax，每对独立判别
# 参考：Zhai et al. Sigmoid Loss for Language Image Pre-Training. ICCV 2023.
# 优势：不依赖 batch 内归一化，batch size 可降至很小；
#      每个正/负对独立计算二元交叉熵，天然支持极端不平衡
# ============================================================================

def siglip_contrastive_loss(embeddings_a: List[List[float]],
                              embeddings_b: List[List[float]],
                              temperature: float = 0.07,
                              bias: float = -10.0) -> float:
    """SigLIP 对比损失：逐对 sigmoid 二元交叉熵。

    正对标签 = +1，负对标签 = -1（+bias 做 logit 偏置 → 负对期望输出 ≈ 0）。
    独立于 batch size——这是 SigLIP 相比 NT-Xent 的最大实用优势。
    """
    _N = len(embeddings_a)
    if _N < 1:
        return 0.0

    _loss_fn = NTXentLoss()
    _sim = _loss_fn.cosine_similarity_matrix(embeddings_a, embeddings_b)

    _total_loss = 0.0
    _count = 0
    for _i in range(_N):
        for _j in range(_N):
            _logit = _sim[_i][_j] / temperature + bias
            _label = 1.0 if _i == _j else -1.0
            # -log σ(label*logit) = log(1+exp(-label*logit))
            _z = -_label * _logit
            # 数值稳定 log(1+exp(-z))
            if _z > 20:
                _total_loss += _z  # ≈ log(exp(-z)) = -z = label*logit
            else:
                _total_loss += math.log(1.0 + math.exp(_z))
            _count += 1

    return _total_loss / max(1, _count)


# ============================================================================
# 跨模态 Mixup — 在嵌入空间做线性插值增强
# 参考：Zhang et al. mixup: Beyond Empirical Risk Minimization. ICLR 2018.
# 跨模态扩展：同时 mixup 两个模态的样本与标签，
# 产生连续的跨模态插值合成样本
# ============================================================================

def cross_modal_mixup(embeddings_a: List[List[float]],
                       embeddings_b: List[List[float]],
                       labels: List[int],
                       alpha_mix: float = 0.4) -> Tuple[List[List[float]], List[List[float]], List[int], List[int], List[float]]:
    """跨模态 mixup：在嵌入空间中对 batch 内样本对做凸组合。

    λ ~ Beta(α, α)，混合 A = λ·A_i + (1-λ)·A_j，B 同理。
    标签也混合（用于 SupCon 等标签感知损失）。
    返回 (mixed_A, mixed_B, labels_i, labels_j, lambdas)。
    """
    _N = len(embeddings_a)
    if _N < 2:
        return embeddings_a, embeddings_b, labels, labels, [1.0]*_N

    _d_a = len(embeddings_a[0]) if _N > 0 else 0
    _d_b = len(embeddings_b[0]) if _N > 0 else 0

    _mixed_a = [[0.0]*_d_a for _ in range(_N)]
    _mixed_b = [[0.0]*_d_b for _ in range(_N)]
    _labels_i = list(labels)
    _labels_j = [0]*_N
    _lambdas = [0.0]*_N

    for _i in range(_N):
        _j = (_i + 1 + int(math.sin(_i*1.37)*100)) % _N  # 伪随机配对
        _lam = random.betavariate(alpha_mix, alpha_mix) if alpha_mix > 0 else 1.0
        _lambdas[_i] = _lam
        _labels_j[_i] = labels[_j]
        for _d in range(_d_a):
            _mixed_a[_i][_d] = _lam * embeddings_a[_i][_d] + (1-_lam) * embeddings_a[_j][_d]
        for _d in range(_d_b):
            _mixed_b[_i][_d] = _lam * embeddings_b[_i][_d] + (1-_lam) * embeddings_b[_j][_d]

    return _mixed_a, _mixed_b, _labels_i, _labels_j, _lambdas


# ============================================================================
# 对齐均匀性指标 — 评估嵌入空间在超球面上的分布质量
# 参考：Wang & Isola. Understanding Contrastive Representation Learning
#       through Alignment and Uniformity. ICML 2020.
# 对齐：正样本对距离小；均匀性：嵌入在整个球面上均匀散布
# ============================================================================

def uniformity_metric(embeddings: List[List[float]], t: float = 2.0) -> float:
    """嵌入均匀性：所有嵌入对之间的平均 RBF 核值。

    L_uniform = log(E_{i≠j}[exp(-t·||z_i - z_j||²)])
    低值 → 嵌入在超球面上更均匀分布 → 保留更多信息容量。
    配合对齐损失，可达 alignment+uniformity 的 Pareto 前沿。
    """
    _N = len(embeddings)
    if _N < 2:
        return 0.0
    _d = len(embeddings[0]) if _N > 0 else 0
    _total = 0.0
    _pairs = 0
    for _i in range(_N):
        for _j in range(_i+1, _N):
            _dist_sq = sum((embeddings[_i][_k]-embeddings[_j][_k])**2 for _k in range(_d))
            _total += math.exp(-t * _dist_sq)
            _pairs += 1
    return -math.log(_total / max(1, _pairs) + _EPS)
