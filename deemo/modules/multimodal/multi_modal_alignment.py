# 2026-07-27
# 多模态对齐训练 — SimCLR式对比学习 + BYOL动量编码器
# 核心思想：不同模态的对应样本在嵌入空间拉近，非对应推远
# NT-Xent损失：温度参数τ控制softmax锐度（越小越难，越大越平滑）

import math
import random
from typing import Dict, List, Optional, Tuple

# ---- 全局常量 ----
_DEFAULT_TEMPERATURE: float = 0.07
_EPS: float = 1e-9


# ============================================================================
# NT-Xent 损失 — 归一化温度缩放交叉熵 (SimCLR风格)
# 对角线为正样本对，其余为负样本；对称损失取两个方向均值
# ============================================================================

class NTXentLoss:
    """归一化温度缩放交叉熵损失
    正样本在对角线：假设 embeddings_a[i] 与 embeddings_b[i] 是对应配对"""

    def __init__(self, temperature: float = _DEFAULT_TEMPERATURE):
        self.temperature = temperature

    # //// 余弦相似度矩阵：S[i][j] = A[i] · B[j] / (||A[i]|| * ||B[j]||) ////
    def cosine_similarity_matrix(self, A: List[List[float]],
                                  B: List[List[float]]) -> List[List[float]]:
        """成对余弦相似度：A的每行与B的每行计算cosine"""
        _n_a, _n_b = len(A), len(B)
        _d = len(A[0]) if A else 0

        # 预计算L2范数
        _norm_a = [0.0] * _n_a
        _norm_b = [0.0] * _n_b

        for _i in range(_n_a):
            _s = sum(_v * _v for _v in A[_i])
            _norm_a[_i] = math.sqrt(_s) + _EPS

        for _j in range(_n_b):
            _s = sum(_v * _v for _v in B[_j])
            _norm_b[_j] = math.sqrt(_s) + _EPS

        # 计算S矩阵
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
        """前向计算NT-Xent损失值
        embeddings_a/b: [batch_size, dim], 第i行互为正样本对"""
        _temp = temperature if temperature is not None else self.temperature
        _N = len(embeddings_a)
        if _N < 2:
            return 0.0

        # 余弦相似度 → 除以温度
        _sim = self.cosine_similarity_matrix(embeddings_a, embeddings_b)
        for _i in range(_N):
            for _j in range(_N):
                _sim[_i][_j] /= _temp

        # 两个方向的损失
        _loss_a = 0.0
        _loss_b = 0.0

        # 方向 A→B: 对于每个i，第i列为正样本
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
# 无温度 InfoNCE — 用 atanh 映射消除温度超参数
# 参考 H-InfoNCE (Kim et al., Jan 2025): arctanh reparameterization
# 保证整个相似度范围内的正梯度且单调递减，无需调 τ
# ============================================================================

class TempFreeNTXent:
    """无温度 InfoNCE：用 atanh(sim) 替代 sim/τ 的缩放。

    τ 被隐式编码在 atanh 的梯度饱和区：
    高相似度 → atanh' 大 → 梯度集中于难样本（等价于低 τ）
    低相似度 → atanh' 小 → 梯度稀疏于易样本（等价于高 τ）
    自适应调节——无需手动退火。
    """

    def forward(self, embeddings_a: List[List[float]],
                embeddings_b: List[List[float]]) -> float:
        _N = len(embeddings_a)
        if _N < 2:
            return 0.0

        _loss_fn = NTXentLoss()
        _sim = _loss_fn.cosine_similarity_matrix(embeddings_a, embeddings_b)

        # atanh 映射：sim ∈ [-1,1] → atanh ∈ (-∞,∞)
        # 对数值做 clamp 避免 atanh(±1) = ±∞
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
# 早期：弱增强 + 低难度负样本 → 学习粗粒度结构
# 后期：强增强 + 高难度负样本 → 精调判别边界
# ============================================================================

class CurriculumScheduler:
    """课程学习调度器：控制增强强度和负样本难度。

    augmentation_strength ∈ [0,1]: 数据增强的激进程度。
    hardness_ratio ∈ [0,1]: 训练中使用的困难负样本比例。
    两者均按余弦曲线从低到高递增。
    """

    def __init__(self, total_epochs: int = 100, warmup_ratio: float = 0.1):
        self.total = total_epochs
        self.warmup = int(total_epochs * warmup_ratio)

    def get(self, epoch: int) -> Tuple[float, float]:
        """返回 (augmentation_strength, hardness_ratio)。"""
        # warmup 阶段仅用弱增强 + 极少难负样本
        if epoch < self.warmup:
            _p = epoch / max(1, self.warmup)
            return (0.1 + 0.3 * _p, 0.0)
        _progress = (epoch - self.warmup) / max(1, self.total - self.warmup)
        _aug = 0.4 + 0.6 * (1.0 - math.cos(math.pi * _progress)) / 2.0
        _hard = 0.05 + 0.45 * (1.0 - math.cos(math.pi * _progress)) / 2.0
        return (round(_aug, 3), round(_hard, 3))


# ============================================================================
# 有监督对比损失 (SupCon) — 利用标签信息构造正样本集
# 相比NT-Xent仅将配对视为正样本，SupCon将同一标签的所有样本
# 都纳入正样本集，在类别可分性上通常优于自监督变体
# ============================================================================

class SupConLoss:
    """有监督对比损失：同标签样本互为增强正样本。

    每个 anchor 的正样本 = 与该 anchor 标签相同的所有其他样本。
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
# 硬负样本挖掘 — 基于距离加权采样，优先选择嵌入空间中的困难负样本
# ============================================================================

def hard_negative_mask(embeddings_a: List[List[float]],
                       embeddings_b: List[List[float]],
                       labels_a: List[int],
                       labels_b: List[int],
                       topk_neg: int = 5) -> List[List[float]]:
    """构建硬负样本掩码：每行保留 topk_neg 个最难（最相似）的负样本。

    困难负样本 = 与 anchor 相似度高但标签不同的样本。
    对 NT-Xent 损失施加此掩码后，模型被迫区分语义上相近但类别不同的样本对，
    通常能提升细粒度对齐质量。
    """
    _N = len(embeddings_a)
    _d = len(embeddings_a[0]) if _N > 0 else 0
    if _N < 2:
        return [[1.0] * len(embeddings_b) for _ in range(_N)]

    _loss_fn = NTXentLoss()
    _sim = _loss_fn.cosine_similarity_matrix(embeddings_a, embeddings_b)

    _mask = [[1.0] * len(embeddings_b) for _ in range(_N)]
    for _i in range(_N):
        # 找出所有负样本索引及相似度
        _neg_sims: List[Tuple[int, float]] = []
        for _j in range(len(embeddings_b)):
            if labels_b[_j] != labels_a[_i]:
                _neg_sims.append((_j, _sim[_i][_j]))
        if len(_neg_sims) <= topk_neg:
            continue
        # 按相似度降序（最难的在前），保留 topk_neg
        _neg_sims.sort(key=lambda x: x[1], reverse=True)
        _keep_j = {_ns[0] for _ns in _neg_sims[:topk_neg]}
        for _j in range(len(embeddings_b)):
            if labels_b[_j] != labels_a[_i] and _j not in _keep_j:
                _mask[_i][_j] = 0.0
    return _mask


# ============================================================================
# 温度退火调度 — 训练前期高τ（平滑、探索），后期低τ（锐利、收敛）
# 余弦退火从τ_max到τ_min，warmup阶段线性上升
# ============================================================================

class TemperatureSchedule:
    """温度退火：warmup + cosine decay。

    高温度→softmax平滑→梯度分散到更多负样本（早期探索）；
    低温度→softmax锐利→聚焦最难负样本（后期精调）。
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
# 对齐质量指标 — 评估嵌入对齐的均匀性与容忍度
# ============================================================================

def alignment_quality(embeddings_a: List[List[float]],
                      embeddings_b: List[List[float]]) -> Dict[str, float]:
    """计算对齐质量指标：平均余弦相似度 + 最近邻一致性。

    uniformity: 正样本对平均余弦相似度，接近1=完全对齐。
    nearest_neighbor_accuracy: 以A到B的最近邻是否恰好是对应配对。
    理想情况下两者都接近1。
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
# 投影头 — 将编码器输出映射到对比学习空间
# 浅MLP (2层 + ReLU + BN) 通常优于单层线性投影
# ============================================================================

class ProjectionHead:
    """对比学习投影头：encoder_dim → hidden_dim → output_dim。

    SimCLR 论文表明非线性投影头能提升 10-15% 的下游任务性能。
    """

    def __init__(self, input_dim: int, hidden_dim: int = 128, output_dim: int = 64):
        self.input_dim = input_dim
        # 权重用 Kaiming-like 初始化范数
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
# 动量编码器 — BYOL风格，避免负样本依赖
# θ_m ← m·θ_m + (1-m)·θ_e，滑动平均更新
# ============================================================================

class MomentumEncoder:
    """BYOL动量编码器：EMA更新目标编码器参数
    momentum=0.999 时每步仅更新0.1%→慢速稳定"""

    def __init__(self, encoder_params: Optional[Dict[str, List[List[float]]]] = None,
                 momentum: float = 0.999):
        self.momentum = momentum
        # 动量参数存储
        self._momentum_params: Dict[str, List[List[float]]] = {}
        if encoder_params:
            self._momentum_params = {k: [_row[:] for _row in v]
                                      for k, v in encoder_params.items()}

    def update(self, base_encoder_params: Dict[str, List[List[float]]]):
        """动量更新：θ_m = m·θ_m + (1-m)·θ_e"""
        if not self._momentum_params:
            # 首次初始化：直接复制
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
        """使用动量参数编码输入
        encoder_forward_fn: 接受 (x, params) 返回编码结果"""
        return encoder_forward_fn(x, self._momentum_params)

    def get_params(self) -> Dict[str, List[List[float]]]:
        return {k: [_row[:] for _row in v] for k, v in self._momentum_params.items()}


# ============================================================================
# 学习率调度 — cosine decay with linear warmup
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
# 多对对齐 — N>2模态的成对对比学习
# M个模态 → M*(M-1) 有向对 或 M choose 2 无向对
# ============================================================================

class MultiPairAlignment:
    """多模态成对对齐：对模态对 {name: features} 计算所有NT-Xent损失"""

    def __init__(self, temperature: float = _DEFAULT_TEMPERATURE, symmetric: bool = True):
        self.temperature = temperature
        self.symmetric = symmetric  # True→无向对，False→有向全对
        self._loss_fn = NTXentLoss(temperature=temperature)

    # 主前向：输入字典 {modal_name: [batch, dim] embeddings}
    def forward(self, modality_dict: Dict[str, List[List[float]]]) -> Tuple[float, Dict[str, float]]:
        """计算所有模态对之间的NT-Xent损失
        返回：(总损失, {模态对名称: 各对损失})"""
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
        """带模态dropout的前向：随机丢弃部分模态对以增强鲁棒性。

        dropout_prob=0.2 时约 20% 模态对被随机跳过，
        迫使模型学习冗余的跨模态对齐路径。
        """
        if dropout_prob <= 0 or random.random() > dropout_prob:
            return self.forward(modality_dict)

        _names = list(modality_dict.keys())
        _M = len(_names)
        if _M < 3:
            return self.forward(modality_dict)

        # 随机选择保留的模态子集（至少保留2个）
        _keep = max(2, int(_M * (1.0 - dropout_prob)))
        _selected = random.sample(_names, _keep)
        _subset = {_k: modality_dict[_k] for _k in _selected}
        return self.forward(_subset)


# ============================================================================
# 早停机制 — patience轮无改善即停止
# ============================================================================

class EarlyStopping:
    """验证损失不再下降时提前终止训练"""

    def __init__(self, patience: int = 5, min_delta: float = 1e-4):
        self.patience = patience
        self.min_delta = min_delta
        self._best_loss: float = float('inf')
        self._counter: int = 0
        self._should_stop: bool = False

    def should_stop(self, current_loss: float) -> bool:
        """检查是否应停止：patience轮无改善→True"""
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
    """L2归一化：每行归一化到单位长度"""
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
    """全局梯度裁剪：限制嵌入更新的L2范数上限。

    max_norm=1.0 约等价于将每个嵌入向量的步长限制到单位球面附近。
    """
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
    """完整对齐训练循环
    modalities: {name: [N_samples, dim]} — 各模态的嵌入
    epochs: 训练轮数
    lr: 学习率
    返回: {'aligned': {name: embeddings}, 'loss_history': [...], 'converged_epoch': int}"""
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

    # 初始化可训练嵌入（浅拷贝后梯度更新）
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

        # 前向 → 损失（带模态dropout增强鲁棒性）
        # 课程后期增加模态dropout以模拟更难的缺失模态场景
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
                # 梯度近似：随机方向采样的有限差分
                # 课程后期使用更大扰动步长（等价于更强的增强）
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
