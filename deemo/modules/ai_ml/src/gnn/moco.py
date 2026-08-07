"""
GraphMoCo: 基于动量对比学习的图级二进制函数嵌入模块。

理论依据:
  1. GraphMoCo: 动量编码器 + 预洗牌机制防止信息泄露,
     大字典负样本队列不依赖大批量训练。
  2. IRBinDiff: LLVM-IR 中间表示提升 + GGNN 结构编码器,
     配合 MoCo 对比学习实现跨架构二进制相似性检测。
  3. 节点结构重要性驱动的图增强: 通过组合质量分数 (度数+聚类系数+PageRank)
     生成语义上有意义的增强视图, 替代随机 dropout。

差异点: 现有 ai_ml 模块的 GNN 模型使用端到端 InfoNCE 对比损失, 缺乏动量编码器
和负样本队列机制。GraphMoCo 的动量队列提供更稳定的对比信号, 且 BEGA 的重力模型
增强比随机 dropout 更真实地模拟编译器变换。

模块位置: ai_ml/src/gnn/moco.py
"""

import math
import random
from collections import deque
from typing import Optional

# 无外部 ML 框架依赖 — 纯 NumPy 实现, 与现有 ai_ml 模块保持一致
try:
    import numpy as np
except ImportError:
    np = None  # 优雅降级: 调用方可注入其他数值后端


# 动量编码器 (Momentum Encoder)

class MomentumEncoder:
    """
    动量更新的目标编码器 — GraphMoCo 的核心组件。

    设计意图:
      维护一个参数缓慢更新的编码器副本, 避免端到端对比学习中因梯度回传
      到目标分支而导致的表示坍缩。动量系数 m 控制目标编码器的更新速度,
      m 越接近 1.0, 目标编码器越稳定但适应越慢。

    参数选择依据:
      m = 0.999: GraphMoCo 论文推荐值, 在稳定性和适应速度间取平衡。
      更新公式: θ_target = m * θ_target + (1 - m) * θ_source
    """

    def __init__(self, source_encoder, momentum: float = 0.999):
        if np is None:
            raise ImportError("GraphMoCo 需要 NumPy — pip install numpy")
        self._src = source_encoder
        self._m = momentum
        self._params: dict[str, np.ndarray] = {}
        self._initialized = False

    def _capture_params(self) -> dict[str, np.ndarray]:
        """
        从源编码器提取可训练参数。依赖源编码器暴露 _get_params() 方法。

        边界条件:
          若源编码器未实现 _get_params(), 降级为尝试复制 __dict__ 中的
          所有 ndarray 属性。此降级路径精度较低 (可能包含非参数数组),
          但保证不崩溃。
        """
        if hasattr(self._src, '_get_params'):
            return {k: v.copy() for k, v in self._src._get_params().items()}

        # 降级路径: 从 __dict__ 过滤 ndarray
        params = {}
        for attr_name, attr_val in self._src.__dict__.items():
            if isinstance(attr_val, np.ndarray):
                params[attr_name] = attr_val.copy()
        return params

    def init_target(self):
        """首次快照源编码器的所有参数到目标编码器。"""
        self._params = self._capture_params()
        self._initialized = True

    def update(self):
        """
        动量更新目标编码器参数。

        调用约定: 每次源编码器参数更新后调用一次。
        若未初始化则自动执行 init_target()。
        """
        if not self._initialized:
            self.init_target()
            return

        src_params = self._capture_params()
        for key in self._params:
            if key in src_params:
                self._params[key] = (
                    self._m * self._params[key] + (1.0 - self._m) * src_params[key]
                )

    def forward(self, x: np.ndarray) -> np.ndarray:
        """
        使用目标编码器参数前向传播。

        实现说明:
          此处采用简化的参数注入模式 — 临时替换源编码器的参数,
          前向传播后恢复。此设计的权衡是:
          - 优点: 复用源编码器的 forward 实现, 不需要复制网络结构。
          - 缺点: 非线程安全。在多线程训练环境中需加锁保护。
        """
        if not self._initialized:
            self.init_target()

        # 保存源参数, 注入目标参数
        src_backup = {}
        for key, val in self._params.items():
            if hasattr(self._src, key):
                src_backup[key] = getattr(self._src, key)
                setattr(self._src, key, val)

        result = self._src.forward(x)

        # 恢复源参数
        for key, val in src_backup.items():
            setattr(self._src, key, val)

        return result


# 负样本队列 (Negative Sample Queue)

class NegativeQueue:
    """
    FIFO 负样本队列 — 存储最近 K 个批次的嵌入向量作为对比学习的负样本。

    设计意图:
      GraphMoCo 核心创新之一: 通过维护大字典大小的负样本队列 (K=65536),
      在不增加批量大小的前提下提供丰富的负样本, 使对比学习更有效。

    队列容量选择:
      K=65536: GraphMoCo 论文中的默认字典大小。对于二进制函数嵌入任务,
      可以根据可用内存调整为 32768 (约 128MB, float32×1024dim)。
      较小值 (4096-16384) 适用于内存受限环境, 但可能降低对比学习效果。

    预洗牌机制 (Pre-shuffle):
      每次入队前随机打乱批次内的嵌入顺序, 打破相邻批次间的伪相关性。
      GraphMoCo 论文证明此机制可显著减少信息泄露。
    """

    def __init__(self, dim: int, max_size: int = 65536):
        if np is None:
            raise ImportError("NegativeQueue 需要 NumPy")
        if max_size < 1:
            raise ValueError(f"队列容量必须为正整数, 收到: {max_size}")
        self._dim = dim
        self._max = max_size
        self._queue: deque = deque(maxlen=max_size)
        self._buffer: list[np.ndarray] = []

    @property
    def size(self) -> int:
        return len(self._queue)

    @property
    def is_full(self) -> bool:
        return len(self._queue) >= self._max

    def enqueue(self, embeddings: np.ndarray, pre_shuffle: bool = True):
        """
        将嵌入向量加入队列。

        参数:
          embeddings: shape (batch_size, dim) 的嵌入向量矩阵。
          pre_shuffle: 是否在入队前随机打乱。默认开启, 对应 GraphMoCo 预洗牌。
        """
        if embeddings.ndim != 2 or embeddings.shape[1] != self._dim:
            raise ValueError(
                f"嵌入维度不匹配: 期望 ({self._dim},), 收到 {embeddings.shape}"
            )

        batch = embeddings.copy()
        if pre_shuffle:
            np.random.shuffle(batch)

        for i in range(batch.shape[0]):
            self._queue.append(batch[i])

    def sample(self, count: int) -> np.ndarray:
        """
        从队列中随机采样指定数量的负样本。

        返回: shape (count, dim) 的矩阵。若队列不足 count, 返回全部队列内容。
        """
        if len(self._queue) == 0:
            return np.empty((0, self._dim), dtype=np.float32)

        available = min(count, len(self._queue))
        indices = random.sample(range(len(self._queue)), available)
        sampled = np.stack([self._queue[i] for i in indices], axis=0)
        return sampled

    def get_all(self) -> np.ndarray:
        """返回队列中的所有嵌入。"""
        if len(self._queue) == 0:
            return np.empty((0, self._dim), dtype=np.float32)
        return np.stack(list(self._queue), axis=0)

    def clear(self):
        self._queue.clear()


# GraphMoCo 对比损失

def moco_contrastive_loss(
    query: np.ndarray,
    key: np.ndarray,
    queue_negatives: np.ndarray,
    temperature: float = 0.07,
) -> float:
    """
    计算 MoCo 风格的 InfoNCE 对比损失。

    参数:
      query:   源编码器输出的查询嵌入, shape (batch_size, dim)
      key:     动量编码器输出的键嵌入, shape (batch_size, dim)
      queue_negatives: 从负样本队列采样的负样本, shape (K, dim)
      temperature: softmax 温度参数。0.07 是 MoCo/SimCLR 的标准值。

    返回:
      标量 InfoNCE 损失值 (正样本对数似然的负值)。

    计算过程:
      1. L2 归一化所有向量到单位超球面。
      2. 计算 query 与 key 的正样本相似度 (对角线)。
      3. 计算 query 与所有负样本的相似度。
      4. 拼接 [正样本, 负样本] 后用温度缩放的 softmax + 交叉熵。

    边界条件:
      若 queue_negatives 为空 (训练的初始阶段), 仅使用正样本计算损失。
    """
    eps = 1e-8
    batch_size = query.shape[0]

    # L2 归一化 — 将嵌入投影到单位超球面
    query_norm = query / (np.linalg.norm(query, axis=1, keepdims=True) + eps)
    key_norm = key / (np.linalg.norm(key, axis=1, keepdims=True) + eps)

    # 正样本: query_i 与 key_i 的余弦相似度 (对角线)
    pos_logits = np.sum(query_norm * key_norm, axis=1)  # (batch_size,)

    # 负样本: 查询 与队列中所有负样本的余弦相似度
    if queue_negatives.shape[0] > 0:
        neg_norm = queue_negatives / (
            np.linalg.norm(queue_negatives, axis=1, keepdims=True) + eps
        )
        neg_logits = np.dot(query_norm, neg_norm.T)  # (batch_size, K)
    else:
        neg_logits = np.empty((batch_size, 0), dtype=np.float32)

    # 拼接 logits 并用温度缩放
    all_logits = np.concatenate(
        [pos_logits[:, np.newaxis], neg_logits], axis=1
    )  # (batch_size, 1+K)
    all_logits = all_logits / temperature

    # 稳定性处理: 减去每行最大值防止 softmax 上溢
    max_logits = np.max(all_logits, axis=1, keepdims=True)
    exp_logits = np.exp(all_logits - max_logits)
    sum_exp = np.sum(exp_logits, axis=1)

    # InfoNCE: -log(exp(pos) / sum(exp(all)))
    loss = np.mean(-np.log(exp_logits[:, 0] / sum_exp + eps))

    return float(loss)


# 辅助工具: 嵌入 L2 归一化

def l2_normalize(embeddings: np.ndarray) -> np.ndarray:
    """L2 归一化到单位超球面 (用于检索前的预处理)。"""
    eps = 1e-8
    return embeddings / (np.linalg.norm(embeddings, axis=-1, keepdims=True) + eps)


def cosine_similarity(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """计算两组嵌入间的余弦相似度矩阵。"""
    a_n = l2_normalize(a)
    b_n = l2_normalize(b)
    return np.dot(a_n, b_n.T)


__all__ = [
    "MomentumEncoder",
    "NegativeQueue",
    "moco_contrastive_loss",
    "l2_normalize",
    "cosine_similarity",
]
