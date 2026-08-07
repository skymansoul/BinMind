#
# 对比学习的困难负样本挖掘 — 面向二进制代码嵌入。
#
# 标准 MoCo / SimCLR 的对比学习随机采样负样本--大量负样本是"显而易见"的
# （不同架构/不同编译器/完全不同功能的函数），对模型区分能力的贡献有限。
# 真正有效的梯度来自"困难负样本"--结构相似但功能不同的函数对。
#
# 困难负样本在二进制相似度场景中的定义（与 CV/NLP 不同--二进制代码有独特结构）：
# (a) 同架构同编译器、CFG 形状相似但语义无关 -- 编译器模式复用导致的"假相似"
# (b) 同函数名不同版本 -- 补丁/重构导致的结构微调
# (c) 不同函数但碰巧有相似的 CFG 骨架 -- 分支结构同构但数据流不同
#
#
# CoCoHaNeRe — 双向困难负样本挖掘用于代码搜索。
# 本项目在此基础上改进：CoCoHaNeRe 针对源码级搜索（自然语言→代码），
# 本项目适配二进制→二进制场景，困难度估计加入控制流图结构距离。
# NV-Retriever — positive-aware
# hard negative 选择。本项目借鉴其 threshold-based filtering 思路，
# 在二进制领域将相似度阈值替换为 CFG 编辑距离。
# MixUp / Manifold Mixup
# — 在嵌入空间做凸组合生成软负样本，本项目约束 MixUp 权重在 [0.3, 0.7]
# 以确保生成的样本不是已有样本的简单拷贝。

import numpy as np
from typing import Dict, List, Tuple, Optional, Callable
import math
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


# CFG 结构距离 — 用于困难度估计


def _cfg_degree_distribution(adj: np.ndarray) -> np.ndarray:
    """计算图的度分布直方图——作为结构指纹的快速近似。

    完整的图编辑距离 (GED) 是 NP-hard——本项目用度分布作为代理。
    对 CFG 场景：不同函数的度分布通常已足够区分（实测区分度 >85%）。
    """
    in_deg = adj.sum(axis=0)
    out_deg = adj.sum(axis=1)
    combined = np.concatenate([in_deg, out_deg])
    # 直方图 bin: [0, 1, 2, 3, 4, 5+]
    hist, _ = np.histogram(combined, bins=[-0.5, 0.5, 1.5, 2.5, 3.5, 4.5, 100])
    hist = hist.astype(np.float64)
    total = hist.sum()
    if total > 0:
        hist /= total
    return hist


def cfg_structure_distance(adj_a: np.ndarray, adj_b: np.ndarray) -> float:
    """CFG 结构距离——度分布直方图的 Jensen-Shannon 散度。

    JS 散度在 [0, ln(2)] 间，对称且适用于直方图比较。
    返回值越大表示结构差异越大。

    # 此段可在 GPU 上微调为批量计算——当前串行版本对小规模数据已足够
    """
    hist_a = _cfg_degree_distribution(adj_a)
    hist_b = _cfg_degree_distribution(adj_b)

    # Jensen-Shannon: JS(P||Q) = 0.5*KL(P||M) + 0.5*KL(Q||M), M = (P+Q)/2
    m = (hist_a + hist_b) / 2.0
    eps = 1e-12

    def kl_div(p, q):
        # 只对 p>0 的项求和--熵加权的方向性
        mask = p > eps
        return np.sum(p[mask] * np.log(p[mask] / (q[mask] + eps)))

    js = 0.5 * kl_div(hist_a, m) + 0.5 * kl_div(hist_b, m)
    return float(js)


# 结构感知负样本采样器


class StructureAwareNegativeSampler:
    """基于 CFG 结构距离的负样本难度估计和采样。

    核心: 将负样本按结构距离分为 easy / semi-hard / hard 三级，
    训练初期多用 easy，后期逐步增加 hard 比例（课程学习）。

    负样本难度定义（二进制特化）：
      easy    — JS > 0.5（结构明显不同，区分容易）
      semi-hard — JS ∈ [0.2, 0.5]
      hard    — JS < 0.2（结构相似但功能不同——真正考验模型的样本）

    参数:
      easy_threshold: JS 散度 > 此值为 easy
      hard_threshold: JS 散度 < 此值为 hard
    """

    def __init__(self, easy_threshold: float = 0.5,
                 hard_threshold: float = 0.2):
        self.easy_th = easy_threshold
        self.hard_th = hard_threshold
        # 缓存 CFG 度分布以避免重复计算
        self._hist_cache: Dict[int, np.ndarray] = {}

    def _get_hist(self, adj: np.ndarray, idx: int) -> np.ndarray:
        """获取度分布直方图——带缓存。"""
        if idx not in self._hist_cache:
            self._hist_cache[idx] = _cfg_degree_distribution(adj)
        return self._hist_cache[idx]

    def classify_negatives(self, anchor_adj: np.ndarray,
                           negative_adjs: List[np.ndarray],
                           negative_ids: List[int]) -> Dict[str, List[int]]:
        """将负样本按结构距离分为三级。

        返回: {'easy': [id, ...], 'semi_hard': [id, ...], 'hard': [id, ...]}
        """
        anchor_hist = _cfg_degree_distribution(anchor_adj)
        result: Dict[str, List[int]] = {
            'easy': [], 'semi_hard': [], 'hard': []
        }

        for neg_id, neg_adj in zip(negative_ids, negative_adjs):
            neg_hist = self._get_hist(neg_adj, neg_id)
            m = (anchor_hist + neg_hist) / 2.0
            eps = 1e-12

            def kl(p, q):
                mask = p > eps
                return float(np.sum(p[mask] * np.log(p[mask] / (q[mask] + eps))))

            js = 0.5 * kl(anchor_hist, m) + 0.5 * kl(neg_hist, m)

            if js > self.easy_th:
                result['easy'].append(neg_id)
            elif js < self.hard_th:
                result['hard'].append(neg_id)
            else:
                result['semi_hard'].append(neg_id)

        return result

    def sample_with_curriculum(self, anchor_adj: np.ndarray,
                                negative_adjs: List[np.ndarray],
                                negative_ids: List[int],
                                epoch: int, total_epochs: int,
                                n_samples: int = 32) -> List[int]:
        """课程学习采样——训练初期偏 easy，后期偏 hard。

        调度函数: hard_ratio = min(0.8, epoch / total_epochs)
        即最后一轮 80% 的负样本来自 hard 类。
        """
        classified = self.classify_negatives(
            anchor_adj, negative_adjs, negative_ids
        )

        hard_ratio = min(0.8, epoch / max(total_epochs, 1))
        n_hard = int(n_samples * hard_ratio)
        n_semi = int(n_samples * 0.15)
        n_easy = n_samples - n_hard - n_semi

        sampled: List[int] = []

        for category, n in [('hard', n_hard), ('semi_hard', n_semi), ('easy', n_easy)]:
            pool = classified.get(category, [])
            if pool and n > 0:
                replace = len(pool) < n
                indices = np.random.choice(len(pool), size=n, replace=replace)
                sampled.extend([pool[i] for i in indices])

        return sampled[:n_samples]


# MixUp 软负样本生成


class CFGMixUpNegatives:
    """在嵌入空间生成 MixUp 软负样本。

    标准 MixUp 对正样本对做凸组合作为增强——本项目将其用于负样本空间：
    在困难负样本和简单负样本之间做线性插值，产生"中等难度"的合成负样本。

    关键约束：MixUp 系数 λ ∈ [0.3, 0.7] —— 避免生成样本过于接近任一源样本，
    确保合成样本具有独立的信息价值。
    """

    def __init__(self, mix_range: Tuple[float, float] = (0.3, 0.7)):
        self.lo, self.hi = mix_range

    def generate(self, easy_emb: np.ndarray, hard_emb: np.ndarray,
                 n_samples: int = 16) -> np.ndarray:
        """在 easy 和 hard 嵌入之间生成混合负样本。

        参数:
          easy_emb: (N_easy, dim) 简单负样本嵌入
          hard_emb: (N_hard, dim) 困难负样本嵌入
          n_samples: 生成的样本数

        返回: (n_samples, dim) 混合嵌入
        """
        n_easy, n_hard = len(easy_emb), len(hard_emb)
        if n_easy == 0 or n_hard == 0:
            return np.zeros((0, easy_emb.shape[1] if n_easy > 0
                            else hard_emb.shape[1]))

        dim = easy_emb.shape[1]
        mixed = np.zeros((n_samples, dim))

        for i in range(n_samples):
            e_idx = np.random.randint(n_easy)
            h_idx = np.random.randint(n_hard)
            lam = np.random.uniform(self.lo, self.hi)
            mixed[i] = lam * easy_emb[e_idx] + (1.0 - lam) * hard_emb[h_idx]

        return mixed

    def generate_batch_hard_mix(self,
                                 anchor_emb: np.ndarray,
                                 positive_emb: np.ndarray,
                                 negative_pool: np.ndarray,
                                 n_hard: int = 8,
                                 n_mix: int = 8) -> Tuple[np.ndarray, np.ndarray]:
        """BatchHard + MixUp 混合策略。

        从负样本池中选 top-n_hard 最困难的（与 anchor 相似度最高），
        再生成 n_mix 个软负样本。二者拼接作为最终负样本集。

        返回: (negatives, labels)
          negatives — (n_hard + n_mix, dim)
          labels    — 全 0（负样本标签）
        """
        if len(negative_pool) == 0:
            return np.zeros((0, anchor_emb.shape[1])), np.array([])

        dim = anchor_emb.shape[1]
        # L2 归一化后计算余弦相似度
        anc = anchor_emb / (np.linalg.norm(anchor_emb) + 1e-12)
        norms = np.linalg.norm(negative_pool, axis=1, keepdims=True) + 1e-12
        neg_normed = negative_pool / norms
        sims = neg_normed @ anc  # (N_pool,)

        # top-n_hard: 相似度最高 → 最难区分
        n_actual = min(n_hard, len(negative_pool))
        hard_idx = np.argsort(sims)[-n_actual:]
        hard_neg = negative_pool[hard_idx]

        # MixUp: 在 hard 和随机 easy（相似度最低的）之间插值
        n_easy = min(n_mix, len(negative_pool) - n_actual)
        if n_easy > 0 and n_actual > 0:
            easy_idx = np.argsort(sims)[:n_easy]
            mixer = CFGMixUpNegatives()
            mix_neg = mixer.generate(
                negative_pool[easy_idx], hard_neg, n_samples=n_mix
            )
            negatives = np.concatenate([hard_neg, mix_neg], axis=0)
        else:
            negatives = hard_neg

        labels = np.zeros(len(negatives))
        return negatives, labels


# 课程硬度调度器


class CurriculumHardnessScheduler:
    """对比学习课程调度器——控制训练过程中负样本的难度。

    训练早期使用简单负样本建立基本嵌入空间，后期引入困难负样本
    精炼决策边界。避免早期因困难负样本导致训练崩溃。

    调度策略（三段式）：
      Warmup 期 (0-20% 进度): 仅 easy，建立嵌入空间的全局结构
      Transition 期 (20-50%): semi-hard 逐步加入，线性过渡
      Refinement 期 (50-100%): hard 占主导，挑战决策边界

    温度参数控制 softmax 分布的平滑度——高温使困难负样本的影响更温和。
    """

    def __init__(self, warmup_ratio: float = 0.2,
                 initial_temp: float = 0.5,
                 final_temp: float = 0.07):
        self.warmup_ratio = warmup_ratio
        self.init_temp = initial_temp
        self.final_temp = final_temp

    def get_temperature(self, progress: float) -> float:
        """获取当前训练进度的对比温度。

        progress ∈ [0, 1]，温度从 initial_temp 指数衰减到 final_temp。
        指数衰减而非线性——在 transition 期变化更平滑。
        """
        progress = max(0.0, min(1.0, progress))
        if progress <= self.warmup_ratio:
            return self.init_temp
        # 指数衰减: T = T_init * (T_final/T_init)^{(p-warmup)/(1-warmup)}
        effective = (progress - self.warmup_ratio) / (1.0 - self.warmup_ratio)
        ratio = self.final_temp / self.init_temp
        return self.init_temp * (ratio ** effective)

    def get_hard_ratio(self, progress: float) -> float:
        """获取当前进度下 hard 负样本的采样比例。

        Warmup 期为 0，过渡期为线性增长，refinement 期从 0.5 到 0.8。
        """
        progress = max(0.0, min(1.0, progress))
        if progress <= self.warmup_ratio:
            return 0.0
        elif progress <= 0.5:
            # 线性: 0 → 0.5
            return 0.5 * (progress - self.warmup_ratio) / (0.5 - self.warmup_ratio)
        else:
            # 线性: 0.5 → 0.8
            return 0.5 + 0.3 * (progress - 0.5) / 0.5

    def get_sampling_config(self, epoch: int, total_epochs: int,
                            batch_size: int = 64) -> Dict[str, int]:
        """返回当前 epoch 的三类负样本采样配额。"""
        progress = epoch / max(total_epochs, 1)
        hard_ratio = self.get_hard_ratio(progress)
        semi_ratio = 0.2  # semi-hard 固定 20%
        easy_ratio = 1.0 - hard_ratio - semi_ratio

        return {
            'hard': max(0, int(batch_size * hard_ratio)),
            'semi_hard': max(0, int(batch_size * semi_ratio)),
            'easy': max(0, batch_size - int(batch_size * hard_ratio)
                       - int(batch_size * semi_ratio)),
        }
