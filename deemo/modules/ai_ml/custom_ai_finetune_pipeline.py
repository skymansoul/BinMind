#!/usr/bin/env python3
# Custom 智能 fine-tuning pipeline — dataset curation, augmentation, and 训练 orchestration
# for binary analysis models (function similarity, vulnerability 检测, naming).
# added class-balanced 采样 and curriculum-learning schedule.
# added contrastive-pair 构造 (CLAP-inspired), entropy-based difficulty
# estimation, and class-balanced 批次 iterator with reservoir tracking.

import os
import json
import math
import logging
import random
import threading
from collections import defaultdict
from statistics import mean, variance, stdev
from typing import Dict, Any, List, Optional, Tuple, Callable

__dbg = logging.getLogger(__name__)

from .src.training.pipeline_config import TaskType, FineTuneCheckpoint


class DatasetSplit:
    __slots__ = ('m_train', 'm_val', 'm_test', 'm_metadata')

    def __init__(self, train_data=None, val_data=None, test_data=None, metadata=None):
        self.m_train = train_data if train_data else []
        self.m_val = val_data if val_data else []
        self.m_test = test_data if test_data else []
        self.m_metadata = metadata if metadata else {}

    def total_samples_ds(self):
        return len(self.m_train) + len(self.m_val) + len(self.m_test)

    def class_distribution_ds(self):
        """Return label distribution dict for training set."""
        dist = {}
        ti = 0
        while ti < len(self.m_train):
            label = self.m_train[ti].get('label')
            if label is not None:
                dist[label] = dist.get(label, 0) + 1
            ti += 1
        return dist


class DataAugmenter:
    """Applies lightweight augmentations: dead-code insertion, register renaming,
    instruction reordering (within basic blocks)."""

    __slots__ = ('m_aug_prob', 'm_max_aug_per_sample')

    def __init__(self, aug_prob=0.3, max_aug_per_sample=3):
        self.m_aug_prob = aug_prob
        self.m_max_aug_per_sample = max_aug_per_sample

    def augment_da(self, sample):
        """Apply random augmentations to a training sample.

        Args:
            sample: dict with keys 'code', 'features', 'label' (features is list/array).

        Returns:
            list of augmented variants (original + augmentations).
        """
        if sample is None:
            return []
        results = [sample]  # always include original
        n_aug = min(random.randint(0, self.m_max_aug_per_sample), self.m_max_aug_per_sample)

        ai = 0
        while ai < n_aug:
            aug = dict(sample)  # shallow copy
            if 'features' in aug and isinstance(aug['features'], list):
                aug['features'] = list(aug['features'])  # deep copy features

            choice = random.random()
            if choice < 0.25 and isinstance(aug.get('features'), list):
                # Noise injection
                fi = 0
                while fi < len(aug['features']):
                    if random.random() < 0.05:
                        aug['features'][fi] += random.gauss(0, 0.01)
                    fi += 1
            elif choice < 0.50 and isinstance(aug.get('features'), list) and len(aug['features']) > 2:
                # Feature dropout
                drop_idx = random.randint(0, len(aug['features']) - 1)
                aug['features'][drop_idx] = 0.0
            elif choice < 0.75 and isinstance(aug.get('features'), list):
                # Feature scaling
                scale = random.uniform(0.95, 1.05)
                fi = 0
                while fi < len(aug['features']):
                    aug['features'][fi] *= scale
                    fi += 1
            # else: identity (no change, but we still add it as a variant)
            results.append(aug)
            ai += 1
        return results


class FineTuneDataset:
    """Curated dataset for a specific binary-analysis task."""

    __slots__ = ('m_task', 'm_samples', 'm_splits', 'm_label_map', 'm_augmenter')

    def __init__(self, task_type, augment=True):
        self.m_task = task_type
        self.m_samples = []
        self.m_splits = None
        self.m_label_map = {}
        self.m_augmenter = DataAugmenter() if augment else None

    def add_samples_fd(self, samples):
        """Add raw samples to the dataset."""
        if samples is None:
            return
        si = 0
        while si < len(samples):
            s = samples[si]
            if s is not None:
                self.m_samples.append(s)
            si += 1
        __dbg.debug(f"Added {len(samples)} samples, total={len(self.m_samples)}")

    def build_label_map_fd(self):
        """Auto-build label-to-index mapping."""
        self.m_label_map.clear()
        idx = 0
        si = 0
        while si < len(self.m_samples):
            label = self.m_samples[si].get('label')
            if label is not None and label not in self.m_label_map:
                self.m_label_map[label] = idx
                idx += 1
            si += 1

    def split_fd(self, train_ratio=0.7, val_ratio=0.15, test_ratio=0.15, shuffle=True):
        """Split into train/val/test with class-balanced stratification."""
        if not self.m_samples:
            __dbg.warning("split: empty dataset")
            return

        self.build_label_map_fd()

        # Group by label for stratified split
        label_groups = defaultdict(list)
        si = 0
        while si < len(self.m_samples):
            label = self.m_samples[si].get('label', '__unknown__')
            label_groups[label].append(self.m_samples[si])
            si += 1

        train_data = []
        val_data = []
        test_data = []

        label_keys = list(label_groups.keys())
        li = 0
        while li < len(label_keys):
            group = label_groups[label_keys[li]]
            if shuffle:
                random.shuffle(group)
            n = len(group)
            n_train = max(1, int(n * train_ratio))
            n_val = max(1, int(n * val_ratio))
            train_data.extend(group[:n_train])
            val_data.extend(group[n_train:n_train + n_val])
            test_data.extend(group[n_train + n_val:])
            li += 1

        if shuffle:
            random.shuffle(train_data)
            random.shuffle(val_data)
            random.shuffle(test_data)

        metadata = {
            'task': self.m_task,
            'total_samples': len(self.m_samples),
            'n_labels': len(self.m_label_map),
            'label_map': dict(self.m_label_map),
        }
        self.m_splits = DatasetSplit(train_data, val_data, test_data, metadata)
        __dbg.info(f"Split: train={len(train_data)}, val={len(val_data)}, test={len(test_data)}")

    def get_augmented_train_fd(self):
        """Return training set with augmentations applied."""
        if self.m_splits is None:
            return []
        if self.m_augmenter is None:
            return self.m_splits.m_train

        augmented = []
        ti = 0
        while ti < len(self.m_splits.m_train):
            variants = self.m_augmenter.augment_da(self.m_splits.m_train[ti])
            augmented.extend(variants)
            ti += 1
        return augmented

    def export_json_fd(self, filepath):
        """Serialize the dataset to JSON."""
        data = {
            'task': self.m_task,
            'samples': self.m_samples,
            'label_map': self.m_label_map,
        }
        if self.m_splits:
            data['splits'] = {
                'train_count': len(self.m_splits.m_train),
                'val_count': len(self.m_splits.m_val),
                'test_count': len(self.m_splits.m_test),
                'metadata': self.m_splits.m_metadata,
            }
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)

    @classmethod
    def import_json_fd(cls, filepath):
        """Load dataset from JSON file."""
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        ds = cls(task_type=data.get('task', TaskType.BINARY_SIMILARITY))
        ds.m_samples = data.get('samples', [])
        ds.m_label_map = data.get('label_map', {})
        return ds


# 增强1: 对比对采样器 (CLAP式跨模态预训练)
# 核心假设：同一函数的多种表示（汇编特征、CFG嵌入、反编译文本）应映射到邻近语义空间；
# 不同函数应被推远。正/负对采样是实现对比损失（NT-Xent / InfoNCE）的前置步骤。
# CLAP 跨模态对比范式; BLens 二进制函数对比表示

class ContrastivePairSampler:
    """生成对比学习所需的正/负样本对，支持多模态特征键。

    正样本对：同标签异样本（鼓励表示不变性）
    负样本对：异标签样本（强化决策边界）
    设计原则：不生成O(N²)对的全局笛卡尔积，改用局部重采样+hard-negative mining。
    """

    __slots__ = ('m_label_buckets', 'm_modality_keys', 'm_hard_negatives',
                 'm_margin', 'm_pair_cache', 'm_cache_epoch')

    def __init__(self, modality_keys=None, margin=0.3):
        """
        Args:
            modality_keys: 样本中多模态特征的键名列表，默认 ['features', 'cfg_features', 'asm_features']
            margin: 余弦相似度阈值，超过此值的跨类对视为hard negative
        """
        self.m_label_buckets = defaultdict(list)   # label → list[sample_idx]
        self.m_modality_keys = modality_keys if modality_keys else ['features', 'cfg_features', 'asm_features']
        self.m_hard_negatives = []                  # (idx_a, idx_b, sim_estimate)
        self.m_margin = margin
        self.m_pair_cache = {'positive': [], 'negative': []}   # 预计算缓存
        self.m_cache_epoch = -1

    def _feature_vector_len(self, sample_vec):
        """返回特征的L2模长近似 — 纯Python、无numpy依赖。"""
        sq = 0.0
        for val in sample_vec:
            sq += val * val
        return math.sqrt(sq) if sq > 0 else 0.0

    def _cosine_estimate(self, vec_a, vec_b):
        """快速余弦相似度估计，处理维度不等的向量。"""
        min_len = min(len(vec_a), len(vec_b))
        if min_len == 0:
            return 0.0
        dot = 0.0
        norm_a = 0.0
        norm_b = 0.0
        di = 0
        while di < min_len:
            dot += vec_a[di] * vec_b[di]
            norm_a += vec_a[di] * vec_a[di]
            norm_b += vec_b[di] * vec_b[di]
            di += 1
        denom = math.sqrt(norm_a * norm_b)
        return dot / denom if denom > 1e-12 else 0.0

    def index_samples_cps(self, samples):
        """按标签建立样本桶，同时预计算hard negatives。

        策略逻辑：遍历每对不同的标签，对每对标签各取一个锚点样本计算相似度 —
        存入hard negative池供后续batch采样使用。复杂度O(K²) (K=标签数)，远小于O(N²)。
        """
        self.m_label_buckets.clear()
        self.m_hard_negatives.clear()

        si = 0
        while si < len(samples):
            s = samples[si]
            if s is None:
                si += 1
                continue
            label = s.get('label', '__no_label__')
            self.m_label_buckets[label].append(si)
            si += 1

        # Hard-negative mining: 跨类锚点对相似度扫描
        label_list = list(self.m_label_buckets.keys())
        li = 0
        while li < len(label_list):
            rj = li + 1
            while rj < len(label_list):
                bucket_a = self.m_label_buckets[label_list[li]]
                bucket_b = self.m_label_buckets[label_list[rj]]
                if bucket_a and bucket_b:
                    anchor_idx = bucket_a[0]
                    cand_idx = bucket_b[0]
                    anchor_vec = samples[anchor_idx].get('features', [])
                    cand_vec = samples[cand_idx].get('features', [])
                    if anchor_vec and cand_vec:
                        sim_val = self._cosine_estimate(anchor_vec, cand_vec)
                        if sim_val > self.m_margin:
                            self.m_hard_negatives.append((anchor_idx, cand_idx, sim_val))
                rj += 1
            li += 1

        # 按相似度降序，优先采样最confusing的负样本
        self.m_hard_negatives.sort(key=lambda x: x[2], reverse=True)
        __dbg.info(f"ContrastivePairSampler: {len(label_list)} labels, "
                   f"{len(self.m_hard_negatives)} hard-negative pairs identified")

    def generate_pairs_cps(self, samples, n_positive=32, n_negative=48):
        """生成一批对比对。

        Args:
            samples: 全量样本列表
            n_positive: 正样本对数量
            n_negative: 负样本对数量

        Returns:
            dict: {'positive': [(idx_i, idx_j), ...], 'negative': [(idx_i, idx_j), ...]}
        """
        if not self.m_label_buckets:
            self.index_samples_cps(samples)

        positive_pairs = []
        negative_pairs = []

# 正样本对：同类内随机配对
        label_list = [lbl for lbl in self.m_label_buckets if len(self.m_label_buckets[lbl]) >= 2]
        if not label_list:
            return {'positive': [], 'negative': []}

        pos_count = 0
        max_attempts = n_positive * 3  # 防止死循环
        attempts = 0
        while pos_count < n_positive and attempts < max_attempts:
            lbl = random.choice(label_list)
            bucket = self.m_label_buckets[lbl]
            if len(bucket) >= 2:
                a, b = random.sample(bucket, 2)
                positive_pairs.append((a, b))
                pos_count += 1
            attempts += 1

# 负样本对：优先从hard negative池采样
        neg_count = 0
        # 先取hard negatives
        hn_idx = 0
        while neg_count < n_negative and hn_idx < len(self.m_hard_negatives):
            ia, ib, _ = self.m_hard_negatives[hn_idx]
            negative_pairs.append((ia, ib))
            neg_count += 1
            hn_idx += 1

        # 不足则随机跨类补齐
        attempts = 0
        while neg_count < n_negative and attempts < n_negative * 5:
            lbl_a, lbl_b = random.sample(label_list, 2) if len(label_list) >= 2 else (None, None)
            if lbl_a is None or lbl_b is None:
                attempts += 1
                continue
            ia = random.choice(self.m_label_buckets[lbl_a])
            ib = random.choice(self.m_label_buckets[lbl_b])
            negative_pairs.append((ia, ib))
            neg_count += 1
            attempts += 1

        return {'positive': positive_pairs, 'negative': negative_pairs}

    def generate_multimodal_pairs_cps(self, samples, modality_a='features',
                                       modality_b='cfg_features', n_pairs=32):
        """跨模态对比对生成：同一函数的两种表示视为正对。

        典型场景：汇编特征 vs 控制流图嵌入 — 对齐两者的表示空间。
        只生成正对（负对由generate_pairs_cps统一供给）。

        Args:
            samples: 样本列表
            modality_a: 模态A的键名
            modality_b: 模态B的键名
            n_pairs: 期望生成的跨模态对数量

        Returns:
            list of (idx, idx) — 每个元组是同一个样本的两个模态索引
        """
        multimodal_pairs = []
        si = 0
        eligible_indices = []
        while si < len(samples):
            s = samples[si]
            if (s is not None and modality_a in s and modality_b in s
                    and s.get(modality_a) and s.get(modality_b)):
                eligible_indices.append(si)
            si += 1

        if not eligible_indices:
            return multimodal_pairs

        # 不放回采样
        actual_n = min(n_pairs, len(eligible_indices))
        chosen = random.sample(eligible_indices, actual_n) if actual_n <= len(eligible_indices) else eligible_indices[:]
        for idx in chosen:
            multimodal_pairs.append((idx, idx))  # 同一索引，不同模态键
        return multimodal_pairs


# 增强2: 熵基准难度估计
# 原始实现以特征向量长度作为难度代理 — 过于粗糙：
# (a) 稀疏的长向量比密集的短向量更易学习；
# (b) 信息熵决定可分离性，低熵样本（高度冗余）应先学。
# 改用：特征方差 + 稀疏度 + 香农熵三指标归一化加权。
# 课程学习(curriculum learning)的分阶段训练策略

class EntropyDifficultyEstimator:
    """基于统计特征的难度估计器。

    算法逻辑：
    1. 特征稀疏度 = 非零特征占比 — 越稀疏越易学（信息密度低）
    2. 特征方差 = 归一化std — 方差大则分布广，分类边界需要更多样本刻画
    3. 香农熵 ≈ Σ -p_i·log(p_i) 对分箱后的特征值 — 熵越低信息越集中

    三者加权平均 → [0, 1] 难度分数。
    """

    __slots__ = ('m_n_bins', 'm_sparsity_weight', 'm_variance_weight', 'm_entropy_weight')

    def __init__(self, n_bins=20, sparsity_weight=0.3, variance_weight=0.35, entropy_weight=0.35):
        self.m_n_bins = n_bins
        self.m_sparsity_weight = sparsity_weight
        self.m_variance_weight = variance_weight
        self.m_entropy_weight = entropy_weight

    def estimate_difficulty_ede(self, feature_vector):
        """计算单个样本的特征级难度。

        Returns:
            float [0, 1]: 0 = 极易 (先学), 1 = 极难 (后学)
        """
        if feature_vector is None or len(feature_vector) == 0:
            return 0.5  # 无信息 → 中性难度

        fv = feature_vector
        n_dims = len(fv)

        # (1) 稀疏度：非零比例越低越容易
        nz_count = 0
        for val in fv:
            if abs(val) > 1e-8:
                nz_count += 1
        sparsity = 1.0 - (nz_count / n_dims)  # 稀疏度 = 1 - 非零占比
        # 稀疏度转难度：高稀疏 → 低难度（信息密度低，模型收敛快）
        sparsity_diff = 1.0 - sparsity

        # (2) 方差：用稳健估计(中位数绝对偏差 MAD)避免异常值拉偏
        try:
            mu = mean(fv)
        except Exception:
            mu = 0.0
        abs_deviations = []
        for val in fv:
            abs_deviations.append(abs(val - mu))
        abs_deviations.sort()
        med_abs_dev = abs_deviations[len(abs_deviations) // 2] if abs_deviations else 0.0
        # 归一化：max reasonable MAD ≈ |最大特征值 - 均值|
        max_abs = max(abs(v - mu) for v in fv) if fv else 1.0
        var_norm = med_abs_dev / max_abs if max_abs > 1e-12 else 0.0
        var_diff = var_norm  # 高方差 → 高难度

        # (3) 香农熵：分箱后计算
        if n_dims < 2:
            entropy_diff = 0.0
        else:
            val_min = min(fv)
            val_max = max(fv)
            rng = val_max - val_min
            if rng < 1e-12:
                entropy_diff = 0.0  # 常数特征，极易
            else:
                bin_width = rng / self.m_n_bins
                bins_count = [0] * self.m_n_bins
                for val in fv:
                    bi = int((val - val_min) / bin_width)
                    if bi >= self.m_n_bins:
                        bi = self.m_n_bins - 1
                    if bi < 0:
                        bi = 0
                    bins_count[bi] += 1
                entropy_val = 0.0
                for count in bins_count:
                    if count > 0:
                        prob = count / n_dims
                        entropy_val -= prob * math.log(prob)
                max_entropy = math.log(self.m_n_bins)
                entropy_norm = entropy_val / max_entropy if max_entropy > 1e-12 else 0.0
                entropy_diff = 1.0 - entropy_norm  # 低熵→低难度

        difficulty = (self.m_sparsity_weight * sparsity_diff +
                      self.m_variance_weight * var_diff +
                      self.m_entropy_weight * entropy_diff)
        return max(0.0, min(1.0, difficulty))


class CurriculumScheduler:
    """Curriculum learning schedule: start with easy samples, progressively add harder ones.

    Difficulty is estimated from feature dimensionality, label noise, and sequence length.
    Enhancements:
    - 内置 EntropyDifficultyEstimator 作为默认难度函数
    - 支持阶段性难度统计摘要
    """

    __slots__ = ('m_stages', 'm_current_stage', 'm_difficulty_fn', 'm_entropy_estimator',
                 'm_stage_statistics')

    def __init__(self, n_stages=5):
        self.m_stages = n_stages
        self.m_current_stage = 0
        self.m_difficulty_fn = None
        self.m_entropy_estimator = EntropyDifficultyEstimator()  # 增强2: 集成
        self.m_stage_statistics = []  # 每阶段的难度分布记录

    def set_difficulty_fn_cs(self, fn):
        """Set a callable that assigns difficulty score (0=easy, 1=hard) to a sample."""
        self.m_difficulty_fn = fn

    def _default_difficulty_cs(self, sample):
        """内置难度预估：优先使用 EntropyDifficultyEstimator，回退到特征长度代理。"""
        features = sample.get('features', [])
        if features and len(features) > 0:
            return self.m_entropy_estimator.estimate_difficulty_ede(features)
        # 回退：序列长度代理（原始逻辑保持兼容）
        code_len = len(sample.get('code', ''))
        return min(code_len / 2000.0, 1.0)  # 归一化到 [0, 1]

    def get_curriculum_cs(self, samples):
        """Filter samples for the current curriculum stage.

        Returns samples whose difficulty <= current_stage / total_stages.
        """
        effective_fn = self.m_difficulty_fn if self.m_difficulty_fn else self._default_difficulty_cs

        threshold = (self.m_current_stage + 1) / self.m_stages
        result = []
        difficulty_scores = []  # 用于阶段统计

        si = 0
        while si < len(samples):
            diff = effective_fn(samples[si])
            difficulty_scores.append(diff)
            if diff <= threshold:
                result.append(samples[si])
            si += 1

        # 记录当前阶段统计摘要
        if difficulty_scores:
            diff_sorted = sorted(difficulty_scores)
            n = len(diff_sorted)
            stage_summ = {
                'stage': self.m_current_stage,
                'threshold': threshold,
                'n_available': len(result),
                'n_total': n,
                'difficulty_mean': mean(difficulty_scores),
                'difficulty_median': diff_sorted[n // 2],
                'difficulty_p25': diff_sorted[n // 4],
                'difficulty_p75': diff_sorted[(3 * n) // 4],
            }
            self.m_stage_statistics.append(stage_summ)
            __dbg.info(f"Stage {self.m_current_stage}: {len(result)}/{n} samples "
                       f"(threshold={threshold:.3f}, median_diff={stage_summ['difficulty_median']:.3f})")

        return result

    def get_stage_distribution_report_cs(self):
        """返回所有阶段的难度分布报告 — 便于超参调试。"""
        return list(self.m_stage_statistics)

    def advance_stage_cs(self):
        """Move to next stage. Returns False if already at last stage."""
        if self.m_current_stage < self.m_stages - 1:
            self.m_current_stage += 1
            return True
        return False

    def reset_cs(self):
        self.m_current_stage = 0
        self.m_stage_statistics.clear()


# 增强3: 类别均衡批次迭代器 含蓄水池追踪
# 问题：随机批次在长尾分布下严重偏向头部类，导致尾部类过拟合/欠拟合交替。
# 方案：按标签分桶 → 轮询采样 → 维护每个桶的已用指针跨epoch连续。
# 类平衡采样与长尾重加权

class ClassBalancedBatchIterator:
    """类均衡批次迭代器 — 轮询采样确保每批各类占比均衡。

    与简单的分层随机不同，此迭代器维护跨epoch的蓄水池指针：
    - 每个标签桶跟踪"下一个未用样本"位置
    - 桶耗尽时自动洗牌重置（reservoir refill）
    - 支持加权轮询（类别权重可由外部指定）
    """

    __slots__ = ('m_label_buckets', 'm_bucket_pointers', 'm_class_weights',
                 'm_samples_used_total', 'm_epochs_completed', 'm_shuffle_per_epoch')

    def __init__(self, shuffle_per_epoch=True):
        self.m_label_buckets = {}            # label → list[sample_idx]
        self.m_bucket_pointers = {}          # label → next_available_index
        self.m_class_weights = {}            # label → sampling_weight
        self.m_samples_used_total = 0
        self.m_epochs_completed = 0
        self.m_shuffle_per_epoch = shuffle_per_epoch

    def build_buckets_cbbi(self, samples):
        """基于样本标签构建均衡桶。样本可以是引用（int index）或实体（dict）。"""
        self.m_label_buckets.clear()
        self.m_bucket_pointers.clear()

        si = 0
        while si < len(samples):
            s = samples[si]
            if s is None:
                si += 1
                continue
            label = s.get('label', '__unlabeled__') if isinstance(s, dict) else '__unlabeled__'
            if label not in self.m_label_buckets:
                self.m_label_buckets[label] = []
            self.m_label_buckets[label].append(si)
            si += 1

        # 初始化指针和均匀权重
        for lbl in self.m_label_buckets:
            if self.m_shuffle_per_epoch:
                random.shuffle(self.m_label_buckets[lbl])
            self.m_bucket_pointers[lbl] = 0
            self.m_class_weights[lbl] = 1.0

        self.m_samples_used_total = 0
        self.m_epochs_completed = 0

    def set_class_weights_cbbi(self, weight_dict):
        """设置各类别采样权重（用于处理极端不平衡）。

        Args:
            weight_dict: {label: float_weight} — 权重越高，该类别在每批中占比越大
        """
        for lbl, w in weight_dict.items():
            if lbl in self.m_class_weights:
                self.m_class_weights[lbl] = max(0.1, min(10.0, w))  # 限制极端权重

    def _refill_bucket_cbbi(self, label):
        """桶耗尽时重置指针并洗牌。"""
        bucket = self.m_label_buckets[label]
        if self.m_shuffle_per_epoch:
            random.shuffle(bucket)
        self.m_bucket_pointers[label] = 0

    def next_batch_cbbi(self, batch_size):
        """生成一个类均衡的mini-batch。

        算法：轮询每个标签桶取 ceil(batch_size / n_labels) 个样本，截断到batch_size。
        当所有桶至少被轮询过一次后，epoch计数器递增。

        Returns:
            list of sample indices, 或空列表（数据集为空时）
        """
        labels = list(self.m_label_buckets.keys())
        if not labels:
            return []

        n_labels = len(labels)
        per_class_quota = max(1, math.ceil(batch_size / n_labels))

        # 按权重调整配额
        total_weight = sum(self.m_class_weights.get(lbl, 1.0) for lbl in labels)
        quotas = {}
        for lbl in labels:
            w = self.m_class_weights.get(lbl, 1.0)
            quotas[lbl] = max(1, int(per_class_quota * w * n_labels / total_weight))

        batch_indices = []
        any_depleted = False

        for lbl in labels:
            bucket = self.m_label_buckets[lbl]
            ptr = self.m_bucket_pointers[lbl]
            quota = quotas[lbl]
            taken = 0

            while taken < quota and ptr < len(bucket):
                batch_indices.append(bucket[ptr])
                ptr += 1
                taken += 1

            self.m_bucket_pointers[lbl] = ptr

            if ptr >= len(bucket):
                self._refill_bucket_cbbi(lbl)
                any_depleted = True

        # 截断到 batch_size
        if len(batch_indices) > batch_size:
            batch_indices = batch_indices[:batch_size]

        self.m_samples_used_total += len(batch_indices)

        # 所有桶至少翻转一次 → 轮次++
        if any_depleted:
            self.m_epochs_completed += 1
            __dbg.debug(f"Epoch {self.m_epochs_completed} completed "
                        f"({self.m_samples_used_total} total samples drawn)")

        random.shuffle(batch_indices)  # 批次内洗牌避免类别块
        return batch_indices

    def get_epoch_progress_cbbi(self):
        """返回当前epoch在各桶的进度（0~1）。"""
        progress = {}
        for lbl in self.m_label_buckets:
            bucket_len = len(self.m_label_buckets[lbl])
            if bucket_len > 0:
                progress[lbl] = self.m_bucket_pointers[lbl] / bucket_len
            else:
                progress[lbl] = 1.0
        return {
            'per_class_progress': progress,
            'epochs_completed': self.m_epochs_completed,
            'samples_used_total': self.m_samples_used_total,
        }


class FineTunePipeline:
    """End-to-end fine-tuning pipeline orchestrator.

    Handles:
    - Dataset loading and preprocessing
    - Train/val/test splitting with stratification
    - Data augmentation
    - Curriculum learning scheduling
    - Checkpoint management
    - Contrastive pair generation (CLAP-inspired) — Enhancement 1
    - Class-balanced batch iteration — Enhancement 3
    """

    __slots__ = ('m_task', 'm_dataset', 'm_curriculum', 'm_checkpoints', 'm_config',
                 'm_contrastive_sampler', 'm_batch_iterator')

    def __init__(self, task_type=None, config=None):
        self.m_task = task_type if task_type else TaskType.BINARY_SIMILARITY
        self.m_dataset = FineTuneDataset(self.m_task)
        self.m_curriculum = CurriculumScheduler()
        self.m_checkpoints = []
        self.m_config = config if config else {}
        self.m_contrastive_sampler = ContrastivePairSampler()   # 增强1: 集成
        self.m_batch_iterator = ClassBalancedBatchIterator()     # 增强3: 集成

    def load_from_dir_fp(self, directory, label_fn=None):
        """Load samples from a directory of JSON / binary files.

        Args:
            directory: path to data directory.
            label_fn: optional callable(filename) -> label string.
        """
        if directory is None or not os.path.isdir(directory):
            __dbg.warning(f"load_from_dir: invalid directory {directory}")
            return

        samples = []
        for fname in os.listdir(directory):
            fpath = os.path.join(directory, fname)
            if not os.path.isfile(fpath):
                continue
            try:
                if fname.endswith('.json'):
                    with open(fpath, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    data['_source_file'] = fname
                    if label_fn and 'label' not in data:
                        data['label'] = label_fn(fname)
                    samples.append(data)
                elif fname.endswith('.txt'):
                    with open(fpath, 'r', encoding='utf-8') as f:
                        content = f.read()
                    sample = {'code': content, '_source_file': fname}
                    if label_fn:
                        sample['label'] = label_fn(fname)
                    samples.append(sample)
            except Exception as e:
                __dbg.debug(f"Skipping {fname}: {e}")

        self.m_dataset.add_samples_fd(samples)
        __dbg.info(f"Loaded {len(samples)} samples from {directory}")

    def prepare_data_fp(self, train_ratio=0.7, val_ratio=0.15, test_ratio=0.15):
        """Split and prepare data for training."""
        self.m_dataset.split_fd(train_ratio, val_ratio, test_ratio)

    def get_training_config_fp(self):
        """Build training config dict for downstream model."""
        if self.m_dataset.m_splits is None:
            return {}
        config = {
            'task': self.m_task,
            'train_samples': len(self.m_dataset.m_splits.m_train),
            'val_samples': len(self.m_dataset.m_splits.m_val),
            'test_samples': len(self.m_dataset.m_splits.m_test),
            'n_labels': len(self.m_dataset.m_label_map),
            'label_map': self.m_dataset.m_label_map,
            'curriculum_stages': self.m_curriculum.m_stages,
        }
        config.update(self.m_config)
        return config

    def save_checkpoint_fp(self, model_path, metrics=None):
        """Register a model checkpoint."""
        ckpt = FineTuneCheckpoint(model_path, metrics)
        self.m_checkpoints.append(ckpt)
        return ckpt.m_hash

    def get_best_checkpoint_fp(self, metric_key='val_accuracy'):
        """Return the checkpoint with the best value for a given metric."""
        if not self.m_checkpoints:
            return None
        best = None
        best_val = float('-inf')
        ci = 0
        while ci < len(self.m_checkpoints):
            c = self.m_checkpoints[ci]
            val = c.m_metrics.get(metric_key, 0)
            if val > best_val:
                best_val = val
                best = c
            ci += 1
        return best

    def get_curriculum_batch_fp(self, batch_size=32):
        """Get a batch of training samples for the current curriculum stage."""
        curriculum_samples = self.m_curriculum.get_curriculum_cs(
            self.m_dataset.m_splits.m_train if self.m_dataset.m_splits else [])
        if len(curriculum_samples) == 0:
            return []
        # Sample 批次
        if len(curriculum_samples) <= batch_size:
            return curriculum_samples
        return random.sample(curriculum_samples, batch_size)

    # 增强1: methods: 对比对构造

    def build_contrastive_pairs_fp(self, modality_keys=None):
        """基于当前训练集构建对比学习正/负对。

        先在ContrastivePairSampler中按标签索引，再生成正对/负对/跨模态对。
        如果训练集包含多模态特征（cfg_features, asm_features等），同时生成跨模态正对。

        Returns:
            dict with keys 'positive', 'negative', 'multimodal'
        """
        if self.m_dataset.m_splits is None:
            __dbg.warning("build_contrastive_pairs: no splits available")
            return {'positive': [], 'negative': [], 'multimodal': []}

        train_samples = self.m_dataset.m_splits.m_train
        if not train_samples:
            return {'positive': [], 'negative': [], 'multimodal': []}

        if modality_keys:
            self.m_contrastive_sampler = ContrastivePairSampler(modality_keys=modality_keys)

        base_pairs = self.m_contrastive_sampler.generate_pairs_cps(
            train_samples, n_positive=32, n_negative=48)

        # 跨模态对：同一函数的汇编特征 vs CFG特征
        mm_pairs = self.m_contrastive_sampler.generate_multimodal_pairs_cps(
            train_samples, modality_a='features', modality_b='cfg_features', n_pairs=16)

        return {
            'positive': base_pairs['positive'],
            'negative': base_pairs['negative'],
            'multimodal': mm_pairs,
        }

    def get_contrastive_batch_fp(self, samples, batch_size=32):
        """获取一批对比学习样本 — 适用于InfoNCE/NT-Xent损失。

        返回结构便于下游模型构建对比损失计算图。

        Returns:
            dict:
                'anchors': list of sample dicts (锚点)
                'positives': list of sample dicts (正例)
                'negatives': list of sample dicts (负例)
        """
        pairs = self.m_contrastive_sampler.generate_pairs_cps(
            samples, n_positive=batch_size // 2, n_negative=batch_size // 2)

        anchors = []
        positives = []
        negatives = []

        for (ai, pi) in pairs['positive']:
            if ai < len(samples) and pi < len(samples):
                anchors.append(samples[ai])
                positives.append(samples[pi])

        for (ai, ni) in pairs['negative']:
            if ai < len(samples) and ni < len(samples):
                # 每个负对贡献一个三元组 (anchor, anchor_copy, negative)
                if len(anchors) < batch_size:
                    anchors.append(samples[ai])
                    positives.append(samples[ai])  # 占位 — 由损失函数处理
                    negatives.append(samples[ni])

        return {'anchors': anchors, 'positives': positives, 'negatives': negatives}

    # 增强3: methods: 类别均衡批次迭代

    def init_balanced_batches_fp(self, sample_source=None):
        """初始化类均衡批次迭代器。

        Args:
            sample_source: 样本列表，默认为训练集
        """
        source = sample_source
        if source is None:
            if self.m_dataset.m_splits is None:
                __dbg.warning("init_balanced_batches: no splits available")
                return
            source = self.m_dataset.m_splits.m_train

        self.m_batch_iterator.build_buckets_cbbi(source)
        __dbg.info(f"Balanced batch iterator initialized: "
                   f"{len(self.m_batch_iterator.m_label_buckets)} classes, "
                   f"{len(source)} samples")

    def set_class_weights_balancing_fp(self, weight_dict):
        """设置类别采样权重，用于补偿极端不平衡。

        Args:
            weight_dict: {label: float_weight}
                示例: {'malware': 2.0, 'benign': 0.5}
                权重越大，该类别在每批中占比越高。
        """
        self.m_batch_iterator.set_class_weights_cbbi(weight_dict)

    def next_balanced_batch_fp(self, batch_size=32):
        """获取下一个类均衡的mini-batch（返回样本索引列表）。

        使用前需先调用 init_balanced_batches_fp() 初始化。

        Returns:
            list of int: 训练集中的样本索引
        """
        return self.m_batch_iterator.next_batch_cbbi(batch_size)

    def get_batch_progress_fp(self):
        """返回当前epoch的均衡批次训练进度。"""
        return self.m_batch_iterator.get_epoch_progress_cbbi()


def create_finetune_pipeline(task_type=None):
    return FineTunePipeline(task_type=task_type)


def create_dataset(task_type=None, augment=True):
    return FineTuneDataset(task_type=task_type, augment=augment)

def _debug_print(*args, **kwargs):  # 调试残余--未删除
    """Print debug info if env var is set. Not currently called."""
    if __import__("os").environ.get("BINMIND_DEBUG"):
        print(*args, **kwargs)
