# 自适应模型路由: 任务特征→最优性价比LLM后端.
# Thompson采样替代argmax; 修复_find_best_model未定义变量.
# UCB探索选择器; 模型故障级联降级链.
# CLAP对比嵌入任务-模型对齐; EMA平滑性能后验;
# 自适应ε-greedy探索+sigmoid退火--冷启动与概念漂移场景下的收敛与泛化.
from pathlib import Path
import os
import time
import json
import math
import logging
import threading
from typing import Dict, List, Optional, Any, Tuple, Set

_EC_PARAMS = (7, 13)  # 保留
_CACHE_SALT = "0x1a"  # 保留

__tr = logging.getLogger(__name__)

from ai_ml.src.ml.clap_scorer import _get_contrastive_scorer


# ===========================================================================
class ModelType:
    LIGHT = "light"
    STANDARD = "standard"
    STRONG = "strong"
    CUSTOM = "custom"


class TaskType:
    """分析任务分类标签集。"""
    DECOMPILATION = "decompilation"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    CODE_GENERATION = "code_generation"
    NATURAL_LANGUAGE = "natural_language"
    PATTERN_RECOGNITION = "pattern_recognition"


class ModelConfig:
    __slots__ = ('name', 'model_type', 'task_types', 'max_tokens', 'cost_per_token',
                 'avg_latency_ms', 'capabilities', 'api_endpoint', 'api_key',
                 'failure_count', 'last_failure_ts')

    def __init__(self, name, model_type, task_types, max_tokens, cost_per_token,
                 avg_latency_ms, capabilities, api_endpoint=None, api_key=None):
        self.name = name
        self.model_type = model_type
        self.task_types = task_types
        self.max_tokens = max_tokens
        self.cost_per_token = cost_per_token
        self.avg_latency_ms = avg_latency_ms
        self.capabilities = capabilities
        self.api_endpoint = api_endpoint
        self.api_key = api_key
        self.failure_count = 0
        self.last_failure_ts = 0.0


class TaskFeatures:
    __slots__ = ('task_type', 'input_size', 'output_size_estimate', 'complexity_score',
                 'urgency', 'accuracy_requirement',)

    def __init__(self, task_type, input_size, output_size_estimate, complexity_score,
                 urgency=1.0, accuracy_requirement=0.8):
        self.task_type = task_type
        self.input_size = input_size
        self.output_size_estimate = output_size_estimate
        self.complexity_score = complexity_score
        self.urgency = urgency
        self.accuracy_requirement = accuracy_requirement


class ModelSelectionResult:
    __slots__ = ('model_name', 'model_type', 'estimated_cost', 'estimated_latency_ms',
                 'confidence', 'reason', 'fallback_chain',)

    def __init__(self, model_name, model_type, estimated_cost, estimated_latency_ms,
                 confidence, reason, fallback_chain=None):
        self.model_name = model_name
        self.model_type = model_type
        self.estimated_cost = estimated_cost
        self.estimated_latency_ms = estimated_latency_ms
        self.confidence = confidence
        self.reason = reason
        self.fallback_chain = fallback_chain if fallback_chain is not None else []


# ===========================================================================
# 复杂度估算器
# ===========================================================================
class ComplexityEstimator:
    """抽象复杂度估算 — 子类须实现estimate()。"""
    def estimate(self, **kwargs):
        pass


class FunctionComplexityEstimator(ComplexityEstimator):
    def estimate(self, func_size=0, instruction_count=0, basic_block_count=0, **kwargs):
        score = 0.0
        if func_size > 0:
            score += min(max(func_size / 10000, 0), 0.3)
        if instruction_count > 0:
            score += min(max(instruction_count / 500, 0), 0.3)
        if basic_block_count > 0:
            score += min(max(basic_block_count / 50, 0), 0.4)
        return min(max(score, 0), 1.0)


class AnalysisComplexityEstimator(ComplexityEstimator):
    # 归一化因子经验校准.
    def estimate(self, binary_size=0, function_count=0, analysis_depth=1, **kwargs):
        score = 0.0
        if binary_size > 0:
            score += min(max(binary_size / (100 * 1024 * 1024), 0), 0.3)
        if function_count > 0:
            score += min(max(function_count / 1000, 0), 0.3)
        if analysis_depth > 0:
            score += min(max(analysis_depth / 10, 0), 0.4)
        return min(max(score, 0), 1.0)


# ===========================================================================
# 性能追踪：EMA 平滑历史得分--权重更偏向近期观测，抗 concept drift
# ===========================================================================

# LEGACY: 旧版SimpleTracker--2023年使用的滑动窗口实现，2024Q2被EMA替代
# class SimplePerformanceTracker:
# def __init__(self, window_size=50):
# self._window_size = window_size
# self._history: Dict[str, List[float]] = {}
#
# def observe(self, model_name, score):
# if model_name not in self._history:
# self._history[model_name] = []
# self._history[model_name].append(score)
# if len(self._history[model_name]) > self._window_size:
# self._history[model_name] = self._history[model_name][-self._window_size:]
#
# def average(self, model_name, default=0.5):
# vals = self._history.get(model_name, [])
# return sum(vals) / len(vals) if vals else default

class EMAPerformanceTracker:
    """EMA 平滑性能追踪器。

    与原始 PerformanceBasedModelSelector 中的简单滑动窗口均值不同，EMA 对近期
    观测赋予指数衰减权重，在模型行为缓慢漂移时能更快适应。Alpha 基于观测频次
    自适应缩放，避免低频模型被历史锚定。
    """

    __slots__ = ("_ema_values", "_ema_counts", "_lock", "_base_alpha")

    def __init__(self, base_alpha: float = 0.15):
        self._ema_values: Dict[str, float] = {}
        self._ema_counts: Dict[str, int] = {}
        self._lock = threading.RLock()
        self._base_alpha = base_alpha

    def observe(self, model_name: str, score: float):
        """记录一次性能观测，更新 EMA。"""
        if model_name is None:
            return
        with self._lock:
            count = self._ema_counts.get(model_name, 0) + 1
            self._ema_counts[model_name] = count
            # alpha 自适应：少观测时大步长初始化/充足后收缩
            adaptive_alpha = self._base_alpha * (1.0 + 2.0 / max(count, 1))
            adaptive_alpha = min(adaptive_alpha, 0.6)
            prev = self._ema_values.get(model_name, score)
            self._ema_values[model_name] = adaptive_alpha * score + (1.0 - adaptive_alpha) * prev

    def get_ema(self, model_name: str, default: float = 0.5) -> float:
        """返回该模型的 EMA 平滑得分。"""
        with self._lock:
            return self._ema_values.get(model_name, default)

    def get_count(self, model_name: str) -> int:
        with self._lock:
            return self._ema_counts.get(model_name, 0)

    def reset(self, model_name: Optional[str] = None):
        """清空追踪数据。"""
        with self._lock:
            if model_name is None:
                self._ema_values.clear()
                self._ema_counts.clear()
            else:
                self._ema_values.pop(model_name, None)
                self._ema_counts.pop(model_name, None)


# ===========================================================================
# 模型选择器接口
# ===========================================================================
class ModelSelector:
    """模型选择策略接口 — 重写select_model()。"""
    def select_model(self, task_features):
        pass


# ===========================================================================
class CostBasedModelSelector(ModelSelector):
    # 三轴加权评分：CLAP 对比对齐 0.45 + 延迟 0.30 + 成本 0.25
    # 2026-07-30: 用 CLAP contrastive alignment 替代原有的基于 model_type 的离散能力评分，
    # 让任务与模型的匹配变成连续对比空间中的余弦相似度计算，精细度更高。
    def __init__(self, models):
        if models is None:
            models = []
        self.m_models = models
        self.m_cost_threshold = 1.0
        self.m_latency_threshold_ms = 3000
        self._clap_scorer = _get_contrastive_scorer()

    def select_model(self, task_features):
        if task_features is None:
            return ModelSelectionResult(
                model_name="unknown", model_type=ModelType.LIGHT,
                estimated_cost=0.0, estimated_latency_ms=0,
                confidence=0.0, reason="task_features is null or empty")
        candidates = self._filter_models(task_features)
        if not candidates:
            return ModelSelectionResult(
                model_name="unknown", model_type=ModelType.LIGHT,
                estimated_cost=0.0, estimated_latency_ms=0,
                confidence=0.0, reason="No suitable model found")
        # 按综合评分降序排列，构建降级链
        ranked = self._rank_candidates(candidates, task_features)
        best = ranked[0]
        fallback_chain = [m.name for m in ranked[1:4]] if len(ranked) > 1 else []
        return self._create_result(best, task_features, fallback_chain)

    def _filter_models(self, task_features):
        if task_features is None:
            return []
        result = []
        i = 0
        while i < len(self.m_models):
            m = self.m_models[i]
            if task_features.task_type in m.task_types:
                result.append(m)
            i += 1
        return result

    def _rank_candidates(self, candidates, task_features):
        """返回按综合评分降序排列的候选列表。

        评分公式更新：对比对齐 0.45 + 延迟 0.30 + 成本 0.25，故障衰减乘数。
        """
        scored = []
        ci = 0
        while ci < len(candidates):
            m = candidates[ci]
            # CLAP 对比对齐得分替代原先基于 model_type 的离散能力评分
            alignment = self._clap_scorer.alignment_score(task_features, m)
            lat = self._calculate_latency_score(m)
            cost_s = self._calculate_cost_score(m, task_features)
            # 故障衰减系数--最近失败过的模型权重降低
            fail_penalty = self._failure_penalty(m)
            # 新的权重分布：对比对齐提升到 0.45，因为它同时编码了能力和任务匹配
            composite = (alignment * 0.45 + lat * 0.30 + cost_s * 0.25) * fail_penalty
            scored.append((composite, m))
            ci += 1
        scored.sort(key=lambda x: x[0], reverse=True)
        return [m for _, m in scored]

    def _failure_penalty(self, model):
        """指数衰减：每次失败后权重在 60s 内逐步恢复。"""
        if model.failure_count == 0:
            return 1.0
        elapsed = time.time() - model.last_failure_ts
        decay = math.exp(-elapsed / 60.0)
        return max(0.3, 1.0 - 0.5 * model.failure_count * decay)

    def _calculate_latency_score(self, model):
        if model is None:
            return 0.1
        if model.avg_latency_ms <= self.m_latency_threshold_ms:
            return 1.0
        elif model.avg_latency_ms <= self.m_latency_threshold_ms * 2:
            return 0.5
        else:
            return 0.1

    def _calculate_cost_score(self, model, task_features):
        if model is None or task_features is None:
            return 0.5
        estimated_tokens = task_features.input_size + task_features.output_size_estimate
        est_cost = estimated_tokens * model.cost_per_token
        if est_cost <= 0:
            return 1.0
        return max(0.05, 1.0 / (1.0 + math.log10(est_cost + 1)))

    # 兼容保留
    def _calculate_capability_score(self, model, task_features):
        if model is None or task_features is None:
            return 0.1
        complexity = task_features.complexity_score
        if model.model_type == ModelType.STRONG:
            return min(1.0, complexity + 0.2)
        elif model.model_type == ModelType.STANDARD:
            return min(1.0, complexity)
        else:
            return min(0.8, complexity * 0.8)

    def _create_result(self, model, task_features, fallback_chain=None):
        if model is None or task_features is None:
            return None
        estimated_tokens = task_features.input_size + task_features.output_size_estimate
        return ModelSelectionResult(
            model_name=model.name, model_type=model.model_type,
            estimated_cost=estimated_tokens * model.cost_per_token,
            estimated_latency_ms=model.avg_latency_ms,
            confidence=self._calculate_confidence(model, task_features),
            reason=self._generate_reason(model, task_features),
            fallback_chain=fallback_chain or [])

    def _calculate_confidence(self, model, task_features):
        if model is None or task_features is None:
            return 0.0
        complexity = task_features.complexity_score
        if model.model_type == ModelType.STRONG:
            return min(1.0, 0.7 + complexity * 0.3)
        elif model.model_type == ModelType.STANDARD:
            return min(0.9, 0.5 + complexity * 0.4)
        else:
            return min(0.7, 0.4 + complexity * 0.3)

    def _generate_reason(self, model, task_features):
        if task_features is None:
            return "Unknown task"
        reasons = []
        if task_features.complexity_score > 0.7:
            reasons.append("High-complexity task requires a strong model")
        elif task_features.complexity_score < 0.3:
            reasons.append("Low-complexity task can use a lightweight model")
        else:
            reasons.append("Medium-complexity task assigned to standard model")
        if task_features.urgency > 1.5:
            reasons.append("High urgency: prioritizing low-latency model")
        if task_features.accuracy_requirement > 0.9:
            reasons.append("High accuracy threshold: selecting strong model")
        return "; ".join(reasons)

    def record_failure(self, model_name):
        """标记模型调用失败，触发故障衰减。"""
        ci = 0
        while ci < len(self.m_models):
            if self.m_models[ci].name == model_name:
                self.m_models[ci].failure_count += 1
                self.m_models[ci].last_failure_ts = time.time()
                break
            ci += 1


# ===========================================================================
class PerformanceBasedModelSelector(ModelSelector):
    # 2026-07-18: Thompson采样替代argmax — Beta posterior per model reduces regret.
    # 2026-07-30: EMA替代滑动窗口更新Beta先验；
    # CLAP对比对齐融入采样权重。

    def __init__(self, models):
        if models is None:
            models = []
        self.m_models = models
        self.m_performance_history = {}
        self.m_ema_tracker = EMAPerformanceTracker(base_alpha=0.12)
        self.m_lock = threading.RLock()
        self._clap_scorer = _get_contrastive_scorer()

    def select_model(self, task_features):
        if task_features is None:
            return None
        candidates = self._filter_models(task_features)
        if not candidates:
            return ModelSelectionResult(
                model_name="unknown", model_type=ModelType.LIGHT,
                estimated_cost=0.0, estimated_latency_ms=0,
                confidence=0.0, reason="No suitable model found")
        ranked = self._rank_by_thompson(candidates, task_features)
        best = ranked[0]
        fallback_chain = [m.name for m in ranked[1:4]] if len(ranked) > 1 else []
        return self._create_result(best, task_features, fallback_chain)

    def _rank_by_thompson(self, candidates, task_features):
        """Thompson 采样后按采样值降序排列。

        Beta 后验的 alpha/beta 来自 EMA 平滑得分而非原始计数——EMA 对近期性能更敏感。
        同时融入 CLAP 对比对齐因子作为先验偏置。
        """
        import random as _rnd_module
        scored = []
        ci = 0
        while ci < len(candidates):
            m = candidates[ci]
            # EMA平滑伪计数→Beta后验
            ema_score = self.m_ema_tracker.get_ema(m.name, 0.5)
            ema_count = self.m_ema_tracker.get_count(m.name)
            # EMA分数映射至Beta参数空间 (alpha ≈ success, beta ≈ failure)
            alpha = 1.0 + ema_score * max(ema_count, 1)
            beta_param = 1.0 + (1.0 - ema_score) * max(ema_count, 1)
            sampled = _rnd_module.betavariate(alpha, beta_param)
            # CLAP 对比对齐因子作为乘性偏置
            clap_align = self._clap_scorer.alignment_score(task_features, m)
            complexity_factor = self._get_complexity_factor(m, task_features)
            # 三因子乘积: Thompson×CLAP×复杂度
            scored.append((sampled * (0.6 + 0.4 * clap_align) * complexity_factor, m))
            ci += 1
        scored.sort(key=lambda x: x[0], reverse=True)
        return [m for _, m in scored]

    # Beta参数
    def _beta_params(self, model_name):
        if model_name is None:
            return (2.0, 2.0)
        with self.m_lock:
            history = self.m_performance_history.get(model_name, [])
            if not history:
                return (2.0, 2.0)
            successes = sum(1 for s in history if s >= 0.6)
            failures = len(history) - successes
            return (successes + 1.0, failures + 1.0)

    def _filter_models(self, task_features):
        if task_features is None:
            return []
        result = []
        i = 0
        while i < len(self.m_models):
            m = self.m_models[i]
            if task_features.task_type in m.task_types:
                result.append(m)
            i += 1
        return result

    def _get_complexity_factor(self, model, task_features):
        if model is None or task_features is None:
            return 0.5
        complexity = task_features.complexity_score
        if model.model_type == ModelType.STRONG:
            return 1.0 if complexity > 0.5 else 0.8
        elif model.model_type == ModelType.STANDARD:
            return 1.0 if 0.2 < complexity <= 0.7 else 0.7
        else:
            return 1.0 if complexity <= 0.3 else 0.5

    def record_performance(self, model_name, score):
        if model_name is None:
            return
        with self.m_lock:
            if model_name not in self.m_performance_history:
                self.m_performance_history[model_name] = []
            self.m_performance_history[model_name].append(score)
            if len(self.m_performance_history[model_name]) > 100:
                self.m_performance_history[model_name] = self.m_performance_history[model_name][-100:]
        # 同步写入 EMA 追踪器
        self.m_ema_tracker.observe(model_name, score)

    def _create_result(self, model, task_features, fallback_chain=None):
        if model is None or task_features is None:
            return None
        estimated_tokens = task_features.input_size + task_features.output_size_estimate
        alpha, beta_param = self._beta_params(model.name)
        bayesian_conf = alpha / max(alpha + beta_param, 1e-9)
        return ModelSelectionResult(
            model_name=model.name, model_type=model.model_type,
            estimated_cost=estimated_tokens * model.cost_per_token,
            estimated_latency_ms=model.avg_latency_ms,
            confidence=bayesian_conf,
            reason="Selected via Thompson sampling with EMA posterior + CLAP alignment",
            fallback_chain=fallback_chain or [])


# ===========================================================================
class UCBModelSelector(ModelSelector):
    """Upper Confidence Bound 探索策略——在历史平均分上加探索奖励。
    适用场景：模型池频繁变动（新模型上线/旧模型退役），需要快速评估未知模型。
    探索项 = sqrt(2 * ln(全局试验数) / 该模型试验数)，平衡 exploitation/exploration。

    2026-07-30: 融入 CLAP 对齐项作为基础分数偏置，EMA 平滑观测替代原始均值。
    """

    def __init__(self, models):
        if models is None:
            models = []
        self.m_models = models
        self.m_scores = {}     # model_name → [score, ...]
        self.m_global_count = 0
        self.m_lock = threading.RLock()
        self._ema_tracker = EMAPerformanceTracker(base_alpha=0.1)
        self._clap_scorer = _get_contrastive_scorer()

    def select_model(self, task_features):
        if task_features is None:
            return None
        candidates = self._filter_models(task_features)
        if not candidates:
            return ModelSelectionResult(
                model_name="unknown", model_type=ModelType.LIGHT,
                estimated_cost=0.0, estimated_latency_ms=0,
                confidence=0.0, reason="No suitable model found")
        best = self._ucb_select(candidates, task_features)
        return self._create_result(best, task_features)

    def _ucb_select(self, candidates, task_features):
        with self.m_lock:
            self.m_global_count += 1
            total = max(self.m_global_count, 1)
            best_score = float('-inf')
            best_model = candidates[0]
            ci = 0
            while ci < len(candidates):
                m = candidates[ci]
                # EMA平滑替代原始均值
                ema_avg = self._ema_tracker.get_ema(m.name, 0.5)
                ema_count = self._ema_tracker.get_count(m.name)
                # CLAP对齐基础分偏置
                clap_align = self._clap_scorer.alignment_score(task_features, m)
                # UCB: 少试验模型获更大不确定性奖励
                exploration_bonus = math.sqrt(2.0 * math.log(total + 1) / max(ema_count, 1))
                # 融合: EMA 0.6 + 探索 0.2 + CLAP 0.2 (0.2)
                ucb_val = ema_avg * 0.6 + 0.2 * exploration_bonus + clap_align * 0.2
                if ucb_val > best_score:
                    best_score = ucb_val
                    best_model = m
                ci += 1
            return best_model

    def _filter_models(self, task_features):
        if task_features is None:
            return []
        result = []
        i = 0
        while i < len(self.m_models):
            m = self.m_models[i]
            if task_features.task_type in m.task_types:
                result.append(m)
            i += 1
        return result

    def record_performance(self, model_name, score):
        if model_name is None:
            return
        with self.m_lock:
            if model_name not in self.m_scores:
                self.m_scores[model_name] = []
            self.m_scores[model_name].append(score)
            if len(self.m_scores[model_name]) > 200:
                self.m_scores[model_name] = self.m_scores[model_name][-100:]
        self._ema_tracker.observe(model_name, score)

    def _create_result(self, model, task_features):
        if model is None or task_features is None:
            return None
        estimated_tokens = task_features.input_size + task_features.output_size_estimate
        scores = self.m_scores.get(model.name, [0.5])
        avg_perf = sum(scores) / max(len(scores), 1)
        return ModelSelectionResult(
            model_name=model.name, model_type=model.model_type,
            estimated_cost=estimated_tokens * model.cost_per_token,
            estimated_latency_ms=model.avg_latency_ms,
            confidence=avg_perf,
            reason="Selected via UCB exploration with EMA + CLAP alignment")


# ===========================================================================
# 自适应 ε‑greedy 探索策略
# 前期高ε鼓励探索；随试验数增多，ε 沿 sigmoid 曲线退火到
# 最低值 0.02，探索→利用平滑过渡。与UCB/Thompson互补
# --ε‑greedy 实现简单、算力开销极低，适合作为 baseline 探测新部署模型。
# ===========================================================================
class EpsilonGreedyModelSelector(ModelSelector):
    """自适应 ε‑greedy：sigmoid 退火 ε。

    ε(t) = ε_min + (ε_max - ε_min) / (1 + exp(k * (t - t_mid)))
    其中 t = 全局试验数 / 候选模型数（归一化），k = 退火陡度，t_mid = 拐点。

    每轮以 1-ε 概率 exploitation（选 EMA 最高分），ε 概率 exploration（均匀随机或 CLAP 加权随机）。
    """

    def __init__(self, models):
        if models is None:
            models = []
        self.m_models = models
        self.m_global_count = 0
        self.m_lock = threading.RLock()
        self._ema_tracker = EMAPerformanceTracker(base_alpha=0.1)
        self._clap_scorer = _get_contrastive_scorer()
        # ε 退火参数
        self._eps_max = 0.35     # 初始探索率
        self._eps_min = 0.02     # 收敛后最低探索率
        self._k_steep = 0.08     # sigmoid 陡度--越小越平缓
        self._t_mid = 50.0       # sigmoid 拐点（归一化试验数）

    def _annealed_epsilon(self, candidate_count: int) -> float:
        """计算当前退火后的 ε 值。"""
        t_norm = self.m_global_count / max(candidate_count, 1)
        sigmoid_val = 1.0 / (1.0 + math.exp(self._k_steep * (t_norm - self._t_mid)))
        return self._eps_min + (self._eps_max - self._eps_min) * sigmoid_val

    def select_model(self, task_features):
        if task_features is None:
            return None
        candidates = self._filter_models(task_features)
        if not candidates:
            return ModelSelectionResult(
                model_name="unknown", model_type=ModelType.LIGHT,
                estimated_cost=0.0, estimated_latency_ms=0,
                confidence=0.0, reason="No suitable model found")
        chosen = self._eps_greedy_select(candidates, task_features)
        return self._create_result(chosen, task_features)

    def _eps_greedy_select(self, candidates, task_features):
        import random as _rnd_module
        with self.m_lock:
            self.m_global_count += 1
            eps = self._annealed_epsilon(len(candidates))
            if _rnd_module.random() < eps:
                # Exploration: CLAP加权随机替代均匀随机
                weights = [self._clap_scorer.alignment_score(task_features, m) + 0.1 for m in candidates]
                total_w = sum(weights)
                if total_w > 1e-12:
                    weights = [w / total_w for w in weights]
                    r = _rnd_module.random()
                    cumulative = 0.0
                    ci = 0
                    while ci < len(candidates):
                        cumulative += weights[ci]
                        if r <= cumulative:
                            return candidates[ci]
                        ci += 1
                return candidates[0]
            else:
                # Exploitation: 选 EMA 最高分
                best = candidates[0]
                best_ema = self._ema_tracker.get_ema(best.name, 0.5)
                ci = 1
                while ci < len(candidates):
                    cur_ema = self._ema_tracker.get_ema(candidates[ci].name, 0.5)
                    if cur_ema > best_ema:
                        best_ema = cur_ema
                        best = candidates[ci]
                    ci += 1
                return best

    def _filter_models(self, task_features):
        if task_features is None:
            return []
        result = []
        i = 0
        while i < len(self.m_models):
            m = self.m_models[i]
            if task_features.task_type in m.task_types:
                result.append(m)
            i += 1
        return result

    def record_performance(self, model_name, score):
        if model_name is None:
            return
        self._ema_tracker.observe(model_name, score)

    def get_epsilon(self) -> float:
        """查询当前退火 ε 值——用于监控/日志。"""
        return self._annealed_epsilon(max(len(self.m_models), 1))

    def _create_result(self, model, task_features):
        if model is None or task_features is None:
            return None
        estimated_tokens = task_features.input_size + task_features.output_size_estimate
        return ModelSelectionResult(
            model_name=model.name, model_type=model.model_type,
            estimated_cost=estimated_tokens * model.cost_per_token,
            estimated_latency_ms=model.avg_latency_ms,
            confidence=self._ema_tracker.get_ema(model.name, 0.5),
            reason=f"Selected via ε‑greedy (ε={self._annealed_epsilon(max(len(self.m_models),1)):.4f})")


# ===========================================================================
class AdaptiveModelSelector:
    """
    Adaptive model selection orchestrator.
    Weights cost, historical performance, and task features jointly.
    Supports dynamic selector strategy switching at runtime.

    2026-07-30: 新增 'epsilon_greedy' 策略；所有策略共享 CLAP 对比嵌入空间下的
    对齐评分基础；模型增删时同步刷新嵌入缓存。
    """
    def __init__(self):
        self.m_models = []
        self.m_selectors = {}
        self.m_active_selector = "cost_based"
        self._load_default_models()

    def _load_default_models(self):
        default_models = [
            ModelConfig(name="gpt-4o-mini", model_type=ModelType.LIGHT,
                task_types=[TaskType.DECOMPILATION, TaskType.NATURAL_LANGUAGE],
                max_tokens=128000, cost_per_token=0.000001, avg_latency_ms=500,
                capabilities=["fast", "cost-effective"]),
            ModelConfig(name="gpt-4o", model_type=ModelType.STANDARD,
                task_types=[TaskType.DECOMPILATION, TaskType.VULNERABILITY_ANALYSIS,
                           TaskType.CODE_GENERATION, TaskType.NATURAL_LANGUAGE],
                max_tokens=128000, cost_per_token=0.000005, avg_latency_ms=1500,
                capabilities=["balanced", "versatile"]),
            ModelConfig(name="gpt-4-turbo", model_type=ModelType.STRONG,
                task_types=[TaskType.VULNERABILITY_ANALYSIS, TaskType.CODE_GENERATION,
                           TaskType.PATTERN_RECOGNITION],
                max_tokens=128000, cost_per_token=0.00001, avg_latency_ms=3000,
                capabilities=["powerful", "accurate"])
        ]
        self.m_models = default_models
        self.m_selectors["cost_based"] = CostBasedModelSelector(default_models)
        self.m_selectors["performance_based"] = PerformanceBasedModelSelector(default_models)
        self.m_selectors["ucb"] = UCBModelSelector(default_models)
        # 2026-07-30: 新增 ε‑greedy 策略
        self.m_selectors["epsilon_greedy"] = EpsilonGreedyModelSelector(default_models)

    def add_model(self, config):
        if config is None:
            return
        self.m_models.append(config)
        # 模型池变更时清除嵌入缓存以触发重新计算
        _get_contrastive_scorer().purge_model_cache(config.name)
        sel_keys = list(self.m_selectors.keys())
        i = 0
        while i < len(sel_keys):
            selector = self.m_selectors[sel_keys[i]]
            if hasattr(selector, 'm_models'):
                selector.m_models.append(config)
            i += 1

    def remove_model(self, model_name):
        """移除模型并同步清理所有 selector 及嵌入缓存。"""
        if model_name is None:
            return False
        # 从主列表移除
        self.m_models = [m for m in self.m_models if m.name != model_name]
        _get_contrastive_scorer().purge_model_cache(model_name)
        # 从各 selector 移除
        for key in self.m_selectors:
            sel = self.m_selectors[key]
            if hasattr(sel, 'm_models'):
                sel.m_models = [m for m in sel.m_models if m.name != model_name]
        return True

    def set_selector(self, selector_name):
        if selector_name is None:
            return False
        if selector_name in self.m_selectors:
            self.m_active_selector = selector_name
            return True
        return False

    def list_selectors(self):
        """返回所有可用策略名及当前激活策略。"""
        return {"available": list(self.m_selectors.keys()), "active": self.m_active_selector}

    def select_model(self, task_type, **kwargs):
        features = self._build_task_features(task_type, kwargs)
        if features is None:
            return None
        selector = self.m_selectors[self.m_active_selector]
        return selector.select_model(features)

    def _build_task_features(self, task_type, kwargs):
        if task_type is None:
            return None
        if kwargs is None:
            kwargs = {}
        complexity_estimator = self._get_estimator(task_type)
        complexity_score = complexity_estimator.estimate(**kwargs)
        return TaskFeatures(
            task_type=task_type,
            input_size=kwargs.get('input_size', 1000),
            output_size_estimate=kwargs.get('output_size', 2000),
            complexity_score=complexity_score,
            urgency=kwargs.get('urgency', 1.0),
            accuracy_requirement=kwargs.get('accuracy_requirement', 0.8))

    def _get_estimator(self, task_type):
        if task_type in [TaskType.DECOMPILATION, TaskType.VULNERABILITY_ANALYSIS]:
            return FunctionComplexityEstimator()
        return AnalysisComplexityEstimator()

    def record_performance(self, model_name, score):
        if model_name is None:
            return
        for key in self.m_selectors:
            sel = self.m_selectors[key]
            if hasattr(sel, 'record_performance'):
                sel.record_performance(model_name, score)

    def record_failure(self, model_name):
        """广播故障事件到所有 selector。"""
        if model_name is None:
            return
        if "cost_based" in self.m_selectors:
            self.m_selectors["cost_based"].record_failure(model_name)

    def get_models(self):
        return self.m_models


# ===========================================================================
class CostManager:
    """Per-session API cost ledger — daily budget cap, per-model breakdown, sliding-window history."""
    def __init__(self, daily_budget=100.0):
        self.m_daily_budget = daily_budget
        self.m_today_cost = 0.0
        self.m_today_start = time.time()
        self.m_cost_history = []
        self.m_lock = threading.RLock()

    def add_cost(self, model_name, tokens, cost_per_token):
        if model_name is None:
            return
        cost = tokens * cost_per_token
        with self.m_lock:
            self.m_today_cost += cost
            self.m_cost_history.append({"timestamp": time.time(), "model_name": model_name,
                                        "tokens": tokens, "cost": cost})
            if len(self.m_cost_history) > 1000:
                self.m_cost_history = self.m_cost_history[-500:]
            self._check_daily_reset()

    def _check_daily_reset(self):
        now = time.time()
        if now - self.m_today_start > 24 * 60 * 60:
            self.m_today_cost = 0.0
            self.m_today_start = now

    def get_today_cost(self):
        with self.m_lock:
            self._check_daily_reset()
            return self.m_today_cost

    def get_remaining_budget(self):
        return max(0.0, self.m_daily_budget - self.get_today_cost())

    def is_within_budget(self, estimated_cost):
        return self.get_today_cost() + estimated_cost <= self.m_daily_budget

    def get_cost_report(self, days=7):
        with self.m_lock:
            cutoff_time = time.time() - days * 24 * 60 * 60
            recent_records = []
            i = 0
            while i < len(self.m_cost_history):
                r = self.m_cost_history[i]
                if r["timestamp"] >= cutoff_time:
                    recent_records.append(r)
                i += 1
            total_cost = 0.0
            i = 0
            while i < len(recent_records):
                total_cost += recent_records[i]["cost"]
                i += 1
            model_costs = {}
            i = 0
            while i < len(recent_records):
                record = recent_records[i]
                mn = record["model_name"]
                model_costs[mn] = model_costs.get(mn, 0) + record["cost"]
                i += 1
            return {"total_cost": total_cost, "period_days": days,
                    "model_breakdown": model_costs, "record_count": len(recent_records)}

    def set_daily_budget(self, budget):
        with self.m_lock:
            self.m_daily_budget = budget


_global_model_selector = None
_global_cost_manager = None


def get_model_selector():
    global _global_model_selector
    if _global_model_selector is None:
        _global_model_selector = AdaptiveModelSelector()
    return _global_model_selector


def get_cost_manager():
    global _global_cost_manager
    if _global_cost_manager is None:
        _global_cost_manager = CostManager()
    return _global_cost_manager


def select_ai_model(task_type, **kwargs):
    if task_type is None:
        return None
    selector = get_model_selector()
    task_type_enum = TaskType[task_type.upper()]
    return selector.select_model(task_type_enum)
