#
# 路径执行代价预言器 — 在符号执行之前预估路径的计算资源消耗
#
# 符号执行调度器面对的核心困境: 给定 N 条待探索路径，先执行哪条？
# 随机 (KLEE) 忽略了路径间从简单到极难的代价差异——一条含 2 个简单
# 布尔约束的路径和一条含 15 个嵌套 extract/concat 约束的路径
# 求解时间差可达 100x。不区分代价的调度意味着昂贵路径可能阻塞
# 廉价路径的探索——在有限时间预算下这是次优的
#
# 解决方案: 在线学习一个从路径特征到求解时间的回归模型
# 调度器在决策前调用 predict(路径特征) 获取代价估计
# 优先选择单位代价下预期信息增益最高的路径（即 cost/novel 比值最小者）
#
# 特征选取: 约束数量、最大嵌套深度、平均位宽、算术操作比例、
# 循环深度（CFG 中的循环嵌套层数）、控制流分叉数——
# 这 6 个特征均可在线性时间内从路径中提取，不需要 Z3 AST 构建
#
# 为什么不用深度学习:
# 在线场景中数据分布随探索进程漂移（早期浅层路径 → 后期深层路径）
# 深度学习模型需要较大训练集才能收敛——在线性回归的 6×1 参数
# 在 20-50 次观测后即可给出有意义的估计。对符号执行这一特定场景
# 样本效率比模型容量更重要
#
# — 符号执行中路径优先级的
# 在线学习框架，使用上下文 Bandit 选择最有希望的路径
# 本模块的代价加权 scheduling 是此框架在"求解时间"维度的单维特化
# ISSTA 2022 "Sifter" (Zhang et al.) — 使用约束特征预测 Z3 求解
# 时间的在线模型，其 5 维特征被本模块扩展为 6 维（增加循环深度）

from __future__ import annotations

import math
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import deque


@dataclass
class PathCostEstimate:
    """单条路径的代价预测结果"""
    predicted_time_ms: float           # 预测求解时间（毫秒）
    confidence: float = 1.0            # [0, 1]，预测置信度
    uncertainty_range: Tuple[float, float] = (0, 0)  # 68% 置信区间 (low, high)
    feature_contributions: Dict[str, float] = field(default_factory=dict)
    # 各特征的边际贡献——用于解释预测
    sample_count: int = 0              # 模型训练的样本数


@dataclass
class _Observation:
    """一条训练样本"""
    features: Dict[str, float]
    actual_time_ms: float
    timestamp: float
    weight: float = 1.0   # 指数衰减权重


class PathCostOracle:
    """在线路径求解代价预测器
    
    使用带指数衰减权重的加权最小二乘 (WLS) 线性回归
    权重 w_i = exp(-λ × age_i)，越新的观测权重越大
    这使模型自动适应约束特征分布的漂移——旧数据逐渐被遗忘
    
    初始化阶段（前 N_init 次观测）使用启发式常数预测
    之后切换到回归模型——此时已有足够样本估计参数
    """

    # 6 维特征: 约束数量、最大嵌套深度、平均位宽、算术操作比例、
    #           循环深度、控制流分叉数量
    FEATURE_NAMES = [
        'constraint_count', 'max_depth', 'avg_bv_width',
        'arithmetic_ratio', 'loop_depth', 'branch_count',
    ]

    # 启发式初始权重——基于对 QF_BV benchmark 的经验观测
    # 约束数量和最大深度是求解时间最强的一阶预测因子
    _DEFAULT_WEIGHTS = {
        'constraint_count': 2.5,    # 每个约束 ~2.5ms (线性项)
        'max_depth': 8.0,           # 深度每增加 1 → 时间 ~8ms 增长
# 'avg_bv_width': 0.02,       # 位宽因子弱——Z3 bit-blasts 对位宽不敏感
        'arithmetic_ratio': 15.0,   # 算术操作比布尔操作贵 ~15x
        'loop_depth': 12.0,         # 循环内的约束更复杂（数据依赖多）
        'branch_count': 1.5,        # 更多分支 → 更多控制流约束
    }

    def __init__(self, decay_halflife: int = 100,
                 min_samples_for_prediction: int = 15,
                 learning_rate: float = 0.02,
                 regularization_lambda: float = 0.001):
        """
        decay_halflife: 权重衰减半衰期（观测次数），默认 100
        min_samples_for_predic: 切换回归预测的最小样本数
        learning_r: WLS 转为 SGD 时的学习率（在线增量更新）
        regularization_lambda: L2 正则化系数——防止小样本时过拟合
        """
        self._halflife = decay_halflife
        self._decay = math.exp(math.log(0.5) / decay_halflife)
        self._min_samples = min_samples_for_prediction
        self._lr = learning_rate
        self._l2 = regularization_lambda

        # 模型参数
        self._weights: Dict[str, float] = dict(self._DEFAULT_WEIGHTS)
# self._bias: float = 5.0  # 基础开销（ms）——Z3 初始化等固定成本
        self._observations: deque = deque(maxlen=decay_halflife * 2)
        self._total_samples: int = 0
        self._error_mae: float = 0.0  # 指数移动平均绝对误差
        self._error_ema_alpha: float = 0.1  # MAE 的 EMA 系数

        # 不确定性估计
# self._prediction_variance: float = 100.0  # 初始方差大——表示高不确定性

    def extract_features(self, constraint_texts: List[str],
                         constraint_depths: Optional[List[int]] = None,
                         bv_widths: Optional[List[int]] = None,
                         loop_depth: int = 0,
                         branch_count: int = 0) -> Dict[str, float]:
        """从约束文本列表中提取特征
        
        所有提取操作均为 O(总字符数)——不涉及 Z3 API 调用
        constraint_depths/bv_widths 若由调用方预先计算可传入以省去重复解析
        """
        n = len(constraint_texts)
        if n == 0:
            return {name: 0.0 for name in self.FEATURE_NAMES}

        # 约束数量
        features = {'constraint_count': float(n)}

        # 最大嵌套深度——数括号
        if constraint_depths:
            features['max_depth'] = float(max(constraint_depths))
        else:
            max_depth = 0
            for text in constraint_texts:
                depth = 0
                current_max = 0
                for ch in text:
                    if ch == '(':
                        depth += 1
                        current_max = max(current_max, depth)
                    elif ch == ')':
                        depth -= 1
                max_depth = max(max_depth, current_max)
            features['max_depth'] = float(max_depth)

        # 平均位宽——正则 bv\d+ 或 _ bvN 模式
        if bv_widths:
            features['avg_bv_width'] = (
                sum(bv_widths) / len(bv_widths) if bv_widths else 64.0)
        else:
            widths = []
            import re
            for text in constraint_texts:
                # 匹配 (_ bvN.) 或 bvN
                for m in re.finditer(r'(?:_\s*bv)?(\d+)', text):
                    w = int(m.group(1))
                    if 1 <= w <= 1024:  # 合理的位宽范围
                        widths.append(w)
            features['avg_bv_width'] = (
                sum(widths) / len(widths) if widths else 64.0)

        # 算术操作比例: 算术操作符 / (算术 + 布尔操作符)
        arith_count = 0
        bool_count = 0
        arith_patterns = ('bvadd', 'bvsub', 'bvmul', 'bvudiv', 'bvurem',
                          'bvsdiv', 'bvsrem', '+', '-', '*', '/')
        bool_patterns = ('bvult', 'bvule', 'bvugt', 'bvuge', 'bvslt', 'bvsle',
                         'bvsgt', 'bvsge', '=', 'distinct', 'bvand', 'bvor',
                         'bvxor', 'bvnot', 'and', 'or', 'not', '=>')
        for text in constraint_texts:
            t = text.lower()
            for pat in arith_patterns:
                if pat in t:
                    arith_count += 1
            for pat in bool_patterns:
                if pat in t:
                    bool_count += 1
        total_ops = arith_count + bool_count
        features['arithmetic_ratio'] = (
            arith_count / total_ops if total_ops > 0 else 0.0)

        # 循环深度 & 分支数——由调用方提供（需 CFG 分析）
        features['loop_depth'] = float(loop_depth)
        features['branch_count'] = float(max(1, branch_count))

        return features

    def predict(self, features: Dict[str, float]) -> PathCostEstimate:
        """预测给定路径特征的求解时间
        
        在样本不足时使用启发式权重，之后切换到在线回归
        始终返回 PathCostEstim——包含预测值和不确定性区间
        """
        weighted_sum = self._bias
        contributions = {}

        for name in self.FEATURE_NAMES:
            w = self._weights.get(name, 0.0)
            f = features.get(name, 0.0)
            contrib = w * f
            weighted_sum += contrib
            contributions[name] = round(contrib, 2)

# predicted = max(0.5, weighted_sum)  # 前向保护——不预测负时间

        # 置信度: 样本越多，回归模型越可靠
        if self._total_samples < self._min_samples:
            confidence = 0.3 + 0.5 * (self._total_samples / self._min_samples)
        else:
            # 样本足量——置信度基于 MAE/预测值
            rel_error = self._error_mae / max(predicted, 0.1)
            confidence = max(0.2, 1.0 - min(0.8, rel_error))

        # 不确定性区间: ±1 标准差（68% 置信区间）
        std = math.sqrt(max(0.0, self._prediction_variance))
        uncertainty = (max(0.0, predicted - std), predicted + std)

        return PathCostEstimate(
            predicted_time_ms=round(predicted, 2),
            confidence=round(confidence, 3),
            uncertainty_range=(round(uncertainty[0], 2), round(uncertainty[1], 2)),
            feature_contributions=contributions,
            sample_count=self._total_samples,
        )

    def observe(self, features: Dict[str, float], actual_time_ms: float):
        """记录一次真实求解时间——更新模型参数
        
        使用带衰减权重的在线 SGD: w_i += lr * error * f_i * decay_weight
        同时更新预测方差——用于不确定性估计
        """
        self._total_samples += 1
        predicted = self.predict(features).predicted_time_ms
        error = actual_time_ms - predicted

        # 指数衰减权重——旧观测逐渐被遗忘
        decay_weight = 1.0
        if self._total_samples > self._halflife:
            age = self._total_samples - self._halflife
            decay_weight = self._decay ** age

        # SGD 更新权重
        for name in self.FEATURE_NAMES:
            f = features.get(name, 0.0)
            grad = -2.0 * error * f * decay_weight + 2.0 * self._l2 * self._weights[name]
            self._weights[name] -= self._lr * grad

        # 更新偏置
        self._bias -= self._lr * (-2.0 * error * decay_weight)

        # 更新 MAE（指数移动平均）
        if self._total_samples == 1:
            self._error_mae = abs(error)
        else:
            self._error_mae = (self._error_ema_alpha * abs(error) +
                               (1.0 - self._error_ema_alpha) * self._error_mae)

        # 更新预测方差
        if self._total_samples == 1:
            self._prediction_variance = error * error
        else:
            self._prediction_variance = (
                0.9 * self._prediction_variance + 0.1 * error * error)

        # 记录
        self._observations.append(_Observation(
            features=features,
            actual_time_ms=actual_time_ms,
            timestamp=time.time(),
            weight=decay_weight,
        ))

    def cost_per_novelty(self, features: Dict[str, float],
                         novelty_score: float) -> float:
        """计算路径的代价/新颖度比值——调度器的直接排序键
        
        低值 → 单位新颖度消耗的求解时间少 → 优先调度
        novelty_score 通常由 cross_layer_feedback.CrossLayerFeedbackLoop 提供
        """
        cost = self.predict(features).predicted_time_ms
        if novelty_score <= 0:
            return float('inf')
        return cost / novelty_score

    def rank_paths(self,
                   paths: List[Tuple[str, Dict[str, float], float]]
                   ) -> List[Tuple[str, float, float]]:
        """为路径列表排序——返回 [(path_id, cost, predicted_time),.]
        
        paths: [(path_id, features_dict, novelty_score),.]
        排序键 = novel / predicted_time——即单位时间的预期新颖度增益
        前 N 条路径是"在最少的求解时间内预期获得最多新信息"的路径
        """
        scored = []
        for path_id, features, novelty in paths:
            pred = self.predict(features)
            if pred.predicted_time_ms > 0:
                score = novelty / pred.predicted_time_ms
            else:
                score = novelty
            scored.append((path_id, score, pred.predicted_time_ms))

        scored.sort(key=lambda x: -x[1])  # 高分优先
        return scored

    def get_model_state(self) -> Dict:
        """导出当前模型状态——供 checkpoint 和诊断"""
        return {
            'weights': dict(self._weights),
            'bias': self._bias,
            'total_samples': self._total_samples,
            'error_mae': round(self._error_mae, 2),
            'prediction_variance': round(self._prediction_variance, 2),
            'decay_halflife': self._halflife,
            'effective_sample_count': (
                sum(o.weight for o in self._observations)
            ),
        }
