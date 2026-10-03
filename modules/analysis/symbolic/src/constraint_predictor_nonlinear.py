# 增加 log-transform 目标变量，解决线性模型对指数关系的欠拟合
# 引入 phase detec 自动切换特征集
# 增加 na baseline 对比，在线输出 MAE ratio

"""非线性约束求解时间预测器

ConstraintComplexityEstimator (symexec_opt_passes.py) 使用 5 特征 SGD 线性回归
但 Z3 求解时间与 constraint_count 的关系更接近指数而非线性-
bit-blasting 将 n 个布尔变量展开为 2^n 种可能赋值，SAT 求解器在此空间搜索
线性模型在低约束数区域预测尚可，高约束数区域系统性低估

本模块不替代 ConstraintComplexityEstimator-作为可选增强层叠加：
a. 对 5 个原始特征做 degree-2 多项式展开（含交互项），捕获非线性关系
b. 对目标变量做 log(1 + solve_time) 变换，将指数增长线性化
c. Phase detec：根据约束内容自动判定当前处于何种求解阶段
（数值运算 / 位向量 / 字符串），每阶段使用专用特征权重
d. 内置 na baseline（历史均值预测），在线输出 MAE_ratio =
MAE_nonlinear / MAE_baseline，当 ratio > 0.8 时发出退化警告

ref: FSE 2024 "Partial Solu Based 约束求解缓存" 证明了求解时间
预测对缓存策略的关键性-本模块将此预测从线性提升为非线性
ref: DeepSolver 使用 GNN 预测 SMT 求解时间，但依赖 GPU 推理；
本方法使用多项式特征展开 + SGD，纯 CPU 且在线更新，适用于符号执行场景
"""

import math
import time
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field
from collections import deque

@dataclass
class PredictionResult:
    predicted_seconds: float
    raw_linear_pred: float       # 线性部分预测值（log 空间）
    nonlinear_correction: float   # 非线性修正量（log 空间）
    phase: str                    # 当前判定阶段
    confidence: float             # [0,1]，基于近期 MAE 的置信度

class ConstraintPhaseDetector:
    """基于约束内容的求解阶段检测

    不同阶段的求解复杂度特征不同：
    - numeric: 算术约束为主，Z3 用 simplex + 整数规划，复杂度中等
    - bitvector: 位运算为主，触发 bit-blasting→SAT，复杂度最高
    - string: 字符串操作，Z3 有专用 string solver，复杂度与长度正相关

    硬编码关键词映射，而非 ML 分类——此类特征的分布稳定
    不需要在线学习，确定性规则更可靠且零延迟
    """

    _NUMERIC_PATTERNS = ('+', '-', '*', '/', '%', '<=', '>=', '<', '>', '==')
    _BV_PATTERNS = ('&', '|', '^', '~', '<<', '>>', 'bv', 'extract', 'concat')
    _STRING_PATTERNS = ('str.', 'strlen', 'substring', 'indexof', 'replace')

    def detect(self, constraint_texts: List[str]) -> str:
        if not constraint_texts:
            return 'empty'

        combined = ' '.join(constraint_texts).lower()
        bv_score = sum(1 for p in self._BV_PATTERNS if p in combined)
        str_score = sum(1 for p in self._STRING_PATTERNS if p in combined)
        num_score = sum(1 for p in self._NUMERIC_PATTERNS if p in combined)

        if bv_score >= str_score and bv_score >= num_score:
            return 'bitvector'
        elif str_score >= bv_score and str_score >= num_score:
            return 'string'
        else:
            return 'numeric'

class NaiveBaselinePredictor:
    """历史均值预测器-用于对比评估非线性模型的改进幅度"""

    def __init__(self, window: int = 100):
        self._window = window
        self._history: deque = deque(maxlen=window)

    def predict(self) -> float:
        if not self._history:
            return 1.0
        return sum(self._history) / len(self._history)

    def update(self, actual: float) -> None:
        self._history.append(actual)

    @property
    def mae(self) -> float:
        if not self._history:
            return float('inf')
        mean = self.predict()
        return sum(abs(x - mean) for x in self._history) / len(self._history)

class NonlinearConstraintPredictor:
    """多项式特征展开 + log 目标变换的求解时间预测器

    特征工程：
    - 5 个原始特征：constraint_count, max_depth, bv_width
    arithmetic_ratio, boolean_ratio
    - 展开为 20 维：5 个一次项 + 5 个平方项 + C(5,2)=10 个交互项
    - 交互项捕获跨特征的非线性效应，如 constraint_count × bv_width
    （大量位向量约束的组合代价远超各自独立贡献之和）

    权重矩阵：[20, 3] -每个 phase 一组 20 维权重
    SGD 在线更新，lr 随预测误差自调整
    """

    _NUM_PHASES = 3
    _PHASE_INDICES = {'numeric': 0, 'bitvector': 1, 'string': 2}

    def __init__(self, learning_rate: float = 0.005):
        self.lr = learning_rate
        # 20 维特征 × 3 个 phase
        self._weights = [[0.0] * 20 for _ in range(self._NUM_PHASES)]
        # 启发式初始权重-与 ConstraintComplexityEstimator._DEFAULT_WEIGHTS 对齐
        self._init_default_weights()
        self._phase_detector = ConstraintPhaseDetector()
        self._baseline = NaiveBaselinePredictor()
        self._mae_accumulator = 0.0
        self._mae_count = 0
        self._prediction_count = 0

    def _init_default_weights(self):
        """启发式初始权重-给一次项设非零初值，平方项和交互项从零开始学习"""
        defaults = {
            'constraint_count': 0.08, 'max_depth': 0.04,
            'bv_width': 0.0001, 'arithmetic_ratio': 0.5, 'boolean_ratio': 0.3,
        }
        feature_names = ['constraint_count', 'max_depth', 'bv_width',
                         'arithmetic_ratio', 'boolean_ratio']
        for phase_idx in range(self._NUM_PHASES):
            for i, name in enumerate(feature_names):
                self._weights[phase_idx][i] = defaults.get(name, 0.0)

    def _expand_features(self, raw: Dict[str, float]) -> List[float]:
        """5 维 → 20 维多项式展开（含交互项）"""
        x = [
            raw.get('constraint_count', 0),
            raw.get('max_depth', 0),
            raw.get('bv_width', 0),
            raw.get('arithmetic_ratio', 0),
            raw.get('boolean_ratio', 0),
        ]
        # 一次项 (5)
        feats = list(x)
        # 平方项 (5)
        feats.extend(v * v for v in x)
        # 交互项 C(5,2) = 10
        for i in range(5):
            for j in range(i + 1, 5):
                feats.append(x[i] * x[j])
        return feats

    def predict(self, features: Dict[str, float],
                constraint_texts: List[str] = None) -> PredictionResult:
        """预测求解时间（秒）

        constraint_texts 可选-提供时用于 phase detec；
        不提供时默认 numeric phase
        """
        phase = 'numeric'
        if constraint_texts:
            phase = self._phase_detector.detect(constraint_texts)

        expanded = self._expand_features(features)
        phase_idx = self._PHASE_INDICES.get(phase, 0)
        weights = self._weights[phase_idx]

        # log 空间线性组合
        log_pred = sum(w * f for w, f in zip(weights, expanded))
        # 分离一次项贡献和非线性贡献-用于可解释性诊断
        linear_contrib = sum(weights[i] * expanded[i] for i in range(5))
        nonlinear_contrib = log_pred - linear_contrib

        # 记录 → linear 变换：exp(log_pred) - 1
        predicted = math.exp(max(log_pred, -10.0)) - 1.0
        predicted = max(predicted, 0.001)

        # 置信度：基于近期 MAE，MAE 越高置信度越低
        confidence = 1.0
        if self._mae_count > 10:
            avg_mae = self._mae_accumulator / self._mae_count
            confidence = max(0.1, 1.0 - avg_mae / max(predicted, 0.01))

        self._prediction_count += 1
        return PredictionResult(
            predicted_seconds=predicted,
            raw_linear_pred=linear_contrib,
            nonlinear_correction=nonlinear_contrib,
            phase=phase,
            confidence=confidence,
        )

    def update(self, features: Dict[str, float], actual_seconds: float,
               constraint_texts: List[str] = None) -> float:
        """在线 SGD 更新-返回当前 MAE ratio（vs baseline）"""
        phase = 'numeric'
        if constraint_texts:
            phase = self._phase_detector.detect(constraint_texts)

        expanded = self._expand_features(features)
        phase_idx = self._PHASE_INDICES.get(phase, 0)
        weights = self._weights[phase_idx]

        # log 变换目标
        target_log = math.log(1.0 + max(actual_seconds, 0.001))
        pred_log = sum(w * f for w, f in zip(weights, expanded))

        error = target_log - pred_log
        abs_error_seconds = abs(math.exp(target_log) - math.exp(pred_log))

        # SGD 更新-学习率随误差自适应：大误差→大步长加速收敛
        adaptive_lr = self.lr * min(1.0 + abs(error), 5.0)
        for i in range(len(weights)):
            weights[i] += adaptive_lr * error * expanded[i]

        # 更新评估指标
        self._baseline.update(actual_seconds)
        self._mae_accumulator += abs_error_seconds
        self._mae_count += 1

        # 周期性重置累积器-防止 32-bit float 溢出，保留最近 200 次统计
        if self._mae_count > 200:
            self._mae_accumulator *= 0.5
            self._mae_count = 100

        baseline_mae = self._baseline.mae
        current_mae = self._mae_accumulator / max(self._mae_count, 1)
        mae_ratio = current_mae / max(baseline_mae, 0.001)

        return mae_ratio

    @property
    def degradation_warning(self) -> bool:
        """MAE ratio > 0.8 → 模型不比 na baseline 好多少，可能退化"""
        if self._mae_count < 20:
            return False
        current_mae = self._mae_accumulator / self._mae_count
        return current_mae > 0.8 * max(self._baseline.mae, 0.001)

    @property
    def weights_snapshot(self) -> Dict[str, List[float]]:
        """返回当前权重快照，供外部 calibrator 诊断"""
        return {
            'numeric': list(self._weights[0]),
            'bitvector': list(self._weights[1]),
            'string': list(self._weights[2]),
        }
