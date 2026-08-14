# 误报在线分类器 — 基于人工反馈的逻辑回归特征学习。
# 每条人工确认产生一个标注样本 (特征向量, 真/假), 积累后可训练可解释分类器,
# 对新结果建议"抑制/报告"。特征维度低 (~8维) 且样本少 (<1000), 故用逻辑回归
# (SGD 在线更新, lr=0.01) 而非神经网络, 可解释且不易过拟合。


import math
import time
from typing import Any, Dict, List, Optional, Tuple


class OnlineFPClassifier:
    """在线误报分类器——逻辑回归 + SGD更新。

    每次人工确认后调用 update(features, is_true_positive),
    权重即时更新。predict(features) 返回 [0,1] 的真实概率。
    """

    def __init__(self, dim: int = 8, lr: float = 0.01):
        self._dim = dim
        self._lr = lr
        self._weights = [0.0] * dim
        self._bias = 0.0
        self._samples = 0

    def predict(self, features: List[float]) -> float:
        """sigmoid(w·x + b) → [0, 1] 真实概率"""
        if len(features) < self._dim:
            padded = list(features) + [0.0] * (self._dim - len(features))
        else:
            padded = features[:self._dim]
        z = sum(w * x for w, x in zip(self._weights, padded)) + self._bias
        # clip防溢出
        z = max(-20.0, min(20.0, z))
        return 1.0 / (1.0 + math.exp(-z))

    def update(self, features: List[float], is_true_positive: bool) -> None:
        """SGD单步更新"""
        if len(features) < self._dim:
            padded = list(features) + [0.0] * (self._dim - len(features))
        else:
            padded = features[:self._dim]

        prob = self.predict(padded)
        target = 1.0 if is_true_positive else 0.0
        error = prob - target

        for i in range(self._dim):
            self._weights[i] -= self._lr * error * padded[i]
        self._bias -= self._lr * error
        self._samples += 1

    def should_suppress(self, features: List[float],
                         threshold: float = 0.3) -> bool:
        """建议抑制: 预测真实概率 < threshold"""
        return self.predict(features) < threshold

    @property
    def samples_trained(self) -> int:
        return self._samples


def extract_finding_features(finding: Dict[str, Any],
                              binary_info: Optional[Dict[str, Any]] = None,
                              ) -> List[float]:
    """从一条检测结果中提取分类特征向量。

    特征维度 (8维):
      [0] log1p(函数大小_指令数) / 10
      [1] CFG分支密度 (branch_count / max(1, bb_count))
      [2] 危险调用在函数中的深度 (行号/总行数)
      [3] 是否含sanitization信号 (snprintf/strndup等) 0/1
      [4] 二进制是否有canary (来自binary_info) 0/1
      [5] 二进制是否PIE 0/1
      [6] 检测置信度 (原始)
      [7] 该类型漏洞的历史真阳性率 (来自分类器——初始0.5)
    """
    features = [0.0] * 8

    # f0: 函数大小
    func_size = finding.get('func_size', 50)
    features[0] = min(1.0, math.log1p(func_size) / 10.0)

    # f1: CFG密度
    bb_count = max(1, finding.get('bb_count', 5))
    branch_count = finding.get('branch_count', 0)
    features[1] = min(1.0, branch_count / bb_count)

    # f2: 调用深度
    depth = finding.get('call_depth', 3)
    features[2] = min(1.0, depth / 20.0)

    # f3: sanitization
    features[3] = 1.0 if finding.get('has_sanitization') else 0.0

    # f4-f5: 二进制属性
    if binary_info:
        features[4] = 0.0 if binary_info.get('has_canary') else 1.0
        features[5] = 1.0 if binary_info.get('is_pie') else 0.0

    # f6: 原始置信度
    features[6] = finding.get('confidence', 0.5)

    # f7: 初始中性
    features[7] = 0.5

    return features
