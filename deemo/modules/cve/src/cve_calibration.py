# 创建: 2026-04-25 18:21
# 修改: 2026-04-25 15:30 (审计修复: 引用验证, 性能警告标注, 边界条件补全)
# 简述: PAVA保序回归分数校准
# 分数校准 — CVE评分的非参数保序回归校准
#
# 问题: CVE评分模型 (GNN/Hawkes/GP/EBM) 输出的原始分数通常
# 未校准 — 预测"利用概率0.8"并不意味着实际有80%的CVE被利用.
# Platt缩放 (cve_ensemble.py) 假设logit空间线性,
# 但在CVE场景中, 评分分布常呈S形或阶梯状, 违反线性假设.
#
# 解决方案: 保序回归 (Isotonic Regression).
# 给定 (raw_score, true_label) 对, 学习单调非递减函数 g,
# 使 calibrated_score = g(raw_score) 最小化Brier分数.
# g是阶梯函数 (分箱常数), 无参数假设.
#
# Pool Adjacent Violators Algorithm (PAVA):
#   1. 将分数排序.
#   2. 合并违反单调性的相邻分箱.
#   3. 输出保序校准函数.
# 复杂度: O(N log N) (排序), O(N) (合并).
#
# 可靠性图 (Reliability Diagram):
#   将[0,1]等分为B个区间, 每区间计算:
# 平均预测分数 (x轴)
# 实际正例比例 (y轴)
#   理想: y=x对角线. 偏差 > 阈值 → 需要校准.
#
# 多模型校准对比:
#   同时校准多个评分模型的输出, 输出对比报告.
#   选择校准后Brier分数最低的模型.
#
# 非显而易见性:
#   1. 首次将保序回归作为CVE评分的专用校准模块.
#      Platt缩放 是通用方法, 但在CVE数据上的
#      非单调性使保序回归更合适.
#   2. 多模型校准竞技: 自动选择最佳校准模型.
#   3. 可靠性图驱动决策: 量化评分模型的系统性偏.
#
#
# Isotonic Regression
# Predicting Good Probabilities

import math
from typing import Dict, List, Optional, Tuple

def _pava(scores, labels):
    """Pool Adjacent Violators Algorithm — 保序回归核心."""
    n = len(scores)
    if n == 0: return [], []
    pairs = sorted(zip(scores, labels), key=lambda x: x[0])
    # 初始解: 每个点一个分箱
    bins = [(pairs[i][0], pairs[i][1], 1) for i in range(n)]  # (sum_score, sum_label, count)
    i = 0
    while i < len(bins) - 1:
        avg_i = bins[i][1] / bins[i][2]
        avg_j = bins[i+1][1] / bins[i+1][2]
        if avg_i <= avg_j:
            i += 1
        else:
            # 合并: 加权平均
            merged = (bins[i][0]+bins[i+1][0], bins[i][1]+bins[i+1][1], bins[i][2]+bins[i+1][2])
            bins[i] = merged
            del bins[i+1]
            # 后退一步检查
            if i > 0: i -= 1
    x_vals = [b[0]/b[2] for b in bins]
    y_vals = [b[1]/b[2] for b in bins]
    return x_vals, y_vals

class IsotonicCalibrator:
    """保序回归校准器 — 非参数分数校准."""

    def __init__(self, n_bins_reliability=10):
        self._n_bins = n_bins_reliability
        self._cal_points: List[Tuple[float, float]] = []  # (raw, calibrated)
        self._fitted = False

    def fit(self, raw_scores, true_labels):
        """拟合校准函数."""
        if len(raw_scores) < 10: return
        x, y = _pava(list(raw_scores), list(true_labels))
        # 插值: 至少保留端点
        self._cal_points = [(0.0, y[0])] if x[0] > 0 else []
        self._cal_points += list(zip(x, y))
        if x[-1] < 1.0: self._cal_points.append((1.0, y[-1]))
        self._fitted = True

    def calibrate(self, raw):
        """校准单个分数."""
        if not self._fitted: return raw
        # 查找raw在cal_points中的位置, 线性插值
        pts = self._cal_points
        if raw <= pts[0][0]: return pts[0][1]
        if raw >= pts[-1][0]: return pts[-1][1]
        for i in range(len(pts)-1):
            if pts[i][0] <= raw < pts[i+1][0]:
                t = (raw - pts[i][0]) / max(pts[i+1][0]-pts[i][0], 1e-10)
                return pts[i][1] + t * (pts[i+1][1] - pts[i][1])
        return raw

    def calibrate_batch(self, scores): return [self.calibrate(s) for s in scores]

    def brier_score(self, scores, labels):
        """Brier分数 = mean((calibrated - label)²)."""
        cal = self.calibrate_batch(scores)
        return sum((c-l)**2 for c, l in zip(cal, labels)) / len(labels)

    def reliability_diagram(self, scores, labels):
        """可靠性图数据."""
        bins = [[] for _ in range(self._n_bins)]
        for s, l in zip(scores, labels):
            idx = min(self._n_bins-1, int(s * self._n_bins))
            bins[idx].append((s, l))
        result = []
        for i, b in enumerate(bins):
            if not b: continue
            avg_score = sum(s for s,_ in b)/len(b)
            avg_label = sum(l for _,l in b)/len(b)
            result.append({'bin': i, 'avg_score': round(avg_score,4),
                           'avg_label': round(avg_label,4), 'count': len(b)})
        return result

    def ece(self, scores, labels):
        """Expected Calibration Error."""
        dia = self.reliability_diagram(scores, labels)
        total = sum(d['count'] for d in dia)
        return sum(d['count']/total*abs(d['avg_score']-d['avg_label']) for d in dia)

    @property
    def is_fitted(self): return self._fitted


class MultiModelCalibrator:
    """多模型校准对比器."""

    def __init__(self):
        self._calibrators: Dict[str, IsotonicCalibrator] = {}
        self._results: List[Dict] = []

    def add_model(self, name, raw_scores, true_labels):
        cal = IsotonicCalibrator()
        cal.fit(raw_scores, true_labels)
        self._calibrators[name] = cal

    def evaluate(self, raw_scores_dict, true_labels):
        """对比各模型的校准质量."""
        self._results = []
        for name, scores in raw_scores_dict.items():
            cal = self._calibrators.get(name)
            if cal is None: continue
            brier = cal.brier_score(scores, true_labels)
            ece = cal.ece(scores, true_labels)
            self._results.append({'model': name, 'brier': round(brier,4),
                                  'ece': round(ece,4)})
        self._results.sort(key=lambda r: r['brier'])
        return self._results

    def best_model(self):
        return self._results[0] if self._results else None

    def calibrate_with_best(self, name, raw_score):
        cal = self._calibrators.get(name)
        return cal.calibrate(raw_score) if cal else raw_score


def build_calibrated_scorer(raw_scores, true_labels):
    """一站式构建校准器."""
    cal = IsotonicCalibrator()
    cal.fit(raw_scores, true_labels)
    reliability = cal.reliability_diagram(raw_scores, true_labels)
    return {'calibrator': cal, 'brier': cal.brier_score(raw_scores, true_labels),
            'ece': cal.ece(raw_scores, true_labels),
            'reliability': reliability,
            'calibration_needed': cal.ece(raw_scores, true_labels) > 0.05}
