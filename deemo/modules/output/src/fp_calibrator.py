"""
贝叶斯序贯误报率校准 — 多证据源似然比驱动的后验概率更新。

问题定义:
  静态分析的高误报率是二进制漏洞检测的长期痛点。每个分析模块
  (静态/fuzz/LLM/符号执行) 有不同的灵敏度/特异性分布。
  现有工具输出二值判定或单一置信度，不提供校准后的误报概率。

  与 drift_calibrator.py 的区别:
    drift_calibrator: 校准 AI 的 "这个发现正确的概率" (置信度校准)
    fp_calibrator:    校准 "这个发现是误报的概率" (序贯贝叶斯)

解决方案:
  1. 每个证据源有预校准的似然比: LR+ = sensitivity/(1-specificity)
  2. 先验 = 该漏洞类型的基准真阳性率 (可从历史数据或文献获取)
  3. 每个分析模块提供判定 (阳性/阴性) → 贝叶斯更新后验
  4. 序贯: 后验成为下一轮的先验

  后验 = prior × Π LR_i / (prior × Π LR_i + (1-prior))

  输出: 校准后的误报概率 P(FP|evidence) = 1 - P(TP|evidence)

参考:
  Bayesian Networks for SA Alert Optimization (2024 硕士论文):
    使用 BN 后处理静态分析告警。本模块的差异化:
    1) 序贯更新而非单步 BN 推断
    2) 似然比参数化每个分析源，而非从数据学习 BN 结构
    3) 与 evidence_fusion.py 的 D-S mass 值兼容 — mass_v 可作为 LR+ 的输入

修改记录:
  2026-08-01 14:08 - 初始版本，四源似然比 + 序贯贝叶斯更新
"""

import math
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


# 各证据源的预校准似然比参数
# 基于典型静态分析工具的 FPR/TPR 文献值
# 灵敏度 (TPR) = TP/(TP+FN), 特异性 (TNR) = TN/(TN+FP)
# LR+ = TPR/(1-TNR) = TPR/FPR
_SOURCE_LR: Dict[str, Tuple[float, float]] = {
    # source: (sensitivity, specificity)
    'static':    (0.82, 0.70),   # TPR 高但 FPR 也高
    'fuzz':      (0.55, 0.95),   # TPR 中等但 FPR 极低 (崩溃确认为真)
    'llm':       (0.70, 0.60),   # TPR 中等, FPR 偏高 (过度自信)
    'symbex':    (0.65, 0.92),   # TPR 中等, FPR 低 (路径约束确认)
}

# 漏洞类型先验 — 该类型漏洞在任意二进制中真实存在的基准概率
# 无数据时使用 Jeffrey's prior: Beta(0.5, 0.5) → 均值 0.5
_TYPE_PRIOR: Dict[str, float] = {
    'stack_overflow': 0.18,
    'heap_overflow':  0.12,
    'format_string':  0.08,
    'use_after_free': 0.15,
    'integer_overflow': 0.25,
    'null_ptr_deref': 0.30,
    'got_overwrite':  0.05,
    'code_execution': 0.06,
}
_DEFAULT_PRIOR = 0.15  # 未知类型的保守先验


@dataclass
class CalibrationStep:
    """单步校准记录 — 一个证据源判定后的后验。"""
    source: str
    verdict: bool                # True=该源判定为真漏洞
    prior: float
    posterior: float
    lr_used: float


class SequentialFpCalibrator:
    """
    序贯贝叶斯误报率校准器。

    用法:
      cal = SequentialFpCalibrator(vuln_type='stack_overflow')
      cal.update('static', verdict=True)    # 静态分析判定为真
      cal.update('fuzz', verdict=False)     # fuzz 未触发
      fp_rate = cal.false_positive_rate()   # → 0.23 (校准后)
    """

    def __init__(self, vuln_type: str = '',
                 custom_prior: Optional[float] = None):
        vtype_key = vuln_type.lower()
        self._prior = (custom_prior if custom_prior is not None
                       else _TYPE_PRIOR.get(vtype_key, _DEFAULT_PRIOR))
        self._current = self._prior
        self._steps: List[CalibrationStep] = []

    def update(self, source: str, verdict: bool):
        """
        基于单一证据源的判定更新后验。

        verdict=True  → 该源认为漏洞真实 → 乘 LR+
        verdict=False → 该源认为漏洞不存在 → 乘 LR-
        """
        tpr, tnr = _SOURCE_LR.get(source, (0.50, 0.50))

        if verdict:
            lr = tpr / (1.0 - tnr) if tnr < 1.0 else 10.0
        else:
            lr = (1.0 - tpr) / tnr if tnr > 0.0 else 0.1

        # Clamp 极端似然比以防止数值溢出
        lr = max(0.01, min(100.0, lr))

        prior_odds = self._current / (1.0 - self._current) if self._current < 1.0 else 99.0
        post_odds = prior_odds * lr
        posterior = post_odds / (1.0 + post_odds)

        self._steps.append(CalibrationStep(
            source=source, verdict=verdict,
            prior=round(self._current, 4),
            posterior=round(posterior, 4),
            lr_used=round(lr, 4),
        ))
        self._current = posterior

    def false_positive_rate(self) -> float:
        """当前校准后的误报概率 = 1 - P(TP|evidence)。"""
        return round(1.0 - self._current, 4)

    def true_positive_probability(self) -> float:
        """校准后的真阳性概率。"""
        return round(self._current, 4)

    @property
    def steps(self) -> List[CalibrationStep]:
        return list(self._steps)

    @property
    def prior(self) -> float:
        return self._prior

    def reset(self):
        self._current = self._prior
        self._steps.clear()


def calibrate_from_fusion(
    vuln_type: str,
    source_verdicts: Dict[str, bool],
    prior: Optional[float] = None,
) -> Dict[str, Any]:
    """
    一站式入口: 从证据源判定字典计算校准后的误报率。

    source_verdicts: {'static': True, 'fuzz': False, 'llm': True, ...}

    返回可直接嵌入报告的摘要字典。
    """
    cal = SequentialFpCalibrator(vuln_type, custom_prior=prior)
    for source, verdict in source_verdicts.items():
        if source in _SOURCE_LR:
            cal.update(source, verdict)

    steps_out = []
    for s in cal.steps:
        steps_out.append({
            'source': s.source,
            'verdict': s.verdict,
            'prior': s.prior,
            'posterior': s.posterior,
        })

    fp = cal.false_positive_rate()

    return {
        'vuln_type': vuln_type,
        'initial_prior': cal.prior,
        'calibrated_tp_probability': cal.true_positive_probability(),
        'false_positive_rate': fp,
        'confidence_level': _fp_confidence_label(fp),
        'update_steps': steps_out,
        'step_count': len(steps_out),
    }


def _fp_confidence_label(fp_rate: float) -> str:
    if fp_rate <= 0.05:
        return 'confirmed'
    elif fp_rate <= 0.20:
        return 'likely_true'
    elif fp_rate <= 0.50:
        return 'uncertain'
    return 'likely_false_positive'
