# 修改记录:
# 2025-08-04 11:36 - 初始实现：基于模态感知非一致性得分的分布式保形预测

"""多模态保形集成 — 模态缺失感知的分布式保形预测。

将标准保形预测 扩展到模态可缺失的多模态场景。
核心是双层校准 + Bonferroni 交集策略：

模态层校准：每模态独立维护校准分数分位数门限。
交叉层：追踪各模态子集的历史经验覆盖率，缺失模态回退至全集。
门限修正：α_mod = α / M（Bonferroni），保证联合覆盖 ≥ 1-α 对任意模态子集成立。

与 Bos et al.  的区别：
他们的方法假设至少两视图可用且均质；本方案处理任意 1..M 模态子集，
缺失模态产生最大预测集（无区分力但不引入风险），
有效模态的 Bonferroni 门限自动收紧以补偿。

参考：Angelopoulos & Bates, Barber et al. AOS,
      Bose et al. arXiv 2410.19653.
"""

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

_EPS: float = 1e-9

@dataclass
class ModalConformalResult:
    """单个模态的保形预测结果。"""
    prediction_set: List[int] = field(default_factory=list)
    p_values: List[float] = field(default_factory=list)
    threshold: float = 0.0
    modal_name: str = ""
    is_missing: bool = False  # 模态在预测时是否缺失

@dataclass
class MultimodalConformalResult:
    """多模态保形集成输出。"""
    # 交集预测集（最保守但覆盖保证最强）
    intersection_set: List[int] = field(default_factory=list)
    # 并集预测集（最宽松但覆盖最全）
    union_set: List[int] = field(default_factory=list)
    # 加权多数投票结果
    majority_set: List[int] = field(default_factory=list)
    # 各模态的单独结果（审计用）
    per_modal_results: Dict[str, ModalConformalResult] = field(
        default_factory=dict
    )
    # 覆盖保证水平
    guaranteed_coverage: float = 0.0
    # 有效模态数
    active_modalities: int = 0

class MultimodalConformalPredictor:
    """模态感知的分布式保形预测器。

    使用范式：
      mcp = MultimodalConformalPredictor(n_classes=5, alpha=0.1)
      for modal_name, cal_scores, cal_labels in calibration_data:
          mcp.calibrate_modal(modal_name, cal_scores, cal_labels)
      result = mcp.predict(
          test_scores={"static": scores_s, "dynamic": scores_d},
          available_modalities={"static", "dynamic"},
      )
    """

    def __init__(
        self,
        n_classes: int = 2,
        alpha: float = 0.1,
        modality_names: Optional[List[str]] = None,
        bonferroni_correction: bool = True,
        coverage_history_window: int = 50,
    ):
        """
        n_classes: 分类类别数。
        alpha: 全局错误率（如 0.1 对应 90% 置信）。
        modality_names: 已知模态名单。
        bonferroni_correction: 是否使用 Bonferroni 校正。
                               True → 更严格的单模态门限，更保守但覆盖保证更强。
        coverage_history_window: 覆盖率历史追踪窗口大小。
        """
        self.n_classes = n_classes
        self.alpha = alpha
        self.bonferroni_correction = bonferroni_correction
        self.modality_names = modality_names or []

        # 每模态校准分数
        self._cal_scores: Dict[str, List[float]] = {}
        self._cal_labels: Dict[str, List[int]] = {}
        # 每模态分位数阈值
        self._thresholds: Dict[str, float] = {}
        # 覆盖率追踪
        self._coverage_history: Dict[FrozenSet[str], List[float]] = defaultdict(list)
        self._coverage_window = coverage_history_window
        # 预测历史记录数
        self._prediction_count: int = 0

    def calibrate_modal(
        self,
        modal_name: str,
        calibration_scores: List[float],
        calibration_labels: List[int],
    ):
        """校准单个模态的分数分布。

        calibration_scores: 非一致性分数——越低越好（代表预测与真实一致）。
        calibration_labels: 对应真实标签（仅用于经验覆盖审计，不参与分位数计算）。
        """
        if modal_name not in self.modality_names:
            self.modality_names.append(modal_name)

        self._cal_scores[modal_name] = list(calibration_scores)
        self._cal_labels[modal_name] = list(calibration_labels)

        _n = len(calibration_scores)
        if _n < 5:
            self._thresholds[modal_name] = float("inf")
            return

        # 分位数含有限样本修正：q_idx = ceil((1-α_mod)*(n+1)) - 1
        _alpha_mod = self._per_modal_alpha()
        _sorted = sorted(calibration_scores)
        _q_idx = min(
            math.ceil((1.0 - _alpha_mod) * (_n + 1)) - 1,
            _n - 1,
        )
        _q_idx = max(0, _q_idx)
        self._thresholds[modal_name] = _sorted[_q_idx]

    def predict(
        self,
        test_scores: Dict[str, List[float]],
        available_modalities: Optional[Set[str]] = None,
        calibration_fallback: bool = True,
    ) -> MultimodalConformalResult:
        """对多模态测试样本进行保形预测。

        test_scores: {modal_name: [score_per_class]}。
        available_modalities: 测试时可用的模态集合。
                             未提供时使用 test_scores 的所有键。
        calibration_fallback: 未校准模态是否回退至全局门限。
        """
        self._prediction_count += 1

        _avail = available_modalities or set(test_scores.keys())
        _active_count = len(_avail)

        if _active_count == 0:
            return MultimodalConformalResult(
                intersection_set=list(range(self.n_classes)),
                union_set=list(range(self.n_classes)),
                majority_set=list(range(self.n_classes)),
                guaranteed_coverage=0.0,
                active_modalities=0,
            )

        _per_modal: Dict[str, ModalConformalResult] = {}
        _all_pred_sets: List[Set[int]] = []

        for _name in self.modality_names:
            _is_missing = _name not in _avail or _name not in test_scores

            if _is_missing:
                # 缺失模态：预测集 = 全集
                _full_set = list(range(self.n_classes))
                _per_modal[_name] = ModalConformalResult(
                    prediction_set=_full_set,
                    p_values=[self.alpha] * self.n_classes,
                    threshold=0.0,
                    modal_name=_name,
                    is_missing=True,
                )
                _all_pred_sets.append(set(_full_set))
                continue

            _scores = test_scores[_name]
            _threshold = self._thresholds.get(_name)

            if _threshold is None or _threshold == float("inf"):
                if calibration_fallback:
                    _threshold = self._global_threshold()
                else:
                    _full_set = list(range(self.n_classes))
                    _per_modal[_name] = ModalConformalResult(
                        prediction_set=_full_set,
                        p_values=[0.5] * self.n_classes,
                        threshold=0.0,
                        modal_name=_name,
                    )
                    _all_pred_sets.append(set(_full_set))
                    continue

            # 构造预测集：{y: score(x, y) ≤ threshold}
            _pred_set: List[int] = []
            _p_vals: List[float] = []
            _cal_scores_for_modal = self._cal_scores.get(_name, [])
            _n_cal = len(_cal_scores_for_modal)

            for _y in range(self.n_classes):
                _score_y = (
                    _scores[_y] if _y < len(_scores) else float("inf")
                )
                if _n_cal > 0:
                    _p_val = (
                        sum(1 for s in _cal_scores_for_modal if s >= _score_y) + 1
                    ) / (_n_cal + 1)
                else:
                    _p_val = 0.5
                _p_vals.append(round(_p_val, 4))
                if _score_y <= _threshold:
                    _pred_set.append(_y)

            _per_modal[_name] = ModalConformalResult(
                prediction_set=_pred_set,
                p_values=_p_vals,
                threshold=round(_threshold, 4),
                modal_name=_name,
            )
            _all_pred_sets.append(set(_pred_set))

        # 三路聚合
        if _all_pred_sets:
            _intersection = set.intersection(*_all_pred_sets)
            # 空交集 → 回退到最小预测集
            if not _intersection and _all_pred_sets:
                _intersection = min(_all_pred_sets, key=len)
            _union = set.union(*_all_pred_sets)
        else:
            _intersection = set()
            _union = set()

        # 多数投票
        _majority = self._majority_vote(_per_modal)

        # 覆盖保证：交集策略 + Bonferroni → P(covered) ≥ 1 - K*α_mod
        _k = sum(
            1 for r in _per_modal.values() if not r.is_missing
        )
        _guaranteed_coverage = max(
            0.0, 1.0 - _k * self._per_modal_alpha()
        )

        _result = MultimodalConformalResult(
            intersection_set=sorted(_intersection),
            union_set=sorted(_union),
            majority_set=sorted(_majority),
            per_modal_results=_per_modal,
            guaranteed_coverage=round(_guaranteed_coverage, 4),
            active_modalities=_k,
        )

        # 追踪覆盖率历史
        _avail_key = frozenset(
            n for n, r in _per_modal.items() if not r.is_missing
        )
        self._coverage_history[_avail_key].append(_guaranteed_coverage)
        if len(self._coverage_history[_avail_key]) > self._coverage_window:
            self._coverage_history[_avail_key] = self._coverage_history[
                _avail_key
            ][-self._coverage_window :]

        return _result

    def get_modal_coverage_empirical(
        self, modal_subset: Optional[Set[str]] = None
    ) -> Optional[float]:
        """返回特定模态子集的经验覆盖率均值。

        若未指定子集，返回全模态的覆盖率。
        """
        if modal_subset is None:
            _key = frozenset(self.modality_names)
        else:
            _key = frozenset(modal_subset)

        _hist = self._coverage_history.get(_key, [])
        if not _hist:
            return None
        return sum(_hist) / len(_hist)

    def adaptive_alpha_reallocate(
        self, empirical_coverages: Dict[str, float]
    ):
        """基于经验覆盖率自适应重分配 α。

        覆盖率高的模态可以接受更宽松的 α（释放更大的预测集），
        覆盖率低的模态收紧 α（更小的预测集以减少风险）。
        此方法应在积累足够预测历史后周期性调用。
        """
        _total_modals = len(self.modality_names)
        if _total_modals < 2:
            return

        _total_budget = self.alpha * _total_modals  # Bonferroni 拆分前的总预算

        # 覆盖率越低 → α 越小 → 更保守
        _mean_cov = sum(empirical_coverages.values()) / max(
            len(empirical_coverages), 1
        )
        _new_alphas: Dict[str, float] = {}
        for _name in self.modality_names:
            _cov = empirical_coverages.get(_name, _mean_cov)
            # 距离目标覆盖率 (1-α) 的偏差 → 调节 α
            _target_cov = 1.0 - self.alpha
            _deviation = _cov - _target_cov
            _adj = _deviation * 0.5  # 温和调节
            _new_alpha_mod = self._per_modal_alpha() - _adj
            _new_alphas[_name] = max(0.01, min(0.3, _new_alpha_mod))

        # 重归一化：确保总和不超过总预算
        _sum_new = sum(_new_alphas.values())
        if _sum_new > _EPS:
            _scale = _total_budget / _sum_new
            for _name in _new_alphas:
                _new_alphas[_name] *= _scale

        self._custom_modality_alphas = _new_alphas

    # 内部方法

    def _per_modal_alpha(self) -> float:
        """单模态的错误率预算。

        Bonferroni 校正：α_mod = α / M。
        无 Bonferroni：α_mod = α（更宽松但联合覆盖保证较弱）。
        """
        if hasattr(self, "_custom_modality_alphas"):
            # 使用自适应分配的值
            _avail_alphas = list(self._custom_modality_alphas.values())
            if _avail_alphas:
                return sum(_avail_alphas) / len(_avail_alphas)

        if self.bonferroni_correction:
            _m = max(len(self.modality_names), 1)
            return self.alpha / _m
        return self.alpha

    def _global_threshold(self) -> float:
        """跨模态全局分数门限（未校准模态的保守回退）。"""
        _all_scores: List[float] = []
        for _scores in self._cal_scores.values():
            _all_scores.extend(_scores)
        if len(_all_scores) < 5:
            return float("inf")
        _sorted = sorted(_all_scores)
        _q_idx = int((1.0 - self.alpha) * (len(_all_scores) + 1))
        _q_idx = min(_q_idx, len(_all_scores) - 1)
        return _sorted[_q_idx]

    def _majority_vote(
        self, per_modal: Dict[str, ModalConformalResult]
    ) -> Set[int]:
        """模态间多数投票：被超过半数模态预测集包含的类别。"""
        _vote_counts: Dict[int, int] = defaultdict(int)
        _active_count = 0
        for _r in per_modal.values():
            if not _r.is_missing:
                _active_count += 1
                for _y in _r.prediction_set:
                    _vote_counts[_y] += 1

        if _active_count == 0:
            return set(range(self.n_classes))

        _threshold = max(1, _active_count // 2 + 1)
        return {y for y, c in _vote_counts.items() if c >= _threshold}

def multimodal_conformal_predict(
    test_scores: Dict[str, List[float]],
    calibrators: Dict[str, Tuple[List[float], List[int]]],
    n_classes: int,
    alpha: float = 0.1,
    available_modalities: Optional[Set[str]] = None,
) -> MultimodalConformalResult:
    """多模态保形预测的便捷函数接口。

    calibrators: {modal_name: (cal_scores, cal_labels)}。
    """
    _mcp = MultimodalConformalPredictor(
        n_classes=n_classes, alpha=alpha,
        modality_names=list(calibrators.keys()),
    )
    for _name, (_scores, _labels) in calibrators.items():
        _mcp.calibrate_modal(_name, _scores, _labels)
    return _mcp.predict(test_scores, available_modalities)

# 冒烟测试
def _smoke_test():
    import random
    random.seed(42)

    _n_classes = 5
    _alpha = 0.1
    _modals = ["static", "dynamic", "symbolic"]

    _mcp = MultimodalConformalPredictor(
        n_classes=_n_classes, alpha=_alpha, modality_names=_modals,
    )

    # 校准各模态
    for _name in _modals:
        _cal_scores = [random.random() for _ in range(50)]
        _cal_labels = [random.randint(0, _n_classes - 1) for _ in range(50)]
        _mcp.calibrate_modal(_name, _cal_scores, _cal_labels)

    # 全模态预测
    _test_scores_full = {
        _name: [random.random() for _ in range(_n_classes)] for _name in _modals
    }
    _result_full = _mcp.predict(_test_scores_full)

    print(f"[conf_mm] full modalities:")
    print(f"  intersection_set: {_result_full.intersection_set}")
    print(f"  union_set: {_result_full.union_set}")
    print(f"  guaranteed_coverage: {_result_full.guaranteed_coverage}")

    # 部分模态缺失
    _result_partial = _mcp.predict(
        _test_scores_full,
        available_modalities={"static", "dynamic"},
    )
    print(f"[conf_mm] partial modalities (2/3): intersection={_result_partial.intersection_set}")
    for _nm, _r in _result_partial.per_modal_results.items():
        _tag = " [MISSING]" if _r.is_missing else ""
        print(f"  {_nm}{_tag}: pred_set_size={len(_r.prediction_set)}")

    # 验证缺失模态产生全集
    _sym_result = _result_partial.per_modal_results.get("symbolic")
    assert _sym_result is not None and _sym_result.is_missing, (
        "symbolic should be missing"
    )
    assert len(_sym_result.prediction_set) == _n_classes, (
        "missing modal should produce full set"
    )
    assert _result_full.guaranteed_coverage > 0.7, (
        f"coverage guarantee too low: {_result_full.guaranteed_coverage}"
    )

    print("[OK] MultimodalConformalPredictor smoke test passed.")

if __name__ == "__main__":
    _smoke_test()
