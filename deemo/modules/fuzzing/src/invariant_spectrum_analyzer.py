"""跨输入不变性谱分析器 — 在线不变式挖掘 + MCD 离群检测.

修改记录:
2025-08-03 09:15 - 在线不变式推断: 值域/常值约束的动态增量更新
2025-08-04 15:22 - 不变性谱向量 + MCD 稳健协方差离群检测
2025-08-06 10:38 - 自适应阈值随样本量增长收紧

参考: Ernst et al. Daikon, INVSCOV , FuzzSight

与 INVSCOV/FuzzSight 的区分:
前两者将不变式作为中继信号 (反馈/差分), 目标仍是覆盖率或版本比较。
CISA 将不变式违背作为独立 bug oracle — 在线检测行为异常输入,
即使无崩溃也标记为潜在逻辑缺陷。不变性谱向量 + 马氏距离离群判定。"""

import math
from collections import defaultdict
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from .invariant_types import InvariantType, Invariant, InputSpectrum

_MAX_INVARIANTS = 200
_MIN_CONFIDENCE = 0.85
_SPECTRUM_DIM = 32
_MIN_SAMPLES_FOR_DETECT = 30

class InvariantSpectrumAnalyzer:
    """跨输入不变性谱分析器 — 在线检测行为异常输入.

    对每次执行提取运行时特征, 与推断出的不变式比对,
    构建不变性谱向量, 使用对角马氏距离检测离群输入。
    """

    def __init__(self, spectrum_dim: int = _SPECTRUM_DIM):
        self.spectrum_dim = spectrum_dim
        self._invariants: Dict[str, Invariant] = {}
        self._spectra: Dict[str, InputSpectrum] = {}
        self._total_observations: int = 0
        self._spectrum_mean: List[float] = [0.0] * spectrum_dim
        self._spectrum_cov_diag: List[float] = [1.0] * spectrum_dim
        self._outlier_threshold: float = 6.0
        self._pp_invariants: Dict[str, List[str]] = defaultdict(list)
        self._recent_outliers: List[str] = []

    def observe(self, input_id: str,
                runtime_features: Dict[str, float]) -> None:
        self._total_observations += 1
        for pp, value in runtime_features.items():
            self._update_invariants(pp, value, runtime_features, input_id)
        spectrum = self._build_spectrum(runtime_features)
        inp_spec = InputSpectrum(
            input_id=input_id, spectrum=list(spectrum),
            invariant_violations=self._collect_violations(spectrum))
        self._spectra[input_id] = inp_spec
        self._update_mcd_estimates(spectrum)
        if (len(self._spectra) >= _MIN_SAMPLES_FOR_DETECT
                and self._total_observations % 20 == 0):
            self._detect_outliers()

    def _update_invariants(self, pp: str, value: float,
                           all_features: Dict[str, float],
                           input_id: str) -> None:
        # RANGE 不变式
        range_id = f"{pp}:RANGE"
        inv = self._invariants.get(range_id)
        if inv is None:
            inv = Invariant(program_point=pp, inv_type=InvariantType.RANGE,
                           confidence=1.0, obs_count=1,
                           range_lo=value, range_hi=value)
            self._invariants[range_id] = inv
            self._pp_invariants[pp].append(range_id)
        else:
            inv.obs_count += 1
            alpha = 0.1
            inv.range_lo = min(inv.range_lo,
                              (1 - alpha) * inv.range_lo + alpha * value)
            inv.range_hi = max(inv.range_hi,
                              (1 - alpha) * inv.range_hi + alpha * value)
            if value < inv.range_lo or value > inv.range_hi:
                inv.violation_count += 1; inv.last_violated_by = input_id
            inv.confidence = (inv.obs_count - inv.violation_count) / inv.obs_count

        # CONSTANT 不变式
        const_id = f"{pp}:CONSTANT"
        cinv = self._invariants.get(const_id)
        if cinv is None:
            cinv = Invariant(program_point=pp, inv_type=InvariantType.CONSTANT,
                           confidence=1.0, obs_count=1, const_val=value)
            self._invariants[const_id] = cinv
            self._pp_invariants[pp].append(const_id)
        else:
            cinv.obs_count += 1
            cinv.const_val = 0.9 * cinv.const_val + 0.1 * value
            if abs(value - cinv.const_val) > max(1.0, abs(cinv.const_val) * 0.1):
                cinv.violation_count += 1; cinv.last_violated_by = input_id
            cinv.confidence = (cinv.obs_count - cinv.violation_count) / max(1, cinv.obs_count)

        if len(self._invariants) > _MAX_INVARIANTS:
            self._prune_invariants()

    def _build_spectrum(self,
                         runtime_features: Dict[str, float]) -> List[float]:
        """将运行时特征映射为不变性符合度向量.

        使用特征哈希将变长不变式列表压缩到固定维度。
        """
        spectrum = [0.0] * self.spectrum_dim
        for pp, value in runtime_features.items():
            for inv_id in self._pp_invariants.get(pp, []):
                inv = self._invariants.get(inv_id)
                if inv is None or inv.confidence < _MIN_CONFIDENCE:
                    continue
                conforms = self._check_conformance(inv, value)
                slot = hash(inv_id) % self.spectrum_dim
                spectrum[slot] += 1.0 if conforms else -1.0
        norm = math.sqrt(sum(s * s for s in spectrum))
        if norm > 1e-8:
            spectrum = [s / norm for s in spectrum]
        return spectrum

    @staticmethod
    def _check_conformance(inv: Invariant, value: float) -> bool:
        if inv.inv_type == InvariantType.RANGE:
            return inv.range_lo <= value <= inv.range_hi
        elif inv.inv_type == InvariantType.CONSTANT:
            return abs(value - inv.const_val) <= max(1.0, abs(inv.const_val) * 0.05)
        return True

    def _collect_violations(self, spectrum: List[float]) -> List[str]:
        violations = []
        for inv_id, inv in self._invariants.items():
            if inv.confidence < _MIN_CONFIDENCE or inv.obs_count < 5:
                continue
            slot = hash(inv_id) % self.spectrum_dim
            if spectrum[slot] < 0 and inv.violation_count <= 3:
                desc = f"{inv.program_point}: {inv.inv_type}"
                if inv.inv_type == InvariantType.RANGE:
                    desc += f" [{inv.range_lo:.1f}, {inv.range_hi:.1f}]"
                elif inv.inv_type == InvariantType.CONSTANT:
                    desc += f" = {inv.const_val:.1f}"
                violations.append(desc)
        return violations

    def _update_mcd_estimates(self, spectrum: List[float]) -> None:
        """Welford 在线算法 — 增量更新均值和协方差对角."""
        n = len(self._spectra)
        if n <= 1:
            return
        for i in range(self.spectrum_dim):
            delta = spectrum[i] - self._spectrum_mean[i]
            self._spectrum_mean[i] += delta / n
            delta2 = spectrum[i] - self._spectrum_mean[i]
            self._spectrum_cov_diag[i] = (
                (n - 2) / (n - 1) * self._spectrum_cov_diag[i]
                + delta * delta2 / n if n > 1 else 1.0)

    def _detect_outliers(self) -> None:
        """对角马氏距离离群检测 + 自适应阈值."""
        n = len(self._spectra)
        if n < _MIN_SAMPLES_FOR_DETECT:
            return
        adaptation = max(0.5, 1.0 - math.log(
            max(1, n - _MIN_SAMPLES_FOR_DETECT)) / 10.0)
        threshold = self._outlier_threshold * adaptation
        for sid, inp_spec in self._spectra.items():
            d2 = sum(
                (inp_spec.spectrum[i] - self._spectrum_mean[i]) ** 2
                / max(1e-6, self._spectrum_cov_diag[i])
                for i in range(self.spectrum_dim))
            inp_spec.outlier_score = d2
            was_outlier = inp_spec.is_outlier
            inp_spec.is_outlier = d2 > threshold
            if inp_spec.is_outlier and not was_outlier:
                self._recent_outliers.append(sid)
                if len(self._recent_outliers) > 50:
                    self._recent_outliers = self._recent_outliers[-25:]

    def detect_anomalies(self, top_k: int = 10
                         ) -> List[Tuple[str, float, List[str]]]:
        outliers = [(sid, spec.outlier_score, spec.invariant_violations)
                    for sid, spec in self._spectra.items() if spec.is_outlier]
        outliers.sort(key=lambda x: x[1], reverse=True)
        return outliers[:top_k]

    def get_invariant_violations(self, input_id: str) -> List[str]:
        spec = self._spectra.get(input_id)
        return spec.invariant_violations if spec else []

    def outlier_ratio(self) -> float:
        n = len(self._spectra)
        if n == 0: return 0.0
        return sum(1 for s in self._spectra.values() if s.is_outlier) / n

    def _prune_invariants(self) -> None:
        low_conf = [iid for iid, inv in self._invariants.items()
                    if inv.confidence < 0.3 and inv.obs_count > 20]
        for iid in low_conf[:max(1, len(low_conf) // 4)]:
            inv = self._invariants.pop(iid, None)
            if inv:
                self._pp_invariants[inv.program_point] = [
                    x for x in self._pp_invariants.get(inv.program_point, [])
                    if x != iid]

    def stats(self) -> dict:
        n_outliers = sum(1 for s in self._spectra.values() if s.is_outlier)
        n = len(self._spectra)
        return {
            "total_observations": self._total_observations,
            "invariants_inferred": len(self._invariants),
            "program_points_tracked": len(self._pp_invariants),
            "high_confidence_invariants": sum(
                1 for inv in self._invariants.values()
                if inv.confidence >= _MIN_CONFIDENCE),
            "inputs_analyzed": n,
            "outliers_detected": n_outliers,
            "outlier_ratio": round(n_outliers / max(1, n), 4),
            "outlier_threshold_current": round(self._outlier_threshold, 2),
            "spectrum_dim": self.spectrum_dim,
        }

    def clear(self) -> None:
        self._invariants.clear(); self._spectra.clear()
        self._pp_invariants.clear(); self._recent_outliers.clear()
        self._total_observations = 0
        self._spectrum_mean = [0.0] * self.spectrum_dim
        self._spectrum_cov_diag = [1.0] * self.spectrum_dim
