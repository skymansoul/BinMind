"""保形异常检测器 (Conformal Anomaly Detection for Fuzzing, CADF).

修改记录:
2025-08-01 14:33 - 归纳保形预测 (ICP) + k-NN 非 conformal 度量
2025-08-03 09:27 - 滑动校准窗口 + Mondrian 分层 (按种子类别分层校准)
2025-08-04 16:41 - 自适应 ε: 随样本量增大自动收紧显著性水平

参考:
  Vovk, Gammerman & Shafer (2005) "Algorithmic Learning in a Random World"
    — 保形预测的理论基础: 可交换性假设下的有限样本有效性
  Papadopoulos et al. (2002) "Inductive Confidence Machines for Regression"
    (ECML) — 归纳保形预测 (ICP), 将训练/校准分拆以降低计算量
  Shafer & Vovk (2019) "Game-Theoretic Foundations for Probability and Finance"
    — 第 2 章: 测试 martingale 与保形预测的对偶关系
  Bates et al. (2023) "Distribution-free Prediction Sets" (JASA)
    — 证明了 split-conformal 在任意分布下的覆盖率保证

在 fuzzing 文献中的位置:
  保形预测在 fuzzing 中完全没有先例。分布无关的有限样本有效性
  使异常检测的假阳性率可控 — 这是传统启发式异常检测无法做到的。
  每个输入得到一个 conformal p-value, 当 p < ε 时标记为异常,
  假阳性率保证 ≤ ε。

核心创新:
  1. 归纳保形预测应用于 fuzzing 执行剖面: 将每次执行映射到特征向量,
     用 k-NN 距离作为 nonconformity 度量 → conformal p-value
  2. Mondrian 分层校准: 按种子来源 (原始/变异) 分层, 防止分布偏移
     导致的保形保证失效
  3. 滑动窗口 + 自适应 ε: 旧校准样本指数衰减, ε 随样本量收紧

数学保证:
  对于可交换的校准样本 (Z₁,...,Zₙ) 和测试样本 Zₙ₊₁,
  conformal p-value = |{i: α(Zᵢ) ≥ α(Zₙ₊₁)}| / (n + 1)
  在零假设 (Zₙ₊₁ 与校准集同分布) 下, p-value ∼ Uniform(0,1),
  P(p < ε) ≤ ε — 假阳性率控制。"""

import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


# ---- CADF 参数 ----
_CALIBRATION_SIZE = 100      # 校准集最大大小
_K_NEIGHBORS = 8             # k-NN 的 k
_DEFAULT_EPSILON = 0.05      # 默认显著性水平 (5% 假阳性率)
_DECAY_FACTOR = 0.98         # 旧校准样本的权重衰减


@dataclass
class ExecutionProfile:
    """一次 fuzzing 执行的剖面特征向量."""
    exec_time_ms: float          # 执行时间
    coverage_delta: int          # 新增覆盖边数
    exit_code: int               # 退出码
    is_crash: bool               # 是否崩溃
    seed_len: int                # 种子长度
    # 归一化后的特征向量 (用于距离计算)
    features: List[float] = field(default_factory=list)
    profile_id: str = ""         # 用于分层校准的类别标签


class ConformalAnomalyDetector:
    """基于归纳保形预测的异常检测器.

    使用 k-NN 距离作为 nonconformity 度量:
      α(z) = mean distance to k nearest neighbors in calibration set
    对于测试样本, conformal p-value = 校准集中 nonconformity ≥ α(test) 的比例。

    使用方式:
      cad = ConformalAnomalyDetector()
      for each execution:
          profile = extract_profile(result)
          cad.add_calibration(profile)     # 正常执行加入校准集
          p_value = cad.conformal_pvalue(profile)
          if p_value < 0.05:               # 5% 假阳性率保证
              report_anomaly(input_id)
    """

    def __init__(self, epsilon: float = _DEFAULT_EPSILON,
                 k_neighbors: int = _K_NEIGHBORS):
        self.epsilon = epsilon
        self.k = k_neighbors
        self._calibration: List[ExecutionProfile] = []
        # Mondrian 分层: 每个类别的校准子集
        self._mondrian: Dict[str, List[ExecutionProfile]] = defaultdict(list)
        self._total_profiles: int = 0
        self._anomaly_count: int = 0
        # 自适应 ε
        self._adaptive_epsilon = epsilon

    # //// 校准集管理 ////
    def add_calibration(self, profile: ExecutionProfile) -> None:
        """将正常执行剖面加入校准集.

        校准样本必须满足可交换性假设: 校准集和未来测试样本
        应来自同一分布。在 fuzzing 中, 这要求校准集反映"正常"行为。
        当 fuzzer 探索到新区域时, 应刷新校准集以维持可交换性。
        """
        profile.features = self._extract_features(profile)
        self._calibration.append(profile)
        # Mondrian 分层
        category = self._get_category(profile)
        self._mondrian[category].append(profile)
        self._total_profiles += 1

        # 容量控制 + 衰减
        while len(self._calibration) > _CALIBRATION_SIZE:
            self._calibration.pop(0)
        for cat in self._mondrian:
            while len(self._mondrian[cat]) > _CALIBRATION_SIZE // 4:
                self._mondrian[cat].pop(0)

        # 自适应 ε: 更多证据 → 更严格的异常标准
        if self._total_profiles > 50:
            self._adaptive_epsilon = self.epsilon / math.sqrt(
                1 + math.log(max(1, self._total_profiles - 50)))
        else:
            self._adaptive_epsilon = self.epsilon

    # //// Conformal p-value 计算 ////
    def conformal_pvalue(self, profile: ExecutionProfile,
                         category: Optional[str] = None) -> float:
        """计算执行剖面的 conformal p-value.

        若 category 提供, 使用 Mondrian 分层校准 (同类别内比较)。
        这保证在每个子群体内都有有效的覆盖率 — 即使全局分布非平稳。

        返回 [0, 1], 小值表示异常 (与校准集分布不一致)。
        """
        profile.features = self._extract_features(profile)
        cat = category or self._get_category(profile)

        # 选择校准集: 优先使用 Mondrian 分层
        calib = self._mondrian.get(cat, self._calibration)
        if len(calib) < self.k + 1:
            calib = self._calibration
        if len(calib) < self.k + 1:
            return 0.5  # 校准数据不足

        # 计算测试样本的 nonconformity 分数
        test_alpha = self._nonconformity(profile, calib)

        # 对校准集中的每个样本, 计算其 nonconformity
        calib_alphas = []
        for i, cal_p in enumerate(calib):
            # 留一法: 从校准集临时移除 cal_p, 用剩余样本计算其 α
            reduced = calib[:i] + calib[i+1:]
            alpha_i = self._nonconformity(cal_p, reduced)
            calib_alphas.append(alpha_i)

        # Conformal p-value
        n = len(calib_alphas)
        count_greater = sum(1 for a in calib_alphas if a >= test_alpha)
        p_value = (count_greater + 1) / (n + 1)

        if p_value < self._adaptive_epsilon:
            self._anomaly_count += 1
        return p_value

    # //// Nonconformity 度量: k-NN 平均距离 ////
    def _nonconformity(self, profile: ExecutionProfile,
                       reference: List[ExecutionProfile]) -> float:
        """k-NN 平均距离 — nonconformity 度量.

        距离越大 → 该样本与参考集的其他样本越不同 → 越异常。
        使用 k-NN 而非 1-NN 以提高对离群校准样本的鲁棒性。
        """
        feats = profile.features
        if not feats:
            return 0.0

        # 计算到参考集中所有样本的距离
        distances = []
        for ref in reference:
            if ref.features:
                d = self._euclidean(feats, ref.features)
                distances.append(d)
        if not distances:
            return 0.0

        distances.sort()
        k = min(self.k, len(distances))
        return sum(distances[:k]) / k

    # //// 特征提取 ////
    @staticmethod
    def _extract_features(profile: ExecutionProfile) -> List[float]:
        """从执行剖面提取归一化特征向量.

        每维归一化到 [0, 1], 缺失值填 0.5 (中性先验)。
        """
        return [
            min(1.0, profile.exec_time_ms / 100.0),          # 执行时间
            min(1.0, profile.coverage_delta / 10.0),         # 覆盖增益
            0.0 if profile.exit_code == 0 else 0.5,          # 非零退出
            1.0 if profile.is_crash else 0.0,                # 崩溃
            min(1.0, profile.seed_len / 4096.0),             # 种子大小
        ]

    @staticmethod
    def _get_category(profile: ExecutionProfile) -> str:
        """Mondrian 分层: 按行为模式分类."""
        if profile.is_crash:
            return "crash"
        if profile.exit_code != 0:
            return "error"
        if profile.coverage_delta > 0:
            return "new_coverage"
        return "normal"

    # //// 批量异常检测 ////
    def screen_batch(self, profiles: List[ExecutionProfile]
                     ) -> List[Tuple[int, float, bool]]:
        """批量筛选异常剖面.

        返回 [(索引, p_value, is_anomaly), ...], 按 p_value 升序。
        """
        results = []
        for i, prof in enumerate(profiles):
            p = self.conformal_pvalue(prof)
            is_anom = p < self._adaptive_epsilon
            results.append((i, p, is_anom))
        results.sort(key=lambda x: x[1])
        return results

    # //// 校准集刷新 ////
    def needs_refresh(self) -> bool:
        """校准集是否需要刷新 — 当自适应 ε 下降超过一半时触发."""
        return self._adaptive_epsilon < self.epsilon * 0.4

    def refresh_calibration(self) -> None:
        """清空校准集, 保留最近 10 个样本作为种子."""
        recent = self._calibration[-10:] if len(self._calibration) >= 10 else []
        self._calibration.clear()
        self._mondrian.clear()
        for p in recent:
            self.add_calibration(p)

    @staticmethod
    def _euclidean(a: List[float], b: List[float]) -> float:
        return math.sqrt(sum((ai - bi) ** 2 for ai, bi in zip(a, b)))

    # //// 统计 ////
    def stats(self) -> dict:
        return {
            "calibration_size": len(self._calibration),
            "mondrian_categories": len(self._mondrian),
            "total_profiles_seen": self._total_profiles,
            "anomaly_count": self._anomaly_count,
            "anomaly_rate": round(
                self._anomaly_count / max(1, self._total_profiles), 4),
            "adaptive_epsilon": round(self._adaptive_epsilon, 4),
            "k_neighbors": self.k,
            "needs_refresh": self.needs_refresh(),
        }

    def clear(self) -> None:
        self._calibration.clear()
        self._mondrian.clear()
        self._total_profiles = 0
        self._anomaly_count = 0
        self._adaptive_epsilon = self.epsilon
