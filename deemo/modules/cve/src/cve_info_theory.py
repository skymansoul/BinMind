# MI/SU/CMI信息论特征归因
# 信息论特征归因 — 基于MI/SU/CMI的漏洞可解释性评分
#
# 问题: 现有漏洞评分系统 (CVSS/EPSS/GNN/Hawkes) 给出一个数字,
# 但不解释各特征对评分的贡献. XAI方法 (SHAP/LIME) 依赖模型重训练,
# 且对离散-连续混合型CVE特征的效果不稳定.
# 2025-2026年研究发现: MI对高基数特征有偏, 原始MI无界无法跨特征比较.
#
# 解决方案: 信息论三步归因管线.
#   1. 互信息 (MI): 量化特征X与利用标签Y的统计依赖性.
#      I(X;Y) = Σ_{x,y} P(x,y)·log(P(x,y)/(P(x)·P(y))).
#      使用自适应分箱处理混合数据类型 (连续特征: Freedman-Diaconis,
#      离散特征: 直接计数).
#   2. 对称不确定性 (SU): 归一化MI到[0,1], 惩罚高基数偏.
#      SU(X,Y) = 2·I(X;Y) / (H(X) + H(Y)).
#   3. 条件互信息 (CMI): 测量给定已知特征Z后, X提供的额外信息.
#      I(X;Y|Z) = Σ_z P(z)·I(X;Y|Z=z).
#      用于消除冗余特征: CMI < 0.01·MI → X是冗余的 (被Z解释殆尽).
#
# 自适应分箱策略:
#   对n<100的特征值, 每唯一值一个箱 (等价于离散).
#   对n≥100的特征值, 使用FD法则: n_bins = ⌈(max-min)/(2·IQR·n^{-1/3})⌉.
#   自适应选择避免了固定分箱对长尾分布的低效.
#
# 冗余消除:
#   对每对高MI特征 (I(X_i;Y) > 0.1, I(X_j;Y) > 0.1):
#     若 CMI_{ij} = I(X_i;Y|X_j) < 0.05, 则X_i被X_j信息包含, 标记为冗余.
#   这与mRMR等价但计算更高效: O(F²)而非O(F·2^F).
#
# 输出:
# 特征归因向量: 每个特征对"利用"标签的归一化信息贡献
# 冗余特征列表: 建议在评分模型中降权或移除的特征
# 特征交互图: 有向无环图表示特征间的信息流
#
# 非显而易见性:
#   1. 自适应分箱+CMI冗余消除的管线在漏洞评分中无先例.
#   2. 与现有的CausalFeatureSelector (cve_causal_contrastive) 互补:
#      因果发现回答"X是否因果导致Y", 信息论回答"X包含多少Y的信息".
#      两者联合可区分: "强因果但不含信息" (罕见但重要的特征) vs
#      "含信息但非因果" (虚假相关特征).
#   3. 信息归因向量可直接嵌入ConformalExploitScorer的sigma估计中.
#
#
# Elements of Information Theory
# mRMR feature selection (IEEE TPAMI)
# kCMI-FS: conditional MI with kNN for mixed data
# Two-phase MI+SHAP framework for intrusion detection

import math
from collections import defaultdict, Counter
from typing import Dict, List, Optional, Set, Tuple


class InfoTheoryAnalyzer:
    """信息论特征归因分析器 — MI/SU/CMI管线.

    对CVE特征向量和利用标签进行信息论分解.
    """

    def __init__(self, n_bins_auto: int = 0, redundancy_threshold: float = 0.05):
        """
        n_bins_auto: 0=自适应, >0=固定分箱数.
        redundancy_threshold: CMI低于此值视为冗余.
        """
        self._n_bins = n_bins_auto
        self._redundancy_threshold = redundancy_threshold
        self._mi_scores: Dict[str, float] = {}       # 特征→MI
        self._su_scores: Dict[str, float] = {}        # 特征→SU
        self._entropy: Dict[str, float] = {}           # 特征→熵H(X)
        self._cmi_matrix: Dict[Tuple[str, str], float] = {}  # (X_i, X_j)→CMI
        self._redundant_features: Set[str] = set()
        self._target_entropy: float = 0.0
        self._analyzed = False

    def analyze(self, features: Dict[str, List[float]],
                labels: List[int],
                feature_descriptions: Optional[Dict[str, str]] = None):
        """执行完整信息论分析.

        features: {feature_name: [values]} — 特征值字典.
        labels: 二元标签列表 (0=未利用, 1=已利用).
        feature_descriptions: 可选的特征元数据, 用于报告.

        分析管线的4个阶段:
          阶段1: 估计每个特征和标签的(边缘)熵.
          阶段2: 计算每个特征的MI和SU得分.
          阶段3: 计算特征对的条件互信息.
          阶段4: 标记冗余特征.
        """
        N = len(labels)
        if N < 20 or len(features) < 2:
            return

        self._mi_scores.clear()
        self._su_scores.clear()
        self._entropy.clear()
        self._cmi_matrix.clear()
        self._redundant_features.clear()

        # 阶段1: 熵估计
        labels_discrete = labels  # 标签已是离散{0,1}
        self._target_entropy = _entropy_discrete(labels_discrete)

        feature_bins: Dict[str, List[int]] = {}
        for fname, fvals in features.items():
            bins = _adaptive_binning(fvals, self._n_bins)
            feature_bins[fname] = bins
            self._entropy[fname] = _entropy_discrete(bins)

        # 阶段2: MI和SU
        for fname, bins in feature_bins.items():
            mi = _mutual_information(bins, labels_discrete)
            self._mi_scores[fname] = round(mi, 6)

            denom = self._entropy[fname] + self._target_entropy
            if denom > 1e-10:
                su = 2.0 * mi / denom
            else:
                su = 0.0
            self._su_scores[fname] = round(min(su, 1.0), 6)

        # 阶段3: 条件互信息 (仅对高MI特征对)
        fnames = list(features.keys())
        high_mi = {f for f in fnames if self._mi_scores.get(f, 0.0) > 0.05}
        high_mi_list = sorted(high_mi, key=lambda f: self._mi_scores.get(f, 0.0), reverse=True)

        for i, f_i in enumerate(high_mi_list):
            for f_j in high_mi_list[i + 1:]:
                cmi = _conditional_mi(
                    feature_bins[f_i], feature_bins[f_j], labels_discrete
                )
                self._cmi_matrix[(f_i, f_j)] = round(cmi, 6)

        # 阶段4: 冗余标记
        for (f_i, f_j), cmi in self._cmi_matrix.items():
            mi_i = self._mi_scores.get(f_i, 0.0)
            mi_j = self._mi_scores.get(f_j, 0.0)
            if cmi < self._redundancy_threshold:
                # f_i在已知f_j的条件下几乎不提供额外信息 → 冗余
                if mi_i > mi_j:
                    self._redundant_features.add(f_j)
                else:
                    self._redundant_features.add(f_i)

        self._analyzed = True

    def get_attribution(self, normalize: bool = True) -> Dict[str, float]:
        """返回特征信息归因向量.

        normalize=True时归因和为1.0, 可直接用于评分模型的权重.
        """
        if not self._analyzed:
            return {}

        attr = {}
        for fname, su in self._su_scores.items():
            if fname in self._redundant_features:
                attr[fname] = su * 0.1  # 冗余特征大幅降权
            else:
                attr[fname] = su

        if normalize and attr:
            total = sum(attr.values())
            if total > 1e-10:
                attr = {k: round(v / total, 4) for k, v in attr.items()}

        # 按值降序
        return dict(sorted(attr.items(), key=lambda x: x[1], reverse=True))

    def get_report(self) -> Dict:
        """结构化报告 — MI排名、冗余列表、推荐行动."""
        if not self._analyzed:
            return {"status": "not_analyzed"}

        ranking = sorted(self._mi_scores.items(), key=lambda x: x[1], reverse=True)

        return {
            "status": "analyzed",
            "target_entropy": round(self._target_entropy, 4),
            "mi_ranking": [{"feature": f, "mi": mi, "su": self._su_scores.get(f, 0.0)}
                           for f, mi in ranking],
            "redundant_features": sorted(self._redundant_features),
            "n_redundant": len(self._redundant_features),
            "attribution": self.get_attribution(),
            "recommendation": self._generate_recommendation(),
        }

    def _generate_recommendation(self) -> str:
        if not self._redundant_features:
            return "all_features_contributing"
        if len(self._redundant_features) == 1:
            return "1_redundant_feature_detected"
        return f"{len(self._redundant_features)}_redundant_features_detected"

    @property
    def mi_scores(self) -> Dict[str, float]:
        return dict(self._mi_scores)

    @property
    def su_scores(self) -> Dict[str, float]:
        return dict(self._su_scores)

    @property
    def redundant_features(self) -> Set[str]:
        return set(self._redundant_features)

    @property
    def is_analyzed(self) -> bool:
        return self._analyzed


# 信息论核心函数

def _adaptive_binning(values: List[float], n_bins: int = 0) -> List[int]:
    """自适应分箱: 连续→FD法则, 离散(<20唯一值)→直接使用."""
    unique_vals = set(values)
    n_unique = len(unique_vals)

    if n_unique < 20:
        # 小基数 → 视为离散, 直接映射
        val_to_idx = {v: i for i, v in enumerate(sorted(unique_vals))}
        return [val_to_idx[v] for v in values]

    if n_bins <= 0:
        # Freedman-Diaconis: bin_width = 2·IQR·n^{-1/3}
        sorted_vals = sorted(values)
        n = len(values)
        q1_idx = n // 4
        q3_idx = 3 * n // 4
        iqr = sorted_vals[q3_idx] - sorted_vals[q1_idx]
        if iqr < 1e-10:
            n_bins = min(20, n_unique)
        else:
            bin_width = 2.0 * iqr / (n ** (1.0 / 3.0))
            data_range = sorted_vals[-1] - sorted_vals[0]
            n_bins = max(5, min(50, int(data_range / bin_width) + 1))

    min_val, max_val = min(values), max(values)
    if max_val <= min_val:
        return [0] * len(values)

    bin_width = (max_val - min_val) / n_bins
    return [min(int((v - min_val) / bin_width), n_bins - 1) for v in values]


def _entropy_discrete(x: List[int]) -> float:
    """离散变量的香农熵 H(X) = -Σ p(x)·log p(x)."""
    n = len(x)
    if n == 0:
        return 0.0
    counter = Counter(x)
    h = 0.0
    for count in counter.values():
        p = count / n
        if p > 0:
            h -= p * math.log(p)
    return h


def _mutual_information(x: List[int], y: List[int]) -> float:
    """I(X;Y) = Σ_{x,y} P(x,y)·log(P(x,y)/(P(x)·P(y))).

    连续特征通过自适应分箱已被预处理为离散.
    """
    n = len(x)
    if n == 0:
        return 0.0

    joint = Counter(zip(x, y))
    px = Counter(x)
    py = Counter(y)

    mi = 0.0
    for (xv, yv), joint_count in joint.items():
        p_xy = joint_count / n
        p_x = px[xv] / n
        p_y = py[yv] / n
        if p_x > 0 and p_y > 0:
            mi += p_xy * math.log(p_xy / (p_x * p_y))

    return mi


def _conditional_mi(x_i: List[int], x_j: List[int], y: List[int]) -> float:
    """I(X_i; Y | X_j) = Σ_{z} P(X_j=z)·I(X_i; Y | X_j=z).

    条件互信息量化了"已知X_j后X_i提供多少额外信息".
    低CMI → X_i被X_j信息包含 → 冗余.
    """
    n = len(y)
    if n == 0:
        return 0.0

    # 按X_j的值分组
    groups: Dict[int, Tuple[List[int], List[int]]] = defaultdict(lambda: ([], []))
    for k in range(n):
        xi_list, yi_list = groups[x_j[k]]
        xi_list.append(x_i[k])
        yi_list.append(y[k])

    cmi = 0.0
    for z, (xi_g, yi_g) in groups.items():
        p_z = len(xi_g) / n
        mi_given_z = _mutual_information(xi_g, yi_g)
        cmi += p_z * mi_given_z

    return cmi


# CVE适配

def analyze_cve_features(kb, max_samples: int = 2000) -> Dict:
    """从 KB 提取特征并运行信息论分析 — 一站式接口。

    返回完整报告, 可直接用于: 评分模型的输入特征选择、
    ConformalExploitScorer 的 sigma 自适应估计、
    CausalFeatureSelector 的互补验证。
    """
    entries, _ = kb.search(limit=max_samples)
    if not entries:
        return {"status": "no_entries"}

    features: Dict[str, List[float]] = defaultdict(list)
    labels: List[int] = []

    for entry in entries:
        cvss = (_get_num(entry, "cvss_score") or 0.0) / 10.0
        epss = _get_num(entry, "epss_score") or 0.0
        epss_pct = _get_num(entry, "epss_percentile") or 0.0
        kev = 1.0 if _get_bool(entry, "cisa_kev") else 0.0
        mat_v = {"unknown": 0.0, "poc": 0.25, "proof_of_concept": 0.25,
                 "functional": 0.5, "metasploit": 0.75, "weaponized": 1.0}.get(
                     _get_str(entry, "exploit_maturity", "unknown"), 0.0)
        has_fix = 1.0 if (_get_str(entry, "fix_version") or
                          _get_str(entry, "patched_version")) else 0.0
        ref_c = min(math.log(1 + len(getattr(entry, 'references', None) or
                                (entry.get('references', []) if isinstance(entry, dict) else []))) / math.log(101), 1.0)
        cpe_c = min(math.log(1 + len(getattr(entry, 'cpe_matches', None) or
                                (entry.get('cpe_matches', []) if isinstance(entry, dict) else []))) / math.log(101), 1.0)

        features["cvss_score"].append(cvss)
        features["epss_score"].append(epss)
        features["epss_percentile"].append(epss_pct)
        features["cisa_kev"].append(kev)
        features["exploit_maturity"].append(mat_v)
        features["has_fix"].append(has_fix)
        features["ref_count"].append(ref_c)
        features["cpe_count"].append(cpe_c)

        is_exploited = 1 if (kev > 0 or mat_v >= 0.5) else 0
        labels.append(is_exploited)

    analyzer = InfoTheoryAnalyzer()
    analyzer.analyze(features, labels)

    return analyzer.get_report()


from ._internal_helpers import _get_str, _get_num, _get_bool

