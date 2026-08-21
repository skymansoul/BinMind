# 分析质量元评分: 5维+Bayesian证据累积+自适应阈值+可操作建议.
# 区别于表格数据质量工具(Deequ等), 面向二进制分析结果的多维自动化评估.
# _compl/_consis/_confid 升级为Beta-Binomial共轭证据累积

import math, time, json
from collections import deque
from typing import Dict, List, Optional, Tuple

class QualityScorer:
    """分析质量元评分器.

    输入: 单条签名的分析结果摘要 (findings_meta dict).
    输出: QualityReport 含 0-1 质量分数 + 维度分解 + 改进建议.

    用法:
      qs = QualityScorer()
      for sig in db.list_signatures():
          meta = extract_quality_features(sig, db)
          report = qs.score(meta)
          if report.quality < 0.4:
              print(f"Low quality sig#{sig['id']}: {report.suggestions}")
    """

    # 维度权重: (正权重, 缺失惩罚, 最小可接受值)
    # 权重设计依据: completeness > consistency > richness > confidence > freshness
    DIM_WEIGHTS = {
        "completeness":  (0.35, 0.5, 0.3),
        "consistency":    (0.25, 0.3, 0.2),
        "richness":       (0.20, 0.1, 0.2),
        "confidence":     (0.12, 0.1, 0.1),
        "freshness":      (0.08, 0.0, 0.0),
    }

    def __init__(self, history_size: int = 1000,
                 adaptive_threshold: bool = True):
        self._score_history: deque = deque(maxlen=history_size)
        self._adaptive = adaptive_threshold

    def score(self, dims: Dict[str, float]) -> "QualityReport":
        """计算质量分数.

        dims 应包含:
          completeness:  [0,1] 分析覆盖比例
          consistency:   [0,1] 多工具结论一致性
          richness:      [0,1] 输出信息密度 (IOC数/函数数/模式数归一化)
          confidence:    [0,1] 工具自报置信度聚合
          freshness:     [0,1] 时效性 (1=刚刚分析, 0=超过1年)
        """
        weighted_sum = 0.0
        total_weight = 0.0
        dimension_scores = {}
        dimension_missing = []

        for dim_name, (weight, penalty, minimum) in self.DIM_WEIGHTS.items():
            value = dims.get(dim_name)
            if value is None:
                # 维度缺失: 施加惩罚
                value = max(0.0, minimum - penalty)
                dimension_missing.append(dim_name)
            # 钳制到 [0,1]
            value = max(0.0, min(1.0, value))
            weighted_sum += weight * value
            total_weight += weight
            dimension_scores[dim_name] = round(value, 4)

        quality = weighted_sum / max(total_weight, 1e-9)
        quality = round(quality, 4)

        self._score_history.append(quality)

        # 生成建议
        suggestions = self._generate_suggestions(
            dimension_scores, dimension_missing, quality
        )

        # 自适应阈值
        threshold = self._current_threshold() if self._adaptive else 0.5
        is_low_quality = quality < threshold

        return QualityReport(
            quality=quality,
            dimensions=dimension_scores,
            missing_dimensions=dimension_missing,
            suggestions=suggestions,
            threshold=round(threshold, 4),
            is_low_quality=is_low_quality,
            baseline_median=round(self._baseline_median(), 4),
        )

    def _generate_suggestions(self, dims: Dict[str, float],
                                missing: List[str],
                                quality: float) -> List[str]:
        """基于维度缺陷生成可操作建议."""
        suggestions = []

        if dims.get("completeness", 0) < 0.4:
            if "stripped" in str(missing).lower():
                suggestions.append("binary_is_stripped: run symbol recovery or use dynamic analysis")
            else:
                suggestions.append("low_coverage: enable additional analysis passes (cfg reconstruction, taint tracking)")

        if dims.get("consistency", 0) < 0.3:
            suggestions.append("tool_disagreement: cross-validate findings with third independent tool")

        if dims.get("richness", 0) < 0.2:
            suggestions.append("sparse_output: binary may be packed or obfuscated, run unpacker first")

        if dims.get("freshness", 0) < 0.3:
            suggestions.append("stale_analysis: re-run analysis with updated tool versions")

        if missing:
            suggestions.append(f"missing_dimensions: {','.join(missing)}")

        if not suggestions and quality < 0.5:
            suggestions.append("overall_low_quality: consider manual review")

        return suggestions

    def _current_threshold(self) -> float:
        """自适应阈值: max(0.35, median - 0.15)."""
        median = self._baseline_median()
        return max(0.35, median - 0.15)

    def _baseline_median(self) -> float:
        if len(self._score_history) < 10:
            return 0.5
        scores = sorted(self._score_history)
        n = len(scores)
        if n % 2 == 1:
            return scores[n // 2]
        return (scores[n//2 - 1] + scores[n//2]) / 2.0

    @property
    def stats(self) -> dict:
        scores = list(self._score_history)
        if not scores:
            return {"count": 0}
        n = len(scores)
        return {
            "count": n,
            "mean": round(sum(scores)/n, 4),
            "median": round(sorted(scores)[n//2], 4),
            "min": round(min(scores), 4),
            "max": round(max(scores), 4),
            "below_threshold_ratio": round(
                sum(1 for s in scores if s < self._current_threshold())/n, 4),
        }


class QualityReport:
    """质量评分报告."""
    __slots__ = ("quality","dimensions","missing_dimensions",
                 "suggestions","threshold","is_low_quality","baseline_median")
    def __init__(self, quality: float, dimensions: Dict[str, float],
                 missing_dimensions: List[str], suggestions: List[str],
                 threshold: float, is_low_quality: bool, baseline_median: float):
        self.quality = quality
        self.dimensions = dimensions
        self.missing_dimensions = missing_dimensions
        self.suggestions = suggestions
        self.threshold = threshold
        self.is_low_quality = is_low_quality
        self.baseline_median = baseline_median

    def to_dict(self) -> dict:
        return {
            "quality": self.quality,
            "is_low_quality": self.is_low_quality,
            "threshold": self.threshold,
            "baseline_median": self.baseline_median,
            "dimensions": self.dimensions,
            "missing": self.missing_dimensions,
            "suggestions": self.suggestions,
        }


# 特征提取器: 从 signature 记录 + analysis_results 提取质量维度

def extract_quality_dims(sig: dict, analyses: List[dict],
                          now: float = None) -> Dict[str, float]:
    """从签名记录和分析结果中提取 5 维质量特征.

    输入要求:
      sig: signatures 表的一行 (含 stage, file_size, compressed_size 等)
      analyses: analysis_results 表的多行 (含 tool_name, findings, status, analyzed_at)
    返回: {completeness, consistency, richness, confidence, freshness}
    """
    if now is None:
        now = time.time()

    return {
        "completeness": _compl(sig, analyses),
        "consistency": _consis(analyses),
        "richness": _rich(analyses),
        "confidence": _confid(analyses),
        "freshness": _fresh(analyses, now),
    }

class BayesianEvidence:
    """Beta-Binomial 共轭证据累积: 先验 Beta(α,β), 后验均值=α/(α+β)."""
    def __init__(self, prior_alpha: float = 2.0, prior_beta: float = 2.0):
        self.alpha = prior_alpha; self.beta = prior_beta
    def add_evidence(self, success_weight: float):
        if success_weight >= 0.5: self.alpha += success_weight
        else: self.beta += (1.0 - success_weight)
    def mean(self) -> float:
        return self.alpha / (self.alpha + self.beta)
    def uncertainty(self) -> float:
        a, b = self.alpha, self.beta
        return (a*b)/((a+b)**2*(a+b+1)) if (a+b) > 0 else 0.25


def _parse_findings(findings_raw):
    if isinstance(findings_raw, str):
        try: return json.loads(findings_raw)
        except Exception: pass
    return findings_raw if isinstance(findings_raw, list) else []

def _compl(sig, analyses):
    """completeness: Beta-Binomial 证据累积.

    正向证据: 有分析结果 (+0.7), 含CFG分析 (+0.8), 有3+工具 (+0.9)
    负向证据: stripped binary (+0.2), 无分析结果 (+0.1)
    先验 Beta(2,2) → 均值=0.5 (中性), 随证据收敛.
    """
    ev = BayesianEvidence(prior_alpha=2.0, prior_beta=2.0)
    meta = sig.get("metadata",{})
    if isinstance(meta, str):
        try: meta = json.loads(meta)
        except Exception: meta = {}
    # 负向证据
    if meta.get("stripped") or (sig.get("tags") and "stripped" in str(sig.get("tags",""))):
        ev.add_evidence(0.2)
    # 正向证据
    na = len(analyses)
    if na >= 3:       ev.add_evidence(0.9)
    elif na >= 1:     ev.add_evidence(0.7)
    else:             ev.add_evidence(0.1)
    if any("cfg" in str(a.get("tool_name","")).lower() for a in analyses):
        ev.add_evidence(0.8)
    return ev.mean()

def _consis(analyses):
    """consistency: Beta-Binomial 基于工具间 Jaccard 均值."""
    if len(analyses) < 2: return 0.3
    tt = {}
    for a in analyses:
        f = _parse_findings(a.get("findings",[]))
        tt[a.get("tool_name","?")] = {x.get("type","") for x in f if isinstance(x,dict)}
    if len(tt) < 2: return 0.3
    tools = list(tt.keys()); js = []
    for i in range(len(tools)):
        for j in range(i+1, len(tools)):
            u = len(tt[tools[i]] | tt[tools[j]])
            js.append(len(tt[tools[i]] & tt[tools[j]]) / max(u,1))
    avg_j = sum(js)/len(js) if js else 0.0
    # Bayesian: 每个工具对的 Jaccard 作为一次证据
    ev = BayesianEvidence(prior_alpha=1.5, prior_beta=1.5)
    for j in js: ev.add_evidence(min(1.0, j*1.5))
    return ev.mean()

def _rich(analyses, sig=None):
    n = sum(len(_parse_findings(a.get("findings",[]))) for a in analyses)
    return min(1.0, n/50.0)

def _confid(analyses):
    """confidence: Beta-Binomial 累积各工具的状态+自报置信度."""
    if not analyses: return 0.0
    ev = BayesianEvidence(prior_alpha=2.0, prior_beta=2.0)
    for a in analyses:
        st = a.get("status","")
        w = 0.8 if st=="completed" else (0.5 if st=="partial" else (0.1 if st=="failed" else 0.4))
        ev.add_evidence(w)
        f = _parse_findings(a.get("findings",[]))
        fc = [x.get("confidence",0.5) for x in f if isinstance(x,dict)]
        for c in fc: ev.add_evidence(c)
    return ev.mean()

def _fresh(analyses, now):
    if not analyses: return 0.0
    ages = [(now-a.get("analyzed_at",0))/86400.0 for a in analyses if a.get("analyzed_at",0)>0]
    return max(0.0, 1.0-min(ages)/365.0) if ages else 0.0


__all__ = [
    "QualityScorer",
    "QualityReport",
    "extract_quality_dims",
]
