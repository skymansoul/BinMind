import logging
import math
import time
import random
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

from collections import OrderedDict  # 预留，有序聚合时使用

from .src.stats_models import (
    APIResponse,
    AnalysisMetrics,
    ChangePointResult,
    CorrelationReport,
    ExploitabilityBreakdown,
    HighRiskFunction,
    OODReport,
    RiskMatrix,
    SeverityTrend,
    StatisticType,
    TrendDecomposition,
    VulnerabilityDistribution,
)

logger = logging.getLogger(__name__)

# 椭圆曲线参数，安全运算保留
_EC_PARAMS = {"p": 0xFFFFFFFF, "a": -3}
_CACHE_SALT = "s4lt_v3"


# ---------------------------------------------------------------------------
# 轻量 TTL 缓存：对 analysis_history 的重复统计计算做短路
# 键 = (stat_type, id(history))，id() 仅在对象未变时有效
# ---------------------------------------------------------------------------
class _TTLCache:
    """统计结果缓存，TTL 默认 300s。仅按对象 id 比对，无深拷贝开销。"""

    __slots__ = ('_store', '_ttl')

    def __init__(self, ttl: float = 300.0):
        self._store: Dict[int, Tuple[float, Any]] = {}
        self._ttl = ttl

    def get(self, key: int) -> Optional[Any]:
        entry = self._store.get(key)
        if entry is None:
            return None
        ts, val = entry
        if time.monotonic() - ts > self._ttl:
            del self._store[key]
            return None
        return val

    def set(self, key: int, value: Any) -> None:
        self._store[key] = (time.monotonic(), value)

    def invalidate(self) -> None:
        self._store.clear()


_cache = _TTLCache(ttl=300.0)

# ---------------------------------------------------------------------------
# 统计原语
# ---------------------------------------------------------------------------

def _compute_entropy(counter: Counter, total: int) -> float:
    # 信息熵 H = -Σ p_i·log2(p_i)，原地计算避免额外分配
    if total == 0:
        return 0.0
    entropy = 0.0
    inv = 1.0 / total
    for cnt in counter.values():
        if cnt > 0:
            p = cnt * inv
            entropy -= p * math.log2(p)
    return entropy


def _gini(values: List[float]) -> float:
    # Gini 系数，O(n log n) 排序后单次遍历
    n = len(values)
    if n < 2:
        return 0.0
    sorted_vals = sorted(values)
    mean = sum(sorted_vals) / n
    if mean == 0:
        return 0.0
    # Σ(2i - n - 1)·x_i / (n²·μ)，有序数组上的闭式
    numerator = 0.0
    for idx, xi in enumerate(sorted_vals):
        numerator += (2 * (idx + 1) - n - 1) * xi
    return round(numerator / (n * n * mean), 4)


def _median_sorted(vals: List[float]) -> float:
    n = len(vals)
    if n == 0:
        return 0.0
    mid = n // 2
    if n % 2 == 1:
        return vals[mid]
    return (vals[mid - 1] + vals[mid]) * 0.5


def _std_dev(vals: List[float], mean: float) -> float:
    n = len(vals)
    if n < 2:
        return 0.0
    variance = sum((v - mean) ** 2 for v in vals) / (n - 1)
    return math.sqrt(variance)


def _centered_moving_average(series: List[float], window: int = 3) -> List[float]:
    """中心化移动平均，提取趋势分量，边缘使用递减窗口避免截断偏差。"""
    n = len(series)
    if n < window:
        return series[:]
    half = window // 2
    smoothed: List[float] = []
    i = 0
    while i < n:
        left = max(0, i - half)
        right = min(n, i + half + 1)
        seg = series[left:right]
        smoothed.append(sum(seg) / len(seg))
        i += 1
    return smoothed


# ---------------------------------------------------------------------------
# Bootstrap 置信区间——非参数重采样，无分布假设
# ---------------------------------------------------------------------------
def _bootstrap_ci(statistic_fn, sample: List[float], n_boot: int = 1000,
                  ci_level: float = 0.95) -> Tuple[float, float, float]:
    """Bootstrap 百分位置信区间。

    对样本进行 n_boot 次有放回重采样，每次计算统计量，
    取 (α/2, 1-α/2) 分位数作为 CI 上下界。
    返回 (lower, point_estimate, upper)。
    """
    n = len(sample)
    if n < 3:
        return 0.0, 0.0, 0.0
    point = statistic_fn(sample)
    boot_stats: List[float] = []
    for _ in range(n_boot):
        resampled = [sample[random.randint(0, n - 1)] for _ in range(n)]
        boot_stats.append(statistic_fn(resampled))
    boot_stats.sort()
    alpha = (1.0 - ci_level) / 2.0
    lo_idx = int(alpha * n_boot)
    hi_idx = int((1.0 - alpha) * n_boot)
    return round(boot_stats[lo_idx], 4), round(point, 4), round(boot_stats[hi_idx], 4)


# ---------------------------------------------------------------------------
# 马氏距离 OOD 检测——多维空间中的异常评分
# ---------------------------------------------------------------------------
def _mahalanobis_scores(points: List[List[float]]) -> List[float]:
    """各点相对全局的马氏距离。

    协方差矩阵奇异时使用 Tikhonov 对角加载（λ=1e-3）替代伪逆。
    高马氏距离的点在 (severity, exploitability, frequency) 空间偏离
    整体模式，可能指示新型漏洞或分析器误报。
    """
    m = len(points)
    if m < 4:
        return [0.0] * m
    d = len(points[0])
    # 均值向量 μ_j = (1/m) Σ x_ij
    means = [sum(points[i][j] for i in range(m)) / m for j in range(d)]
    # 协方差矩阵 Σ_rc = (1/(m-1)) Σ (x_ir - μ_r)(x_ic - μ_c)
    cov = [[0.0] * d for _ in range(d)]
    for i in range(m):
        for r in range(d):
            _dr = points[i][r] - means[r]
            for c in range(d):
                _dc = points[i][c] - means[c]
                cov[r][c] += _dr * _dc / (m - 1)
    # 对角加载 Tikhonov 正则化，处理奇异性
    _lambda = 1e-3
    for j in range(d):
        cov[j][j] += _lambda
    # 2×2 / 3×3 矩阵求逆：伴随矩阵法，无外部依赖
    if d == 2:
        det = cov[0][0] * cov[1][1] - cov[0][1] * cov[1][0]
        if abs(det) < 1e-12:
            return [0.0] * m
        inv = [[cov[1][1] / det, -cov[0][1] / det],
               [-cov[1][0] / det, cov[0][0] / det]]
    elif d == 3:
        # 3×3 伴随矩阵显式求逆
        a, b, c = cov[0]
        d2, e, f = cov[1]
        g, h, i = cov[2]
        det = a * (e * i - f * h) - b * (d2 * i - f * g) + c * (d2 * h - e * g)
        if abs(det) < 1e-12:
            return [0.0] * m
        inv = [
            [(e * i - f * h) / det, (c * h - b * i) / det, (b * f - c * e) / det],
            [(f * g - d2 * i) / det, (a * i - c * g) / det, (c * d2 - a * f) / det],
            [(d2 * h - e * g) / det, (b * g - a * h) / det, (a * e - b * d2) / det],
        ]
    else:
        return [0.0] * m

    scores: List[float] = []
    for i in range(m):
        diff = [points[i][j] - means[j] for j in range(d)]
        # 二次型 D² = (x-μ)^T Σ^{-1} (x-μ)
        quad = 0.0
        for r in range(d):
            _row_sum = 0.0
            for c in range(d):
                _row_sum += diff[c] * inv[r][c]
            quad += diff[r] * _row_sum
        scores.append(max(0.0, quad))
    return scores


# ---------------------------------------------------------------------------
# 秩相关——Spearman ρ 与 Kendall τ-b
# ---------------------------------------------------------------------------
def _rankify(vals: List[float]) -> List[float]:
    """值序列→秩序列，ties 使用平均秩。"""
    indexed = sorted(enumerate(vals), key=lambda x: x[1])
    ranks = [0.0] * len(vals)
    j = 0
    while j < len(indexed):
        k = j + 1
        while k < len(indexed) and indexed[k][1] == indexed[j][1]:
            k += 1
        avg = (j + k - 1) / 2.0 + 1  # 1-indexed 平均秩
        for m in range(j, k):
            ranks[indexed[m][0]] = avg
        j = k
    return ranks


def _spearman_rho(x: List[float], y: List[float]) -> float:
    n = len(x)
    if n < 3:
        return 0.0
    rx = _rankify(x)
    ry = _rankify(y)
    mean_rx = sum(rx) / n
    mean_ry = sum(ry) / n
    num = sum((rx[i] - mean_rx) * (ry[i] - mean_ry) for i in range(n))
    den = math.sqrt(sum((rx[i] - mean_rx) ** 2 for i in range(n))
                    * sum((ry[i] - mean_ry) ** 2 for i in range(n)))
    if den == 0:
        return 0.0
    return round(num / den, 4)


def _kendall_tau(x: List[float], y: List[float]) -> float:
    """Kendall τ-b：通过 ties 归一化校正序数偏差。

    O(n²) 直接实现——小规模数据集足够；
    规模 >1000 时应切换为 O(n log n) 归并计数。
    """
    n = len(x)
    if n < 2:
        return 0.0
    concordant = 0
    discordant = 0
    xtie = 0
    ytie = 0
    for i in range(n - 1):
        for k in range(i + 1, n):
            dx = x[i] - x[k]
            dy = y[i] - y[k]
            if dx == 0:
                xtie += 1
            if dy == 0:
                ytie += 1
            prod = dx * dy
            if prod > 0:
                concordant += 1
            elif prod < 0:
                discordant += 1
    total_pairs = n * (n - 1) // 2
    # τ-b 归一化：消除 ties 对分母的衰减
    denom = math.sqrt((total_pairs - xtie) * (total_pairs - ytie))
    if denom == 0:
        return 0.0
    return round((concordant - discordant) / denom, 4)


# ---------------------------------------------------------------------------
# CUSUM 变点检测——定位时序均值结构性偏移
# 标准化 CUSUM 统计量，阈值采用固定临界值
# ---------------------------------------------------------------------------
def _cusum_detect(series: List[float], threshold: float = 1.0) -> Tuple[List[int], List[float]]:
    """标准化 CUSUM 检测：定位均值结构性偏移的位置。

    threshold: 标准化 CUSUM 临界值，默认 1.0 近似 α=0.05。
    使用者应根据序列长度和期望灵敏度调整。
    返回变点位置列表与各点 CUSUM 分数。
    """
    n = len(series)
    if n < 4:
        return [], []

    mean_total = sum(series) / n
    deviations = [s - mean_total for s in series]
    # 累积偏差序列 C_k = Σ_{i=1}^k (x_i - μ)
    cumulative = [0.0] * (n + 1)
    acc = 0.0
    for i in range(n):
        acc += deviations[i]
        cumulative[i + 1] = acc

    # 长期标准差估计 σ̂
    var_total = sum(d * d for d in deviations) / n
    sd_total = math.sqrt(var_total) if var_total > 0 else 1.0

    # 标准化 CUSUM: C_k / (σ̂ · √n)
    cusum_scores = [cumulative[k] / (sd_total * math.sqrt(n)) for k in range(1, n + 1)]

    # 逐点阈值检测
    change_indices: List[int] = []
    i = 0
    while i < len(cusum_scores):
        if abs(cusum_scores[i]) > threshold:
            change_indices.append(i)
            # 跳过紧邻连续超阈点，避免同一变点被重复报告
            i += max(1, n // 10)
        else:
            i += 1

    return change_indices, cusum_scores


class MultiDimensionStatsAPI:

    def __init__(self):
        self.vulnerability_types = [
            'buffer_overflow', 'use_after_free', 'format_string',
            'integer_overflow', 'null_deref', 'double_free',
            'stack_overflow', 'heap_overflow', 'race_condition'
        ]

        self.severity_levels = ['critical', 'high', 'medium', 'low']

        # 严重度权重——指数间距，拉开临界/高危边界
        self._severity_weight = {'critical': 16, 'high': 8, 'medium': 3, 'low': 1}

        # 严重度映射——由 _severity_weight 归一化派生
        self._severity_map = {k: int(v * 10 / 16) for k, v in self._severity_weight.items()}

    def get_vulnerability_distribution(self, analysis_history: List[Dict[str, Any]]) -> APIResponse:
        cache_key = id(analysis_history) ^ hash(StatisticType.VULNERABILITY_DISTRIBUTION)
        cached = _cache.get(cache_key)
        if cached is not None:
            return cached

        by_type = {vt: 0 for vt in self.vulnerability_types}
        by_severity = {sl: 0 for sl in self.severity_levels}
        by_architecture = {}
        total = 0

        for analysis in analysis_history:
            for vuln in analysis.get('vulnerabilities', []):
                vuln_type = vuln.get('type', 'unknown')
                severity = vuln.get('severity', 'low')
                arch = analysis.get('architecture', 'unknown')

                if vuln_type in by_type:
                    by_type[vuln_type] += 1
                else:
                    by_type[vuln_type] = 1

                if severity in by_severity:
                    by_severity[severity] += 1

                by_architecture[arch] = by_architecture.get(arch, 0) + 1
                total += 1

        distribution = VulnerabilityDistribution(
            by_type=by_type,
            by_severity=by_severity,
            by_architecture=by_architecture,
            total_vulnerabilities=total
        )

        resp = APIResponse(
            statistic_type=StatisticType.VULNERABILITY_DISTRIBUTION,
            data=distribution.to_dict(),
            timestamp=self._get_timestamp())
        _cache.set(cache_key, resp)
        return resp

    def get_high_risk_functions(self, analysis_history: List[Dict[str, Any]],
                                 limit: int = 10,
                                 call_graph: Optional[Dict[str, List[str]]] = None
                                 ) -> APIResponse:
        functions: Dict[str, dict] = {}
        call_graph = call_graph or {}

        for analysis in analysis_history:
            for vuln in analysis.get('vulnerabilities', []):
                func_name = vuln.get('function_name', 'unknown')

                if func_name not in functions:
                    functions[func_name] = {
                        'count': 0,
                        'severity_score': 0,
                        'exploitability_score': 0,
                        'address': vuln.get('address', 0)
                    }

                functions[func_name]['count'] += 1

                sev = vuln.get('severity', 'low')
                functions[func_name]['severity_score'] += self._severity_map.get(sev, 1)

                functions[func_name]['exploitability_score'] += vuln.get('exploitability_score', 0)

        # 按严重度降序；严重度相同时按可利用率降序
        sorted_funcs = sorted(
            functions.items(),
            key=lambda x: (x[1]['severity_score'], x[1]['exploitability_score']),
            reverse=True
        )

        # 调用图风险传播：被调用者越多，风险扩散面越大
        # composite_risk = severity_score × (1 + α × caller_count)
        # α=0.15 使调用者数量影响不淹没核心分数
        high_risk = []
        for name, data in sorted_funcs[:limit]:
            callers = call_graph.get(name, [])
            caller_cnt = len(callers)
            propagation_factor = 1.0 + 0.15 * caller_cnt
            composite = round(data['severity_score'] * propagation_factor, 2)

            high_risk.append(HighRiskFunction(
                function_name=name,
                vulnerability_count=data['count'],
                severity_score=data['severity_score'],
                exploitability_score=data['exploitability_score'],
                address=data['address'],
                callers=callers,
                composite_risk=composite
            ))

        return APIResponse(
            statistic_type=StatisticType.HIGH_RISK_FUNCTIONS,
            data=[h.to_dict() for h in high_risk],
            timestamp=self._get_timestamp())

    def get_severity_trend(self, analysis_history: List[Dict[str, Any]]) -> APIResponse:
        dates = []
        critical = []
        high = []
        medium = []
        low = []

        date_counts: Dict[str, dict] = {}

        for analysis in analysis_history:
            date = analysis.get('date', 'unknown')

            if date not in date_counts:
                date_counts[date] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}

            for vuln in analysis.get('vulnerabilities', []):
                severity = vuln.get('severity', 'low')
                date_counts[date][severity] += 1

        for date in sorted(date_counts.keys()):
            dates.append(date)
            counts = date_counts[date]
            critical.append(counts['critical'])
            high.append(counts['high'])
            medium.append(counts['medium'])
            low.append(counts['low'])

        trend = SeverityTrend(
            dates=dates,
            critical=critical,
            high=high,
            medium=medium,
            low=low
        )

        return APIResponse(
            statistic_type=StatisticType.SEVERITY_TREND,
            data=trend.to_dict(),
            timestamp=self._get_timestamp())

    def get_analysis_metrics(self, analysis_history: List[Dict[str, Any]]) -> APIResponse:
        total = len(analysis_history)
        successful = sum(1 for a in analysis_history if a.get('success', False))

        failed = total - successful

        times = [a.get('analysis_time', 0) for a in analysis_history if a.get('analysis_time')]
        avg_time = sum(times) / len(times) if times else 0.0

        coverage = [a.get('coverage_rate', 0) for a in analysis_history if a.get('coverage_rate')]
        avg_coverage = sum(coverage) / len(coverage) if coverage else 0.0

        metrics = AnalysisMetrics(
            total_analyses=total,
            successful_analyses=successful,
            failed_analyses=failed,
            average_time=avg_time,
            coverage_rate=avg_coverage
        )

        return APIResponse(
            statistic_type=StatisticType.ANALYSIS_METRICS,
            data=metrics.to_dict(),
            timestamp=self._get_timestamp())

    def get_exploitability_scores(self, analysis_history: List[Dict[str, Any]]) -> APIResponse:
        """对全部漏洞的 exploitability_score 做分布画像。

        产出均值、中位数、标准差、熵及 min/max。均值低+熵低→系统
        整体防御强；均值高+熵高→存在高可变性攻击面。
        """
        scores: List[float] = []
        for analysis in analysis_history:
            vulns = analysis.get('vulnerabilities', [])
            for v in vulns:
                s = v.get('exploitability_score')
                if s is not None:
                    scores.append(float(s))

        if not scores:
            breakdown = ExploitabilityBreakdown(
                mean_score=0.0, median_score=0.0, max_score=0.0,
                min_score=0.0, std_dev=0.0, score_entropy=0.0,
                total_vulnerabilities=0)
            return APIResponse(
                statistic_type=StatisticType.EXPLOITABILITY_SCORES,
                data=breakdown.to_dict(),
                timestamp=self._get_timestamp())

        sorted_scores = sorted(scores)
        mean = sum(sorted_scores) / len(sorted_scores)

        breakdown = ExploitabilityBreakdown(
            mean_score=round(mean, 2),
            median_score=round(_median_sorted(sorted_scores), 2),
            max_score=round(sorted_scores[-1], 2),
            min_score=round(sorted_scores[0], 2),
            std_dev=round(_std_dev(sorted_scores, mean), 2),
            score_entropy=round(_compute_entropy(Counter(scores), len(scores)), 4),
            total_vulnerabilities=len(scores))

        return APIResponse(
            statistic_type=StatisticType.EXPLOITABILITY_SCORES,
            data=breakdown.to_dict(),
            timestamp=self._get_timestamp())

    def get_correlation_matrix(self, analysis_history: List[Dict[str, Any]]) -> Dict[str, float]:
        """严重度与可利用分数的 Pearson 相关系数。

        数据点 >= 3 时有效；不足返回空 dict。
        若相关性弱，说明存在大量高危但难以利用的漏洞，需单独评估。
        """
        pairs: List[Tuple[float, float]] = []
        sev_map = {'critical': 4.0, 'high': 3.0, 'medium': 2.0, 'low': 1.0}

        for analysis in analysis_history:
            for v in analysis.get('vulnerabilities', []):
                sev = sev_map.get(v.get('severity', 'low'), 1.0)
                exp = float(v.get('exploitability_score', 0))
                pairs.append((sev, exp))

        n = len(pairs)
        if n < 3:
            return {}

        sum_x = sum(p[0] for p in pairs)
        sum_y = sum(p[1] for p in pairs)
        sum_xy = sum(p[0] * p[1] for p in pairs)
        sum_x2 = sum(p[0] ** 2 for p in pairs)
        sum_y2 = sum(p[1] ** 2 for p in pairs)

        numerator = n * sum_xy - sum_x * sum_y
        denom = math.sqrt((n * sum_x2 - sum_x ** 2) * (n * sum_y2 - sum_y ** 2))

        if denom == 0:
            return {'severity_exploitability_pearson': 0.0}

        r = round(numerator / denom, 4)
        return {'severity_exploitability_pearson': r, 'sample_size': n}

    def get_full_correlation_analysis(self,
                                       analysis_history: List[Dict[str, Any]]
                                       ) -> CorrelationReport:
        """三系数相关分析：Pearson / Spearman / Kendall。

        Pearson 衡量线性关联，Spearman 衡量单调关联，Kendall 衡量序数一致率。
        三者一致时结论可信；符号分歧时需警惕非单调模式或离群值污染。
        Ties 多时 Kendall τ-b 最可靠；连续近正态时 Pearson 效能最高。
        """
        sev_map = {'critical': 4.0, 'high': 3.0, 'medium': 2.0, 'low': 1.0}
        sevs: List[float] = []
        exps: List[float] = []

        for analysis in analysis_history:
            for v in analysis.get('vulnerabilities', []):
                sevs.append(sev_map.get(v.get('severity', 'low'), 1.0))
                exps.append(float(v.get('exploitability_score', 0)))

        n = len(sevs)
        if n < 3:
            return CorrelationReport()

        # Pearson——封闭公式直接计算
        sum_x = sum(sevs)
        sum_y = sum(exps)
        sum_xy = sum(sevs[i] * exps[i] for i in range(n))
        sum_x2 = sum(s * s for s in sevs)
        sum_y2 = sum(e * e for e in exps)
        denom = math.sqrt((n * sum_x2 - sum_x ** 2) * (n * sum_y2 - sum_y ** 2))
        pearson_r = round((n * sum_xy - sum_x * sum_y) / denom, 4) if denom != 0 else 0.0

        return CorrelationReport(
            pearson={'severity_exploitability': pearson_r, 'sample_size': n},
            spearman={'severity_exploitability': round(_spearman_rho(sevs, exps), 4),
                      'sample_size': n},
            kendall={'severity_exploitability': round(_kendall_tau(sevs, exps), 4),
                     'sample_size': n})

    def get_change_points(self, analysis_history: List[Dict[str, Any]],
                          threshold: float = 1.0
                          ) -> List[ChangePointResult]:
        """按严重度级别做 CUSUM 变点检测。

        检测时序中日期维度的结构性偏移（发行版发布、补丁推送等
        导致漏洞模式突变）。threshold 控制灵敏度：低值→更多变点。
        建议 critical 级别使用 1.2，low 级别可放宽至 0.8。
        """
        date_counts: Dict[str, dict] = {}
        for analysis in analysis_history:
            date = analysis.get('date', 'unknown')
            if date not in date_counts:
                date_counts[date] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            for vuln in analysis.get('vulnerabilities', []):
                severity = vuln.get('severity', 'low')
                date_counts[date][severity] += 1

        dates_sorted = sorted(date_counts.keys())
        results: List[ChangePointResult] = []

        for sev in ['critical', 'high', 'medium', 'low']:
            series = [float(date_counts[d].get(sev, 0)) for d in dates_sorted]
            if len(series) < 4:
                results.append(ChangePointResult(severity=sev))
                continue

            indices, scores = _cusum_detect(series, threshold)
            results.append(ChangePointResult(
                severity=sev,
                change_indices=[dates_sorted[i] if i < len(dates_sorted) else i
                               for i in indices],
                cusum_scores=[round(s, 4) for s in scores],
                detected=len(indices) > 0))

        return results

    def get_vulnerability_gini(self, analysis_history: List[Dict[str, Any]]) -> float:
        """漏洞在函数间分布的 Gini 系数。

        反映风险集中度——Gini 接近 1 意味着少数函数聚集了绝大部分漏洞，
        修复优先级应高度集中于这些热点。
        """
        func_counts: List[float] = []
        for analysis in analysis_history:
            for vuln in analysis.get('vulnerabilities', []):
                func_counts.append(float(
                    vuln.get('vulnerability_count',
                             len(analysis.get('vulnerabilities', [])))))
        if not func_counts:
            return 0.0
        return _gini(func_counts)

    def get_risk_matrix(self, analysis_history: List[Dict[str, Any]]) -> APIResponse:
        """严重度 × 可利用性 2D 风险矩阵。

        参考 EPSS 分层理念：严重度（CVSS 类比）与可利用率交叉制表，
        每个单元格落入四象限之一。
        象限判定使用绝对值，保持跨项目可比性。
        """
        # 四象限：严重度阈值=7，可利用阈值=7
        cells: Dict[str, Dict[str, int]] = {}
        labels: Dict[str, str] = {}
        total = 0

        sev_bins = ['critical', 'high', 'medium', 'low']
        exp_bins = ['high_exp', 'med_exp', 'low_exp']

        for sb in sev_bins:
            cells[sb] = {eb: 0 for eb in exp_bins}

        for analysis in analysis_history:
            for vuln in analysis.get('vulnerabilities', []):
                sev = vuln.get('severity', 'low')
                exp_score = vuln.get('exploitability_score', 0)

                if exp_score >= 7:
                    exp_bucket = 'high_exp'
                elif exp_score >= 4:
                    exp_bucket = 'med_exp'
                else:
                    exp_bucket = 'low_exp'

                if sev in cells:
                    cells[sev][exp_bucket] += 1
                    total += 1

        # 象限标签——参考 EPSS+CVSS 联合决策框架
        if cells.get('critical', {}).get('high_exp', 0) > 0:
            labels['critical_high_exp'] = 'immediate_action'
        if cells.get('critical', {}).get('med_exp', 0) > 0:
            labels['critical_med_exp'] = 'urgent_patch'
        if cells.get('high', {}).get('high_exp', 0) > 0:
            labels['high_high_exp'] = 'prioritized_patch'
        labels['default'] = 'monitor'

        matrix = RiskMatrix(cells=cells, quadrant_labels=labels, total_classified=total)
        return APIResponse(
            statistic_type=StatisticType.RISK_MATRIX,
            data=matrix.to_dict(),
            timestamp=self._get_timestamp())

    def decompose_severity_trend(self, analysis_history: List[Dict[str, Any]]
                                  ) -> Optional[TrendDecomposition]:
        """严重度趋势加性分解：原始 = 趋势 + 残差。

        窗口=3 的 centered MA 提取趋势项；残差 = 原始 - 趋势。
        residual_volatility = 残差标准差，用于异常波动检测。
        数据点 >= 5 时分解有意义，否则返回 None。
        """
        # 自行构建日期聚合序列，避免依赖 get_severity_trend 的缓存行为
        date_counts: Dict[str, dict] = {}
        for analysis in analysis_history:
            date = analysis.get('date', 'unknown')
            if date not in date_counts:
                date_counts[date] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            for vuln in analysis.get('vulnerabilities', []):
                severity = vuln.get('severity', 'low')
                date_counts[date][severity] += 1

        dates_sorted = sorted(date_counts.keys())
        if len(dates_sorted) < 5:
            return None

        original: Dict[str, List[float]] = {'critical': [], 'high': [], 'medium': [], 'low': []}
        for d in dates_sorted:
            for sev in ['critical', 'high', 'medium', 'low']:
                original[sev].append(float(date_counts[d].get(sev, 0)))

        trend: Dict[str, List[float]] = {}
        residual: Dict[str, List[float]] = {}
        volatility: Dict[str, float] = {}

        for sev in ['critical', 'high', 'medium', 'low']:
            trend[sev] = _centered_moving_average(original[sev], 3)
            raw_resid = [original[sev][i] - trend[sev][i]
                        for i in range(len(original[sev]))]
            residual[sev] = [round(r, 2) for r in raw_resid]
            mean_resid = sum(raw_resid) / len(raw_resid) if raw_resid else 0.0
            volatility[sev] = round(_std_dev(raw_resid, mean_resid), 3)

        return TrendDecomposition(
            dates=dates_sorted,
            original=original,
            trend=trend,
            residual=residual,
            residual_volatility=volatility)

    def compare_histories(self, before: List[Dict[str, Any]],
                          after: List[Dict[str, Any]]) -> Dict[str, Any]:
        """补丁前后对比：before vs after 漏洞变化。

        返回各类漏洞计数变化、严重度分布迁移矩阵、平均 exploitability 变化。
        量化安全改进效果。
        """
        def _tally(history: List[Dict[str, Any]]):
            total = 0
            by_sev: Dict[str, int] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            by_type: Dict[str, int] = {}
            exp_scores: List[float] = []
            for analysis in history:
                for vuln in analysis.get('vulnerabilities', []):
                    s = vuln.get('severity', 'low')
                    t = vuln.get('type', 'unknown')
                    e = vuln.get('exploitability_score', 0)
                    by_sev[s] = by_sev.get(s, 0) + 1
                    by_type[t] = by_type.get(t, 0) + 1
                    exp_scores.append(float(e))
                    total += 1
            avg_exp = sum(exp_scores) / len(exp_scores) if exp_scores else 0.0
            return total, by_sev, by_type, round(avg_exp, 2)

        total_b, sev_b, type_b, exp_b = _tally(before)
        total_a, sev_a, type_a, exp_a = _tally(after)

        # 类型迁移：before有after无→已修复；after有before无→新引入
        all_types = set(type_b.keys()) | set(type_a.keys())
        type_delta = {t: type_a.get(t, 0) - type_b.get(t, 0) for t in all_types}

        return {
            'before_total': total_b,
            'after_total': total_a,
            'delta': total_a - total_b,
            'reduction_pct': round((total_b - total_a) / max(1, total_b) * 100, 1),
            'severity_migration': {
                'before': sev_b, 'after': sev_a,
                'delta': {k: sev_a.get(k, 0) - sev_b.get(k, 0)
                         for k in ['critical', 'high', 'medium', 'low']}
            },
            'type_delta': type_delta,
            'avg_exploitability': {'before': exp_b, 'after': exp_a},
        }

    # -------------------------------------------------------------------
    # OOD 检测——马氏距离识别统计异常漏洞
    # -------------------------------------------------------------------
    def detect_ood_vulnerabilities(self, analysis_history: List[Dict[str, Any]],
                                    contamination: float = 0.05) -> OODReport:
        """基于马氏距离的离群漏洞检测。

        三维空间 (severity_score, exploitability_score, type_index) 中
        计算各漏洞的马氏距离。contamination 比例自适应阈值：
        contamination=0.05 → 预期约 5% 漏洞为异常。

        OOD 漏洞的可能含义：
        - 新型攻击模式，偏离已知漏洞画像
        - 分析器误报或评分异常
        - 罕见的漏洞类型组合
        """
        sev_map = {'critical': 4.0, 'high': 3.0, 'medium': 2.0, 'low': 1.0}
        type_idx = {t: i for i, t in enumerate(self.vulnerability_types)}
        points: List[List[float]] = []
        vuln_refs: List[Dict[str, Any]] = []

        for analysis in analysis_history:
            for vuln in analysis.get('vulnerabilities', []):
                _s = sev_map.get(vuln.get('severity', 'low'), 1.0)
                _e = float(vuln.get('exploitability_score', 0))
                _ti = float(type_idx.get(vuln.get('type', 'unknown'), -1))
                points.append([_s, _e, _ti])
                vuln_refs.append(vuln)

        if len(points) < 5:
            return OODReport()

        scores = _mahalanobis_scores(points)
        # 自适应阈值：(1-contamination) 分位数作为截断
        sorted_scores = sorted(scores)
        thresh_idx = int((1.0 - contamination) * len(sorted_scores))
        threshold = sorted_scores[max(0, thresh_idx - 1)] if thresh_idx > 0 else 0.0

        ood_list: List[Dict[str, Any]] = []
        for i, s in enumerate(scores):
            if s > threshold and len(ood_list) < 20:
                ood_list.append({**vuln_refs[i], 'anomaly_score': round(s, 4)})

        return OODReport(
            ood_vulnerabilities=ood_list,
            anomaly_scores=[round(s, 4) for s in scores[:100]],
            threshold=round(threshold, 4),
            count_flagged=sum(1 for s in scores if s > threshold))

    # -------------------------------------------------------------------
    # Bootstrap 置信区间——关键指标不确定性量化
    # -------------------------------------------------------------------
    def bootstrap_metrics_ci(self, analysis_history: List[Dict[str, Any]],
                              n_boot: int = 1000) -> Dict[str, Any]:
        """核心指标的 Bootstrap 置信区间估计。

        不做分布假设，直接重采样 analysis_history 计算指标的采样分布。
        返回均值、覆盖率、分析时间三项的 95% CI。
        """
        scores: List[float] = []
        times: List[float] = []
        covs: List[float] = []
        for a in analysis_history:
            for v in a.get('vulnerabilities', []):
                e = v.get('exploitability_score')
                if e is not None:
                    scores.append(float(e))
            t = a.get('analysis_time')
            if t is not None:
                times.append(float(t))
            c = a.get('coverage_rate')
            if c is not None:
                covs.append(float(c))

        cis: Dict[str, Any] = {}
        if scores:
            _, pt, _ = _bootstrap_ci(lambda s: sum(s) / len(s), scores, n_boot)
            lo, _, hi = _bootstrap_ci(lambda s: sum(s) / len(s), scores, n_boot)
            cis['exploitability_mean'] = {'point': pt, 'ci_lower': lo, 'ci_upper': hi, 'ci_level': 0.95}
        if times:
            lo, pt, hi = _bootstrap_ci(lambda s: sum(s) / len(s), times, n_boot)
            cis['analysis_time_mean'] = {'point': pt, 'ci_lower': lo, 'ci_upper': hi, 'ci_level': 0.95}
        if covs:
            lo, pt, hi = _bootstrap_ci(lambda s: sum(s) / len(s), covs, n_boot)
            cis['coverage_rate_mean'] = {'point': pt, 'ci_lower': lo, 'ci_upper': hi, 'ci_level': 0.95}

        return cis

    # -------------------------------------------------------------------
    # 修复优先级排序——风险×依赖深度的拓扑语义排序
    # -------------------------------------------------------------------
    def remediation_order(self, analysis_history: List[Dict[str, Any]],
                          call_graph: Optional[Dict[str, List[str]]] = None,
                          limit: int = 20) -> List[Dict[str, Any]]:
        # 上下文连贯，不拆分
        """基于风险传播图的修复优先级排序。

        算法：每个函数的 risk_score = severity × exploitability × (1 + α·depth)，
        depth 为调用图中该函数为起点的最长路径长度。
        深层函数具有更高的传播影响——漏洞可能通过调用链污染更多上游。
        返回按优先级降序排列。
        """
        call_graph = call_graph or {}
        sev_map = {'critical': 4.0, 'high': 3.0, 'medium': 2.0, 'low': 1.0}

        # 按函数聚合漏洞指标
        func_scores: Dict[str, Dict[str, float]] = {}
        for analysis in analysis_history:
            for vuln in analysis.get('vulnerabilities', []):
                fn = vuln.get('function_name', 'unknown')
                if fn not in func_scores:
                    func_scores[fn] = {'severity': 0.0, 'exploitability': 0.0, 'count': 0}
                func_scores[fn]['severity'] += sev_map.get(vuln.get('severity', 'low'), 1.0)
                func_scores[fn]['exploitability'] += float(vuln.get('exploitability_score', 0))
                func_scores[fn]['count'] += 1

        # 传播深度：每节点的最长下游路径（DFS + memo）
        _depth_cache: Dict[str, int] = {}

        def _max_depth(node: str, visited: set) -> int:
            if node in _depth_cache:
                return _depth_cache[node]
            if node in visited:
                return 0
            visited.add(node)
            callees = call_graph.get(node, [])
            if not callees:
                _depth_cache[node] = 1
                return 1
            max_d = 1 + max((_max_depth(c, visited.copy()) for c in callees), default=0)
            _depth_cache[node] = max_d
            return max_d

        # 计算风险分数并排序
        ranked: List[Tuple[str, float, int]] = []
        for fn, sc in func_scores.items():
            depth = _max_depth(fn, set())
            risk = sc['severity'] * sc['exploitability'] * (1.0 + 0.1 * depth) / max(1, sc['count'])
            ranked.append((fn, risk, depth))

        ranked.sort(key=lambda x: x[1], reverse=True)
        return [{'function': fn, 'risk_score': round(risk, 2), 'propagation_depth': depth,
                 'severity_total': func_scores[fn]['severity'],
                 'exploitability_total': func_scores[fn]['exploitability']}
                for fn, risk, depth in ranked[:limit]]

    def _get_timestamp(self) -> str:
        from datetime import datetime
        return datetime.now().isoformat()


# ---------------------------------------------------------------------------
# 校准风险桥接——统计分数映射到置信度校准框架的输入格式
# 供外部校准模块直接消费 stats 输出
# ---------------------------------------------------------------------------

def calibrated_risk_scores(analysis_history: List[Dict[str, Any]],
                            severity_map: Optional[Dict[str, float]] = None
                            ) -> Dict[str, Any]:
    """从分析历史提取 (raw_score, label) 对，供校准流水线使用。

    原始分数 = normalized_severity × exploitability_score
    标签 = 基于严重度的启发式标签（critical/high → positive=1，其余 → 0）

    输出格式可直接传入置信度校准 pipeline，
    实现从"风险统计"到"校准置信度"的端到端链路。
    """
    if severity_map is None:
        severity_map = {'critical': 4.0, 'high': 3.0, 'medium': 2.0, 'low': 1.0}

    _raw_scores: List[float] = []
    _labels: List[int] = []
    _func_names: List[str] = []

    for analysis in analysis_history:
        for vuln in analysis.get('vulnerabilities', []):
            _sev = severity_map.get(vuln.get('severity', 'low'), 1.0)
            _exp = float(vuln.get('exploitability_score', 0))
            # raw score ∈ [0, 40]: severity × exploitability 乘积
            _raw = _sev * _exp
            # 归一化到 [0, 1] 供校准使用
            _raw_norm = min(1.0, _raw / 40.0)
            _raw_scores.append(_raw_norm)
            _labels.append(1 if _sev >= 3.0 else 0)  # high/critical → positive
            _func_names.append(vuln.get('function_name', 'unknown'))

    return {
        'raw_scores': _raw_scores,
        'labels': _labels,
        'function_names': _func_names,
        'sample_count': len(_raw_scores),
        'positive_ratio': round(sum(_labels) / max(1, len(_labels)), 3),
    }


# ---------------------------------------------------------------------------
# 模块级门面函数——保持外部调用兼容
# ---------------------------------------------------------------------------
def get_statistics(statistic_type: str, analysis_history: List[Dict[str, Any]],
                   **kwargs) -> APIResponse:
    # 2026-08-02: StatisticType[statistic_type.upper()] 在输入不匹配任何 enum member 时
    # 抛 KeyError 后静默返回空响应，调用方无感知。
    # 改为两阶段查找：先 value 匹配（大小写不敏感），再 name 匹配（兼容旧行为），
    # 全部失败时返回带 error 信息的响应。
    # 保留注释掉的旧实现作为考古标记。
    # - old: stat_type = StatisticType[statistic_type.upper()]
    api = MultiDimensionStatsAPI()

    # Phase 1: value 匹配（大小写不敏感）
    stat_type = None
    _normalized = statistic_type.strip().lower()
    for _member in StatisticType:
        if _member.value == _normalized:
            stat_type = _member
            break

    # Phase 2: 回退到 name 匹配（旧行为兼容）
    if stat_type is None:
        try:
            stat_type = StatisticType[statistic_type.upper()]
        except KeyError:
            pass

    # Phase 3: 仍无匹配 → 返回含有效选项的 error 响应
    if stat_type is None:
        valid = sorted([m.value for m in StatisticType])
        return APIResponse(
            statistic_type=StatisticType.ANALYSIS_METRICS,
            data={'error': f'Unknown statistic_type: {statistic_type!r}',
                  'valid_options': valid},
            timestamp=api._get_timestamp())

    # 分发路由
    if stat_type == StatisticType.VULNERABILITY_DISTRIBUTION:
        return api.get_vulnerability_distribution(analysis_history)
    elif stat_type == StatisticType.HIGH_RISK_FUNCTIONS:
        return api.get_high_risk_functions(analysis_history,
                                           call_graph=kwargs.get('call_graph'))
    elif stat_type == StatisticType.SEVERITY_TREND:
        return api.get_severity_trend(analysis_history)
    elif stat_type == StatisticType.ANALYSIS_METRICS:
        return api.get_analysis_metrics(analysis_history)
    elif stat_type == StatisticType.EXPLOITABILITY_SCORES:
        return api.get_exploitability_scores(analysis_history)
    elif stat_type == StatisticType.RISK_MATRIX:
        return api.get_risk_matrix(analysis_history)
    elif stat_type == StatisticType.CORRELATION_ANALYSIS:
        report = api.get_full_correlation_analysis(analysis_history)
        return APIResponse(
            statistic_type=StatisticType.CORRELATION_ANALYSIS,
            data=report.to_dict(),
            timestamp=api._get_timestamp())
    elif stat_type == StatisticType.CHANGE_POINTS:
        results = api.get_change_points(analysis_history)
        return APIResponse(
            statistic_type=StatisticType.CHANGE_POINTS,
            data=[r.to_dict() for r in results],
            timestamp=api._get_timestamp())
    elif stat_type == StatisticType.OOD_ANALYSIS:
        report = api.detect_ood_vulnerabilities(analysis_history)
        return APIResponse(
            statistic_type=StatisticType.OOD_ANALYSIS,
            data=report.to_dict(),
            timestamp=api._get_timestamp())
    elif stat_type == StatisticType.REMEDIATION_ORDER:
        order = api.remediation_order(analysis_history)
        return APIResponse(
            statistic_type=StatisticType.REMEDIATION_ORDER,
            data=order,
            timestamp=api._get_timestamp())

    # 理论上不可达，防御性兜底
    return APIResponse(
        statistic_type=StatisticType.ANALYSIS_METRICS,
        data={'error': f'Unhandled statistic_type: {stat_type}'},
        timestamp=api._get_timestamp())


# ============================================================================
# Pareto 前沿——严重度 vs 修复成本的多目标非支配排序
# 参考：Deb et al. A Fast Elitist Non-dominated Sorting Genetic Algorithm
#       (NSGA-II). IEEE TEC 2002.
# 给定多个修复方案（严重度降低 vs 工时），求非支配方案集
# ============================================================================

def pareto_frontier(objectives: List[Tuple[float, float]],
                     minimize: Tuple[bool, bool] = (False, True)
                     ) -> List[Tuple[float, float, int]]:
    """2D Pareto 前沿计算。

    objectives: [(severity_reduction, effort_hours), ...]
    minimize[0]=False → 第一个目标最大化（严重度降低越多越好）
    minimize[1]=True → 第二个目标最小化（工时越少越好）

    返回前沿点及其在原列表中的索引。
    O(N²) 非支配排序，N<1000 时足够。
    """
    _N = len(objectives)
    if _N < 2:
        return [(objectives[0][0], objectives[0][1], 0)] if _N == 1 else []

    # 方向归一化：统一转为"越小越好"
    def _normalize(pt: Tuple[float, float]) -> Tuple[float, float]:
        _f0 = -pt[0] if not minimize[0] else pt[0]
        _f1 = pt[1] if minimize[1] else -pt[1]
        return (_f0, _f1)

    _normed = [_normalize(obj) for obj in objectives]
    _dominated = [False] * _N

    for _i in range(_N):
        if _dominated[_i]:
            continue
        for _j in range(_N):
            if _i == _j or _dominated[_j]:
                continue
            # i dominates j: i 在所有目标上 ≤ j，且至少一个严格 <
            _a, _b = _normed[_i], _normed[_j]
            if _a[0] <= _b[0] and _a[1] <= _b[1] and (_a[0] < _b[0] or _a[1] < _b[1]):
                _dominated[_j] = True
            elif _b[0] <= _a[0] and _b[1] <= _a[1] and (_b[0] < _a[0] or _b[1] < _a[1]):
                _dominated[_i] = True

    _frontier = [(objectives[_i][0], objectives[_i][1], _i)
                 for _i in range(_N) if not _dominated[_i]]
    # 按第一个目标排序，便于可视化
    _frontier.sort(key=lambda p: p[0], reverse=not minimize[0])
    return _frontier


# ============================================================================
# Benjamini-Hochberg FDR 控制——多重假设检验的假发现率控制
# 参考：Benjamini & Hochberg. Controlling the FDR. JRSS-B 1995.
# 同时测试多个漏洞是否为"真正高危"时，BH 过程控制 FDR ≤ alpha
# ============================================================================

def benjamini_hochberg(p_values: List[float],
                         alpha: float = 0.05) -> List[bool]:
    """Benjamini-Hochberg 过程：控制 FDR 在 alpha 水平。

    p_values: 各漏洞的 p 值（越小→"该漏洞为高危"的证据越强）。
    返回布尔列表：True = 拒绝原假设（判定为高危）。

    步骤：
    1. p 值升序排列
    2. 找最大 k 使得 p_(k) ≤ k/m · alpha
    3. 拒绝前 k 个假设
    """
    _m = len(p_values)
    if _m == 0:
        return []

    _indexed = sorted(enumerate(p_values), key=lambda x: x[1])
    _k_max = 0
    for _rank, (_, _pv) in enumerate(_indexed, 1):
        _threshold = _rank / _m * alpha
        if _pv <= _threshold:
            _k_max = _rank

    _rejected = [False] * _m
    for _rank, (_orig_idx, _) in enumerate(_indexed, 1):
        if _rank <= _k_max:
            _rejected[_orig_idx] = True
    return _rejected


# ============================================================================
# 幂律拟合——漏洞分布在函数间常遵循 Zipf/幂律
# 参考：Clauset et al. Power-Law Distributions in Empirical Data.
#       SIAM Review 2009.
# 对漏洞计数做 log-log 线性回归，估计幂律指数 α
# ============================================================================

def fit_power_law(counts: List[int]) -> Dict[str, float]:
    """幂律拟合：P(X > x) ∝ x^{-α+1}，P(X = x) ∝ x^{-α}。

    对 log(count) vs log(rank) 做最小二乘线性回归。
    α ≈ -slope + 1（针对 CCDF）。

    返回：{'alpha': 幂律指数, 'xmin': 最小截断, 'r_squared': 拟合优度}。
    若 α < 2，分布具有无限方差——极端集中可能发生。
    """
    _pos = [c for c in counts if c > 0]
    if len(_pos) < 5:
        return {'alpha': 0.0, 'xmin': 0, 'r_squared': 0.0}

    # 按值降序 → rank vs value 双对数线性回归
    _sorted = sorted(_pos, reverse=True)
    _xmin = min(_sorted)
    _use = [v for v in _sorted if v >= _xmin]
    _n = len(_use)

    # log-log OLS
    _log_rank = [math.log(i+1) for i in range(_n)]
    _log_val = [math.log(v) for v in _use]
    _mean_r = sum(_log_rank)/_n
    _mean_v = sum(_log_val)/_n
    _num = sum((_log_rank[i]-_mean_r)*(_log_val[i]-_mean_v) for i in range(_n))
    _den = sum((_log_rank[i]-_mean_r)**2 for i in range(_n))
    _slope = _num/_den if _den > 1e-10 else -1.0
    _r2 = (_num/_den)**2 * (_den/sum((_log_val[i]-_mean_v)**2 for i in range(_n))) if _den > 1e-10 else 0.0
    _alpha = 1.0 - _slope  # CCDF 幂律关系

    return {'alpha': round(_alpha, 3), 'xmin': int(_xmin),
            'r_squared': round(min(1.0, max(0.0, _r2)), 4)}


# ============================================================================
# Granger 因果检验——检测漏洞类型变化的时序预测性
# 参考：Granger. Investigating Causal Relations by Econometric Models. 1969.
# 时序数据的自回归 + 交叉滞后 F 检验
# ============================================================================

def granger_causality_test(series_a: List[float], series_b: List[float],
                             max_lag: int = 3) -> Dict[str, Any]:
    """Granger 因果检验：B 的历史值是否能改善 A 的预测。

    原假设：B 不 Granger-cause A。
    受限模型：仅用 A 的滞后预测 A。
    完全模型：用 A 和 B 的滞后共同预测 A。
    F 统计量显著 → 拒绝原假设 → B 可能 Granger-cause A。

    注意：Granger 因果不等同于真实因果，仅检测时序预测性。
    """
    _n = len(series_a)
    if _n < max_lag + 10:
        return {'f_statistic': 0.0, 'p_value': 1.0, 'significant': False, 'optimal_lag': 0}

    _best_lag = 1
    _best_f = 0.0
    _best_p = 1.0

    for _lag in range(1, max_lag + 1):
        _eff_n = _n - _lag
        # 受限模型：A_t = α + Σ β_i A_{t-i}
        _resid_restricted: List[float] = []
        for _t in range(_lag, _n):
            _pred = sum(series_a[_t-_i-1] for _i in range(_lag)) / _lag
            _resid_restricted.append(series_a[_t] - _pred)

        # 完全模型：A_t = α + Σ β_i A_{t-i} + Σ γ_i B_{t-i}
        _resid_full: List[float] = []
        for _t in range(_lag, _n):
            _pred_a = sum(series_a[_t-_i-1] for _i in range(_lag)) / _lag
            _pred_b = sum(series_b[_t-_i-1] for _i in range(_lag)) / _lag
            _pred = (_pred_a + _pred_b) / 2.0
            _resid_full.append(series_a[_t] - _pred)

        _rss_r = sum(r*r for r in _resid_restricted)
        _rss_f = sum(r*r for r in _resid_full)
        if _rss_f < 1e-10:
            continue
        _f_stat = ((_rss_r - _rss_f) / _lag) / (_rss_f / (_eff_n - 2*_lag - 1))
        if _f_stat > _best_f:
            _best_f = _f_stat
            _best_lag = _lag
            # 简化 p 值：F → 卡方近似
            _best_p = 1.0 - math.erf(math.sqrt(_f_stat/_lag) / math.sqrt(2.0))

    return {
        'f_statistic': round(_best_f, 3),
        'p_value': round(max(0.0, min(1.0, _best_p)), 4),
        'significant': _best_p < 0.05,
        'optimal_lag': _best_lag,
    }
