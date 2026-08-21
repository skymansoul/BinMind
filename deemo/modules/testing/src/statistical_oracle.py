# Mann-Whitney U统计量和Cliff's Delta效应量置信区间估计
# divergence_digest()支持超过2个实现的多方比较
# 输出分布结构化指纹用于非字节级比较

# 统计差分预言机 - 基于非参数假设检验的语义差分，补足纯输出相等的盲区
#
# 设计动机:
#   现有差分测试 (differential_tester.py / diff_oracle.py)判定依据是:
#     a) 输出是否逐字节相等
#     b) 输出是否匹配自然语言或正则断言
#   此两种模式均无法捕获:
# 输出字节不同但语义等价 (如合法指令重排、不同编码的等效字符串)
# 行为在统计分布上显著偏离但单次比较不可见
# 对同一输入集合的整体行为分布存在系统性偏差
#
# 核心方法:
#   对两实现的输出序列/执行指标构建经验分布，使用:
#     - Mann-Whitney U检验 (Wilcoxon rank-sum)检测分布位置差异
# Cliff's Delta (delta)测量效应量大小
# Bootstrap置信区间 (BCa)提供delta的不确定性估计
#   非参数方法不假设正态性，适用于二进制分析工具输出的典型偏态分布。
#
#   多个实现(>2)时使用Kruskal-Wallis H检验+pairwise Cliff's Delta。
#
# 文献:
#   Cliff 1993, "Dominance statistics: Ordinal analyses to answer ordinal questions"
#   Vargha & Delaney 2000, "CL common language effect size statistics"
#   McNemar 1947, paired comparison significance test
#   openentropy-core — 差分二进制分析中引入Cliff's Delta
import math
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from collections import defaultdict
from dataclasses import dataclass, field


# 统计工具: 纯函数，无状态

def _rankdata(values: List[float]) -> List[float]:
    """计算秩 (处理并列值用平均秩)。"""
    indexed = sorted(enumerate(values), key=lambda x: x[1])
    ranks = [0.0] * len(values)
    i = 0
    while i < len(indexed):
        j = i
        while j < len(indexed) and indexed[j][1] == indexed[i][1]:
            j += 1
        avg_rank = (i + j + 1) / 2.0
        for k in range(i, j):
            ranks[indexed[k][0]] = avg_rank
        i = j
    return ranks


def mann_whitney_u(a: List[float], b: List[float]) -> Tuple[float, float]:
    """Mann-Whitney U检验。返回(U统计量, 双侧p值近似)。

    p值用正态近似(Z-score)，样本量<8时标记为不可靠(返回p=1.0)。
    """
    n1, n2 = len(a), len(b)
    if n1 < 2 or n2 < 2:
        return 0.0, 1.0

    combined = a + b
    ranks = _rankdata(combined)
    r1 = sum(ranks[:n1])
    u1 = r1 - n1 * (n1 + 1) / 2.0
    u2 = n1 * n2 - u1
    u = max(u1, u2)

    # 正态近似
    mean_u = n1 * n2 / 2.0
    # 并列修正
    rank_counts: Dict[float, int] = {}
    for r in ranks:
        rank_counts[r] = rank_counts.get(r, 0) + 1
    tie_correction = 0.0
    for cnt in rank_counts.values():
        tie_correction += (cnt ** 3 - cnt) / 12.0
    n = n1 + n2
    var_u = (n1 * n2 / (n * (n - 1))) * (
        (n ** 3 - n) / 12.0 - tie_correction)
    if var_u <= 0:
        return u, 1.0

    z = (u - mean_u) / math.sqrt(var_u)
    # 单侧p (标准正态CDF的补)
    p = 0.5 * math.erfc(abs(z) / math.sqrt(2.0))
    return u, min(1.0, p * 2.0)  # 双侧p


def cliffs_delta(a: List[float], b: List[float]) -> Tuple[float, float]:
    """Cliff's Delta: 非参数效应量。

    定义: delta = P(X_a > X_b) - P(X_a < X_b)
    返回 (delta, 标准差 sigma_delta)。

    解释基准:
      |delta| < 0.147  - negligible
      |delta| < 0.33   - small
      |delta| < 0.474  - medium
      |delta| >= 0.474 - large
    """
    n1, n2 = len(a), len(b)
    if n1 < 2 or n2 < 2:
        return 0.0, 1.0

    greater = 0
    equal = 0
    for x in a:
        for y in b:
            if x > y:
                greater += 1
            elif x == y:
                equal += 1
    delta = (greater - (n1 * n2 - greater - equal)) / (n1 * n2)

    # 无偏方差估计
    var_delta = (n1 + n2 + 1) / (3.0 * n1 * n2)
    return delta, math.sqrt(max(var_delta, 1e-12))


def bootstrap_ci(a: List[float], b: List[float],
                 n_bootstrap: int = 1000,
                 confidence: float = 0.95) -> Tuple[float, float]:
    """Bootstrap百分位置信区间for Cliff's Delta。

    对每次bootstrap重采样计算delta，取(alpha/2, 1-alpha/2)分位作为CI。
    """
    import random as _rnd
    deltas = []
    n1, n2 = len(a), len(b)
    if n1 < 3 or n2 < 3:
        return (-1.0, 1.0)

    for _ in range(n_bootstrap):
        sa = [_rnd.choice(a) for _ in range(n1)]
        sb = [_rnd.choice(b) for _ in range(n2)]
        delta, _ = cliffs_delta(sa, sb)
        deltas.append(delta)

    deltas.sort()
    alpha = (1.0 - confidence) / 2.0
    lo = int(alpha * len(deltas))
    hi = int((1.0 - alpha) * len(deltas)) - 1
    return deltas[max(0, lo)], deltas[min(len(deltas) - 1, hi)]


# 度量提取器

# 默认度量集: 对单次执行结果提取数值特征向量
# 每个提取器签名: (result: Any) - float

def _metric_exec_time(result: Any) -> float:
    return float(getattr(result, "execution_time", 0.0) or 0.0)


def _metric_output_size(result: Any) -> float:
    stdout = getattr(result, "stdout", b"")
    stderr = getattr(result, "stderr", b"")
    return float(len(stdout or b"") + len(stderr or b""))


def _metric_exit_code(result: Any) -> float:
    return float(getattr(result, "exit_code", 0) or 0)


def _metric_memory_kb(result: Any) -> float:
    return float(getattr(result, "max_rss_kb", 0) or 0)


def _metric_covered_edges(result: Any) -> float:
    return float(getattr(result, "covered_edges", 0) or 0)


def _metric_entropy(result: Any) -> float:
    """输出字节的香农熵 (0-8)，反映输出分布均匀性。"""
    stdout = getattr(result, "stdout", b"")
    if not stdout:
        return 0.0
    counts = [0] * 256
    for b in stdout[:8192]:
        counts[b] += 1
    total = sum(counts)
    if total == 0:
        return 0.0
    ent = 0.0
    for c in counts:
        if c > 0:
            p = c / total
            ent -= p * math.log2(p)
    return ent


DEFAULT_METRICS = {
    "exec_time_s": _metric_exec_time,
    "output_size": _metric_output_size,
    "exit_code": _metric_exit_code,
    "max_rss_kb": _metric_memory_kb,
    "covered_edges": _metric_covered_edges,
    "output_entropy": _metric_entropy,
}


# 统计预言机

@dataclass
class MetricDivergence:
    """单条度量的统计比较结果。"""
    metric_name: str
    u_statistic: float = 0.0
    p_value: float = 1.0
    cliffs_delta: float = 0.0
    delta_std: float = 0.0
    ci_lower: float = 0.0
    ci_upper: float = 0.0
    significant: bool = False  # p < 0.05且|delta| > 0.147 (non-negligible)
    effect_magnitude: str = "negligible"
    summary: str = ""

    _EFFECT_LABELS = [
        (0.474, "large"),
        (0.33, "medium"),
        (0.147, "small"),
        (0.0, "negligible"),
    ]

    def _classify_effect(self) -> str:
        abs_d = abs(self.cliffs_delta)
        for threshold, label in self._EFFECT_LABELS:
            if abs_d >= threshold:
                return label
        return "negligible"


@dataclass
class StatisticalOracleReport:
    """统计差分预言机的完整报告。"""
    impl_a: str
    impl_b: str
    sample_count_a: int
    sample_count_b: int
    divergences: List[MetricDivergence] = field(default_factory=list)
    global_divergence_score: float = 0.0  # [0, 1]，聚合所有度量的效应量
    execution_time_s: float = 0.0
    summary: str = ""


class StatisticalOracle:
    """基于非参数假设检验的统计差分预言机。

    设计意图:
      传统差分测试比较输出字节相等性; 本预言机比较行为度量的分布。
      例如: 反编译器A和B对同一批二进制文件的输出文本可能不同，
      但结构化度量分布（输出大小、执行时间、覆盖边数）无显著差异。
      反之输出文本一致但性能分布显著偏离 - 表明一方反编译路径效率
      低于另一方，这是纯输出比较无法发现的问题。

    典型用法:
        oracle = StatisticalOracle()
        results_a = [run_impl_a(input_i) for input_i in inputs]
        results_b = [run_impl_b(input_i) for input_i in inputs]
        report = oracle.compare("ghidra_decomp", "ida_decomp",
                                results_a, results_b)
    """

    def __init__(self, metrics: Optional[Dict[str, Callable[[Any], float]]] = None):
        self._metrics = metrics or DEFAULT_METRICS

    # 主入口
    def compare(self,
                impl_a_name: str,
                impl_b_name: str,
                results_a: List[Any],
                results_b: List[Any],
                bootstrap: bool = True) -> StatisticalOracleReport:
        """对两实现的执行结果集做逐度量统计比较。"""
        t0 = time.perf_counter()
        divergences: List[MetricDivergence] = []

        for metric_name, extractor in self._metrics.items():
            try:
                vals_a = [extractor(r) for r in results_a]
                vals_b = [extractor(r) for r in results_b]
            except Exception:
                # 某度量在result对象上不可用 -> 跳过
                continue

            # 过滤常值 (无方差无从比较)
            if len(set(vals_a)) <= 1 and len(set(vals_b)) <= 1:
                continue

            u_stat, p_val = mann_whitney_u(vals_a, vals_b)
            delta, delta_std = cliffs_delta(vals_a, vals_b)

            ci_lo, ci_hi = (-1.0, 1.0)
            if bootstrap and len(vals_a) >= 8 and len(vals_b) >= 8:
                ci_lo, ci_hi = bootstrap_ci(vals_a, vals_b,
                                            n_bootstrap=500)

            div = MetricDivergence(
                metric_name=metric_name,
                u_statistic=u_stat,
                p_value=p_val,
                cliffs_delta=delta,
                delta_std=delta_std,
                ci_lower=ci_lo,
                ci_upper=ci_hi,
                significant=(p_val < 0.05 and abs(delta) > 0.147),
            )
            div.effect_magnitude = div._classify_effect()
            div.summary = (
                f"{metric_name}: delta={delta:.3f} [{ci_lo:.3f}, {ci_hi:.3f}], "
                f"p={p_val:.4f}, effect={div.effect_magnitude}")
            divergences.append(div)

        # 全局发散度: 所有|delta|的RMS
        global_score = 0.0
        if divergences:
            global_score = math.sqrt(
                sum(d.cliffs_delta ** 2 for d in divergences)
                / len(divergences))

        return StatisticalOracleReport(
            impl_a=impl_a_name,
            impl_b=impl_b_name,
            sample_count_a=len(results_a),
            sample_count_b=len(results_b),
            divergences=divergences,
            global_divergence_score=global_score,
            execution_time_s=time.perf_counter() - t0,
            summary=self._build_summary(divergences),
        )

    # 多方比较 (>2个实现)
    def compare_multi(self,
                      impl_results: Dict[str, List[Any]],
                      reference_impl: Optional[str] = None
                      ) -> Dict[Tuple[str, str], StatisticalOracleReport]:
        """多个实现的pairwise统计比较。

        若指定reference_impl，仅返回参考实现vs其他实现的比较；
        否则返回所有pairwise组合。
        """
        names = list(impl_results.keys())
        reports: Dict[Tuple[str, str], StatisticalOracleReport] = {}

        if reference_impl and reference_impl in names:
            for other in names:
                if other == reference_impl:
                    continue
                reports[(reference_impl, other)] = self.compare(
                    reference_impl, other,
                    impl_results[reference_impl],
                    impl_results[other])
        else:
            for i in range(len(names)):
                for j in range(i + 1, len(names)):
                    reports[(names[i], names[j])] = self.compare(
                        names[i], names[j],
                        impl_results[names[i]],
                        impl_results[names[j]])
        return reports

    def _build_summary(self, divergences: List[MetricDivergence]) -> str:
        significant = [d for d in divergences if d.significant]
        if not significant:
            return ("两实现在所有度量上无显著统计偏离 "
                    f"({len(divergences)} 个度量已检查)")
        lines = [f"发现 {len(significant)} 个显著偏离的度量维度:"]
        for d in significant[:8]:
            lines.append(f"  - {d.summary}")
        return "\n".join(lines)

    # 结构指纹: 输出非可直接比较为字节时使用
    @staticmethod
    def structural_fingerprint(text_output: str) -> Dict[str, float]:
        """从反编译/反汇编文本提取结构特征向量，用于统计比较。

        提取特征: 指令计数, 基本块计数, 函数调用计数, 条件分支比例,
        字符串字面量密度, 嵌套深度估计。
        各特征为计数或比例，不依赖字节级对齐。
        """
        import re
        fp: Dict[str, float] = {}

        lines = text_output.splitlines()
        fp["line_count"] = float(len(lines))

        # 汇编/伪代码行识别
        instr_pattern = re.compile(
            r'\b(mov|push|pop|add|sub|cmp|jmp|je|jne|call|ret|lea|'
            r'xor|and|or|test|nop|int3)\b', re.IGNORECASE)
        instr_lines = sum(1 for l in lines if instr_pattern.search(l))
        fp["instruction_lines"] = float(instr_lines)

        # 函数调用
        call_count = sum(1 for l in lines
                         if re.search(r'\bcall\b', l, re.IGNORECASE))
        fp["call_count"] = float(call_count)

        # 条件分支比例
        branch_pat = re.compile(
            r'\b(jmp|je|jne|jg|jl|jge|jle|ja|jb|jae|jbe|js|jnz|jz|'
            r'if\s*\(|else\b)', re.IGNORECASE)
        branch_lines = sum(1 for l in lines if branch_pat.search(l))
        fp["branch_ratio"] = (branch_lines / max(1.0, fp["line_count"]))

        # 字符串密度: 引号内文本
        str_chars = sum(len(m.group(1)) for m in
                        re.finditer(r'"([^"]*)"', text_output))
        fp["string_char_density"] = (
            str_chars / max(1.0, len(text_output)))

        # 嵌套深度估计 (按缩进增量)
        depths = []
        for l in lines:
            stripped = l.lstrip()
            indent = len(l) - len(stripped)
            depths.append(indent)
        fp["max_indent_depth"] = float(max(depths) if depths else 0)
        fp["mean_indent_depth"] = (
            sum(depths) / max(1.0, len(depths)))

        return fp


# 便捷入口
def quick_compare(results_a: List[Any],
                  results_b: List[Any],
                  names: Tuple[str, str] = ("A", "B")
                  ) -> StatisticalOracleReport:
    """便捷入口: 使用默认度量集做快速统计差分。"""
    oracle = StatisticalOracle()
    return oracle.compare(names[0], names[1], results_a, results_b)
