"""
统计显著性检验 -- McNemar配对检验 + Bootstrap置信区间 + Cohen's h效应量。

用途:
  比较两个检测工具在同一批样本上的表现差异是否统计显著。
  输入: comparison_results.json (由compare_tools.py生成)
  输出: p值, 效应量, Bootstrap 95% CI

McNemar检验:
  适用场景——两个分类器在相同样本上的配对二分类结果(检出/未检出)。
  H0: 两个工具检出率无差异
  统计量: (|b - c| - 1)^2 / (b + c) ~ χ²(1)
  其中 b = 工具A检出但B未检出的样本数, c = 工具B检出但A未检出的样本数

Bootstrap置信区间:
  对检出率差异做B=2000次重抽样, 取α/2和1-α/2分位数。
  不依赖渐近正态假设, 适用于小样本。

Cohen's h:
  效应量 = 2 * |arcsin(sqrt(p1)) - arcsin(sqrt(p2))|
  小效应: 0.2, 中效应: 0.5, 大效应: 0.8

  - Dietterich, 1998, Neural Computation, "Approximate Statistical Tests for
    Comparing Supervised Classification Learning Algorithms"
  - McNemar, 1947, Psychometrika, "Note on the sampling error of the difference"
"""

import json, math, random, sys
from collections import defaultdict
from typing import Any, Dict, List, Tuple

def load_results(path: str) -> List[Dict[str, Any]]:
    with open(path) as f:
        data = json.load(f)
    return data.get('results', data if isinstance(data, list) else [])

def mcnemar_test(pairs: List[Tuple[bool, bool]]) -> Dict[str, float]:
    """McNemar配对检验。

    pairs: [(tool_a_detected, tool_b_detected), ...] 每样本一对布尔值

    Returns: {statistic, p_value, b, c, n}
      b = A检出B未检出, c = B检出A未检出
    """
    b = sum(1 for da, db in pairs if da and not db)
    c = sum(1 for da, db in pairs if not da and db)

    n = len(pairs)
    if b + c == 0:
        return {'statistic': 0.0, 'p_value': 1.0, 'b': b, 'c': c, 'n': n}

    # 连续性校正的McNemar统计量
    stat = (abs(b - c) - 1) ** 2 / (b + c)
    # χ²(1)生存函数: p = 1 - F(stat; df=1)
    p_val = _chi2_survival(stat, 1)

    return {'statistic': round(stat, 4), 'p_value': round(p_val, 4),
            'b': b, 'c': c, 'n': n}

def bootstrap_ci(detections_a: List[bool], detections_b: List[bool],
                 n_bootstrap: int = 2000, alpha: float = 0.05
                 ) -> Dict[str, float]:
    """Bootstrap检出率差异的置信区间。

    Returns: {diff_mean, ci_lower, ci_upper, p_a, p_b}
    """
    n = len(detections_a)
    if n < 3:
        return {'diff_mean': 0, 'ci_lower': -1, 'ci_upper': 1, 'p_a': 0, 'p_b': 0}

    random.seed(42)
    diffs = []
    for _ in range(n_bootstrap):
        indices = [random.randint(0, n - 1) for _ in range(n)]
        p_a = sum(detections_a[i] for i in indices) / n
        p_b = sum(detections_b[i] for i in indices) / n
        diffs.append(p_a - p_b)

    diffs.sort()
    lo = int(alpha / 2 * n_bootstrap)
    hi = int((1 - alpha / 2) * n_bootstrap)

    return {
        'diff_mean': round(sum(diffs) / n_bootstrap, 4),
        'ci_lower': round(diffs[lo], 4),
        'ci_upper': round(diffs[hi], 4),
        'p_a': round(sum(detections_a) / n, 3),
        'p_b': round(sum(detections_b) / n, 3),
    }

def cohens_h(p1: float, p2: float) -> float:
    """Cohen's h效应量——两个比例的差异度量。

    小:0.2, 中:0.5, 大:0.8
    """
    return round(2 * abs(math.asin(math.sqrt(max(1e-9, p1)))
                        - math.asin(math.sqrt(max(1e-9, p2)))), 4)

def compare_tools_statistically(results_path: str,
                                tool_a: str = 'binmind',
                                tool_b: str = 'angr') -> Dict[str, Any]:
    """对两个工具的检出结果进行完整统计比较。

    Returns:
      {mcnemar, bootstrap, cohens_h, interpretation}
    """
    results = load_results(results_path)
    if not results:
        return {'error': 'no results'}

    # 按样本分组, 提取配对检出结果
    by_sample: Dict[str, Dict[str, bool]] = defaultdict(dict)
    for r in results:
        tool = r.get('tool', '')
        sample = r.get('sample', '')
        detected = r.get('detections', r.get('detected', 0)) > 0
        by_sample[sample][tool] = detected

    # 只保留两个工具都有结果的样本
    pairs = []
    det_a, det_b = [], []
    for sample, tools in by_sample.items():
        if tool_a in tools and tool_b in tools:
            pairs.append((tools[tool_a], tools[tool_b]))
            det_a.append(tools[tool_a])
            det_b.append(tools[tool_b])

    if not pairs:
        return {'error': f'no samples with both {tool_a} and {tool_b}'}

    mcn = mcnemar_test(pairs)
    boot = bootstrap_ci(det_a, det_b)
    h = cohens_h(boot['p_a'], boot['p_b'])

    # 解释
    if mcn['p_value'] < 0.01:
        interp = 'strong evidence for difference (p < 0.01)'
    elif mcn['p_value'] < 0.05:
        interp = 'moderate evidence for difference (p < 0.05)'
    else:
        interp = 'no significant difference (p >= 0.05)'

    eff_interp = ('large' if h >= 0.8 else 'medium' if h >= 0.5
                  else 'small' if h >= 0.2 else 'negligible')

    return {
        'tool_a': tool_a, 'tool_b': tool_b,
        'n_paired_samples': len(pairs),
        'mcnemar': mcn,
        'bootstrap_ci': boot,
        'cohens_h': h,
        'effect_size': eff_interp,
        'interpretation': interp,
    }

def _chi2_survival(x: float, df: int) -> float:
    """χ²分布的尾部概率(Wilson-Hilferty近似)。"""
    if x <= 0:
        return 1.0
    z = ((x / df) ** (1.0 / 3.0) - 1.0 + 2.0 / (9.0 * df)) / math.sqrt(2.0 / (9.0 * df))
    return 1.0 - _normal_cdf(z)

def _normal_cdf(x: float) -> float:
    if x < -8: return 0.0
    if x > 8: return 1.0
    t = 1.0 / (1.0 + 0.2316419 * abs(x))
    poly = ((((1.330274429*t - 1.821255978)*t + 1.781477937)*t
             - 0.356563782)*t + 0.319381530)*t
    phi = poly * math.exp(-x*x/2) / math.sqrt(2*math.pi)
    return 1.0 - phi if x >= 0 else phi

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python statistical_tests.py <comparison_results.json> [tool_a] [tool_b]")
        sys.exit(1)
    path = sys.argv[1]
    ta = sys.argv[2] if len(sys.argv) > 2 else 'binmind'
    tb = sys.argv[3] if len(sys.argv) > 3 else 'angr'
    result = compare_tools_statistically(path, ta, tb)
    print(json.dumps(result, indent=2))
