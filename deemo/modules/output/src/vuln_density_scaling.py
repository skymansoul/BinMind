"""
漏洞密度标度律 — 二进制大小→期望漏洞数的幂律模型 + 离群检测。

问题定义:
  一个 50KB 的二进制有 3 个漏洞 vs 一个 5MB 的二进制有 3 个漏洞 —
  同样的漏洞数量，风险含义完全不同。需要一种方法来判定:
  "这个二进制的漏洞密度是否异常偏高/偏低?"

  全网检索 "vulnerability density scaling law binary" 零结果。
  软件工程领域有缺陷密度研究 (缺陷/KLOC)，但:
    1. 面向源代码，不是二进制
    2. 不区分缺陷和安全漏洞
    3. 假设线性关系 (缺陷 ∝ KLOC)，但二进制中往往是幂律

  本模块的幂律假设: vuln_count ∝ (binary_size_KB)^α
    α ≈ 0.5-0.7 — 大二进制的漏洞增长是次线性的
    (10× 大小 → ~3-5× 漏洞，而非 10×)

  输出: 实际漏洞数 vs 期望漏洞数 → 偏差分 (z-score) → 异常标记。

  异常偏高的二进制 → "值得深度审计"。
  异常偏低的二进制 → "可能存在分析盲区 (加壳/混淆/非标准编译)"。

参考:
  Alhazmi-Malaiya VDM (2005-2007): 源代码级漏洞发现模型。
  本模块差异化: 二进制级 + 幂律 (非线性) + 离群检测。

修改记录:
  2026-08-02 14:08 - 初始版本，幂律标度 + z-score 离群检测
"""

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# 默认幂律指数 — 基于经验观察，后续可用数据集校准
_DEFAULT_ALPHA = 0.55
# 缩放常数: 一个 100KB 的二进制期望约 1.5 个漏洞
_DEFAULT_K = 0.12


@dataclass
class DensityScore:
    """单二进制漏洞密度评估。"""
    binary_name: str
    binary_size_kb: float
    import_count: int
    actual_vuln_count: int
    expected_vuln_count: float      # 幂律预测值
    z_score: float                  # (actual - expected) / sqrt(expected)
    density_anomaly: str = 'normal' # sparse / normal / dense / extreme
    flag: str = ''                  # 行动建议


def _expected_vulns(
    size_kb: float,
    import_count: int = 0,
    alpha: float = _DEFAULT_ALPHA,
    k: float = _DEFAULT_K,
) -> float:
    """
    幂律期望漏洞数: E[V] = k × size^α × (1 + β×log(imports+1))

    导入项修正: 导入越多→攻击面越大→期望漏洞略增。
    β = 0.15 是保守值。
    """
    base = k * (size_kb ** alpha)
    if import_count > 0:
        import_bonus = 0.15 * math.log2(import_count + 1)
        base *= (1.0 + import_bonus)
    return base


def _anomaly_label(z_score: float) -> str:
    az = abs(z_score)
    if az >= 3.0:
        return 'extreme'
    if az >= 2.0:
        return 'dense' if z_score > 0 else 'sparse'
    return 'normal'


def _generate_flag(z_score: float, actual: int, expected: float) -> str:
    if z_score >= 3.0:
        return (f'漏洞密度异常偏高 ({actual} vs 期望 {expected:.1f}) — '
                '建议优先深度审计此二进制')
    if z_score >= 2.0:
        return (f'漏洞密度偏高 ({actual} vs 期望 {expected:.1f}) — '
                '可能存在系统性安全缺陷')
    if z_score <= -2.0:
        return (f'漏洞密度异常偏低 ({actual} vs 期望 {expected:.1f}) — '
                '分析可能存在盲区 (加壳/混淆/非标准编译)')
    if z_score <= -1.5:
        return (f'漏洞密度偏低 ({actual} vs 期望 {expected:.1f}) — '
                '可能分析不完整')
    return ''


def assess_density(
    binary_name: str = '',
    binary_size_kb: float = 100.0,
    import_count: int = 0,
    actual_vuln_count: int = 0,
    alpha: float = _DEFAULT_ALPHA,
    k: float = _DEFAULT_K,
) -> DensityScore:
    """
    评估单个二进制的漏洞密度。

    返回 DensityScore，含期望值、z-score、异常标记。
    """
    expected = _expected_vulns(binary_size_kb, import_count, alpha, k)
    # z-score 使用 Poisson 近似的标准差: σ = sqrt(expected)
    std = math.sqrt(max(expected, 0.5))
    z = round((actual_vuln_count - expected) / std, 2) if std > 0 else 0.0

    return DensityScore(
        binary_name=binary_name or 'unknown',
        binary_size_kb=binary_size_kb,
        import_count=import_count,
        actual_vuln_count=actual_vuln_count,
        expected_vuln_count=round(expected, 2),
        z_score=z,
        density_anomaly=_anomaly_label(z),
        flag=_generate_flag(z, actual_vuln_count, expected),
    )


def batch_density(
    binaries: List[Dict[str, Any]],
    alpha: float = _DEFAULT_ALPHA,
    k: float = _DEFAULT_K,
) -> List[DensityScore]:
    """
    批量评估 — 按 |z_score| 降序 (最异常的排前面)。
    """
    results = []
    for b in binaries:
        score = assess_density(
            binary_name=b.get('name', b.get('binary_name', '')),
            binary_size_kb=b.get('size_kb', b.get('binary_size_kb', 100)),
            import_count=b.get('import_count', 0),
            actual_vuln_count=b.get('vuln_count', b.get('actual_vuln_count', 0)),
            alpha=alpha, k=k,
        )
        results.append(score)
    results.sort(key=lambda s: abs(s.z_score), reverse=True)
    return results


def density_summary(results: List[DensityScore]) -> Dict[str, Any]:
    """漏洞密度评估统计摘要。"""
    if not results:
        return {'total': 0, 'extreme': 0, 'dense': 0, 'sparse': 0, 'normal': 0}

    anomaly_counts = defaultdict(int)
    flags = []
    for r in results:
        anomaly_counts[r.density_anomaly] += 1
        if r.flag:
            flags.append({'binary': r.binary_name, 'z_score': r.z_score, 'flag': r.flag})

    return {
        'total_binaries': len(results),
        'extreme_outliers': anomaly_counts.get('extreme', 0),
        'dense': anomaly_counts.get('dense', 0),
        'sparse': anomaly_counts.get('sparse', 0),
        'normal': anomaly_counts.get('normal', 0),
        'flagged': flags[:5],
        'alpha_used': _DEFAULT_ALPHA,
        'scaling_law': f'E[V] = {_DEFAULT_K} × size^{_DEFAULT_ALPHA}',
    }
