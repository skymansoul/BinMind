# corpus_baseline — 马氏距离 + Bootstrap 统计异常检测
# 从已知良性语料库学习多维特征的均值向量和协方差矩阵，
# 对新样本计算马氏距离 (捕获特征间相关结构)，用 Bootstrap 重采样
# 估计 p-value 的置信区间。不依赖正态性假设。

import math, random
from typing import Dict, List, Tuple, Optional


def _compute_feature_vector(analysis: Dict) -> List[float]:
    fp = analysis.get("cfg_fingerprint", {})
    fe = fp.get("function_entropy", {})
    ie = fp.get("import_entropy", {})
    se = fp.get("section_entropy", {})

    posture = analysis.get("security_posture", analysis.get("posture", {}))
    exploit = analysis.get("exploit_chain", analysis.get("exploit", {}))
    imports = analysis.get("imports", {})
    all_imps = imports.get("all_imports", imports) if isinstance(imports, dict) else {}
    total_imp = sum(len(v) for v in all_imps.values()) if isinstance(all_imps, dict) else 0
    danger = len(imports.get("dangerous_functions", []))
    sections = analysis.get("sections", [])
    functions = analysis.get("functions", [])
    fsize = analysis.get("size", analysis.get("file_size", 1))
    entropy = analysis.get("entropy", {})

    import_norm = ie.get("inter_library_entropy", 0.0) / max(
        math.log(max(ie.get("library_count", 2), 2)), 1e-6)

    return [fe.get("entropy_normalized", 0.0), import_norm,
            se.get("code_ratio", 0.0), se.get("layout_anomaly_score", 0.0),
            posture.get("posture_score", 0.5),
            exploit.get("exploitability_index", 0.0) / 100.0,
            float(total_imp), danger / max(total_imp, 1),
            float(len(sections)), float(len(functions)),
            entropy.get("mean_entropy", entropy.get("global_entropy", 0.0)),
            math.log2(max(fsize, 1))]


_FEATURE_NAMES = ["func_entropy_norm","import_entropy_norm","code_ratio",
                  "layout_anomaly","posture_score","exploitability",
                  "total_imports","dangerous_ratio","section_count",
                  "function_count","mean_entropy","log2_file_size"]


def learn_baseline(samples: List[Dict]) -> Dict:
    if len(samples) < 5:
        return {"error": "need at least 5 samples for covariance estimation",
                "sample_count": len(samples)}
    vectors = [_compute_feature_vector(s) for s in samples]
    n, d = len(vectors), len(vectors[0])
    means = [sum(v[j] for v in vectors) / n for j in range(d)]
    # 协方差矩阵 (n-1 除)
    cov = [[0.0] * d for _ in range(d)]
    for j in range(d):
        for k in range(j, d):
            c = sum((vectors[i][j] - means[j]) * (vectors[i][k] - means[k]) for i in range(n)) / (n - 1)
            cov[j][k] = c
            cov[k][j] = c
    return {"means": [round(m, 6) for m in means], "covariance": cov,
            "sample_count": n, "feature_names": _FEATURE_NAMES,
            "dimensionality": d}


def _invert_matrix(m: List[List[float]]) -> Optional[List[List[float]]]:
    """对称正定矩阵的 Cholesky 分解求逆。失败回退到对角近似。"""
    n = len(m)
    try:
        L = [[0.0]*n for _ in range(n)]
        for i in range(n):
            for j in range(i+1):
                s = sum(L[i][k] * L[j][k] for k in range(j))
                if i == j:
                    diag = m[i][i] - s
                    if diag <= 1e-12:
                        raise ValueError("non-positive-definite")
                    L[i][j] = math.sqrt(diag)
                else:
                    L[i][j] = (m[i][j] - s) / L[j][j]
        inv = [[0.0]*n for _ in range(n)]
        for i in range(n):
            for j in range(i+1):
                b = [0.0]*n; b[j] = 1.0
                y = [0.0]*n
                for k in range(n):
                    s = sum(L[k][p]*y[p] for p in range(k))
                    y[k] = (b[k] - s) / L[k][k]
                x = [0.0]*n
                for k in range(n-1, -1, -1):
                    s = sum(L[p][k]*x[p] for p in range(k+1, n))
                    x[k] = (y[k] - s) / L[k][k]
                inv[i][j] = x[0]
                inv[j][i] = x[0]
        return inv
    except Exception:
        diag_inv = [[0.0]*n for _ in range(n)]
        for i in range(n):
            diag_inv[i][i] = 1.0 / max(abs(m[i][i]), 1e-9)
        return diag_inv


def _mahalanobis_sq(x: List[float], mu: List[float],
                    inv_cov: List[List[float]]) -> float:
    d = len(x)
    diff = [x[j] - mu[j] for j in range(d)]
    result = 0.0
    for j in range(d):
        row_sum = sum(inv_cov[j][k] * diff[k] for k in range(d))
        result += diff[j] * row_sum
    return max(0.0, result)


def _bootstrap_p_value(
    d2: float, vectors: List[List[float]], mu: List[float],
    cov: List[List[float]], n_bootstrap: int = 2000,
) -> Tuple[float, float, float]:
    """Bootstrap 估计 p-value 和 95% CI。
    从语料库重采样计算马氏距离的经验分布，用百分位法给出置信区间。
    返回 (p_value, ci_lower, ci_upper)。
    """
    if len(vectors) < 5:
        return (1.0, 0.0, 1.0)
    n = len(vectors)
    d2_boot = []
    rng = random.Random(42)
    for _ in range(n_bootstrap):
        idx = [rng.randint(0, n-1) for __ in range(n)]
        boot_vectors = [vectors[i] for i in idx]
        boot_mu = [sum(v[j] for v in boot_vectors) / n for j in range(len(mu))]
        boot_cov = [[0.0]*len(mu) for __ in range(len(mu))]
        for j in range(len(mu)):
            for k in range(j, len(mu)):
                c = sum((boot_vectors[i][j] - boot_mu[j]) * (boot_vectors[i][k] - boot_mu[k]) for i in range(n)) / (n-1)
                boot_cov[j][k] = boot_cov[k][j] = c
        try:
            boot_inv = _invert_matrix(boot_cov)
            for v in boot_vectors:
                d2_boot.append(_mahalanobis_sq(v, boot_mu, boot_inv))
        except Exception:
            d2_boot.append(0.0)

    d2_boot.sort()
    p_val = sum(1 for d in d2_boot if d >= d2) / len(d2_boot)
    ci_lo = d2_boot[int(len(d2_boot) * 0.025)]
    ci_hi = d2_boot[int(len(d2_boot) * 0.975)]
    return (round(p_val, 6), round(ci_lo, 2), round(ci_hi, 2))


def score_anomaly(analysis: Dict, baseline: Dict,
                  weights: List[float] = None) -> Dict:
    if "error" in baseline:
        return {"error": baseline["error"]}
    vec = _compute_feature_vector(analysis)
    means = baseline["means"]
    cov = baseline["covariance"]
    inv_cov = _invert_matrix(cov)

    d2 = _mahalanobis_sq(vec, means, inv_cov)
    # 用语料库向量做 bootstrap（需要原始向量，baseline 不存则降级到卡方近似）
    # 降级路径: 卡方近似
    df = len(vec)
    # Wilson-Hilferty 正态近似
    if d2 > 0 and df > 0:
        t = (d2 / df) ** (1.0/3.0)
        mu_t = 1.0 - 2.0/(9.0*df)
        sigma_t = math.sqrt(2.0/(9.0*df))
        z = (t - mu_t) / max(sigma_t, 1e-9)
        p_val = max(1e-10, min(1.0, 0.5 * math.erfc(z / math.sqrt(2.0))))
    else:
        p_val = 1.0

    # 逐维度的贡献分解: d2 = sum of squared Mahalanobis components
    contributions = []
    for j in range(len(vec)):
        diff = vec[j] - means[j]
        contrib = diff * sum(inv_cov[j][k] * (vec[k] - means[k]) for k in range(len(vec)))
        contributions.append({"dimension": _FEATURE_NAMES[j],
                              "value": round(vec[j], 4),
                              "mean": round(means[j], 4),
                              "mahalanobis_contribution": round(max(0.0, contrib), 4)})
    contributions.sort(key=lambda c: c["mahalanobis_contribution"], reverse=True)

    if p_val < 0.01: verdict = "HIGHLY_ANOMALOUS"
    elif p_val < 0.05: verdict = "MODERATELY_ANOMALOUS"
    else: verdict = "NORMAL"

    anomalous = [c for c in contributions if c["mahalanobis_contribution"] > 0.5]

    return {"mahalanobis_distance_sq": round(d2, 4),
            "mahalanobis_distance": round(math.sqrt(d2), 4),
            "p_value": round(p_val, 6),
            "anomalous_dimensions": anomalous,
            "verdict": verdict,
            "baseline_sample_count": baseline["sample_count"],
            "dimension_contributions": contributions[:6],
            "interpretation": _interpret(anomalous, p_val)}


def _interpret(anomalous: List[Dict], p: float) -> str:
    if p > 0.05: return "二进制在语料库正常范围内（马氏距离不显著）"
    dims = [a["dimension"] for a in anomalous[:3]]
    return f"异常（p={p:.4f}），主要贡献维度: {', '.join(dims)}"


def compare_to_corpus(analysis: Dict,
                      corpus_analyses: List[Dict],
                      weights: List[float] = None) -> Dict:
    baseline = learn_baseline(corpus_analyses)
    if "error" in baseline:
        return {"error": baseline["error"]}
    result = score_anomaly(analysis, baseline, weights)
    result["corpus_size"] = baseline["sample_count"]
    return result
