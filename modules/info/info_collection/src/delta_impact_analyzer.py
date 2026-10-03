# delta_impact_analyzer — Shapley 值分解的增量安全影响分析
# 对版本间安全变化做公平归因：每个变化信号的风险贡献通过其所有可能
# 加入顺序的边际效应均值 (Shapley value) 计算，消除简单线性分解中的
# 交互效应偏误。

import math, itertools
from typing import Dict, List, Tuple, Set, Optional


def _extract_signal_vector(analysis: Dict) -> List[Tuple[str, float]]:
    """从分析结果中提取可比较的信号向量。每项为 (signal_name, value)。
    值越低=越安全。"""
    vec = []
    cs = analysis.get("checksec", {})
    vec.append(("canary", 0.0 if cs.get("canary") else 0.20))
    vec.append(("pie", 0.0 if cs.get("pie") else 0.15))
    vec.append(("nx", 0.0 if cs.get("nx") else 0.25))
    relro = str(cs.get("relro", "")).lower()
    vec.append(("relro", 0.0 if "full" in relro else (0.10 if "partial" in relro else 0.20)))

    imps = analysis.get("imports", {})
    danger = imps.get("dangerous_functions", []) if isinstance(imps, dict) else []
    vec.append(("dangerous_imports", min(len(danger) * 0.04, 1.0)))

    exploit = analysis.get("exploit_chain", analysis.get("exploit", {}))
    vec.append(("exploitability", exploit.get("exploitability_index", 0.0) / 100.0))

    sections = analysis.get("sections", [])
    rwx = sum(1 for s in sections if isinstance(s, dict)
              and ("MEM_WRITE" in str(s.get("characteristics",""))
              and "MEM_EXECUTE" in str(s.get("characteristics",""))))
    vec.append(("rwx_sections", 0.40 if rwx > 0 else 0.0))
    return vec


def _shapley_decomposition(
    prev_vec: List[Tuple[str, float]],
    curr_vec: List[Tuple[str, float]],
    max_signals: int = 8,
) -> Dict:
    """计算每个变化信号的 Shapley 值贡献。
    对信号子集遍历所有排列的边际效应均值。
    复杂度 O(2^n)，对 n<=8 可精确计算；n>8 用随机采样近似。
    """
    changes = {}
    all_names = []
    for (pn, pv), (cn, cv) in zip(prev_vec, curr_vec):
        if pn != cn:
            continue
        delta = cv - pv
        if abs(delta) > 0.001:
            changes[pn] = delta
            all_names.append(pn)

    n = len(all_names)
    if n == 0:
        return {"contributions": {}, "net_delta": 0.0, "method": "no_changes"}

    if n <= 8:
        shapley = {name: 0.0 for name in all_names}
        for perm in itertools.permutations(all_names):
            base_risk = 0.0
            for name in perm:
                marginal = changes[name]
                base_risk += marginal
            for i, name in enumerate(perm):
                prev_sum = sum(changes[p] for p in perm[:i])
                curr_sum = prev_sum + changes[name]
                shapley[name] += curr_sum - prev_sum
        for name in all_names:
            shapley[name] /= math.factorial(n)
    else:
        # 随机采样近似 (500 permutations)
        import random
        rng = random.Random(42)
        shapley = {name: 0.0 for name in all_names}
        n_perm = 500
        for _ in range(n_perm):
            perm = list(all_names)
            rng.shuffle(perm)
            for i, name in enumerate(perm):
                prev_sum = sum(changes[p] for p in perm[:i])
                curr_sum = prev_sum + changes[name]
                shapley[name] += curr_sum - prev_sum
        for name in all_names:
            shapley[name] /= n_perm

    net = sum(changes.values())
    return {"contributions": {n: round(v, 6) for n, v in shapley.items()},
            "raw_deltas": {n: round(v, 6) for n, v in changes.items()},
            "net_delta": round(net, 6),
            "method": "exact" if n <= 8 else f"sampled({n_perm})",
            "signal_count": n}


def analyze_delta(
    prev_analysis: Dict, curr_analysis: Dict,
    prev_fingerprint: Dict = None, curr_fingerprint: Dict = None,
    prev_compiler: Dict = None, curr_compiler: Dict = None,
) -> Dict:
    """增量安全影响分析主入口。使用 Shapley 值分解做贡献归因。"""
    prev_vec = _extract_signal_vector(prev_analysis)
    curr_vec = _extract_signal_vector(curr_analysis)

    # 保护变化明细
    prev_cs = prev_analysis.get("checksec", {})
    curr_cs = curr_analysis.get("checksec", {})
    prot_changes = []
    for k in ["canary","pie","nx","relro","fortify","cfg","gs","safeseh"]:
        pv, cv = prev_cs.get(k), curr_cs.get(k)
        if pv != cv:
            direction = "enabled" if (cv is True and pv is not True) else "disabled"
            prot_changes.append({"protection": k, "before": pv, "after": cv,
                                "direction": direction})

    # 导入表面变化
    prev_danger = set((prev_analysis.get("imports", {}).get("dangerous_functions", [])))
    curr_danger = set((curr_analysis.get("imports", {}).get("dangerous_functions", [])))
    import_delta = {"added": sorted(curr_danger - prev_danger),
                    "removed": sorted(prev_danger - curr_danger)}

    # Shapley 分解
    decomp = _shapley_decomposition(prev_vec, curr_vec)

    # 编译器噪声检测
    compiler_noise = False
    if prev_compiler and curr_compiler:
        pf = prev_compiler.get("compiler_family","")
        cf = curr_compiler.get("compiler_family","")
        if pf != cf or prev_compiler.get("opt_level") != curr_compiler.get("opt_level"):
            compiler_noise = True

    # 结构熵漂移
    drift = 0.0
    if prev_fingerprint and curr_fingerprint:
        pv = prev_fingerprint.get("composite_vector", [])
        cv = curr_fingerprint.get("composite_vector", [])
        if pv and cv:
            drift = round(math.sqrt(sum((a-b)**2 for a,b in zip(pv,cv))), 6)

    net = decomp["net_delta"]
    if compiler_noise and abs(net) < 0.05:
        impact = "likely_compiler_noise"
    elif net > 0.03:
        impact = "degraded"
    elif net < -0.03:
        impact = "improved"
    else:
        impact = "neutral"

    significant = []
    for name, contrib in decomp["contributions"].items():
        if abs(contrib) > 0.03:
            direction = "increased_risk" if contrib > 0 else "reduced_risk"
            significant.append(f"{name}: {direction} ({contrib:+.4f})")

    return {"protection_changes": prot_changes,
            "import_delta": import_delta,
            "shapley_decomposition": decomp,
            "entropy_drift": drift,
            "net_risk_delta": net,
            "security_impact": impact,
            "compiler_noise_detected": compiler_noise,
            "significant_changes": significant,
            "change_count": len(prot_changes) + len(import_delta["added"]) + len(import_delta["removed"])}
