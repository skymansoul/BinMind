# 因果依赖发现 — 从执行轨迹自动推断任务依赖关系
#
# GRL-Sched 依赖显式的 TaskDependencyGraph 标注。手工维护依赖图
# 在动态环境中不可靠——遗漏的隐式依赖导致调度违反实际约束。
#
# 本模块从执行时间序列中自动发现因果依赖:
#   方法 A: Granger 因果检验 — 若任务 A 的过去执行时间有助于预测
#           任务 B 的当前执行时间 (在给定 B 自身历史的条件下)，
#           则 A → B 存在 Granger 因果关系。
#   方法 B: 转移熵 (Transfer Entropy) — 信息论度量，非对称。
#           TE_{A→B} = I(B_t ; A_{t-τ} | B_{t-τ})
#           即 A 的过去为 B 的当前提供的信息量 (条件是 B 的过去已知)。
#           TE > 0 → A 对 B 有因果影响。对非线性关系鲁棒。
#
# 综合判定: Granger p < 0.05 且 TE > 阈值 → 建议添加依赖边 A→B
# 输出: 建议的 TaskDependencyGraph 边列表，供人工审核后合并
#
# 与现有工作的区别:
#   TraceCausalNet 做微服务 RCA (根因定位)，不做依赖发现用于调度
#   Apophenia (arXiv:2406.18111) 做代码级 trace 发现，不做时序因果
#   本模块是首个将 Granger + TE 联合用于调度依赖推断的方案

from __future__ import annotations

import math
from collections import deque, defaultdict
from typing import Optional, List, Dict, Tuple, Set


def _mean(vals: List[float]) -> float:
    return sum(vals) / len(vals) if vals else 0.0


def _var(vals: List[float]) -> float:
    if len(vals) < 2:
        return 1.0
    m = _mean(vals)
    return sum((x - m) ** 2 for x in vals) / (len(vals) - 1)


def _residuals(y: List[float], X: List[List[float]],
              ) -> Tuple[List[float], List[float]]:
    """OLS 残差 — y = X·β + ε, 返回 (拟合值, 残差)。"""
    n = len(y)
    p = len(X[0]) if X else 0
    if n < p + 2 or p == 0:
        return [0.0] * n, list(y)
    # 正规方程 (X^T·X)·β = X^T·y, 用 Cholesky
    XtX = [[0.0] * p for _ in range(p)]
    Xty = [0.0] * p
    for i in range(n):
        for j in range(p):
            XtX[j][j] += X[i][j] * X[i][j]
            Xty[j] += X[i][j] * y[i]
            for k in range(j + 1, p):
                XtX[j][k] += X[i][j] * X[i][k]
    for j in range(p):
        for k in range(j + 1, p):
            XtX[k][j] = XtX[j][k]

    # Cholesky: XtX = L·L^T
    L = [[0.0] * p for _ in range(p)]
    for i in range(p):
        s = XtX[i][i] - sum(L[i][k] ** 2 for k in range(i))
        if s <= 1e-9:
            return [0.0] * n, list(y)
        L[i][i] = math.sqrt(s)
        for j in range(i + 1, p):
            L[j][i] = (XtX[j][i] - sum(L[j][k] * L[i][k] for k in range(i))) / L[i][i]

    # 前代: L·z = Xty
    z = [0.0] * p
    for i in range(p):
        z[i] = (Xty[i] - sum(L[i][k] * z[k] for k in range(i))) / L[i][i]
    # 回代: L^T·β = z
    beta = [0.0] * p
    for i in range(p - 1, -1, -1):
        beta[i] = (z[i] - sum(L[k][i] * beta[k] for k in range(i + 1, p))) / L[i][i]

    fitted = [sum(beta[j] * X[i][j] for j in range(p)) for i in range(n)]
    resid = [y[i] - fitted[i] for i in range(n)]
    return fitted, resid


def _f_test(rss_restricted: float, rss_full: float,
            df1: int, df2: int) -> float:
    """F 检验的 p 值近似 — 用 Wilson-Hilferty 变换。"""
    if df2 <= 0 or rss_full <= 0:
        return 1.0
    F = ((rss_restricted - rss_full) / max(df1, 1)) / (rss_full / df2)
    if F <= 0:
        return 1.0
    # Wilson-Hilferty: χ² 近似
    x = F * df1
    nu = df2
    z = (math.pow(x / df1, 1.0 / 3.0) - (1.0 - 2.0 / (9.0 * df1))) / math.sqrt(
        2.0 / (9.0 * df1)
    ) if df1 > 0 else 0.0
    # 标准正态的尾概率近似
    p = 0.5 * math.erfc(z / math.sqrt(2.0))
    return min(1.0, max(0.0, p))


def transfer_entropy(
    source: List[float], target: List[float], lag: int = 1,
    n_bins: int = 5,
) -> float:
    """转移熵 TE_{source→target} — 离散化估计。

    使用等频分箱将连续值离散化，计算条件互信息。
    """
    n = len(source)
    if n < lag + 10:
        return 0.0

    # 对齐时间序列
    src_past = source[0:n - lag]
    tgt_past = target[0:n - lag]
    tgt_curr = target[lag:n]
    m = len(tgt_curr)
    if m < 10:
        return 0.0

    # 等频分箱
    def bin_edges(vals):
        s = sorted(vals)
        k = min(n_bins, len(s) // 3)
        if k <= 1:
            return [min(vals) - 0.1, max(vals) + 0.1]
        edges = [s[0] - 0.01]
        for i in range(1, k):
            edges.append(s[i * len(s) // k])
        edges.append(s[-1] + 0.01)
        return edges

    s_edges = bin_edges(src_past)
    t_edges = bin_edges(tgt_past)
    c_edges = bin_edges(tgt_curr)
    ns, nt, nc = len(s_edges) - 1, len(t_edges) - 1, len(c_edges) - 1

    def binned(vals, edges):
        result = []
        for v in vals:
            for i in range(len(edges) - 1):
                if edges[i] <= v < edges[i + 1]:
                    result.append(i)
                    break
            else:
                result.append(len(edges) - 2)
        return result

    s_idx = binned(src_past, s_edges)
    t_idx = binned(tgt_past, t_edges)
    c_idx = binned(tgt_curr, c_edges)
    if ns <= 0 or nt <= 0 or nc <= 0:
        return 0.0

    # 联合计数
    joint_stc = defaultdict(int)
    joint_tc = defaultdict(int)
    joint_st = defaultdict(int)
    marg_t = defaultdict(int)
    for i in range(m):
        joint_stc[(s_idx[i], t_idx[i], c_idx[i])] += 1
        joint_tc[(t_idx[i], c_idx[i])] += 1
        joint_st[(s_idx[i], t_idx[i])] += 1
        marg_t[t_idx[i]] += 1

    # TE = Σ p(s_past, t_past, t_curr) · log(p(t_curr|s_past,t_past) / p(t_curr|t_past))
    te = 0.0
    for (si, ti, ci), count_stc in joint_stc.items():
        p_stc = count_stc / m
        p_tc = joint_tc.get((ti, ci), 0) / m
        p_st = joint_st.get((si, ti), 0) / m
        p_t = marg_t.get(ti, 0) / m
        if p_stc <= 0 or p_tc <= 0 or p_st <= 0 or p_t <= 0:
            continue
        cond_joint = p_stc / max(p_st, 1e-9)
        cond_marg = p_tc / max(p_t, 1e-9)
        if cond_joint > 0 and cond_marg > 0:
            te += p_stc * math.log(cond_joint / cond_marg)
    return max(0.0, te)


class CausalDependencyDiscoverer:
    """因果依赖发现器 — Granger + 转移熵 联合推断。

    输入: 各任务的执行时间历史 {task_id: [time_1, time_2, ...]}
    输出: 建议添加的依赖边列表 + 置信度评分
    """

    def __init__(self, granger_p_threshold: float = 0.05,
                 te_threshold: float = 0.02, max_lag: int = 3):
        self._p_thr = granger_p_threshold
        self._te_thr = te_threshold
        self._max_lag = max_lag

    def discover(
        self, task_histories: Dict[str, List[float]],
    ) -> List[Dict]:
        """从历史执行时间中发现因果依赖。

        返回: [{"src": A, "dst": B, "granger_p": p, "transfer_entropy": te,
                 "lag": τ, "confidence": score}, ...]
        按 confidence 降序排列。
        """
        task_ids = list(task_histories.keys())
        n_tasks = len(task_ids)
        if n_tasks < 2:
            return []

        edges = []
        for src in task_ids:
            for dst in task_ids:
                if src == dst:
                    continue
                src_hist = task_histories[src]
                dst_hist = task_histories[dst]
                min_len = min(len(src_hist), len(dst_hist)) - self._max_lag
                if min_len < 10:
                    continue

                # 对齐到相同长度
                y = dst_hist[self._max_lag:min_len + self._max_lag]
                n = len(y)

                # 受限模型: y_t = α + Σ β_k · y_{t-k}  (不含 src)
                X_r = [[1.0] + [dst_hist[self._max_lag + i - k - 1]
                       for k in range(self._max_lag)] for i in range(n)]
                _, resid_r = _residuals(y, X_r)
                rss_r = sum(r * r for r in resid_r)

                # 全模型: y_t = α + Σ β_k·y_{t-k} + Σ γ_k·src_{t-k}
                X_f = [row + [src_hist[self._max_lag + i - k - 1]
                       for k in range(self._max_lag)] for i, row in enumerate(X_r)]
                _, resid_f = _residuals(y, X_f)
                rss_f = sum(r * r for r in resid_f)

                df1 = self._max_lag          # 新增参数 = γ_1...γ_k
                df2 = n - 1 - 2 * self._max_lag
                p_val = _f_test(rss_r, rss_f, df1, df2)

                # 转移熵
                te = transfer_entropy(src_hist[:min_len + self._max_lag],
                                     dst_hist[:min_len + self._max_lag],
                                     lag=self._max_lag)

                # 综合置信度: Granger 显著 + TE 足够大
                if p_val < self._p_thr and te > self._te_thr:
                    granger_score = 1.0 - p_val / self._p_thr
                    te_score = min(1.0, te / (self._te_thr * 5.0))
                    conf = 0.6 * granger_score + 0.4 * te_score
                    edges.append({
                        "src": src, "dst": dst,
                        "granger_p": round(p_val, 5),
                        "transfer_entropy": round(te, 5),
                        "lag": self._max_lag,
                        "confidence": round(conf, 4),
                    })

        edges.sort(key=lambda e: -e["confidence"])
        return edges

    def to_dag_edges(self, discoveries: List[Dict],
                     min_confidence: float = 0.5) -> List[Tuple[str, str, float]]:
        """转换为 (src, dst, comm_cost) 格式 — 可直接喂给 TaskDependencyGraph。"""
        return [
            (d["src"], d["dst"], round(1.0 - d["confidence"], 3))
            for d in discoveries if d["confidence"] >= min_confidence
        ]
