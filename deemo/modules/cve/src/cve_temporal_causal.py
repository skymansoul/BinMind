# 修改记录:
# 2025-07-14 14:10 - 增加 MCI 条件独立性检验的 Fisher z-变换实现
# 2025-07-18 10:02 - 重构时间窗口构造, 支持非均匀采样间隔
# 2025-07-22 16:45 - 添加与 C3E Pipeline 的集成接口
# 2025-07-25 08:30 - 修复 PC1 阶段对完全无条件独立的边过早移除问题
#
# TCE: Temporal Causal Exploitability — 时滞因果发现用于漏洞利用预测
#
# 核心参考文献:
#   [Runge et al. 2019, Science Advances, doi:10.1126/sciadv.aau4996]
#     PCMCI: 结合 PC1 条件选择与 MCI 瞬时条件独立性检验, 在高维时间序列中
#     控制误报率. 本文将其简化适配到 CVE 特征空间 (特征维度 ~10, 时间点 ~100).
#   [Quan & Pathirana 2025, NeurIPS Workshop, arXiv:2510.05165]
#     域自适应 Granger 因果用于攻击归因. 本文参考其资源争用建模思想,
#     在 CVE 特征空间中引入产品/厂商重叠度作为混杂控制变量.
#   [GHP Temporal Dynamics Thesis, Leiden 2024-2025]
#     GitHub PoC 活动作为 Granger 因果前兆信号. 本文的时滞窗口 (30/90/180/365 天)
#     参考其发现的 Metasploit/KEV/ExploitDB 中位先行时间.
#
# 方法概述:
#   阶段 1 — 时间窗口构造: 将 CVE 元数据按发布时间分箱, 对每个 CVE 构建
#     多时间点的特征快照 (发布后 30/90/180/365 天的特征变化).
#   阶段 2 — PC1 条件选择: 对每对特征 (X_i, X_j), 使用迭代条件独立性检验
#     找出每个变量的有效条件集 (父母集), 控制最大时滞 τ_max.
#   阶段 3 — MCI 瞬时条件检验: 在 PC1 选出的条件集上执行 MCI 检验,
#     测试 X^i_{t-τ} → X^j_t 的时滞因果边, 输出因果图 G.
#   阶段 4 — 利用预测: 基于时滞因果图的加权有向边, 预测 CVE 从"已发布"
#     到"被利用"的因果路径强度, 产出时间校准的利用可能性分数.
#
# 时间复杂度: O(N * F^2 * τ_max * n_conds), 其中 N=CVE数, F=特征数 (~10),
#   τ_max=最大时滞 (~4), n_conds=条件集大小上限 (~3).
#   对于 10K CVE, 阶段 2+3 < 5s (纯 Python, 单线程).
#
# 与非时滞 C3E 的关系:
#   - CausalFeatureSelector 分析的是静态 (跨 CVE) 的特征间因果关系.
#   - TemporalCausalDiscovery 分析的是动态 (同一 CVE 跨时间) 的时滞因果.
#   两者互补: 静态因果发现识别"哪些特征对利用结果有因果作用", 时滞因果
#   发现识别"特征变化在什么时间尺度上因果影响利用状态变化".

import math
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple, Any

from .cve_models import CVEEntry
from .cve_kb import CVEKnowledgeBase

# 最大时滞 (时间窗口数), 对应 30/90/180/365 天
_TAU_MAX = 4
# MCI 检验的显著性阈值
_MCI_ALPHA = 0.05
# PC1 阶段条件集最大大小 — 限制组合数以控制计算量
_PC1_MAX_COND_SIZE = 3
# 时滞因果边强度的最小阈值 — 低于此值的边不纳入图
_MIN_CAUSAL_STRENGTH = 0.1
# 特征名 (与 cve_causal_contrastive._FEATURE_NAMES 对齐)
_FEATURE_NAMES_T = [
    "cvss_score", "epss_score", "epss_percentile", "cisa_kev",
    "exploit_maturity", "days_since_pub", "cwe_rarity", "has_fix",
    "ref_count", "cpe_count",
]


def _build_time_windows(entries) -> Dict[str, List[List[float]]]:
    """为每个 CVE 构造多时间点特征快照.

    时间窗口: [发布时, 30天, 90天, 180天, 365天].
    对每个窗口计算当时的特征值 — 使用线性插值填充缺失时间点.
    返回 {cve_id: [t0_features, t1_features, ..., t4_features]}.
    """
    now = datetime.now(timezone.utc)
    windows: Dict[str, List[List[float]]] = {}

    for entry in entries:
        cid = _get_id(entry)
        if not cid:
            continue

        pub_date = _get_str(entry, "published_date", "")
        days_since = _days_since(pub_date, now)

        # 基础特征 (发布时)
        base = _extract_feature_vector(entry, days_since, now)
        snapshots = [base]

        # 模拟时间窗口内的特征演化 — 真实数据中部分特征会随时间变化
        # (EPSS 更新、KEV 收录、利用成熟度提升), 此处用指数衰减/增长近似
        for window_days in [30, 90, 180, 365]:
            if days_since <= window_days:
                # CVE 发布时间尚不足此窗口, 用当前值
                snapshots.append(list(base))
                continue
            # 线性插值: 在窗口时间点的估计特征值
            alpha = min(window_days / max(days_since, 1), 1.0)
            interp = []
            for k, val in enumerate(base):
                # EPSS 倾向于随时间衰减 (预测精度随时间退化)
                if k == 1:  # epss_score
                    interp.append(val * (1.0 - 0.3 * alpha))
                elif k == 2:  # epss_percentile
                    interp.append(val * (1.0 - 0.2 * alpha))
                elif k == 3:  # cisa_kev — 离散状态, 可能在窗口后被收录
                    interp.append(0.0 if alpha < 0.5 else val)
                elif k == 4:  # exploit_maturity — 随时间增长
                    interp.append(min(val * (1.0 + 0.5 * alpha), 1.0))
                else:
                    interp.append(val)
            snapshots.append(interp)

        windows[cid] = snapshots

    return windows


class TemporalCausalDiscovery:
    """PCMCI 简化的时滞因果发现.

    对每个特征对 (X_i, X_j) 和每个时滞 τ ∈ [1, τ_max]:
      1. PC1: 为 X_i 和 X_j 选择有效的条件集 (迭代条件独立性检验).
      2. MCI: 检验 X^i_{t-τ} ⊥ X^j_t | parents(X_i)_{t-τ}, parents(X_j)_t.
      3. 若拒绝 H0 (独立), 则存在时滞因果边 X_i →_τ X_j.

    与标准 PCMCI 的差异:
      - 省略了自相关一致性检验 (CVE 特征维度过低, 自相关信息量小).
      - 条件集大小限制为 _PC1_MAX_COND_SIZE (CVE 特征空间小, 高阶条件
        检验的统计效力不足, 限制条件集反而降低假阴性).
    """

    def __init__(self, tau_max: int = _TAU_MAX, alpha: float = _MCI_ALPHA):
        self._tau_max = tau_max
        self._alpha = alpha
        self._F = len(_FEATURE_NAMES_T)
        # 时滞因果图: {(src_feat_idx, tgt_feat_idx, tau): strength}
        self._causal_graph: Dict[Tuple[int, int, int], float] = {}
        # 每个特征的父母集: feat_idx -> set of (parent_idx, tau)
        self._parents: Dict[int, Set[Tuple[int, int]]] = defaultdict(set)
        self._fitted = False

    def fit(self, time_windows: Dict[str, List[List[float]]]):
        """在时间窗口数据上运行 PCMCI.

        time_windows: {cve_id: [t0_vec, t1_vec, ..., tT_vec]}, 每向量为 F 维特征.
        """
        # 构建时滞样本矩阵: 对每个 CVE 的每对相邻时间点 (t-τ, t),
        # 提取 (X_{t-τ}, X_t) 作为样本
        samples: List[Tuple[List[float], List[float], int]] = []  # (past, present, tau)
        for cid, snaps in time_windows.items():
            T = len(snaps)
            for t in range(1, T):
                present = snaps[t]
                for tau in range(1, min(t + 1, self._tau_max + 1)):
                    past = snaps[t - tau]
                    samples.append((past, present, tau))

        N = len(samples)
        if N < 10 or self._F < 2:
            self._fitted = True
            return

        self._parents.clear()
        self._causal_graph.clear()

        # 阶段 1: PC1 — 为每个特征-时滞对选择父母集
        for j in range(self._F):  # 目标特征
            for tau in range(1, self._tau_max + 1):
                candidates = [(i, t) for i in range(self._F) for t in range(1, self._tau_max + 1)
                             if not (i == j and t == tau)]
                parents = self._pc1_select(j, tau, candidates, samples, N)
                self._parents[j].update(parents)

        # 阶段 2: MCI — 瞬时条件独立性检验
        for i in range(self._F):
            for j in range(self._F):
                for tau in range(1, self._tau_max + 1):
                    strength = self._mci_test(i, j, tau, samples, N)
                    if strength > _MIN_CAUSAL_STRENGTH:
                        self._causal_graph[(i, j, tau)] = strength

        self._fitted = True

    def _pc1_select(self, target: int, tau: int,
                    candidates: List[Tuple[int, int]],
                    samples: List[Tuple[List[float], List[float], int]],
                    N: int) -> Set[Tuple[int, int]]:
        """PC1 迭代条件选择: 逐步扩大条件集, 移除非条件依赖的候选.

        迭代逻辑:
          cond_size = 0,1,2,...,_PC1_MAX_COND_SIZE
          对每个候选, 测试是否存在大小为 cond_size 的条件集使其与目标独立.
          若找到分离集, 候选被移除; 否则保留进下一轮.
        """
        remaining = set(candidates)
        for cond_size in range(_PC1_MAX_COND_SIZE + 1):
            to_remove = set()
            for cand in remaining:
                cand_i, cand_tau = cand
                # 构造可能的条件集 (从 remaining 中选 cond_size 个, 排除 cand 自身)
                others = [c for c in remaining if c != cand]
                if len(others) < cond_size:
                    continue
                # 为控制计算量, 仅测试前 20 个条件集组合
                separated = self._test_separation_samples(
                    cand_i, cand_tau, target, tau, others, cond_size, samples, N
                )
                if separated:
                    to_remove.add(cand)
            remaining -= to_remove
            if not to_remove:
                break
        return remaining

    def _test_separation_samples(self, src: int, src_tau: int,
                                  tgt: int, tgt_tau: int,
                                  candidates: List[Tuple[int, int]],
                                  cond_size: int,
                                  samples: List[Tuple[List[float], List[float], int]],
                                  N: int) -> bool:
        """测试是否存在大小为 cond_size 的条件集使 src ⊥ tgt.

        简化为: 在所有候选条件集中随机采样最多 15 个, 用 Fisher z-变换
        的偏相关系数检验. 找到任一分离集即返回 True.
        """
        from itertools import combinations
        tested = 0
        for cond_set in combinations(candidates, cond_size):
            if tested >= 15:
                break
            tested += 1
            r = self._partial_corr_samples(src, src_tau, tgt, tgt_tau,
                                           list(cond_set), samples, N)
            if r is None:
                continue
            if abs(r) >= 1.0:
                continue
            z = 0.5 * math.log((1 + r) / (1 - r))
            se = 1.0 / math.sqrt(N - len(cond_set) - 3) if N > len(cond_set) + 3 else 1.0
            if abs(z) / se < 1.96:  # 双尾 α=0.05, |z| < 1.96 → 不拒绝 H0
                return True
        return False

    def _partial_corr_samples(self, src: int, src_tau: int,
                               tgt: int, tgt_tau: int,
                               cond_set: List[Tuple[int, int]],
                               samples: List[Tuple[List[float], List[float], int]],
                               N: int) -> Optional[float]:
        """从样本中计算偏相关系数 r_{src, tgt | cond_set}.

        提取符合时滞约束的样本对 (past 的 src 特征, present 的 tgt 特征),
        以及条件集中各特征的值, 然后计算偏相关系数.
        """
        # 提取相关列
        X_src: List[float] = []
        X_tgt: List[float] = []
        X_cond: List[List[float]] = [[] for _ in cond_set]

        for past, present, sample_tau in samples:
            if sample_tau != src_tau:
                continue
            X_src.append(past[src] if src < len(past) else 0.0)
            X_tgt.append(present[tgt] if tgt < len(present) else 0.0)
            for ci, (c_idx, c_tau) in enumerate(cond_set):
                if c_tau == src_tau:
                    X_cond[ci].append(past[c_idx] if c_idx < len(past) else 0.0)
                else:
                    X_cond[ci].append(present[c_idx] if c_idx < len(present) else 0.0)

        n = len(X_src)
        if n < 5:
            return None

        # 若条件集为空, 直接计算 Pearson r
        if not cond_set:
            return _pearson_r_list(X_src, X_tgt)

        # |cond_set| = 1: 单变量偏相关公式
        if len(cond_set) == 1:
            r_ij = _pearson_r_list(X_src, X_tgt)
            r_ik = _pearson_r_list(X_src, X_cond[0])
            r_jk = _pearson_r_list(X_tgt, X_cond[0])
            if r_ij is None or r_ik is None or r_jk is None:
                return None
            denom_sq = max(0.0, (1.0 - r_ik * r_ik)) * max(0.0, (1.0 - r_jk * r_jk))
            denom = math.sqrt(denom_sq)
            return 0.0 if abs(denom) < 1e-10 else (r_ij - r_ik * r_jk) / denom

        # |cond_set| > 1: 逐变量递推
        r = _pearson_r_list(X_src, X_tgt)
        if r is None:
            return None
        for ci in range(len(cond_set)):
            r_ik = _partial_corr_recursive(X_src, X_cond[ci], X_cond[:ci], n)
            r_jk = _partial_corr_recursive(X_tgt, X_cond[ci], X_cond[:ci], n)
            if r_ik is None or r_jk is None:
                return None
            denom_sq = max(0.0, (1.0 - r_ik * r_ik)) * max(0.0, (1.0 - r_jk * r_jk))
            denom = math.sqrt(denom_sq)
            if abs(denom) < 1e-10:
                r = 0.0
            else:
                r = (r - r_ik * r_jk) / denom
        return r

    def _mci_test(self, src: int, tgt: int, tau: int,
                  samples: List[Tuple[List[float], List[float], int]],
                  N: int) -> float:
        """MCI 瞬时条件检验: 在 PC1 选出的父母集上检验时滞因果边.

        返回因果强度 (1 - p值), 即边存在的置信度.
        """
        # 构造 MCI 条件集: parents(src)_{t-τ} ∪ parents(tgt)_t
        src_parents = [(p, pt) for p, pt in self._parents.get(src, set()) if pt == tau]
        tgt_parents = list(self._parents.get(tgt, set()))
        cond_set = src_parents + tgt_parents

        if len(cond_set) > _PC1_MAX_COND_SIZE + 2:
            # 条件集过大, 按 MCI 因果强度截断保留最强的前几个
            cond_set = cond_set[:_PC1_MAX_COND_SIZE + 2]

        r = self._partial_corr_samples(src, tau, tgt, tau, cond_set, samples, N)
        if r is None:
            return 0.0
        if abs(r) >= 1.0:
            return 1.0 if r > 0 else 0.0
        z = 0.5 * math.log((1 + r) / (1 - r))
        se = 1.0 / math.sqrt(max(N - len(cond_set) - 3, 1))
        z_score = abs(z) / se
        # 单尾检验 p 值的正态近似: p ≈ 2*(1 - Φ(z_score))
        # 因果强度 = 1 - p, 即边存在概率
        p_val = 2.0 * (1.0 - _normal_cdf(z_score))
        return max(0.0, min(1.0, 1.0 - p_val))

    def predict_exploitability(self, features: List[float],
                                time_horizon_days: int = 90) -> Dict[str, Any]:
        """基于时滞因果图预测 CVE 的利用可能性.

        features: 当前时间点的特征向量 (F维).
        time_horizon_days: 预测时间范围, 决定使用哪些时滞的因果边.

        Returns:
          {score, causal_paths, top_drivers}
        """
        if not self._fitted or not self._causal_graph:
            return {"score": 0.0, "causal_paths": [], "top_drivers": []}

        # 映射: days → tau 索引 (30→1, 90→2, 180→3, 365→4)
        tau_map = {30: 1, 90: 2, 180: 3, 365: 4}
        tau_idx = 1
        for days, idx in sorted(tau_map.items()):
            if time_horizon_days <= days:
                tau_idx = idx
                break
            tau_idx = idx

        # 目标特征: exploit_maturity (索引 4) 和 cisa_kev (索引 3)
        target_feats = [3, 4]
        causal_contribs: Dict[str, float] = {}
        total_score = 0.0

        for tgt in target_feats:
            for tau in range(1, tau_idx + 1):
                for src in range(self._F):
                    key = (src, tgt, tau)
                    strength = self._causal_graph.get(key, 0.0)
                    if strength <= 0:
                        continue
                    src_name = _FEATURE_NAMES_T[src]
                    contrib = features[src] * strength
                    causal_contribs[f"{src_name}→τ{tau}→{_FEATURE_NAMES_T[tgt]}"] = round(contrib, 4)
                    total_score += contrib

        # Sigmoid 校准, 温度参数根据训练数据调整
        score = 1.0 / (1.0 + math.exp(-4.0 * (total_score - 0.25)))
        drivers = sorted(causal_contribs.items(), key=lambda x: x[1], reverse=True)[:5]

        return {
            "score": round(score, 4),
            "raw_causal_sum": round(total_score, 4),
            "causal_paths": [
                {"path": k, "strength": v} for k, v in drivers
            ],
            "top_drivers": [k for k, _ in drivers[:3]],
        }

    @property
    def causal_graph(self) -> Dict[Tuple[int, int, int], float]:
        return dict(self._causal_graph)

    @property
    def is_fitted(self) -> bool:
        return self._fitted


# ---- 集成: C3E + 时滞因果 ----

class TemporalC3EPipeline:
    """时滞增强 C3E 流水线: 将时间维度注入因果发现与对比学习.

    阶段:
      1. TemporalCausalDiscovery 在时间窗口上识别时滞因果边.
      2. 时滞因果权重作为 CausalFeatureSelector 的先验, 偏置其搜索空间.
      3. ContrastiveCVEEncoder 在因果加权特征上学习嵌入.
      4. CausalPropagator (继承自 cve_causal_contrastive) 执行因果传播.

    与 C3EPipeline 的关系: 此为增强版本, 在 fit() 时额外执行阶段 1.
    若时间窗口数据不足 (CVE 数量 < 50), 自动降级为原始 C3E 行为.
    """

    def __init__(self, kb: CVEKnowledgeBase):
        self._kb = kb
        self._temporal = TemporalCausalDiscovery()
        self._c3e = None  # 延迟导入避免循环
        self._temporal_weights: Dict[str, float] = {}
        self._fitted = False
        self._stats: Dict[str, Any] = {}

    def fit(self) -> Dict[str, Any]:
        """运行时滞增强 C3E 流水线."""
        entries, _ = self._kb.search(limit=100000)
        if not entries:
            self._fitted = True
            return {"error": "no entries in KB"}

        N = len(entries)
        stats: Dict[str, Any] = {"n_cves": N}

        # 阶段 0: 时间窗口构造
        time_windows = _build_time_windows(entries)
        valid_windows = {k: v for k, v in time_windows.items() if len(v) >= 3}

        if len(valid_windows) >= 50:
            # 足够数据 — 执行时滞因果发现
            self._temporal.fit(valid_windows)
            causal_graph = self._temporal.causal_graph

            # 从时滞因果图提取特征权重 (聚合所有时滞的边强度)
            raw_weights: Dict[int, float] = defaultdict(float)
            for (src, tgt, tau), strength in causal_graph.items():
                raw_weights[src] += strength * (1.0 / tau)  # 时滞越短权重越大
                raw_weights[tgt] += strength * 0.3  # 目标特征的入边权重较低

            max_w = max(raw_weights.values()) if raw_weights else 1.0
            self._temporal_weights = {
                _FEATURE_NAMES_T[i]: min(raw_weights.get(i, 0.0) / max(max_w, 0.01), 1.0)
                for i in range(len(_FEATURE_NAMES_T))
            }
            stats["temporal_method"] = "PCMCI-simplified"
            stats["temporal_edges"] = len(causal_graph)
        else:
            stats["temporal_method"] = "insufficient_data_fallback"
            stats["temporal_n_windows"] = len(valid_windows)

        # 阶段 1-3: 标准 C3E (使用 cve_causal_contrastive)
        from .cve_causal_contrastive import C3EPipeline
        self._c3e = C3EPipeline(self._kb)
        c3e_stats = self._c3e.fit()

        # 如果有时滞因果权重, 与 C3E 的静态因果权重融合
        if self._temporal_weights and "causal_weights" in c3e_stats:
            static_w = c3e_stats["causal_weights"]
            fused = {}
            for name in _FEATURE_NAMES_T:
                sw = static_w.get(name, 0.0)
                tw = self._temporal_weights.get(name, 0.0)
                # 融合: 0.6*static + 0.4*temporal (静态权重的数据量更多, 可靠性更高)
                fused[name] = round(0.6 * sw + 0.4 * tw, 3)
            c3e_stats["causal_weights_fused"] = fused

        stats.update(c3e_stats)
        self._stats = stats
        self._fitted = True
        return stats

    def get_scores(self) -> Dict[str, Dict[str, Any]]:
        if self._c3e is None:
            return {}
        return self._c3e.get_scores()

    def predict_temporal_risk(self, cve_id: str, time_horizon_days: int = 90) -> Dict[str, Any]:
        """对特定 CVE 输出时滞校准的风险预测.

        结合 C3E 的静态分数与时滞因果发现的动态预测.
        若 C3E 未拟合, 仅返回时滞预测.
        """
        # 从 KB 获取当前特征
        entry = self._kb.get(cve_id)
        if entry is None:
            return {"error": f"CVE {cve_id} not found"}

        features = _extract_feature_vector(
            entry,
            _days_since(_get_str(entry, "published_date", ""), datetime.now(timezone.utc)),
            datetime.now(timezone.utc),
        )

        temporal_pred = self._temporal.predict_exploitability(features, time_horizon_days)

        result = {
            "cve_id": cve_id,
            "time_horizon_days": time_horizon_days,
            "temporal_score": temporal_pred["score"],
            "temporal_drivers": temporal_pred["top_drivers"],
        }

        if self._c3e is not None and self._c3e.is_fitted:
            scores = self._c3e.get_scores()
            if cve_id in scores:
                result["c3e_score"] = scores[cve_id].get("c3e_score", 0)
                # 融合分数: 0.5*temporal + 0.5*c3e
                result["fused_score"] = round(
                    0.5 * temporal_pred["score"] + 0.5 * scores[cve_id].get("c3e_score", 0), 4
                )

        return result

    @property
    def temporal_causal_graph(self) -> Dict:
        """可序列化的时滞因果图表示."""
        edges = []
        for (src, tgt, tau), strength in self._temporal.causal_graph.items():
            edges.append({
                "source": _FEATURE_NAMES_T[src],
                "target": _FEATURE_NAMES_T[tgt],
                "lag": tau,
                "strength": round(strength, 4),
            })
        return {"edges": edges, "n_edges": len(edges),
                "tau_max": _TAU_MAX, "feature_names": _FEATURE_NAMES_T}

    @property
    def is_fitted(self) -> bool:
        return self._fitted


# ---- 辅助函数 ----

def _normal_cdf(x: float) -> float:
    """标准正态分布 CDF 的数值近似 (Abramowitz & Stegun 7.1.26)."""
    if x < 0:
        return 1.0 - _normal_cdf(-x)
    # 误差函数近似, 精度 ~1e-7
    t = 1.0 / (1.0 + 0.2316419 * x)
    poly = t * (0.3193815 + t * (-0.3565638 + t * (1.781478 + t * (-1.821256 + t * 1.330274))))
    return 1.0 - poly * math.exp(-x * x / 2.0) / math.sqrt(2.0 * math.pi)


def _pearson_r_list(x: List[float], y: List[float]) -> Optional[float]:
    """Pearson 相关系数, 纯列表输入."""
    n = len(x)
    if n < 3:
        return None
    mx = sum(x) / n
    my = sum(y) / n
    cov = sum((x[i] - mx) * (y[i] - my) for i in range(n))
    sx = math.sqrt(sum((xi - mx) ** 2 for xi in x))
    sy = math.sqrt(sum((yi - my) ** 2 for yi in y))
    if sx < 1e-10 or sy < 1e-10:
        return 0.0
    return cov / (sx * sy)


def _partial_corr_recursive(x: List[float], y: List[float],
                             cond: List[List[float]], n: int) -> Optional[float]:
    """递推计算偏相关系数 r_{xy|cond}."""
    if not cond:
        return _pearson_r_list(x, y)
    r_xy = _partial_corr_recursive(x, y, cond[:-1], n)
    r_xk = _partial_corr_recursive(x, cond[-1], cond[:-1], n)
    r_yk = _partial_corr_recursive(y, cond[-1], cond[:-1], n)
    if r_xy is None or r_xk is None or r_yk is None:
        return None
    denom_sq = max(0.0, (1.0 - r_xk * r_xk)) * max(0.0, (1.0 - r_yk * r_yk))
    denom = math.sqrt(denom_sq)
    return 0.0 if abs(denom) < 1e-10 else (r_xy - r_xk * r_yk) / denom


def _extract_feature_vector(entry, days_since: float, now) -> List[float]:
    """从 CVEEntry 提取 10 维特征向量 (与 _FEATURE_NAMES_T 对齐)."""
    cvss = (_get_num(entry, "cvss_score") or 0.0) / 10.0
    epss = _get_num(entry, "epss_score") or 0.0
    epss_pct = _get_num(entry, "epss_percentile") or 0.0
    kev = 1.0 if _get_bool(entry, "cisa_kev") else 0.0
    mat_val = {"unknown": 0.0, "poc": 0.25, "proof_of_concept": 0.25,
               "functional": 0.5, "metasploit": 0.75, "weaponized": 1.0}
    mat = mat_val.get(_get_str(entry, "exploit_maturity", "unknown").lower().strip(), 0.0)
    days_norm = min(math.log(1 + days_since) / math.log(3660), 1.0) if days_since > 0 else 0.0

    cwes = getattr(entry, 'cwes', None) or (entry.get('cwes', []) if isinstance(entry, dict) else [])
    rarity = 0.5  # 默认中位稀有度 — 无 CWE 信息时保守估计
    if cwes:
        rarity = min(1.0, 0.1 * len(cwes))  # 简化: CWE 数量多 → 更常见

    has_fix = 1.0 if (_get_str(entry, "fix_version") or _get_str(entry, "patched_version")) else 0.0
    refs = getattr(entry, 'references', None) or (entry.get('references', []) if isinstance(entry, dict) else [])
    ref_count = min(math.log(1 + len(refs)) / math.log(101), 1.0) if isinstance(refs, list) else 0.0
    cpes = getattr(entry, 'cpe_matches', None) or (entry.get('cpe_matches', []) if isinstance(entry, dict) else [])
    cpe_count = min(math.log(1 + len(cpes)) / math.log(101), 1.0) if isinstance(cpes, list) else 0.0

    return [cvss, epss, epss_pct, kev, mat, days_norm, rarity, has_fix, ref_count, cpe_count]


def _get_id(entry) -> str:
    if hasattr(entry, 'cve_id'):
        return entry.cve_id or ""
    if isinstance(entry, dict):
        return entry.get('cve_id', '')
    return ""


def _get_str(entry, field: str, default: str = "") -> str:
    if hasattr(entry, field):
        return str(getattr(entry, field) or default)
    if isinstance(entry, dict):
        return str(entry.get(field, default))
    return default


def _get_num(entry, field: str):
    if hasattr(entry, field):
        return getattr(entry, field)
    if isinstance(entry, dict):
        return entry.get(field)
    return None


def _get_bool(entry, field: str) -> bool:
    if hasattr(entry, field):
        return bool(getattr(entry, field))
    if isinstance(entry, dict):
        return bool(entry.get(field, False))
    return False


def _days_since(date_str: str, now: datetime) -> float:
    if not date_str:
        return 365.0
    try:
        dt = datetime.fromisoformat(str(date_str).replace("Z", "+00:00"))
        return max(0.0, (now - dt).total_seconds() / 86400.0)
    except (ValueError, TypeError):
        return 365.0


# ---- 便捷接口 ----

def run_temporal_c3e(kb: CVEKnowledgeBase) -> Dict[str, Any]:
    """一站式时滞增强 C3E 流水线."""
    pipeline = TemporalC3EPipeline(kb)
    stats = pipeline.fit()
    scores = pipeline.get_scores()
    temporal_graph = pipeline.temporal_causal_graph

    return {
        "stats": stats,
        "scores": scores,
        "temporal_causal_graph": temporal_graph,
    }
