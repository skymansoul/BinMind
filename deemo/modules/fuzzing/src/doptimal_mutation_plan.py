"""信息制导突变规划 (D-Optimal Mutation Planning, DOMP).

修改记录:
2025-08-13 15:22 - 对角 Fisher 交换 + 信息增益排序
2025-08-14 09:45 - 在线 Fisher 信息更新
2025-08-20 09:49 - 修正: Fedorov 交换简化 (3次迭代), 非严格 D-最优收敛;
             对角假设下 D-效率仅近似而非精确最优设计"""
# 参考: Fedorov (1972), Atkinson et al. (2007), Pukelsheim (2006).
# 将突变位置选择建模为最优实验设计: 选择 max det(Fisher) 的位置子集。
# 使用对角 Fisher 信息做 Fedorov 交换 (3次迭代), D-效率近似而非精确最优。

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


# ---- DOMP 参数 ----
_N_DESIGN_POINTS = 16        # 每轮设计点数
_MAX_CANDIDATES = 200         # 最大候选位置数


@dataclass
class DesignPoint:
    """一个可变异位置的实验设计元数据."""
    byte_offset: int
    sensitivity: float          # Fisher 信息敏感度 (来自 FIMS)
    selected: bool = False
    det_contribution: float = 0.0  # 对 det(F) 的边际贡献


class DOptimalMutationPlanner:
    """D-最优突变规划器 — 最大化每次变异的信息增益.

    将突变规划建模为最优实验设计:
      候选 = 尚未充分探索的字节位置
      设计 = 选择 k 个位置使 Fisher 信息矩阵行列式最大
      准则 = D-最优: φ(F) = -log det(F)

    使用方式:
      domp = DOptimalMutationPlanner()
      domp.add_candidate(byte_offset=0, sensitivity=0.5)
      plan = domp.plan_mutations(k=5)
      # plan = [(offset, info_gain), ...]
    """

    def __init__(self, n_points: int = _N_DESIGN_POINTS):
        self.n_points = n_points
        self._candidates: Dict[int, DesignPoint] = {}
        self._selected: List[int] = []
        # Fisher 信息矩阵 (对角近似: 各位置独立)
        self._fisher_diag: Dict[int, float] = defaultdict(float)
        self._fisher_total: float = 0.0

    def add_candidate(self, byte_offset: int,
                      sensitivity: float) -> None:
        """添加/更新候选位置."""
        if byte_offset in self._candidates:
            self._candidates[byte_offset].sensitivity = max(
                self._candidates[byte_offset].sensitivity, sensitivity)
        else:
            self._candidates[byte_offset] = DesignPoint(
                byte_offset=byte_offset, sensitivity=sensitivity)
        # Fisher 信息: 对角上 F_ii = sensitivity²
        self._fisher_diag[byte_offset] = sensitivity * sensitivity
        # 容量
        if len(self._candidates) > _MAX_CANDIDATES:
            self._prune_candidates()

    # //// D-最优规划 ////
    def plan_mutations(self, k: Optional[int] = None
                        ) -> List[Tuple[int, float]]:
        """规划 k 个最高信息增益的变异位置.

        使用 Fedorov 交换: 起点 = top-k 敏感度,
        然后交换: 移除 det 贡献最小的点, 添加贡献最大的候选。
        """
        k = k or self.n_points
        k = min(k, len(self._candidates))
        if k == 0:
            return []

        # 初始设计: top-k by sensitivity
        candidates = sorted(self._candidates.items(),
                          key=lambda x: x[1].sensitivity, reverse=True)
        selected_ids = {c[0] for c in candidates[:k]}

        # Fedorov 交换 (简化: 1 次扫描)
        for _ in range(3):  # 最多3次交换迭代
            # 计算每个已选点的 det 贡献
            current_det = sum(math.log(max(1e-8, self._fisher_diag[off]))
                            for off in selected_ids)
            worst_id = None; worst_loss = float('inf')
            for off in selected_ids:
                det_without = current_det - math.log(
                    max(1e-8, self._fisher_diag[off]))
                loss = current_det - det_without
                if loss < worst_loss:
                    worst_loss = loss; worst_id = off

            # 尝试用更好的候选替换
            best_cand = None; best_gain = 0.0
            for off, dp in self._candidates.items():
                if off in selected_ids:
                    continue
                det_with = current_det - math.log(
                    max(1e-8, self._fisher_diag.get(worst_id, 1e-8))
                ) + math.log(max(1e-8, self._fisher_diag[off]))
                gain = det_with - current_det
                if gain > best_gain:
                    best_gain = gain; best_cand = off

            if best_cand and best_gain > 0:
                selected_ids.discard(worst_id)
                selected_ids.add(best_cand)
            else:
                break

        # 计算信息增益
        total_det = sum(math.log(max(1e-8, self._fisher_diag[off]))
                       for off in selected_ids)
        plan = []
        for off in selected_ids:
            info_gain = math.log(max(1e-8, self._fisher_diag[off]))
            plan.append((off, info_gain))
        plan.sort(key=lambda x: x[1], reverse=True)
        self._selected = [off for off, _ in plan]
        return plan

    # //// 在线更新 ////
    def update_after_mutation(self, byte_offset: int,
                               observed_info: float) -> None:
        """变异执行后更新 Fisher 信息."""
        # Sherman-Morrison 对角更新: F_new = F_old + g·gᵀ
        # 对角: F_ii += observed_info²
        old_val = self._fisher_diag.get(byte_offset, 0.0)
        new_val = old_val + observed_info * observed_info
        self._fisher_diag[byte_offset] = new_val
        if byte_offset in self._candidates:
            self._candidates[byte_offset].sensitivity = math.sqrt(new_val)

    # //// D-效率 ////
    def d_efficiency(self, selected: Optional[List[int]] = None
                      ) -> float:
        """当前设计的 D-效率 [0,1]."""
        sel = selected or self._selected
        k = len(sel)
        if k == 0:
            return 0.0
        det_sel = sum(math.log(max(1e-8, self._fisher_diag.get(off, 1e-8)))
                     for off in sel)
        # 最优可能 det (若选 top-k 信息最大的位置)
        all_info = sorted(self._fisher_diag.values(), reverse=True)
        det_opt = sum(math.log(max(1e-8, v)) for v in all_info[:k])
        if det_opt < -1e10:
            return 0.0
        return math.exp((det_sel - det_opt) / k)

    def _prune_candidates(self) -> None:
        """保留敏感度最高的候选."""
        ranked = sorted(self._candidates.items(),
                       key=lambda x: x[1].sensitivity, reverse=True)
        self._candidates = {off: dp for off, dp
                           in ranked[:_MAX_CANDIDATES // 2]}

    # //// 统计 ////
    def stats(self) -> dict:
        n = len(self._candidates)
        sensitivities = [dp.sensitivity for dp in self._candidates.values()]
        return {
            "n_candidates": n,
            "n_selected": len(self._selected),
            "d_efficiency": round(self.d_efficiency(), 4),
            "mean_sensitivity": round(
                sum(sensitivities) / max(1, n), 4),
            "max_sensitivity": round(max(sensitivities) if sensitivities else 0, 4),
            "total_fisher_info": round(
                sum(self._fisher_diag.values()), 4),
        }

    def clear(self) -> None:
        self._candidates.clear(); self._selected.clear()
        self._fisher_diag.clear(); self._fisher_total = 0.0
