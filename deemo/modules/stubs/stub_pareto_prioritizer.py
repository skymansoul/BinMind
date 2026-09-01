# stub_pareto_prioritizer.py — 多目标 Pareto 前沿排序
# 替代线性加权组合，用非支配排序（Non-Dominated Sorting）对桩模块
# 在多个独立维度上同时优化，无需人工调权。
#
# 问题:
#   ImplementationPrioritizer 使用固定线性权重 (health=0.20, gap=0.40, ...)
#   将多维信号压缩为单一标量分数。这种压缩存在两个根本缺陷:
#     1. 权重选择是主观的 — 不同场景（安全审计 vs 性能优化 vs 日常维护）
#        需要不同权重，但当前仅支持硬编码切换。
#     2. 线性压缩丢失 Pareto 最优信息 — 一个 gap=1.0 + call=0.1 的模块
#        与一个 gap=0.5 + call=0.9 的模块可能得分相同，但实现价值完全不同。
#
# 方案:
#   NSGA-II 风格非支配排序:
#     1. 对每对模块 (A, B) 判定 A 是否支配 B
#        （A 在所有目标 ≥ B 且至少一个目标严格 > B）
#     2. 前沿分层: Front₀ = 非支配集，Front₁ = 仅被 Front₀ 支配的集，...
#     3. 同层内以拥挤距离（Crowding Distance）排序，保证前沿多样性
#     4. 输出: 按 (Front, -crowding_distance) 排序，天然区分"优先实现"与"延后"
#
# 区别于已有工作:
#   Pareto 排序广泛用于演化算法（NSGA-II, SPEA2）的适应度赋值，
#   但在桩模块实现优先级排序中的应用未见文献报告。
#   本模块将"多目标优化"范式引入桩系统管理，使实现排序从
#   "调权艺术"变为"可证明的非支配选择"。
import time as _time
from dataclasses import dataclass as _dc, field as _field


@_dc
class ParetoScore:
    """单个模块的 Pareto 排序结果。"""
    module_name: str
    status: str = ''
    # 原始目标值
    gap: float = 0.0           # 实现缺口（越大越优先）
    call_volume: float = 0.0   # 调用量（越大越优先）
    health: float = 0.0        # 健康度（越大越优先）
    complexity: float = 0.0    # 复杂度（越小越优先 → 内部取反）
    recency: float = 0.0       # 最近调用（越大越优先）
    # Pareto 分层结果
    front: int = -1            # 0 = 第一前沿 (Pareto optimal)
    crowding_distance: float = 0.0
    # 综合排序键: (front, -crowding_distance)
    rank: int = -1
    is_dominated: bool = False  # 是否被至少一个模块支配


class ParetoPrioritizer:
    """基于非支配排序的多目标优先级排序器。

    五个优化目标:
      1. max gap          — 优先填补大缺口
      2. max call_volume  — 优先实现高频调用桩
      3. max health       — 优先维护健康桩
      4. min complexity   — 优先实现简单桩（快速见效）→ 内部取反为 max(-complexity)
      5. max recency      — 优先实现近期活跃桩

    目标向量: [gap, call_volume, health, -complexity, recency]
    支配判定: A ≻ B ⇔ ∀i A_i ≥ B_i ∧ ∃j A_j > B_j
    """

    def __init__(self, monitor=None, contractor=None,
                 registry=None, weights=None):
        # 复用现有基础设施获取原始维度值
        try:
            from modules.stubs.stub_prioritizer import ImplementationPrioritizer
            self._base = ImplementationPrioritizer(
                monitor=monitor, contractor=contractor,
                registry=registry, weights=weights)
        except ImportError:
            self._base = None

    def rank(self) -> list[ParetoScore]:
        """执行非支配排序，返回 Pareto 分层排序结果。"""
        if self._base is None:
            return []

        # 从基础排序器获取原始维度值
        base_ranking = self._base.rank()
        scores = []
        for p in base_ranking:
            scores.append(ParetoScore(
                module_name=p.module_name,
                status=p.status,
                gap=p.gap_score,
                call_volume=p.call_volume_score,
                health=p.health_score,
                complexity=p.complexity_score,
                recency=p.recency_score,
            ))

        if not scores:
            return []

        # 构建目标矩阵
        objectives = []
        for s in scores:
            # 复杂度取反（原始越高越复杂，优化方向应为越小越好）
            objectives.append([
                s.gap,
                s.call_volume,
                s.health,
                1.0 - s.complexity,  # 取反: 低复杂度 → 高分
                s.recency,
            ])

        n = len(scores)

        # 支配计数与被支配集
        domination_count = [0] * n          # S_p: 支配 p 的模块数
        dominated_set = [set() for _ in range(n)]  # 被 p 支配的模块集

        for i in range(n):
            for j in range(n):
                if i == j:
                    continue
                if self._dominates(objectives[i], objectives[j]):
                    dominated_set[i].add(j)
                elif self._dominates(objectives[j], objectives[i]):
                    domination_count[i] += 1

        # 前沿分层
        fronts = []
        remaining = set(range(n))
        while remaining:
            current_front = {
                i for i in remaining if domination_count[i] == 0
            }
            if not current_front:
                break
            fronts.append(current_front)

            for i in current_front:
                for j in dominated_set[i]:
                    domination_count[j] -= 1

            remaining -= current_front

        # 分配 front 编号
        for fi, front_set in enumerate(fronts):
            for idx in front_set:
                scores[idx].front = fi
            # 同层内计算拥挤距离
            self._crowding_distance(scores, objectives, front_set)

        # 未被分配到任何 front 的模块（边界情况）
        for i in remaining:
            scores[i].front = len(fronts)

        # 全局排序: (front, -crowding_distance)
        ordered = sorted(scores, key=lambda s: (
            s.front if s.front >= 0 else 999,
            -s.crowding_distance,
        ))
        for rank, s in enumerate(ordered, start=1):
            s.rank = rank
            s.is_dominated = s.front > 0

        return ordered

    def pareto_front(self) -> list[ParetoScore]:
        """仅返回第一前沿 (Pareto 最优集)。"""
        return [s for s in self.rank() if s.front == 0]

    def implementation_backlog(self, n: int = None) -> list[str]:
        """Pareto 排序的实现积压清单（模块名）。"""
        ranked = self.rank()
        backlog = [s.module_name for s in ranked
                  if s.gap > 0.0]
        return backlog[:n] if n is not None else backlog

    @staticmethod
    def _dominates(a: list[float], b: list[float]) -> bool:
        """判定目标向量 a 是否支配 b。

        a ≻ b ⇔ ∀i a_i ≥ b_i ∧ ∃j a_j > b_j
        容忍微小数值误差: 差值 < 1e-9 视为相等。
        """
        at_least_one_strictly_better = False
        for ai, bi in zip(a, b):
            if ai < bi - 1e-9:
                return False
            if ai > bi + 1e-9:
                at_least_one_strictly_better = True
        return at_least_one_strictly_better

    @staticmethod
    def _crowding_distance(scores: list[ParetoScore],
                           objectives: list[list[float]],
                           front_set: set) -> None:
        """计算同层内各点的拥挤距离（Crowding Distance）。

        拥挤距离 = 各目标维度上相邻点归一化距离之和。
        高拥挤距离 → 位于稀疏区域 → 多样性更高 → 同层内优先。
        边界点（某维度上的 min/max）拥挤距离设为无穷大以保留极端解。
        """
        if len(front_set) <= 2:
            # 避免全部inf导致排序不确定性。
            # 用第一目标值递减作为确定性tiebreaker。
            indices = sorted(front_set, key=lambda i: -objectives[i][0])
            for rank, i in enumerate(indices):
                scores[i].crowding_distance = 1000.0 - rank
            return

        m = len(objectives[0])  # 目标维度数
        indices = list(front_set)

        for obj_idx in range(m):
            # 按该目标值排序
            indices.sort(key=lambda i: objectives[i][obj_idx])

            obj_min = objectives[indices[0]][obj_idx]
            obj_max = objectives[indices[-1]][obj_idx]
            obj_range = obj_max - obj_min

            # 边界点
            scores[indices[0]].crowding_distance = float('inf')
            scores[indices[-1]].crowding_distance = float('inf')

            if obj_range < 1e-9:
                continue

            for k in range(1, len(indices) - 1):
                prev_val = objectives[indices[k - 1]][obj_idx]
                next_val = objectives[indices[k + 1]][obj_idx]
                dist = (next_val - prev_val) / obj_range
                if scores[indices[k]].crowding_distance != float('inf'):
                    scores[indices[k]].crowding_distance += dist
                else:
                    scores[indices[k]].crowding_distance = dist

    def pareto_report(self, top_n: int = 20) -> str:
        """生成 Markdown Pareto 排序报告。"""
        ranked = self.rank()[:top_n]
        lines = [
            '# Pareto 前沿排序报告',
            f'生成时间: {_time.strftime("%Y-%m-%d %H:%M:%S")}',
            '',
            '| Rank | Front | 模块 | Gap | Call | Health | Compl | Recency | CDist |',
            '|-----:|------:|------|----:|-----:|-------:|------:|-------:|------:|',
        ]
        for s in ranked:
            cd = f'{s.crowding_distance:.3f}' if s.crowding_distance != float('inf') else '∞'
            lines.append(
                f'| {s.rank} | F{s.front} | {s.module_name} | '
                f'{s.gap:.2f} | {s.call_volume:.2f} | {s.health:.2f} | '
                f'{s.complexity:.2f} | {s.recency:.2f} | {cd} |')

        # 前沿分布统计
        front_counts = {}
        for s in ranked:
            front_counts[s.front] = front_counts.get(s.front, 0) + 1
        lines.append('')
        lines.append('## 前沿分布')
        for f_idx in sorted(front_counts):
            lines.append(f'- **Front {f_idx}**: {front_counts[f_idx]} 个模块')

        return '\n'.join(lines)


def rank_pareto() -> list[ParetoScore]:
    """一行式 Pareto 排序。"""
    return ParetoPrioritizer().rank()


__all__ = ['ParetoScore', 'ParetoPrioritizer', 'rank_pareto']
