# 跨分析关联规则挖掘 (Cross-Analysis Association Rule Mining)
#
# 核心问题: 二进制分析流水线产出多维信号 (图评分, 向量距离, IOC密度,
#   熵分布, 片段相似度), 但这些信号之间的关系未被显式建模.
#   例如: "当 graph_score > 0.8 且 entropy ∈ [4, 6] 时,
#   IOC 提取命中率是 basline 的 3.2 倍" — 这类规则可指导分析优先级.
#
# 创新点:
#   1. 多模态量化: 将连续分析输出离散化为有序分箱 (quantile-based).
#      每维度 4-5 个箱, 保证每箱样本量均衡. 离散化后应用
#      Apriori 启发式挖掘频繁项集.
#   2. 跨模态关联规则: 规则形式 {A_high, B_medium} → {C_high},
#      其中 A/B/C 来自不同分析通道. 度量: support, confidence, lift.
#      lift > 1 → 正相关, lift < 1 → 负相关, lift = 1 → 独立.
#   3. 可操作规则排序: 按 (lift × log(support+1)) 降序排列,
#      优先展示高影响力且频繁的规则. 过滤平凡规则 (confidence ≈ baserate).
#   4. 时序规则演化: 比较两个时间窗口的规则集差异,
#      检测新增/消失/强度变化的规则 → 分析流水线行为漂移的根因.
#
# 与现有工作:
# 关联规则挖掘 (Apriori, FP-Growth): 面向交易数据.
#     本方案适配连续分析输出的离散化 + 跨模态约束.
# 无已知论文将关联规则应用于二进制分析输出的交叉模式发现.

import math
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple


class AnalysisRuleMiner:
    """跨分析关联规则挖掘器.

    用法:
      arm = AnalysisRuleMiner(n_bins=4, min_support=0.05, min_lift=1.5)
      for sig_id, analysis_dims in dataset:
          arm.add_record(sig_id, analysis_dims)
      rules = arm.mine_rules()
      for r in rules:
          print(f"{r.antecedent} → {r.consequent} (lift={r.lift:.2f})")
    """

    def __init__(self, n_bins: int = 4, min_support: float = 0.05,
                 min_lift: float = 1.5, max_antecedent_size: int = 3):
        self.n_bins = n_bins
        self.min_support = min_support
        self.min_lift = min_lift
        self.max_ant = max_antecedent_size
        self._records: List[Dict[str, float]] = []
        self._discretized: List[Set[str]] = []
        self._dim_names: List[str] = []
        self._bin_edges: Dict[str, List[float]] = {}

    def add_record(self, record_id: int, dims: Dict[str, float]):
        """添加一条分析记录."""
        self._records.append(dims)

    def fit_discretize(self):
        """计算分箱边界并离散化所有记录."""
        if not self._records:
            return
        self._dim_names = sorted(self._records[0].keys())

        # 每维度计算分位数边界
        for dim in self._dim_names:
            values = sorted(r.get(dim, 0.0) for r in self._records)
            n = len(values)
            edges = []
            for b in range(1, self.n_bins):
                idx = int(n * b / self.n_bins)
                edges.append(values[min(idx, n-1)])
            self._bin_edges[dim] = edges

        # 离散化
        self._discretized = []
        for r in self._records:
            items = set()
            for dim in self._dim_names:
                val = r.get(dim, 0.0)
                label = self._value_to_label(dim, val)
                items.add(f"{dim}_{label}")
            self._discretized.append(items)

    def mine_rules(self) -> List["AnalysisRule"]:
        """挖掘关联规则."""
        if not self._discretized:
            self.fit_discretize()
        if not self._discretized:
            return []

        n_total = len(self._discretized)
        all_items = set()
        for itemset in self._discretized:
            all_items.update(itemset)

        # 计数单项
        item_counts = defaultdict(int)
        for itemset in self._discretized:
            for item in itemset:
                item_counts[item] += 1

        # 过滤: support ≥ min_support
        freq_items = {item for item, cnt in item_counts.items()
                      if cnt / n_total >= self.min_support}

        # 枚举 2-itemsets 和 3-itemsets
        rules = []
        freq_list = sorted(freq_items)

        # 候选 antecedent (1-2 items) → 候选 consequent (1 item)
        for ant_size in range(1, self.max_ant):
            for con_item in freq_list:
                con_dim = con_item.split('_')[0]
                con_count = item_counts[con_item]
                con_support = con_count / n_total

                # 枚举 antecedent 组合
                ant_candidates = self._gen_antecedents(
                    freq_list, ant_size, exclude=con_item)

                for ant in ant_candidates:
                    # 跨模态约束: antecedent 和 consequent 必须来自不同维度
                    ant_dims = {item.split('_')[0] for item in ant}
                    if con_dim in ant_dims:
                        continue

                    # 联合计数
                    joint_count = 0
                    for itemset in self._discretized:
                        if ant.issubset(itemset) and con_item in itemset:
                            joint_count += 1

                    if joint_count / n_total < self.min_support:
                        continue

                    ant_count = sum(1 for itemset in self._discretized
                                    if ant.issubset(itemset))
                    if ant_count == 0:
                        continue

                    confidence = joint_count / ant_count
                    lift = confidence / max(con_support, 1e-9)

                    if lift >= self.min_lift:
                        rules.append(AnalysisRule(
                            antecedent=sorted(ant),
                            consequent=con_item,
                            support=round(joint_count/n_total, 4),
                            confidence=round(confidence, 4),
                            lift=round(lift, 2),
                            ant_count=ant_count,
                            joint_count=joint_count,
                        ))

        rules.sort(key=lambda r: r.score, reverse=True)
        return rules[:50]

    def temporal_diff(self, old_rules: List["AnalysisRule"],
                       new_rules: List["AnalysisRule"]) -> dict:
        """比较两个时间窗口的规则差异."""
        old_map = {r.key: r for r in old_rules}
        new_map = {r.key: r for r in new_rules}

        emerged = [r for k, r in new_map.items() if k not in old_map]
        vanished = [r for k, r in old_map.items() if k not in new_map]
        strengthened = []
        for k in set(old_map) & set(new_map):
            if new_map[k].lift > old_map[k].lift * 1.2:
                strengthened.append((old_map[k], new_map[k]))

        return {
            "emerged": len(emerged), "vanished": len(vanished),
            "strengthened": len(strengthened),
            "emerged_rules": [r.to_dict() for r in emerged[:5]],
            "vanished_rules": [r.to_dict() for r in vanished[:5]],
        }

    def _value_to_label(self, dim: str, value: float) -> str:
        edges = self._bin_edges.get(dim, [])
        for i, edge in enumerate(edges):
            if value <= edge:
                return f"L{i}"  # low-0, low-1, ...
        return f"L{len(edges)}"

    def _gen_antecedents(self, items: List[str], size: int,
                          exclude: str) -> List[Set[str]]:
        result = []
        self._combos(items, size, 0, set(), exclude, result)
        return result

    def _combos(self, items, size, start, current, exclude, result):
        if len(current) == size:
            result.append(set(current)); return
        for i in range(start, len(items)):
            if items[i] == exclude: continue
            current.add(items[i])
            self._combos(items, size, i+1, current, exclude, result)
            current.discard(items[i])


class AnalysisRule:
    """单条关联规则."""
    __slots__ = ("antecedent","consequent","support","confidence","lift",
                 "ant_count","joint_count")
    def __init__(self, antecedent: List[str], consequent: str,
                 support: float, confidence: float, lift: float,
                 ant_count: int, joint_count: int):
        self.antecedent = antecedent; self.consequent = consequent
        self.support = support; self.confidence = confidence; self.lift = lift
        self.ant_count = ant_count; self.joint_count = joint_count

    @property
    def key(self) -> str:
        return f"{'&'.join(self.antecedent)}→{self.consequent}"

    @property
    def score(self) -> float:
        return self.lift * math.log(self.support + 1)

    @property
    def interpretation(self) -> str:
        if self.lift > 3: return "strong_positive_correlation"
        elif self.lift > 2: return "moderate_positive_correlation"
        elif self.lift > 1.5: return "weak_positive_correlation"
        return "negligible"

    def to_dict(self) -> dict:
        return {"rule": self.key, "support": self.support,
                "confidence": self.confidence, "lift": self.lift,
                "strength": self.interpretation}


__all__ = [
    "AnalysisRuleMiner",
    "AnalysisRule",
]
