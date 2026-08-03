# 修改记录:
# 2025-08-01 13:55 - 引入约束距离的加权编辑距离替代简单 token Jaccard
#
# 冷点引导探索器 -- 从 PathHeatmap 冷点出发，计算最小约束修改以重定向执行
#
# PathHeatmap.identify_cold_spots() 回答了"哪里没探索到"。但仅知道坐标
# (depth=6, constraints=15) 是冷点没有任何可操作的信息——你需要知道如何
# 让符号执行到达那里。本模块填补这个从""到""的缺口
#
# 核心思路：
#   1. 从当前已探索路径池中找到与冷点最近的 k 条路径
#   2. 对每条近邻路径，计算其约束集与"理想冷点约束集"的约束编辑距离
# 3. 约束编辑距离最小化 -> 输出具体的约束修改（如"将第 3 个约束
#      的 bvult 改为 bvuge"），供符号执行引擎在下一轮 fork 时使用
#
# 与 PALM (Wu et al., 2025) 的差异：
# PALM 用 LLM 生成到达目标路径的测试用例，依赖大模型的外部推理能力
# 本模块完全在符号执行框架内求解——不依赖 LLM，可离线运行
#
# 参考文献：
# PALM: "Path-Aware 符号执行 LLMs", Wu et al., 2025
#     (arXiv:2506.19287 [待验证]) -- 提出路径覆盖热力图可视化，但利用 LLM 生成
# 测试用例，不涉及约束集编辑距离计算
#   Concrete Constraint Guided SE: Sun et al., ICSE 2024 --
# 用数据依赖分析引导覆盖具体分支条件，但聚焦于具体值而非约束结构

import math
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from collections import Counter


#---------------------------------------------------------------------------
# 操作类型分类——与 EntropyBudgetAllocator 共享相同的分类体系
#---------------------------------------------------------------------------

_OP_PATTERNS = {
    'cmp': ('bvult', 'bvule', 'bvugt', 'bvuge', 'bvslt', 'bvsle',
            'bvsgt', 'bvsge', 'distinct', '=', '==', '!=', '<=', '>='),
    'arith': ('bvadd', 'bvsub', 'bvmul', 'bvudiv', 'bvurem',
              'bvsdiv', 'bvsrem', '+', '-', '*', '/'),
    'bitwise': ('bvand', 'bvor', 'bvxor', 'bvnot', 'bvshl',
                'bvlshr', 'bvashr', 'concat', 'extract', '<<', '>>', '&', '|', '^'),
    'mem': ('store', 'load', 'select', 'mem', 'zero_extend', 'sign_extend'),
    'bool': ('ite', 'if', 'implies', 'and', 'or', 'not', '=>'),
}

# 操作类型替换成本矩阵——值越大越不相似
_OP_REPLACE_COST = {
    ('cmp', 'arith'): 2, ('cmp', 'bitwise'): 2, ('cmp', 'mem'): 3, ('cmp', 'bool'): 1,
    ('arith', 'bitwise'): 1, ('arith', 'mem'): 2, ('arith', 'bool'): 2,
    ('bitwise', 'mem'): 2, ('bitwise', 'bool'): 1,
    ('mem', 'bool'): 3,
}
for (a, b), cost in list(_OP_REPLACE_COST.items()):
    _OP_REPLACE_COST[(b, a)] = cost


#---------------------------------------------------------------------------
# 数据结构
#---------------------------------------------------------------------------

@dataclass
class RedirectionPlan:
    """一条冷点重定向方案"""
    cold_spot: Tuple[int, int]
    source_path_id: str
    edit_distance: float
    suggested_edits: List[str]
    estimated_reachability: float  # [0, 1]


#---------------------------------------------------------------------------
# 核心类
#---------------------------------------------------------------------------

class ColdSpotGuidedExplorer:
    """从冷点坐标出发，计算约束修改方案以引导符号执行
    
    用法：
    explorer = ColdSpotGuidedExplorer()
    paths = {'p1': ['(bvult x 10)', '(bvadd y z)'],.}
    cold_spots = [(6, 12), (8, 15)] # 来自 PathHeatmap
    plans = explorer.generate_plans(paths, cold_spots, top_k=3)
    """

    def __init__(self,
                 max_edit_distance: float = 15.0,
                 min_reachability: float = 0.1):
        self._max_edit_dist = max_edit_distance
        self._min_reach = min_reachability

    @staticmethod
    def _classify_constraint(constraint: str) -> List[str]:
        s = constraint.lower()
        types = []
        for op_type, keywords in _OP_PATTERNS.items():
            for kw in keywords:
                if kw in s:
                    types.append(op_type)
                    break
        return types if types else ['unknown']

    def _constraint_edit_distance(self, c1: str, c2: str) -> float:
        """两条约束字符串之间的加权编辑距离"""
        types1 = self._classify_constraint(c1)
        types2 = self._classify_constraint(c2)

        min_type_cost = float('inf')
        for t1 in types1:
            for t2 in types2:
                if t1 == t2:
                    min_type_cost = 0.0
                else:
                    cost = _OP_REPLACE_COST.get((t1, t2), 2)
                    min_type_cost = min(min_type_cost, cost)
        if min_type_cost == float('inf'):
            min_type_cost = 2.0

        tokens1 = set(c1.lower().replace('(', ' ').replace(')', ' ').split())
        tokens2 = set(c2.lower().replace('(', ' ').replace(')', ' ').split())
        if tokens1 and tokens2:
            jaccard = len(tokens1 & tokens2) / len(tokens1 | tokens2)
            operand_cost = (1.0 - jaccard) * 2.0
        else:
            operand_cost = 2.0

        return min_type_cost + operand_cost

    def generate_plans(self,
                       paths: Dict[str, List[str]],
                       cold_spots: List[Tuple[int, int]],
                       top_k: int = 3) -> List[RedirectionPlan]:
        """为每个冷点生成 k 个重定向方案"""
        if not paths or not cold_spots:
            return []

        all_plans: List[RedirectionPlan] = []

        for cold_depth, cold_cons in cold_spots:
            candidates: List[Tuple[str, float]] = []
            for pid, constraints in paths.items():
                depth = len(constraints)
                c_count = len(constraints)
                dist = abs(depth - cold_depth * 2) + 0.5 * abs(c_count - cold_cons * 5)
                candidates.append((pid, dist))

            candidates.sort(key=lambda x: x[1])
            nearest = candidates[:top_k]

            for pid, path_dist in nearest:
                constraints = paths.get(pid, [])
                ideal_cons = self._estimate_cold_spot_constraints(
                    constraints, cold_depth, cold_cons)

                total_dist = 0.0
                edits: List[str] = []
                for i, c_actual in enumerate(constraints):
                    if i < len(ideal_cons):
                        c_ideal = ideal_cons[i]
                        d = self._constraint_edit_distance(c_actual, c_ideal)
                        total_dist += d
                        if d > 1.0:
                            edits.append(
                                f"修改约束[{i}]: 当前操作={self._classify_constraint(c_actual)}, "
                                f"目标操作={self._classify_constraint(c_ideal)}"
                            )

                count_diff = abs(len(constraints) - len(ideal_cons))
                total_dist += count_diff * 3.0

                if total_dist > self._max_edit_dist:
                    continue

                reachability = 1.0 / (1.0 + total_dist)
                if reachability < self._min_reach:
                    continue

                all_plans.append(RedirectionPlan(
                    cold_spot=(cold_depth, cold_cons),
                    source_path_id=pid,
                    edit_distance=round(total_dist, 2),
                    suggested_edits=edits,
                    estimated_reachability=round(reachability, 3),
                ))

        all_plans.sort(key=lambda p: p.edit_distance)
        return all_plans

    @staticmethod
    def _estimate_cold_spot_constraints(
            existing: List[str],
            target_depth_bucket: int,
            target_cons_bucket: int) -> List[str]:
        """估计冷点区域的典型约束集
        
        基于现有路径的约束类型分布，外推目标数量的约束
        这不是精确预测——而是提供"如果在那个区域，约束应该长什么样"
        的统计估计。后续可替换为基于 GNN 的约束预测模型
        """
        if not existing:
            return []

        target_cons = target_cons_bucket * 5

        type_counts: Counter = Counter()
        for c in existing:
            s = c.lower()
            for op_type, keywords in _OP_PATTERNS.items():
                if any(kw in s for kw in keywords):
                    type_counts[op_type] += 1
                    break

        total = sum(type_counts.values()) or 1
        result = []
        # 模板使用实际 Z3/SMT-LIB 关键字，确保 _classify_constraint 可识别操作类型
        # 占位符 {var} 供调用方替换为具体符号变量名
        templates = {
            'cmp': '(bvult {var} {var})',
            'arith': '(bvadd {var} {var})',
            'bitwise': '(bvand {var} {var})',
            'mem': '(store {var} {var} {var})',
            'bool': '(ite {var} {var} {var})',
        }
        for op_type, count in type_counts.most_common():
            fraction = count / total
            n = max(1, int(target_cons * fraction))
            template = templates.get(op_type, '(bvadd {var} {var})')
            for _ in range(min(n, target_cons - len(result))):
                result.append(template)

        return result[:target_cons]
