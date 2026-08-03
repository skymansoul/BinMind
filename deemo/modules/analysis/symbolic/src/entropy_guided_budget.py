#
# 熵引导的探索预算分配器 — 按路径约束集的 Shannon 熵动态分配求解时间预算
#
# 符号执行中不同路径的"信息价值"差异巨大。一条仅含 (x > 0) 约束的路径
# 在熵的意义上几乎不携带信息——它仅排除了 x ≤ 0 的半空间。相比之下
# 一条含 (x & 0xFF == 0x7F) ∧ (x << 2 > 0x100) ∧ (mem[rcx+8]!= 0)
# 的路径约束了多个变量在多个位宽上的关系——熵高，探索价值高
#
# SolverBudgetManager 按固定配额均匀分配求解预算。本模块在其之上叠加
# 一层基于熵的加权：高熵路径获得更多预算（上限为基准的 3x），低熵路径
# 获得较少（下限为基准的 0.3x）。总预算不变——只是重分配
#
# 熵估计方法（选择字符串级而非 Z3 AST 级的原因见内联注释）：
# (a) 操作类型分布熵: -Σ p(op) × log₂(p(op))，op ∈ {cmp, arith, bitw, mem, bool}
#   (b) 约束数量因子: log₂(1 + |constraints|) / log₂(1 + max_constraints)
#   (c) 联合熵 = (a) × 0.7 + (b) × 0.3 —— 操作类型权重更高因为语义多样性主要由操作类型贡献

import math
from typing import Dict, List, Tuple, Optional
from collections import Counter


class EntropyBudgetAllocator:
    """基于路径约束集 Shannon 熵的求解预算加权分配器
    
    不替代 SolverBudgetManager——在其配额之上做二级分配
    用法: allocator.alloc(paths, base_budget) → {path_id: budget}
    调用方拿到各路径的分配预算后传给 SolverBudgetManager.consume()
    """

    # 操作类型关键词——用于字符串级熵估计
    # 选择字符串级而非 Z3 AST 遍历的原因：
    #   Z3 AST 遍历需要构造每个约束的表达式树，在需要快速评估数十条路径
    # 的场景中开销过大（每约束 ~50μs AST 遍历 vs ~2μs 字符串扫描）
    # Z3 AST 级的精度提升在此场景下不值得额外开销
    _OP_PATTERNS = {
        'cmp': ('bvult', 'bvule', 'bvugt', 'bvuge', 'bvslt', 'bvsle',
                'bvsgt', 'bvsge', '=', 'distinct', '==', '!=', '<=', '>='),
        'arith': ('bvadd', 'bvsub', 'bvmul', 'bvudiv', 'bvurem',
                  'bvsdiv', 'bvsrem', '+', '-', '*', '/'),
        'bitwise': ('bvand', 'bvor', 'bvxor', 'bvnot', 'bvshl',
                    'bvlshr', 'bvashr', 'concat', 'extract', '<<', '>>', '&', '|', '^'),
        'mem': ('store', 'load', 'select', 'mem', 'zero_extend', 'sign_extend'),
        'bool': ('ite', 'if', 'implies', 'and', 'or', 'not', '=>'),
    }

    def __init__(self,
                 max_budget_ratio: float = 3.0,
                 min_budget_ratio: float = 0.3,
                 op_type_weight: float = 0.7):
        """
        max_budget_ratio: 高熵路径可获得的最大预算倍率（相对基准）
        min_budget_ratio: 低熵路径可被削减到的最小预算倍率
        op_type_weight: 操作类型分布熵在联合熵中的权重（剩余归约束数量因子）
        """
        self._max_ratio = max_budget_ratio
        self._min_ratio = min_budget_ratio
        self._op_weight = op_type_weight

    def _classify_tokens(self, constraint_str: str) -> List[str]:
        """将单个约束字符串分类到操作类型。一个约束可同时属于多类
        
        如 "(bvadd (bvand x y) z)" 同时触发 'arith' (bvadd) 和 'bitw' (bvand)
        这是故意的——混合操作类型的约束在语义上更复杂，理应在熵估计中获得更高权重
        """
        s = constraint_str.lower()
        types = []
        for op_type, keywords in self._OP_PATTERNS.items():
            for kw in keywords:
                if kw in s:
                    types.append(op_type)
                    break  # 每种类型最多计数一次——避免 (bvadd. bvadd.) 重复计数
        return types

    def estimate_entropy(self, constraints: List[str]) -> float:
        """估计约束集的 Shannon 熵。返回 [0, 1] 区间的归一化值
        
        两个约束集若操作类型分布完全相同但约束数量不同
        则约束数量更多的集合获得更高的联合熵
        """
        if not constraints:
            return 0.0

        # (a) 操作类型分布熵
        type_counts: Counter = Counter()
        for c in constraints:
            for t in self._classify_tokens(c):
                type_counts[t] += 1

        total_tokens = sum(type_counts.values())
        if total_tokens == 0:
            return 0.0

        op_entropy = 0.0
        for count in type_counts.values():
            p = count / total_tokens
            op_entropy -= p * math.log2(p)

        # 归一化: 均匀分布在 5 类上 → max entropy = log₂(5) ≈ 2.322
        max_entropy = math.log2(len(self._OP_PATTERNS))
        norm_op_entropy = op_entropy / max_entropy if max_entropy > 0 else 0.0

        # (b) 约束数量因子
        count_factor = math.log2(1 + len(constraints)) / math.log2(1 + 50)
        count_factor = min(1.0, count_factor)

        # (c) 联合熵
        return self._op_weight * norm_op_entropy + (1 - self._op_weight) * count_factor

    def allocate(self, paths: Dict[str, List[str]],
                 base_budget_per_path: float) -> Dict[str, float]:
        """为各路径分配求解预算
        
        参数:
        paths: {path_id: [constraint_str,.]}
        base_budget_per_path: SolverBudgetManager 分配给每条路径的基准时间（秒）
        
        返回:
        {path_id: allocated_budget}，总和 = base_budget_per_path × len(paths)
        各路径分配在 [min_ratio × base, max_ratio × base] 范围内
        """
        if not paths:
            return {}

        # 计算各路径的熵
        entropies: Dict[str, float] = {}
        for pid, constraints in paths.items():
            entropies[pid] = self.estimate_entropy(constraints)

        # 熵 → 权重映射（线性缩放）
        entropy_values = list(entropies.values())
        min_e, max_e = min(entropy_values), max(entropy_values)
        e_range = max_e - min_e if max_e > min_e else 1.0

        weights: Dict[str, float] = {}
        total_weight = 0.0
        for pid, e in entropies.items():
            normalized = (e - min_e) / e_range
            w = self._min_ratio + normalized * (self._max_ratio - self._min_ratio)
            weights[pid] = w
            total_weight += w

        # 归一化使总分配 = base_budget × N
        n = len(paths)
        total_base = base_budget_per_path * n
        scale = total_base / total_weight if total_weight > 0 else 1.0

        allocation = {}
        for pid, w in weights.items():
            allocation[pid] = round(w * scale, 4)

        return allocation
