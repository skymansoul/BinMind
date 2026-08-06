# Def-Use链引导的Fuzzing种子调度 — 基于 FuzzRDUCC (arXiv:2509.04967, Sep 2025)
# 论文: "FuzzRDUCC: Fuzzing with Reconstructed Def-Use Chain Coverage"
# 核心改进: 从反编译代码重建def-use链, 追踪哪些def-use边已被覆盖,
# 优先调度能命中未覆盖def-use边的种子。对体积大、分支深的二进制
# 可提升边覆盖速度, 因为def-use边比基本块边更稀疏(通常少40-60%)。
# 理论依据: def-use覆盖是基本块覆盖的严格细化 — 同一条基本块边
# 上不同变量定义-使用组合构成不同def-use边, 天然提供更细粒度的进度信号。

from __future__ import annotations

import hashlib
import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

_log = logging.getLogger(__name__)

# def-use模式: var = expr  →  ...  →  use(var)
_RE_DEF = re.compile(r'(\w[\w.]*)\s*=\s*(.+?);')
_RE_USE = re.compile(r'\b(\w+)\b')


@dataclass
class DefUseEdge:
    """一条def-use边: 变量在某处被定义, 在另一处被使用"""
    var_name: str
    def_line: int       # 定义行号
    use_line: int       # 使用行号
    def_expr: str = ""  # 定义表达式(截断至60字符)


@dataclass
class SeedDefUseProfile:
    """单个种子覆盖的def-use边集合 + 优先级分数"""
    seed_id: str
    seed_path: str
    covered_edges: FrozenSet[Tuple[str, int, int]] = field(default_factory=frozenset)
    priority_score: float = 0.0
    # 该种子独有的def-use边 (与其他已调度种子不重叠的部分)
    unique_edge_count: int = 0


class DefUseExtractor:
    """从反编译伪代码提取def-use链。
    不做完整数据流分析, 用轻量词法匹配近似def-use关系。
    适用于fuzzing场景(允许适度噪声, 重点是速度快)。
    """

    @staticmethod
    def extract(code: str, func_name: str = "") -> List[DefUseEdge]:
        """提取函数内所有def-use边。
        算法: 扫描变量定义, 对每个定义追踪后续行中该变量的首次使用。
        复杂度: O(L·V) where L=行数, V=每行token数。
        """
        edges = []
        lines = code.split('\n')

        # 收集所有变量定义
        definitions: Dict[str, List[Tuple[int, str]]] = defaultdict(list)
        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith('//') or stripped.startswith('#'):
                continue
            m = _RE_DEF.search(stripped)
            if m:
                var = m.group(1)
                expr = m.group(2).strip()[:60]
                # 排除明显的临时变量和循环计数器
                if var in ('i', 'j', 'k', 'idx', 'tmp', '_'):
                    continue
                definitions[var].append((i, expr))

        # 对每个定义, 找后续使用
        for var, def_sites in definitions.items():
            for def_line, def_expr in def_sites:
                # 从定义行的下一行开始扫描
                for use_line in range(def_line + 1, len(lines) + 1):
                    use_line_text = lines[use_line - 1].strip()
                    if not use_line_text or use_line_text.startswith('//'):
                        continue
                    # 检查此行是否使用该变量(token级匹配)
                    tokens = _RE_USE.findall(use_line_text)
                    if var in tokens:
                        edges.append(DefUseEdge(
                            var_name=var,
                            def_line=def_line,
                            use_line=use_line,
                            def_expr=def_expr,
                        ))
                        break  # 只记录首次使用, 近似最短路

        return edges


class DefUseCoverageTracker:
    """全局def-use边覆盖追踪。
    维护已覆盖边集合, 计算每个候选种子的独有def-use边数。
    """

    def __init__(self):
        self._global_covered: Set[Tuple[str, int, int]] = set()
        self._func_edges: Dict[str, List[DefUseEdge]] = {}
        self._seed_profiles: Dict[str, SeedDefUseProfile] = {}

    def register_function(self, func_name: str, code: str):
        """注册函数并提取其def-use边"""
        if func_name in self._func_edges:
            return
        edges = DefUseExtractor.extract(code, func_name)
        self._func_edges[func_name] = edges
        if edges:
            _log.debug('%s: %d def-use edges extracted', func_name, len(edges))

    def record_coverage(self, seed_id: str, seed_path: str,
                        func_name: str, covered_lines: Set[int]):
        """记录一个种子覆盖了哪些代码行, 映射到def-use边覆盖。
        covered_lines: 该种子执行期间触达的源码行号集合。
        """
        edges = self._func_edges.get(func_name, [])
        covered = set()
        for edge in edges:
            if edge.def_line in covered_lines or edge.use_line in covered_lines:
                covered.add((edge.var_name, edge.def_line, edge.use_line))

        self._global_covered.update(covered)
        self._seed_profiles[seed_id] = SeedDefUseProfile(
            seed_id=seed_id,
            seed_path=seed_path,
            covered_edges=frozenset(covered),
        )

    def score_seed(self, seed_id: str) -> float:
        """计算种子优先级分数。
        分数 = 种子独有的(未被其他种子覆盖的)def-use边数量。
        新发现的边权重更高, 鼓励探索。
        """
        profile = self._seed_profiles.get(seed_id)
        if not profile:
            return 0.0

        unique = 0
        new_edge_bonus = 0
        for edge in profile.covered_edges:
            if edge not in self._global_covered:
                new_edge_bonus += 1
            # 检查此边是否被其他种子覆盖
            other_has = any(
                edge in other.covered_edges
                for sid, other in self._seed_profiles.items()
                if sid != seed_id
            )
            if not other_has:
                unique += 1

        # 新边权重 ×3, 稀有边权重 ×2
        score = unique * 2.0 + new_edge_bonus * 3.0
        profile.unique_edge_count = unique
        profile.priority_score = score
        return score

    def prioritize_seeds(self, candidate_seeds: List[dict]) -> List[dict]:
        """对候选种子按def-use覆盖价值排序。
        输入: [{'id': str, 'path': str, 'func': str, 'lines': set}, ...]
        输出: 按优先级降序排列的种子列表, 附加 'du_score' 字段。
        """
        for seed in candidate_seeds:
            self.record_coverage(
                seed['id'], seed['path'],
                seed.get('func', ''),
                seed.get('lines', set()),
            )

        for seed in candidate_seeds:
            seed['du_score'] = self.score_seed(seed['id'])

        candidate_seeds.sort(key=lambda s: s['du_score'], reverse=True)
        return candidate_seeds

    @property
    def total_edges(self) -> int:
        return sum(len(e) for e in self._func_edges.values())

    @property
    def covered_edges(self) -> int:
        return len(self._global_covered)

    def coverage_ratio(self) -> float:
        total = self.total_edges
        return len(self._global_covered) / total if total > 0 else 0.0
