# 安全发现因果推断图: 约束因果发现+根因识别+修复优先级
# 参考: Pearl "Causal Inference in Statistics: A Primer" (Wiley 2016)
#       CausalVulGNN (Zhang & Chen, 2025): GNN+因果子图漏洞解释
#       Caro et al. "Causal Digital Twins for Cyber-Physical Security" (arXiv:2510.09616 [待验证], 2025)
# 设计边界:
#   - 基于观测数据, 无干预数据→仅推断至Markov等价类
#   - 方向消歧: (a)时间顺序 (b)CWE层级关系 (c)MITRE ATT&CK技术链
#   - 样本量≥20才启用条件独立性检验
#   - 输出PDAG, 未定向边标记为potential_confounding
from __future__ import annotations
import logging
import math
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict, Counter
from itertools import combinations

log = logging.getLogger(__name__)

# 条件独立性检验显著性阈值
_ALPHA_CI = 0.05
# 最小样本量: 低于此值禁用统计检验
_MIN_SAMPLES_FOR_TEST = 20
# Fisher z-transform atanh截断, 防止|r|≈1时数值不稳定
_FISHER_CLAMP = 0.9999


@dataclass
class CausalEdge:
    """因果边: source→target, 方向+置信度."""
    source: str
    target: str
    edge_type: str          # 'causal' | 'potential_confounding' | 'structural'
    confidence: float       # [0, 1]
    basis: str = ""         # 证据来源
    partial_corr: float = 0.0


@dataclass
class CausalGraph:
    """安全发现因果图 (PDAG). nodes: finding_id→{properties}; edges: 有向边; root_causes: 无入边节点."""
    nodes: Dict[str, Dict] = field(default_factory=dict)
    edges: List[CausalEdge] = field(default_factory=list)
    root_causes: List[str] = field(default_factory=list)

    def adj_matrix(self) -> Dict[str, Set[str]]:
        """邻接表，忽略方向."""
        adj: Dict[str, Set[str]] = defaultdict(set)
        for e in self.edges:
            adj[e.source].add(e.target)
            adj[e.target].add(e.source)
        return dict(adj)

    def in_degree(self, node_id: str) -> int:
        return sum(1 for e in self.edges if e.target == node_id
                   and e.edge_type in ('causal', 'structural'))

    def out_degree(self, node_id: str) -> int:
        return sum(1 for e in self.edges if e.source == node_id
                   and e.edge_type in ('causal', 'structural'))


class FindingCausalDiscoverer:
    """简化PC算法安全发现因果发现器.
    输入: 组件×发现共现矩阵
    输出: CausalGraph (PDAG)
    步骤: (1)全连接无向图 (2)条件独立性检验剪边 (3)方向推断
    """

    def __init__(self, alpha: float = _ALPHA_CI,
                 min_samples: int = _MIN_SAMPLES_FOR_TEST):
        self._alpha = alpha
        self._min_samples = min_samples

    def discover(self,
                 component_findings: Dict[str, List[str]],
                 finding_metadata: Optional[Dict[str, Dict]] = None,
                 finding_timestamps: Optional[Dict[str, float]] = None
                 ) -> CausalGraph:
        """组件-发现共现→因果图.
        component_findings: {comp_id: [finding_id, ...]}
        finding_metadata: {finding_id: {cwe, severity, title, ...}}
        finding_timestamps: {finding_id: posix_timestamp}
        """
        meta = finding_metadata or {}
        ts = finding_timestamps or {}

        all_findings = set()
        comp_sets: Dict[str, Set[str]] = {}
        for cid, flist in component_findings.items():
            fset = set(flist)
            comp_sets[cid] = fset
            all_findings.update(fset)

        fids = sorted(all_findings)
        n_comps = len(component_findings)
        graph = CausalGraph()
        for fid in fids:
            graph.nodes[fid] = meta.get(fid, {})

        if len(fids) < 2 or n_comps < 3:
            graph.root_causes = list(fids)
            return graph

        # 步骤1: 全连接骨架 (基于共现)
        co_occur: Dict[Tuple[str, str], int] = Counter()
        marginal: Dict[str, int] = Counter()
        for fset in comp_sets.values():
            for fid in fset:
                marginal[fid] += 1
            for a, b in combinations(sorted(fset), 2):
                co_occur[(a, b)] += 1

        skeleton: Set[Tuple[str, str]] = set()
        for (a, b), count in co_occur.items():
            if count >= 2:
                skeleton.add((a, b))

        # 步骤2: 条件独立性检验
        if n_comps >= self._min_samples:
            skeleton = self._prune_by_conditional_independence(
                skeleton, fids, comp_sets, n_comps, marginal, co_occur)
        else:
            log.info("样本量 %d < %d, 跳过条件独立性检验",
                     n_comps, self._min_samples)

        # 步骤3: 方向推断
        graph.edges = self._orient_edges(skeleton, fids, meta, ts, co_occur,
                                         n_comps)

        # 步骤4: 根因识别
        in_edges = Counter(e.target for e in graph.edges
                           if e.edge_type in ('causal', 'structural'))
        graph.root_causes = [fid for fid in fids
                             if in_edges.get(fid, 0) == 0]
        return graph

    def _prune_by_conditional_independence(
            self, skeleton: Set[Tuple[str, str]], fids: List[str],
            comp_sets: Dict[str, Set[str]], n_comps: int,
            marginal: Dict[str, int],
            co_occur: Dict[Tuple[str, str], int]
    ) -> Set[Tuple[str, str]]:
        """偏相关系数+Fisher z-transform检验条件独立性.
        H0: A 独立于 B | C. 不能拒绝H0→删除边A-B.
        """
        fid_to_idx = {fid: i for i, fid in enumerate(fids)}
        comp_list = list(comp_sets.keys())
        vectors: Dict[str, List[int]] = {}
        for fid in fids:
            vectors[fid] = [1 if fid in comp_sets.get(c, set()) else 0
                            for c in comp_list]

        def partial_corr(x: str, y: str, z: Optional[str]) -> float:
            """偏相关系数 r_{xy.z}."""
            vx, vy = vectors[x], vectors[y]
            r_xy = _pearson_r(vx, vy)
            if z is None:
                return r_xy
            vz = vectors[z]
            r_xz = _pearson_r(vx, vz)
            r_yz = _pearson_r(vy, vz)
            denom = math.sqrt((1.0 - r_xz * r_xz) * (1.0 - r_yz * r_yz))
            if denom < 1e-10:
                return 0.0
            pc = (r_xy - r_xz * r_yz) / denom
            return max(-_FISHER_CLAMP, min(_FISHER_CLAMP, pc))

        def fisher_test(r: float, n: int) -> float:
            """Fisher z-transform双边检验p-value."""
            if abs(r) >= _FISHER_CLAMP:
                return 0.0
            z = 0.5 * math.log((1.0 + r) / (1.0 - r))
            se = 1.0 / math.sqrt(n - 3)
            p = 2.0 * (1.0 - _norm_cdf(abs(z) / se))
            return p

        pruned = set(skeleton)
        # 0阶: 边缘独立检验
        for a, b in list(pruned):
            r = partial_corr(a, b, None)
            p = fisher_test(r, n_comps)
            if p > self._alpha:
                pruned.discard((a, b))

        # 1阶: 条件于第三个变量
        for a, b in list(pruned):
            candidates = [z for z in fids if z != a and z != b
                          and (a, z) in pruned and (b, z) in pruned]
            for z in candidates[:5]:
                r = partial_corr(a, b, z)
                p = fisher_test(r, n_comps)
                if p > self._alpha:
                    pruned.discard((a, b))
                    break

        return pruned

    def _orient_edges(self, skeleton: Set[Tuple[str, str]],
                      fids: List[str],
                      meta: Dict[str, Dict],
                      ts: Dict[str, float],
                      co_occur: Dict[Tuple[str, str], int],
                      n_comps: int) -> List[CausalEdge]:
        """方向推断: (1)CWE层级 (2)时间顺序 (3)标记为混杂."""
        edges: List[CausalEdge] = []
        for a, b in skeleton:
            count = co_occur.get((a, b), co_occur.get((b, a), 1))
            support = min(1.0, count / max(n_comps, 1) * 3.0)
            directed = False

            # 规则1: CWE层级
            cwe_a = (meta.get(a, {}) or {}).get('cwe', '')
            cwe_b = (meta.get(b, {}) or {}).get('cwe', '')
            if cwe_a and cwe_b:
                direction = _cwe_hierarchy_direction(cwe_a, cwe_b)
                if direction == 'a->b':
                    edges.append(CausalEdge(a, b, 'structural',
                                            min(support + 0.1, 1.0),
                                            f'CWE hierarchy: {cwe_a}->{cwe_b}'))
                    directed = True
                elif direction == 'b->a':
                    edges.append(CausalEdge(b, a, 'structural',
                                            min(support + 0.1, 1.0),
                                            f'CWE hierarchy: {cwe_b}->{cwe_a}'))
                    directed = True

            if directed:
                continue

            # 规则2: 时间顺序
            ts_a = ts.get(a)
            ts_b = ts.get(b)
            if ts_a and ts_b:
                if ts_a < ts_b - 86400:
                    edges.append(CausalEdge(a, b, 'causal', support,
                                            f'temporal: a precedes b by '
                                            f'{(ts_b - ts_a) / 86400:.0f}d'))
                    directed = True
                elif ts_b < ts_a - 86400:
                    edges.append(CausalEdge(b, a, 'causal', support,
                                            f'temporal: b precedes a by '
                                            f'{(ts_a - ts_b) / 86400:.0f}d'))
                    directed = True

            if directed:
                continue

            # 规则3: 无法确定方向，标记为混杂
            edges.append(CausalEdge(a, b, 'potential_confounding',
                                    support * 0.7,
                                    'direction unresolved'))
            edges.append(CausalEdge(b, a, 'potential_confounding',
                                    support * 0.7,
                                    'direction unresolved'))

        return edges


class RootCauseRanker:
    """根因排序: 下游因果边数×严重度权重."""

    _SEV_WEIGHTS = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1, 'info': 0.5}

    def rank(self, graph: CausalGraph) -> List[Dict]:
        """根因按root_cause_score降序."""
        downstream = self._downstream_impact(graph)

        ranked = []
        for root_id in graph.root_causes:
            meta = graph.nodes.get(root_id, {})
            sev = str(meta.get('severity', 'medium')).lower()
            sev_w = self._SEV_WEIGHTS.get(sev, 4)
            impact = downstream.get(root_id, 0)
            score = impact * sev_w

            ranked.append({
                'finding_id': root_id,
                'title': meta.get('title', root_id),
                'severity': sev,
                'downstream_impact': impact,
                'severity_weight': sev_w,
                'root_cause_score': round(score, 1),
            })

        return sorted(ranked, key=lambda x: x['root_cause_score'], reverse=True)

    def _downstream_impact(self, graph: CausalGraph) -> Dict[str, int]:
        """节点通过因果边可到达节点数 (不含自身)."""
        adj: Dict[str, List[str]] = defaultdict(list)
        for e in graph.edges:
            if e.edge_type in ('causal', 'structural'):
                adj[e.source].append(e.target)

        impact: Dict[str, int] = {}
        visited_global: Set[str] = set()

        def dfs(node: str) -> Set[str]:
            if node in visited_global:
                return set()
            visited_global.add(node)
            reachable: Set[str] = set()
            for child in adj.get(node, []):
                if child not in visited_global:
                    reachable.add(child)
                    reachable.update(dfs(child))
            return reachable

        for node in graph.nodes:
            visited_global.clear()
            impact[node] = len(dfs(node))

        return impact


# 统计辅助函数

def _pearson_r(x: List[int], y: List[int]) -> float:
    """Pearson相关系数."""
    n = len(x)
    if n < 3:
        return 0.0
    mx = sum(x) / n
    my = sum(y) / n
    sx = math.sqrt(sum((xi - mx) ** 2 for xi in x) / (n - 1))
    sy = math.sqrt(sum((yi - my) ** 2 for yi in y) / (n - 1))
    if sx < 1e-10 or sy < 1e-10:
        return 0.0
    cov = sum((xi - mx) * (yi - my) for xi, yi in zip(x, y)) / (n - 1)
    return max(-1.0, min(1.0, cov / (sx * sy)))


def _norm_cdf(z: float) -> float:
    """标准正态CDF近似 (Abramowitz & Stegun 7.1.26)."""
    if z < -8.0:
        return 0.0
    if z > 8.0:
        return 1.0
    b0, b1, b2, b3, b4, b5 = 0.2316419, 0.319381530, -0.356563782, 1.781477937, -1.821255978, 1.330274429
    t = 1.0 / (1.0 + b0 * abs(z))
    poly = ((((b5 * t + b4) * t + b3) * t + b2) * t + b1) * t
    pdf = math.exp(-z * z / 2.0) / math.sqrt(2.0 * math.pi)
    cdf = 1.0 - pdf * poly
    return cdf if z >= 0 else 1.0 - cdf


def _cwe_hierarchy_direction(cwe_a: str, cwe_b: str) -> Optional[str]:
    """CWE层级因果方向推断.
    父类(更抽象)→子类(更具体). 修复父类可同时消除子类.
    """
    hierarchy: Dict[str, List[str]] = {
        'CWE-119': ['CWE-120', 'CWE-121', 'CWE-122', 'CWE-123', 'CWE-124',
                     'CWE-125', 'CWE-126', 'CWE-127', 'CWE-129', 'CWE-131',
                     'CWE-134', 'CWE-170', 'CWE-190', 'CWE-680', 'CWE-787'],
        'CWE-20':  ['CWE-22', 'CWE-78', 'CWE-79', 'CWE-89', 'CWE-94',
                     'CWE-918', 'CWE-601', 'CWE-611'],
        'CWE-200': ['CWE-201', 'CWE-202', 'CWE-203', 'CWE-204', 'CWE-209',
                     'CWE-532', 'CWE-535'],
        'CWE-287': ['CWE-288', 'CWE-289', 'CWE-290', 'CWE-294', 'CWE-295',
                     'CWE-306', 'CWE-307', 'CWE-384', 'CWE-798'],
        'CWE-264': ['CWE-269', 'CWE-272', 'CWE-276', 'CWE-284', 'CWE-285'],
        'CWE-399': ['CWE-400', 'CWE-401', 'CWE-404', 'CWE-416', 'CWE-772'],
    }
    if cwe_a in hierarchy and cwe_b in hierarchy.get(cwe_a, []):
        return 'a->b'
    if cwe_b in hierarchy and cwe_a in hierarchy.get(cwe_b, []):
        return 'b->a'
    for parent, children in hierarchy.items():
        if cwe_a in children and cwe_b in children:
            return None  # 兄弟节点
    return None


__all__ = [
    'CausalEdge', 'CausalGraph', 'FindingCausalDiscoverer',
    'RootCauseRanker',
]
