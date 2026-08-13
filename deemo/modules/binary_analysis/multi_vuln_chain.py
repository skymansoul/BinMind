import logging
import re
from enum import Enum
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, deque

__log = logging.getLogger(__name__)


class ExploitPrimitive(Enum):
    READ_MEMORY = "read_memory"
    WRITE_MEMORY = "write_memory"
    ARBITRARY_WRITE = "arbitrary_write"
    ARBITRARY_READ = "arbitrary_read"
    CODE_EXECUTION = "code_execution"
    INFO_LEAK = "info_leak"
    ASLR_BYPASS = "aslr_bypass"
    DEP_BYPASS = "dep_bypass"
    STACK_PIVOT = "stack_pivot"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    ARBITRARY_FREE = "arbitrary_free"
    CONTROLLED_ALLOC = "controlled_alloc"

class ConditionOperator(Enum):
    EQ = "eq"
    GT = "gt"
    LT = "lt"
    CONTAINS = "contains"
    MATCHES = "matches"


@dataclass
class Condition:
    variable: str
    operator: ConditionOperator = ConditionOperator.EQ
    value: str = "true"
    optional: bool = False

    def is_satisfied_by(self, other: "Condition") -> bool:
        if self.variable != other.variable:
            return False
        if self.operator == ConditionOperator.EQ and other.operator == ConditionOperator.EQ:
            return self.value == other.value
        return True

    def __repr__(self) -> str:
        return f"{self.variable} {self.operator.value} {self.value}"


@dataclass
class VulnNode:
    vuln_id: str
    name: str
    cve_id: str = ""
    description: str = ""
    preconditions: List[Condition] = field(default_factory=list)
    postconditions: List[Condition] = field(default_factory=list)
    exploit_difficulty: float = 5.0
    impact_score: float = 5.0
    reliability: float = 0.8
    category: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            'vuln_id': self.vuln_id, 'name': self.name, 'cve_id': self.cve_id,
            'preconditions': [str(p) for p in self.preconditions],
            'postconditions': [str(p) for p in self.postconditions],
            'exploit_difficulty': self.exploit_difficulty,
            'impact_score': self.impact_score, 'reliability': self.reliability
        }


@dataclass
class ExploitChain:
    chain_id: str
    vulns: List[VulnNode]
    total_difficulty: float = 0.0
    total_impact: float = 0.0
    total_reliability: float = 1.0
    chain_length: int = 0
    primitives_obtained: List[ExploitPrimitive] = field(default_factory=list)
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            'chain_id': self.chain_id,
            'vulns': [v.vuln_id for v in self.vulns],
            'chain_length': self.chain_length,
            'total_difficulty': round(self.total_difficulty, 2),
            'total_impact': round(self.total_impact, 2),
            'total_reliability': round(self.total_reliability, 2),
            'primitives_obtained': [p.value for p in self.primitives_obtained],
            'description': self.description
        }


class VulnDependencyGraph:
    def __init__(self):
        self.nodes: Dict[str, VulnNode] = {}
        self.edges: Dict[str, List[str]] = defaultdict(list)

    def add_node(self, node: VulnNode):
        self.nodes[node.vuln_id] = node

    def build_edges(self):
        self.edges.clear()
        for a_id, node_a in self.nodes.items():
            for b_id, node_b in self.nodes.items():
                if a_id == b_id:
                    continue
                if self._conditions_match(node_a.postconditions, node_b.preconditions):
                    self.edges[a_id].append(b_id)

    @staticmethod
    def _conditions_match(posts: List[Condition], pres: List[Condition]) -> bool:
        if not pres:
            return True
        matched = 0
        for pre in pres:
            for post in posts:
                if pre.variable == post.variable:
                    if pre.is_satisfied_by(post):
                        matched += 1
                        break
        required = sum(1 for p in pres if not p.optional)
        return matched >= required

    def find_chains(self, start_node_ids: List[str],
                    target_primitives: List[ExploitPrimitive],
                    max_depth: int = 5) -> List[ExploitChain]:
        chains: List[ExploitChain] = []
        chain_id = 0

        for start_id in start_node_ids:
            start = self.nodes.get(start_id)
            if not start:
                continue

            queue = deque([(start, [start], [])])
            visited: Set[Tuple[str, ...]] = set()

            while queue:
                current, path, prims = queue.popleft()
                path_key = tuple(v.vuln_id for v in path)
                if path_key in visited or len(path) > max_depth:
                    continue
                visited.add(path_key)

                all_prims = list(prims)
                for cond in current.postconditions:
                    try:
                        all_prims.append(ExploitPrimitive(cond.variable))
                    except ValueError:
                        pass

                if all(t in all_prims for t in target_primitives):
                    chain_id += 1
                    difficulty = sum(v.exploit_difficulty for v in path) / len(path)
                    impact = max(v.impact_score for v in path)
                    reliability = 1.0
                    for v in path:
                        reliability *= v.reliability

                    chains.append(ExploitChain(
                        chain_id=f"CHAIN-{chain_id:04d}",
                        vulns=list(path),
                        total_difficulty=difficulty,
                        total_impact=impact,
                        total_reliability=reliability,
                        chain_length=len(path),
                        primitives_obtained=list(set(all_prims)),
                        description=" -> ".join(v.name for v in path)
                    ))
                    continue

                for next_id in self.edges.get(current.vuln_id, []):
                    next_node = self.nodes.get(next_id)
                    if next_node and next_node not in path:
                        queue.append((next_node, path + [next_node], all_prims))

        chains.sort(key=lambda c: (c.total_impact / max(0.1, c.total_difficulty) *
                                   c.total_reliability), reverse=True)
        return chains


class ExploitConflictDetector:
    def detect_conflicts(self, chain: ExploitChain) -> List[str]:
        conflicts = []
        vulns = chain.vulns
        for i in range(len(vulns)):
            for j in range(i + 1, len(vulns)):
                a_posts = {c.variable for c in vulns[i].postconditions}
                b_pres = {c.variable for c in vulns[j].preconditions}
                overlapping = a_posts & b_pres
                conflicting_prims = {
                    ExploitPrimitive.ARBITRARY_WRITE,
                    ExploitPrimitive.ARBITRARY_FREE
                }
                a_prims = {ExploitPrimitive(c.variable)
                          for c in vulns[i].postconditions
                          if c.variable in {p.value for p in conflicting_prims}}
                if a_prims and overlapping:
                    conflicts.append(
                        f"{vulns[i].vuln_id} side effects may impact {vulns[j].vuln_id} preconditions")
        return conflicts


class MultiVulnChainAnalyzer:
    def __init__(self):
        self.graph = VulnDependencyGraph()
        self.conflict_detector = ExploitConflictDetector()
        self._chains: List[ExploitChain] = []
        self._findings: List[Dict[str, Any]] = []

    def add_vulnerability(self, vuln_id: str, name: str,
                          preconditions: Optional[List[Dict[str, str]]] = None,
                          postconditions: Optional[List[Dict[str, str]]] = None,
                          exploit_difficulty: float = 5.0,
                          impact_score: float = 5.0,
                          reliability: float = 0.8,
                          cve_id: str = "", category: str = ""):
        pre_conds = [Condition(c['variable'],
                               ConditionOperator(c.get('operator', 'eq')),
                               c.get('value', 'true'),
                               c.get('optional', False))
                    for c in (preconditions or [])]
        post_conds = [Condition(c['variable'],
                                ConditionOperator(c.get('operator', 'eq')),
                                c.get('value', 'true'))
                     for c in (postconditions or [])]
        node = VulnNode(vuln_id=vuln_id, name=name, cve_id=cve_id,
                       preconditions=pre_conds, postconditions=post_conds,
                       exploit_difficulty=exploit_difficulty,
                       impact_score=impact_score,
                       reliability=reliability, category=category)
        self.graph.add_node(node)

    def analyze(self, entry_vulns: Optional[List[str]] = None,
                target_primitives: Optional[List[str]] = None,
                max_chain_depth: int = 5, **kwargs) -> Dict[str, Any]:
        self.graph.build_edges()

        if target_primitives:
            try:
                prims = [ExploitPrimitive(p) for p in target_primitives]
            except ValueError:
                prims = [ExploitPrimitive.CODE_EXECUTION,
                        ExploitPrimitive.PRIVILEGE_ESCALATION]
        else:
            prims = [ExploitPrimitive.CODE_EXECUTION]

        starts = entry_vulns or list(self.graph.nodes.keys())
        chains = self.graph.find_chains(starts, prims, max_chain_depth)

        for chain in chains:
            conflicts = self.conflict_detector.detect_conflicts(chain)
            if conflicts:
                chain.total_reliability *= 0.5

        self._chains = chains

        return {
            'success': True,
            'total_chains': len(chains),
            'chains': [c.to_dict() for c in chains[:50]],
            'top_chains': [c.to_dict() for c in chains[:5]],
            'stats': {
                'total_vulns': len(self.graph.nodes),
                'total_edges': sum(len(e) for e in self.graph.edges.values()),
                'avg_chain_length': round(
                    sum(c.chain_length for c in chains) / max(1, len(chains)), 2),
                'best_impact': round(max((c.total_impact for c in chains), default=0), 2),
            }
        }

    def generate_report(self) -> Dict[str, Any]:
        if not self._chains:
            return {'success': True, 'summary': 'No exploitable vulnerability chains found',
                    'risk_level': 'none', 'chains': []}
        best = self._chains[0]
        high_impact = [c for c in self._chains if c.total_impact >= 7.0]
        return {
            'success': True,
            'summary': f'Found {len(self._chains)} exploit chains, '
                      f'{len(high_impact)} of which are high-impact chains',
            'risk_level': 'critical' if high_impact else 'high',
            'best_chain': best.to_dict() if best else None,
            'top_10': [c.to_dict() for c in self._chains[:10]],
            'recommendations': [
                'Prioritize fixing the first vulnerability in the chain to break it',
                'Reduce availability of common preconditions (e.g. ASLR bypass)',
                'Harden the most impactful vulnerability in the chain'
            ]
        }


def analyze_multi_vuln_chains(
    vulnerabilities: List[Dict[str, Any]],
    entry_vulns: Optional[List[str]] = None,
    target_primitives: Optional[List[str]] = None,
    **kwargs
) -> Dict[str, Any]:
    analyzer = MultiVulnChainAnalyzer()
    for v in vulnerabilities:
        analyzer.add_vulnerability(
            vuln_id=v['vuln_id'], name=v.get('name', v['vuln_id']),
            preconditions=v.get('preconditions', []),
            postconditions=v.get('postconditions', []),
            exploit_difficulty=v.get('exploit_difficulty', 5.0),
            impact_score=v.get('impact_score', 5.0),
            reliability=v.get('reliability', 0.8),
            cve_id=v.get('cve_id', ''), category=v.get('category', ''))
    result = analyzer.analyze(entry_vulns=entry_vulns,
                              target_primitives=target_primitives,
                              max_chain_depth=kwargs.get('max_depth', 5))
    report = analyzer.generate_report()
    result['report'] = report
    return result


__all__ = ["MultiVulnChainAnalyzer", "VulnDependencyGraph", "ExploitConflictDetector",
           "VulnNode", "ExploitChain", "Condition", "ExploitPrimitive",
           "analyze_multi_vuln_chains"]
