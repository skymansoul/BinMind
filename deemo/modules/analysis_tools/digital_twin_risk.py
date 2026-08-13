"""Digital twin risk assessment engine -- attack-path simulation and scoring."""

import itertools
import logging
import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Iterator, Set, FrozenSet, Tuple

_log = logging.getLogger(__name__)


@dataclass
class Component:
    """A node in the digital-twin graph representing a system component."""
    name: str
    component_type: str = ""          # e.g. endpoint, service, binary, db
    vulnerabilities: List[str] = field(default_factory=list)
    exposed: bool = False             # externally reachable
    criticality: float = 0.0          # 0..1 business importance
    trust_boundary: bool = False      # marks a trust-zone boundary crossing
    # Severity scores of vulns stored alongside
    vuln_scores: Dict[str, float] = field(default_factory=dict)


@dataclass
class Edge:
    """A directed link between two components in the twin graph."""
    source: str
    target: str
    protocol: str = ""
    auth_required: bool = False
    encrypted: bool = False


@dataclass
class AttackPath:
    steps: List[Tuple[str, str]]      # (from_component, to_component)
    risk_score: float = 0.0
    likelihood: float = 0.0
    description: str = ""

@dataclass
class RiskReport:
    components: Dict[str, float] = field(default_factory=dict)  # component -> risk score
    paths: List[AttackPath] = field(default_factory=list)
    overall_risk: float = 0.0
    max_path_risk: float = 0.0


class DigitalTwinRiskAnalyzer:
    """Model a system from binary analysis findings, compute risk scores, discover attack paths.

    Usage::
        analyzer = DigitalTwinRiskAnalyzer()
        analyzer.add_component(Component("auth_svc", exposed=True, criticality=0.8))
        analyzer.add_edge(Edge("internet", "auth_svc", protocol="HTTPS"))
        report = analyzer.analyze()

    The `analyze(model)` method also accepts a dict-based model format for compatibility:
        {"components": [...], "edges": [...]}
    """

    def __init__(self):
        self._components: Dict[str, Component] = {}
        self._edges: List[Edge] = []
        self._adj: Dict[str, List[Edge]] = defaultdict(list)
        self._rev_adj: Dict[str, List[Edge]] = defaultdict(list)

    # -- model construction ----------------------------------------------------

    def add_component(self, comp: Component) -> None:
        self._components[comp.name] = comp

    def add_edge(self, edge: Edge) -> None:
        self._edges.append(edge)
        self._adj[edge.source].append(edge)
        self._rev_adj[edge.target].append(edge)

    # -- main analyze ----------------------------------------------------------

    def analyze(self, model=None) -> RiskReport:
        """Run full risk analysis. `model` can be a dict or None (use built graph)."""
        if model is not None:
            self._load_model(model)

        report = RiskReport()
        report.components = self._score_components()
        report.paths = self._find_attack_paths()
        report.overall_risk = self._overall_risk(report.components)
        report.max_path_risk = max((p.risk_score for p in report.paths), default=0.0)
        return report

    def _score_components(self) -> Dict[str, float]:
        scores: Dict[str, float] = {}
        for name, comp in self._components.items():
            base = 0.0
            # Vulnerability-driven risk
            for vuln_id, sev in comp.vuln_scores.items():
                base += sev / 10.0 * 0.5  # CVSS contributes up to 0.5
            # Exposure bonus
            if comp.exposed:
                base += 0.2
            # Criticality amplifies
            base *= (1.0 + comp.criticality)
            # Trust boundary increases blast radius
            if comp.trust_boundary:
                base *= 1.1
            scores[name] = min(1.0, max(0.0, base))
        return scores

    def _find_attack_paths(self, max_depth: int = 6) -> List[AttackPath]:
        """BFS from exposed components toward critical ones."""
        exposed = [c.name for c in self._components.values() if c.exposed]
        critical = {c.name for c in self._components.values() if c.criticality > 0.5}
        if not exposed:
            # treat all nodes as starting points
            exposed = list(self._components.keys())

        all_paths: List[AttackPath] = []
        visited_edges: Set[FrozenSet[Tuple[str, str]]] = set()

        for start in exposed:
            for depth in range(1, max_depth + 1):
                for path_nodes in self._dfs_paths(start, depth, set(), []):
                    dest = path_nodes[-1][1] if path_nodes else start
                    if dest in critical:
                        edge_set = frozenset(path_nodes)
                        if edge_set not in visited_edges:
                            visited_edges.add(edge_set)
                            score = self._path_risk(path_nodes)
                            all_paths.append(AttackPath(
                                steps=list(path_nodes),
                                risk_score=score,
                                likelihood=self._path_likelihood(path_nodes),
                                description=" -> ".join([s for s, _ in path_nodes] + [dest]),
                            ))
        return sorted(all_paths, key=lambda p: p.risk_score, reverse=True)

    def _dfs_paths(self, current: str, remaining: int, visited: Set[str],
                   path: List[Tuple[str, str]]) -> Iterator[List[Tuple[str, str]]]:
        if remaining == 0:
            yield path
            return
        visited.add(current)
        for edge in self._adj.get(current, []):
            if edge.target not in visited:
                for result in self._dfs_paths(edge.target, remaining - 1, visited.copy(),
                                              path + [(edge.source, edge.target)]):
                    yield result

    def _path_risk(self, steps: List[Tuple[str, str]]) -> float:
        risk = 0.0
        for src, dst in steps:
            comp = self._components.get(dst, self._components.get(src))
            if comp:
                for sev in comp.vuln_scores.values():
                    risk += sev / 10.0 * 0.3
            # unauthenticated edges are easier
            edge = next((e for e in self._edges if e.source == src and e.target == dst), None)
            if edge and not edge.auth_required:
                risk += 0.1
            if edge and not edge.encrypted:
                risk += 0.05
        # Scale down by path length (longer paths are harder)
        factor = 1.0 / math.sqrt(max(1, len(steps)))
        return min(1.0, risk * factor)

    def _path_likelihood(self, steps: List[Tuple[str, str]]) -> float:
        base = 0.8
        for _, dst in steps:
            comp = self._components.get(dst)
            if comp and comp.vuln_scores:
                base *= 0.6  # each vuln step reduces likelihood
            else:
                base *= 0.9
        return base

    def _overall_risk(self, comp_scores: Dict[str, float]) -> float:
        if not comp_scores:
            return 0.0
        # Weighted average biased toward high-criticality components
        weighted = []
        for name, score in comp_scores.items():
            crit = self._components[name].criticality if name in self._components else 0.5
            weighted.append(score * (0.5 + crit))
        return sum(weighted) / len(weighted)

    def _load_model(self, model) -> None:
        """Accept dict: {"components": [...], "edges": [...]}."""
        if isinstance(model, str):
            import json
            with open(model, "r") as fh:
                model = json.load(fh)
        self._components.clear()
        self._edges.clear()
        self._adj.clear()
        self._rev_adj.clear()

        for cd in model.get("components", []):
            if isinstance(cd, Component):
                self.add_component(cd)
            elif isinstance(cd, dict):
                self.add_component(Component(**{k: v for k, v in cd.items()
                    if k in ("name", "component_type", "vulnerabilities", "exposed",
                             "criticality", "trust_boundary", "vuln_scores")}))
        for ed in model.get("edges", []):
            if isinstance(ed, Edge):
                self.add_edge(ed)
            elif isinstance(ed, dict):
                self.add_edge(Edge(**{k: v for k, v in ed.items()
                    if k in ("source", "target", "protocol", "auth_required", "encrypted")}))
