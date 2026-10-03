import logging
import os
from dataclasses import dataclass, field
from typing import Dict, List, Set

logger = logging.getLogger(__name__)


@dataclass
class SBOMComponent:
    name: str = ""
    version: str = ""
    supplier: str = ""
    license: str = ""
    cves: list = field(default_factory=list)
    functions: list = field(default_factory=list)

@dataclass
class ReachabilityResult:
    success: bool = False
    sbom: list = field(default_factory=list)
    reachable_vulns: list = field(default_factory=list)
    unreachable_vulns: list = field(default_factory=list)
    risk_score: float = 0.0

class SBOMGenerator:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path

    def generate(self) -> List[SBOMComponent]:
        components = []
        try:
            import subprocess
            result = subprocess.run(
                ["r2", "-q", "-c", "iL", self.binary_path],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    parts = line.strip().split()
                    if parts and "." in parts[0]:
                        components.append(SBOMComponent(
                            name=parts[0],
                            version=parts[1] if len(parts) > 1 else "unknown",
                            supplier="external",
                            license="unknown",
                        ))

        except Exception:
            logger.debug("suppressed", exc_info=True)
        return components


class CallGraphBuilder:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.graph: Dict[str, Set[str]] = {}

    def build(self) -> Dict[str, Set[str]]:
        try:
            import subprocess
            result = subprocess.run(
                ["r2", "-q", "-c", "aa; agC", self.binary_path],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "->" in line:
                        parts = line.split("->")
                        if len(parts) == 2:
                            src = parts[0].strip()
                            dst = parts[1].strip()
                            self.graph.setdefault(src, set()).add(dst)
        except Exception:
            logger.debug("suppressed", exc_info=True)
        return self.graph

    def is_reachable(self, target: str, entry: str = "main") -> bool:
        # call-graph DFS判定目标函数是否从入口可达
        if entry == target:
            return True
        visited = set()
        stack = [entry]
        while stack:
            node = stack.pop()
            if node == target:
                return True
            if node in visited:
                continue
            visited.add(node)
            stack.extend(self.graph.get(node, set()))

        return False

class CVEMatcher:
    _KNOWN_VULNS = {
        'openssl': ['CVE-2022-0778', 'CVE-2021-3493', 'CVE-2020-1971'],
        'libxml2': ['CVE-2022-29824', 'CVE-2021-3537'],
        'sqlite': ['CVE-2022-35737', 'CVE-2021-36953'],
        'libpng': ['CVE-2019-7317'],
        'zlib': ['CVE-2018-25032'],
        'libjpeg': ['CVE-2018-1152', 'CVE-2018-14498'],
        'glibc': ['CVE-2021-33502', 'CVE-2019-9169'],
    }

    @staticmethod
    def match_components(components: List[SBOMComponent]) -> Dict[str, List[str]]:
        matched: Dict[str, List[str]] = {}
        for c in components:
            name_lower = c.name.lower()
            cves = []
            for lib, vuln_list in CVEMatcher._KNOWN_VULNS.items():
                if lib in name_lower:
                    cves.extend(vuln_list)
            if cves:
                matched[c.name] = cves
        return matched

class SupplyChainAnalyzer:
    def __init__(self, binary_path: str):
        self.binary_path = os.path.abspath(binary_path)
        self.sbom_gen = SBOMGenerator(binary_path)
        self.cg_builder = CallGraphBuilder(binary_path)
        self.cve_matcher = CVEMatcher()

    def run(self) -> ReachabilityResult:
        try:
            sbom = self.sbom_gen.generate()
            graph = self.cg_builder.build()
            cve_map = self.cve_matcher.match_components(sbom)

            reachable: List[str] = []
            unreachable: List[str] = []
            for comp in sbom:
                for cve in cve_map.get(comp.name, []):
                    if comp.functions:
                        if any(self.cg_builder.is_reachable(f) for f in comp.functions):
                            reachable.append(cve)
                        else:
                            unreachable.append(cve)
                    else:
                        unreachable.append(cve)

            risk = len(reachable) * 0.1
            return ReachabilityResult(
                success=True, sbom=sbom,
                reachable_vulns=reachable, unreachable_vulns=unreachable,
                risk_score=min(risk, 1.0)
            )

        except Exception as e:
            logger.error("supply chain analysis failed: %s", e)
            return ReachabilityResult(success=False, sbom=[], reachable_vulns=[], unreachable_vulns=[])


def create_supply_chain_analyzer(binary_path: str) -> SupplyChainAnalyzer:
    return SupplyChainAnalyzer(binary_path)
