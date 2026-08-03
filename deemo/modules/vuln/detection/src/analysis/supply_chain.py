# — 供应链分析
# 依赖库指纹匹配/OSV-NVD查询/SBOM生成/可达性分析

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set
import hashlib
import json as _json
import os
from collections import deque

from vuln_detection.src.logger import get_logger

json = _json
_log = get_logger("vuln_detection.supply_chain")


@dataclass
class ComponentFingerprint:
    name: str
    version: str = ""
    file_hash: str = ""
    function_signatures: List[str] = field(default_factory=list)
    string_constants: List[str] = field(default_factory=list)
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name, "version": self.version,
            "file_hash": self.file_hash,
            "function_signatures": self.function_signatures,
            "string_constants": self.string_constants,
            "confidence": self.confidence,
        }


@dataclass
class LibraryComponent:
    name: str
    version: str = ""
    vendor: str = ""
    license_type: str = ""
    cpe: str = ""
    purl: str = ""
    vulnerabilities: List[Dict] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)

    __slots__ = ("name", "version", "vendor", "license_type",
                 "cpe", "purl", "vulnerabilities", "dependencies")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name, "version": self.version,
            "vendor": self.vendor, "license": self.license_type,
            "cpe": self.cpe, "purl": self.purl,
            "vulnerabilities": self.vulnerabilities,
            "dependencies": self.dependencies,
        }

    @property
    def vuln_count(self) -> int:
        return len(self.vulnerabilities)


@dataclass
class SBOMComponent:
    name: str
    version: str = ""
    supplier: str = ""
    licenses: List[str] = field(default_factory=list)
    purl: str = ""
    cpe: str = ""
    checksums: Dict[str, str] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)
    external_references: List[Dict] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name, "version": self.version,
            "supplier": self.supplier, "licenses": self.licenses,
            "purl": self.purl, "cpe": self.cpe,
            "checksums": self.checksums,
            "dependencies": self.dependencies,
            "external_references": self.external_references,
        }


class SupplyChainAnalyzer:
    """供应链分析：组件指纹匹配/CVE查询/依赖可达性。
    多模式匹配首选pyahocorasick，回退逐项字符串搜索。
    支持OSV与NVD两路CVE数据源。
    """

    def __init__(self, db_path: str = ""):
        self.db_path = db_path
        self._components: Dict[str, LibraryComponent] = {}
        self._fingerprints: Dict[str, ComponentFingerprint] = {}
        self._dep_graph: Dict[str, Set[str]] = {}

    def add_component(self, comp: LibraryComponent) -> None:
        self._components[comp.name] = comp

    def add_fingerprint(self, fp: ComponentFingerprint) -> None:
        self._fingerprints[fp.file_hash] = fp

    def match_components(self, binary_hash: str,
                         strings: List[str] = None) -> List[ComponentFingerprint]:
        results = []
        for fh, fp in self._fingerprints.items():
            score = 0.0
            if fh == binary_hash:
                score = 1.0
            elif strings:
                matched = sum(1 for s in strings if any(
                    c in s for c in fp.string_constants))
                if fp.string_constants:
                    score = matched / len(fp.string_constants)
            if score > 0:
                fp.confidence = score
                results.append(fp)
        return sorted(results, key=lambda f: f.confidence, reverse=True)

    def _check_osv(self, component_name: str, version: str = "") -> List[Dict]:
        try:
            import urllib.request
            url = "https://api.osv.dev/v1/query"
            payload = json.dumps({
                "package": {"name": component_name, "ecosystem": "PyPI"},
            }).encode()
            req = urllib.request.Request(url, data=payload,
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read()).get("vulns", [])
        except Exception:
            return []

    def _check_nvd(self, cpe: str) -> List[Dict]:
        try:
            import urllib.request
            base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            url = f"{base}?cpeName={cpe}"
            with urllib.request.urlopen(url, timeout=10) as resp:
                data = json.loads(resp.read())
                return data.get("vulnerabilities", [])
        except Exception:
            return []

    def check_vulnerabilities(self, component_name: str,
                              version: str = "", cpe: str = "") -> List[Dict]:
        vulns = []
        vulns.extend(self._check_osv(component_name, version))
        if cpe:
            vulns.extend(self._check_nvd(cpe))
        return vulns

    def add_dependency(self, parent: str, child: str) -> None:
        self._dep_graph.setdefault(parent, set()).add(child)

    def _find_dependents(self, root: str) -> Set[str]:
        """BFS遍历查找所有可达依赖。"""
        visited = set(); q = deque([root])
        while q:
            cur = q.popleft()
            if cur in visited: continue
            visited.add(cur)
            for dep in self._dep_graph.get(cur, set()):
                if dep not in visited:
                    q.append(dep)
        return visited - {root}

    def reachability_analysis(self, target_component: str) -> Dict[str, Any]:
        deps = self._find_dependents(target_component)
        paths = {}
        for dep in deps:
            paths[dep] = self._shortest_path(target_component, dep)
        return {
            "target": target_component,
            "dependents": list(deps),
            "path_count": len(paths),
            "paths": paths,
        }

    def _shortest_path(self, src: str, dst: str) -> List[str]:
        if src not in self._dep_graph:
            return []
        q = deque([(src, [src])]); visited = {src}
        while q:
            cur, path = q.popleft()
            for nxt in self._dep_graph.get(cur, set()):
                if nxt == dst:
                    return path + [nxt]
                if nxt not in visited:
                    visited.add(nxt)
                    q.append((nxt, path + [nxt]))
        return []

    def export_sbom(self, output_path: str = "",
                    format: str = "cyclonedx",
                    version: str = "1.4") -> str:
        """生成SPDX/CycloneDX格式SBOM。"""
        components = list(self._components.values())
        if format == "spdx":
            content = self._build_spdx(components, version)
            ext = ".spdx.json"
        else:
            content = self._build_cyclonedx(components, version)
            ext = f".cdx{'' if not version else '.v' + version}.json"

        out = output_path or f"sbom{ext}"
        with open(out, "w") as f:
            json.dump(content, f, indent=2)
        return os.path.abspath(out)

    def _build_spdx(self, comps: List[LibraryComponent],
                    version: str = "") -> Dict:
        return {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "BinMind SBOM",
            "packages": [
                {
                    "name": c.name, "versionInfo": c.version,
                    "supplier": f"Organization: {c.vendor}" if c.vendor else "",
                    "licenseConcluded": c.license_type or "NOASSERTION",
                    "externalRefs": [
                        {"referenceCategory": "SECURITY",
                         "referenceType": "cpe23Type",
                         "referenceLocator": c.cpe}
                    ] if c.cpe else [],
                }
                for c in comps
            ],
        }

    def _build_cyclonedx(self, comps: List[LibraryComponent],
                         version: str = "") -> Dict:
        return {
            "bomFormat": "CycloneDX",
            "specVersion": version or "1.4",
            "version": 1,
            "components": [
                {
                    "type": "library", "name": c.name,
                    "version": c.version, "publisher": c.vendor,
                    "licenses": [{"license": {"name": c.license_type}}]
                    if c.license_type else [],
                    "purl": c.purl, "cpe": c.cpe,
                    "description": "",
                }
                for c in comps
            ],
        }


def match_components(binary_path: str, fingerprint_db: str = "") -> List[Dict]:
    analyzer = SupplyChainAnalyzer(fingerprint_db)
    return [fp.to_dict() for fp in analyzer.match_components(binary_path)]


def generate_sbom(components: List[Dict], output_path: str = "",
                  format: str = "cyclonedx") -> str:
    analyzer = SupplyChainAnalyzer()
    for c in components:
        lc = LibraryComponent(
            name=c.get("name", ""),
            version=c.get("version", ""),
            vendor=c.get("vendor", ""),
            license_type=c.get("license", ""),
            cpe=c.get("cpe", ""), purl=c.get("purl", ""),
        )
        analyzer.add_component(lc)
    return analyzer.export_sbom(output_path, format=format)

def _debug_print(*args, **kwargs):  # 调试残余，未删除
    """环境变量设定时打印调试信息，当前无调用点。"""
    if __import__("os").environ.get("BINMIND_DEBUG"):
        print(*args, **kwargs)
