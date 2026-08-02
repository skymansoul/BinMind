#!/usr/bin/env python3
import os, re, json, subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from enum import Enum

try:
    import pkg_resources; PKG_RESOURCES_AVAILABLE = True
except ImportError:
    PKG_RESOURCES_AVAILABLE = False

logger = __import__('logging').getLogger(__name__)

class LicenseType(Enum):
    MIT = "mit"; BSD_2_CLAUSE = "bsd-2"; BSD_3_CLAUSE = "bsd-3"
    APACHE_2_0 = "apache-2.0"; ISC = "isc"; CC0_1_0 = "cc0-1.0"
    UNLICENSE = "unlicense"; LGPL_2_1 = "lgpl-2.1"; LGPL_3_0 = "lgpl-3.0"
    MPL_2_0 = "mpl-2.0"; GPL_2_0 = "gpl-2.0"; GPL_3_0 = "gpl-3.0"
    AGPL_3_0 = "agpl-3.0"; PROPRIETARY = "proprietary"; UNKNOWN = "unknown"

class LicenseCompatibilityLevel(Enum):
    COMPATIBLE = "compatible"; RESTRICTED = "restricted"
    INCOMPATIBLE = "incompatible"; UNKNOWN = "unknown"

@dataclass
class PackageInfo:
    name: str = ""; version: str = "0.0.0"
    license: str = ""; license_type: LicenseType = LicenseType.UNKNOWN
    location: str = ""; dependencies: List[str] = field(default_factory=list)
    summary: str = ""; homepage: str = ""

class LicenseConflict:
    __slots__ = ('package1','package2','license1','license2','conflict_type','severity','description',)
    def __init__(self, p1, p2, l1, l2, ct, sev, desc):
        self.package1 = p1; self.package2 = p2; self.license1 = l1
        self.license2 = l2; self.conflict_type = ct; self.severity = sev; self.description = desc

class ComplianceReport:
    __slots__ = ('packages', 'conflicts', 'spdx_document', 'summary', 'sbom_json',)
    def __init__(self, packages, conflicts, spdx=None, summary=None, sbom=None):
        self.packages = packages; self.conflicts = conflicts
        self.spdx_document = spdx; self.summary = summary; self.sbom_json = sbom


# ── SPDX SBOM 导出 ──────────────────────────────────────────────────────────
# 生成符合 SPDX 2.3 标准的软件物料清单 (SBOM)。
# NTIA 要求在联邦采购中提供 SBOM——本模块使合规检查输出可直接
# 用于采购审计和供应链安全评估。

class SBOMGenerator:
    """SPDX 2.3 兼容的 SBOM 生成器——输出 JSON 格式的软件物料清单。"""

    @staticmethod
    def generate_spdx_json(packages: List[PackageInfo], doc_name: str = "BinMind-Binary-Analysis") -> str:
        """生成 SPDX 2.3 JSON 格式的 SBOM。"""
        spdx_doc = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": doc_name,
            "documentNamespace": f"https://binmind-project.org/spdx/{doc_name}",
            "creationInfo": {
                "created": __import__('datetime').datetime.now().isoformat() + "Z",
                "creators": ["Tool: BinMind-License-Compliance"],
            },
            "packages": [],
            "relationships": [],
        }
        for pkg in packages:
            spdx_id = f"SPDXRef-{pkg.name.replace('-','_')}"
            spdx_doc["packages"].append({
                "SPDXID": spdx_id,
                "name": pkg.name,
                "versionInfo": pkg.version,
                "licenseConcluded": _license_to_spdx(pkg.license_type),
                "licenseDeclared": _license_to_spdx(pkg.license_type),
                "supplier": "NOASSERTION",
                "downloadLocation": pkg.homepage or "NOASSERTION",
            })
            spdx_doc["relationships"].append({
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relatedSpdxElement": spdx_id,
                "relationshipType": "CONTAINS",
            })
        return json.dumps(spdx_doc, indent=2, ensure_ascii=False)


def _license_to_spdx(lt: LicenseType) -> str:
    mapping = {
        LicenseType.MIT: "MIT", LicenseType.BSD_2_CLAUSE: "BSD-2-Clause",
        LicenseType.BSD_3_CLAUSE: "BSD-3-Clause",
        LicenseType.APACHE_2_0: "Apache-2.0", LicenseType.ISC: "ISC",
        LicenseType.CC0_1_0: "CC0-1.0", LicenseType.UNLICENSE: "Unlicense",
        LicenseType.LGPL_2_1: "LGPL-2.1-only", LicenseType.LGPL_3_0: "LGPL-3.0-only",
        LicenseType.MPL_2_0: "MPL-2.0", LicenseType.GPL_2_0: "GPL-2.0-only",
        LicenseType.GPL_3_0: "GPL-3.0-only", LicenseType.AGPL_3_0: "AGPL-3.0-only",
        LicenseType.PROPRIETARY: "LicenseRef-Proprietary",
        LicenseType.UNKNOWN: "NOASSERTION",
    }
    return mapping.get(lt, "NOASSERTION")


class LicenseClassifier:
    def classify(self, license_text: str) -> LicenseType: pass
    def detect_license(self, file_path: str) -> Optional[LicenseType]: pass

class SimpleLicenseClassifier(LicenseClassifier):
    LICENSE_PATTERNS = {
        LicenseType.MIT: [r"MIT License", r"Permission is hereby granted, free of charge"],
        LicenseType.BSD_3_CLAUSE: [r"BSD 3-Clause"],
        LicenseType.APACHE_2_0: [r"Apache License", r"Version 2\.0, January 2004"],
        LicenseType.GPL_2_0: [r"GNU General Public License", r"Version 2, June 1991"],
        LicenseType.GPL_3_0: [r"GNU General Public License", r"Version 3, 29 June 2007"],
        LicenseType.LGPL_2_1: [r"GNU Lesser General Public License", r"Version 2\.1"],
        LicenseType.MPL_2_0: [r"Mozilla Public License", r"Version 2\.0"],
        LicenseType.AGPL_3_0: [r"GNU Affero General Public License"],
        LicenseType.ISC: [r"ISC License"],
    }
    def classify(self, license_text: str) -> LicenseType:
        text = license_text.lower()
        for lt, patterns in self.LICENSE_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern.lower(), text): return lt
        return LicenseType.UNKNOWN

    def detect_license(self, file_path: str) -> Optional[LicenseType]:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return self.classify(f.read(10000))
        except Exception: return None

class LicenseCompatibilityChecker:
    COMPATIBILITY_MATRIX = {
        (LicenseType.MIT, LicenseType.APACHE_2_0): LicenseCompatibilityLevel.COMPATIBLE,
        (LicenseType.MIT, LicenseType.GPL_2_0): LicenseCompatibilityLevel.RESTRICTED,
        (LicenseType.MIT, LicenseType.GPL_3_0): LicenseCompatibilityLevel.RESTRICTED,
        (LicenseType.APACHE_2_0, LicenseType.GPL_2_0): LicenseCompatibilityLevel.INCOMPATIBLE,
        (LicenseType.GPL_2_0, LicenseType.GPL_3_0): LicenseCompatibilityLevel.INCOMPATIBLE,
    }
    @classmethod
    def check_compatibility(cls, l1: LicenseType, l2: LicenseType) -> str:
        if l1 == l2: return LicenseCompatibilityLevel.COMPATIBLE.value
        return cls.COMPATIBILITY_MATRIX.get((l1, l2), LicenseCompatibilityLevel.UNKNOWN.value).value

class LicenseScanner:
    LICENSE_FILE_PATTERNS = ["LICENSE", "COPYING", "COPYRIGHT"]
    def __init__(self, classifier=None):
        self.classifier = classifier or SimpleLicenseClassifier()

    def scan_package(self, package_name):
        if not PKG_RESOURCES_AVAILABLE: return None
        try:
            pkg = pkg_resources.get_distribution(package_name)
            license_str = pkg.metadata.get('License', '')
            license_type = LicenseType.UNKNOWN
            location = str(pkg.location)
            for pattern in self.LICENSE_FILE_PATTERNS:
                lp = Path(location) / pattern
                if lp.exists():
                    detected = self.classifier.detect_license(str(lp))
                    if detected: license_type = detected; break
            if license_type == LicenseType.UNKNOWN:
                license_type = self._infer_from_string(license_str)
            return PackageInfo(name=pkg.project_name, version=pkg.version,
                               license=license_str, license_type=license_type,
                               location=location)
        except Exception as e:
            logger.warning(f"Package {package_name} scan failed: {e}"); return None

    def scan_requirements(self, requirements_path="requirements.txt"):
        packages = []
        if not os.path.exists(requirements_path): return packages
        try:
            with open(requirements_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        m = re.match(r'^[a-zA-Z0-9_-]+', line)
                        if m:
                            info = self.scan_package(m.group())
                            if info: packages.append(info)
        except Exception as e: logger.error(f"requirements read failed: {e}")
        return packages

    def _infer_from_string(self, s: str) -> LicenseType:
        s = s.lower()
        mapping = {'mit': LicenseType.MIT, 'apache': LicenseType.APACHE_2_0,
                   'gpl': LicenseType.GPL_3_0, 'lgpl': LicenseType.LGPL_3_0,
                   'mpl': LicenseType.MPL_2_0, 'agpl': LicenseType.AGPL_3_0,
                   'isc': LicenseType.ISC, 'cc0': LicenseType.CC0_1_0}
        for key, lt in mapping.items():
            if key in s: return lt
        return LicenseType.UNKNOWN


class ComplianceAnalyzer:
    def __init__(self, scanner=None):
        self.scanner = scanner or LicenseScanner()
        self.checker = LicenseCompatibilityChecker()

    def analyze(self, requirements_path="requirements.txt"):
        packages = self.scanner.scan_requirements(requirements_path)
        conflicts = self._detect_conflicts(packages)
        summary = self._generate_summary(packages, conflicts)
        spdx = self._generate_spdx_document(packages)
        sbom_json = SBOMGenerator.generate_spdx_json(packages)
        return ComplianceReport(packages=packages, conflicts=conflicts,
                                spdx=spdx, summary=summary, sbom=sbom_json)

    def _detect_conflicts(self, packages):
        conflicts = []; n = len(packages)
        for i in range(n):
            for j in range(i + 1, n):
                p1, p2 = packages[i], packages[j]
                compat = self.checker.check_compatibility(p1.license_type, p2.license_type)
                if compat != "compatible":
                    conflicts.append(LicenseConflict(
                        p1.name, p2.name, p1.license_type, p2.license_type,
                        compat, "high" if compat == "incompatible" else "medium",
                        f"License conflict: {p1.license_type.value} vs {p2.license_type.value}"))
        return conflicts

    def _generate_summary(self, packages, conflicts):
        counts: Dict[str, int] = {}
        for p in packages:
            k = p.license_type.value; counts[k] = counts.get(k, 0) + 1
        return {'total_packages': len(packages), 'unique_licenses': len(counts),
                'license_distribution': counts, 'total_conflicts': len(conflicts),
                'incompatible': len([c for c in conflicts if c.conflict_type == 'incompatible']),
                'restricted': len([c for c in conflicts if c.conflict_type == 'restricted'])}

    def _generate_spdx_document(self, packages):
        lines = ["SPDXVersion: SPDX-2.3", "DataLicense: CC0-1.0",
                 "SPDXID: SPDXRef-DOCUMENT", "DocumentName: BinMind"]
        for p in packages:
            lines.append(f"PackageName: {p.name}")
            lines.append(f"PackageLicenseInfoFromFiles: {_license_to_spdx(p.license_type)}")
        return "\n".join(lines)


def generate_compliance_report(requirements_path="requirements.txt", output_path=None):
    analyzer = ComplianceAnalyzer(); report = analyzer.analyze(requirements_path)
    if output_path:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump({'summary': report.summary,
                       'packages': [{'name': p.name, 'version': p.version,
                                     'license': p.license_type.value}
                                    for p in report.packages],
                       'sbom': json.loads(report.sbom_json) if report.sbom_json else {}},
                      f, indent=2)
    return report

def get_license_scanner():
    return LicenseScanner()
