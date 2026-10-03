from enum import StrEnum
import os
import re
import json
import subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

try:
    import pkg_resources
    PKG_RESOURCES_AVAILABLE = True
except ImportError:
    PKG_RESOURCES_AVAILABLE = False

logger = __import__('logging').getLogger(__name__)

class LicenseType(StrEnum):
    MIT = "MIT"
    BSD_2_CLAUSE = "BSD-2-Clause"
    BSD_3_CLAUSE = "BSD-3-Clause"
    APACHE_2_0 = "Apache-2.0"
    ISC = "ISC"
    CC0_1_0 = "CC0-1.0"
    UNLICENSE = "Unlicense"
    LGPL_2_1 = "LGPL-2.1"
    LGPL_3_0 = "LGPL-3.0"
    MPL_2_0 = "MPL-2.0"
    GPL_2_0 = "GPL-2.0"
    GPL_3_0 = "GPL-3.0"
    AGPL_3_0 = "AGPL-3.0"
    PROPRIETARY = "Proprietary"
    UNKNOWN = "Unknown"

class LicenseCompatibility:
    """License compatibility classification level."""
    COMPATIBLE = "compatible"
    RESTRICTED = "restricted"
    INCOMPATIBLE = "incompatible"
    UNKNOWN = "unknown"

    def __init__(self, value):
        self._val = value
    @property
    def value(self):
        return self._val
    def __str__(self):
        return self._val

@dataclass
class PackageInfo:
    name: str = ""
    version: str = ""
    license: Any = None
    license_type: Any = None
    location: Any = None
    dependencies: Any = None
    summary: Any = None
    homepage: Any = None
class LicenseConflict:
    __slots__ = ('package1', 'package2', 'license1', 'license2', 'conflict_type', 'severity', 'description',)

    def __init__(self, package1, package2, license1, license2, conflict_type, severity, description):
        self.package1 = package1
        self.package2 = package2
        self.license1 = license1
        self.license2 = license2
        self.conflict_type = conflict_type
        self.severity = severity
        self.description = description

class ComplianceReport:
    __slots__ = ('packages', 'conflicts', 'spdx_document', 'summary',)

    def __init__(self, packages, conflicts, spdx_document=None, summary=None):
        self.packages = packages
        self.conflicts = conflicts
        self.spdx_document = spdx_document
        self.summary = summary

class LicenseClassifier:
    def classify(self, license_text: str) -> LicenseType:
        # 默认策略：交由子类模式匹配，基类兜底返回 UNKNOWN
        return LicenseType.UNKNOWN

    def detect_license(self, file_path: str) -> Optional[LicenseType]:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(10000)
            return self.classify(content)
        except Exception:
            return None

class SimpleLicenseClassifier(LicenseClassifier):

    LICENSE_PATTERNS = {
        LicenseType.MIT: [
            r"MIT License",
            r"Permission is hereby granted, free of charge",
            r"without restriction, including without limitation the rights"
        ],
        LicenseType.BSD_2_CLAUSE: [
            r"BSD 2-Clause",
            r"Redistributions of source code must retain the above copyright notice"
        ],
        LicenseType.BSD_3_CLAUSE: [
            r"BSD 3-Clause",
            r"Neither the name of the copyright holder nor the names of its contributors"
        ],
        LicenseType.APACHE_2_0: [
            r"Apache License",
            r"Version 2\.0, January 2004"
        ],
        LicenseType.GPL_2_0: [
            r"GNU General Public License",
            r"Version 2, June 1991"
        ],
        LicenseType.GPL_3_0: [
            r"GNU General Public License",
            r"Version 3, 29 June 2007"
        ],
        LicenseType.LGPL_2_1: [
            r"GNU Lesser General Public License",
            r"Version 2\.1"
        ],
        LicenseType.LGPL_3_0: [
            r"GNU Lesser General Public License",
            r"Version 3, 29 June 2007"
        ],
        LicenseType.MPL_2_0: [
            r"Mozilla Public License",
            r"Version 2\.0"
        ],
        LicenseType.AGPL_3_0: [
            r"GNU Affero General Public License",
            r"Version 3, 19 November 2007"
        ],
        LicenseType.ISC: [
            r"ISC License"
        ],
        LicenseType.CC0_1_0: [
            r"CC0 1.0 Universal"
        ],
        LicenseType.UNLICENSE: [
            r"This is free and unencumbered software"
        ]
    }

    def classify(self, license_text: str) -> LicenseType:
        text = license_text.lower()
        for license_type, patterns in self.LICENSE_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern.lower(), text):
                    return license_type
        return LicenseType.UNKNOWN

    def detect_license(self, file_path: str) -> Optional[LicenseType]:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(10000)
            return self.classify(content)
        except Exception:
            return None

class LicenseCompatibilityChecker:

    COMPATIBILITY_MATRIX = {
        (LicenseType.MIT, LicenseType.BSD_2_CLAUSE): LicenseCompatibility.COMPATIBLE,
        (LicenseType.MIT, LicenseType.BSD_3_CLAUSE): LicenseCompatibility.COMPATIBLE,
        (LicenseType.MIT, LicenseType.APACHE_2_0): LicenseCompatibility.COMPATIBLE,
        (LicenseType.MIT, LicenseType.ISC): LicenseCompatibility.COMPATIBLE,
        (LicenseType.MIT, LicenseType.CC0_1_0): LicenseCompatibility.COMPATIBLE,
        (LicenseType.MIT, LicenseType.UNLICENSE): LicenseCompatibility.COMPATIBLE,
        (LicenseType.MIT, LicenseType.LGPL_2_1): LicenseCompatibility.COMPATIBLE,
        (LicenseType.MIT, LicenseType.LGPL_3_0): LicenseCompatibility.COMPATIBLE,
        (LicenseType.MIT, LicenseType.MPL_2_0): LicenseCompatibility.COMPATIBLE,
        (LicenseType.MIT, LicenseType.GPL_2_0): LicenseCompatibility.RESTRICTED,
        (LicenseType.MIT, LicenseType.GPL_3_0): LicenseCompatibility.RESTRICTED,
        (LicenseType.MIT, LicenseType.AGPL_3_0): LicenseCompatibility.RESTRICTED,
        (LicenseType.APACHE_2_0, LicenseType.GPL_2_0): LicenseCompatibility.INCOMPATIBLE,
        (LicenseType.GPL_2_0, LicenseType.APACHE_2_0): LicenseCompatibility.INCOMPATIBLE,
        (LicenseType.GPL_2_0, LicenseType.GPL_3_0): LicenseCompatibility.INCOMPATIBLE,
        (LicenseType.GPL_3_0, LicenseType.GPL_2_0): LicenseCompatibility.INCOMPATIBLE,
        (LicenseType.GPL_3_0, LicenseType.AGPL_3_0): LicenseCompatibility.RESTRICTED,
        (LicenseType.LGPL_2_1, LicenseType.GPL_3_0): LicenseCompatibility.INCOMPATIBLE,
    }

    @classmethod
    def check_compatibility(cls, license1: LicenseType, license2: LicenseType) -> LicenseCompatibility:
        if license1 == license2:
            return LicenseCompatibility.COMPATIBLE
        key = (license1, license2)
        if key in cls.COMPATIBILITY_MATRIX:
            return cls.COMPATIBILITY_MATRIX[key]
        return LicenseCompatibility.UNKNOWN

    @classmethod
    def get_compatibility_description(cls, compatibility: LicenseCompatibility) -> str:
        descriptions = {
            LicenseCompatibility.COMPATIBLE: "Licenses are fully compatible",
            LicenseCompatibility.RESTRICTED: "Licenses are conditionally compatible",
            LicenseCompatibility.INCOMPATIBLE: "Licenses are incompatible",
            LicenseCompatibility.UNKNOWN: "Compatibility unknown"
        }
        return descriptions.get(compatibility, "Unknown")

class LicenseScanner:

    LICENSE_FILE_PATTERNS = [
        "LICENSE", "LICENSE.txt", "LICENCE", "LICENCE.txt",
        "COPYING", "COPYING.txt", "COPYRIGHT", "COPYRIGHT.txt"
    ]

    def __init__(self, classifier=None):
        self.classifier = classifier or SimpleLicenseClassifier()

    def scan_package(self, package_name):
        if not PKG_RESOURCES_AVAILABLE:
            return None
        try:
            pkg = pkg_resources.get_distribution(package_name)
            license_str = pkg.metadata.get('License', 'Unknown')
            license_type = LicenseType.UNKNOWN
            location = pkg.location

            for pattern in self.LICENSE_FILE_PATTERNS:
                license_path = Path(location) / pattern
                if license_path.exists():
                    license_type = self.classifier.detect_license(str(license_path))

                    break

            if license_type == LicenseType.UNKNOWN:
                license_type = self._infer_license_from_string(license_str)

            return PackageInfo(
                name=pkg.project_name,
                version=pkg.version,
                license=license_str,
                license_type=license_type,
                location=location,
                summary=pkg.metadata.get('Summary'),
                homepage=pkg.metadata.get('Home-page'))

        except pkg_resources.DistributionNotFound:
            logger.warning(f"Package {package_name} not found")
            return None
        except Exception as e:
            logger.error(f"Failed to scan package {package_name}: {e}")
            return None

    def scan_requirements(self, requirements_path="requirements.txt"):
        packages = []
        if not os.path.exists(requirements_path):
            logger.warning(f"requirements.txt not found: {requirements_path}")
            return packages

        try:
            with open(requirements_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        match = re.match(r'^[a-zA-Z0-9_-]+', line)
                        if match:
                            pkg_info = self.scan_package(match.group())

                            if pkg_info:
                                packages.append(pkg_info)
        except Exception as e:
            logger.error(f"Failed to read requirements.txt: {e}")

        return packages

    def _infer_license_from_string(self, license_str):
        license_str = license_str.lower()
        mapping = {
            'mit': LicenseType.MIT,
            'bsd': LicenseType.BSD_3_CLAUSE,
            'bsd-2-clause': LicenseType.BSD_2_CLAUSE,
            'bsd-3-clause': LicenseType.BSD_3_CLAUSE,
            'apache': LicenseType.APACHE_2_0,
            'apache-2.0': LicenseType.APACHE_2_0,
            'gpl': LicenseType.GPL_3_0,
            'gpl-2.0': LicenseType.GPL_2_0,
            'gpl-3.0': LicenseType.GPL_3_0,
            'lgpl': LicenseType.LGPL_3_0,
            'lgpl-2.1': LicenseType.LGPL_2_1,
            'lgpl-3.0': LicenseType.LGPL_3_0,
            'mpl': LicenseType.MPL_2_0,
            'mpl-2.0': LicenseType.MPL_2_0,
            'agpl': LicenseType.AGPL_3_0,
            'agpl-3.0': LicenseType.AGPL_3_0,
            'isc': LicenseType.ISC,
            'cc0': LicenseType.CC0_1_0,
            'unlicense': LicenseType.UNLICENSE,
        }
        for key, license_type in mapping.items():
            if key in license_str:
                return license_type
        return LicenseType.UNKNOWN

class ComplianceAnalyzer:

    def __init__(self, scanner=None):
        self.scanner = scanner or LicenseScanner()
        self.compatibility_checker = LicenseCompatibilityChecker()

    def analyze(self, requirements_path="requirements.txt"):
        packages = self.scanner.scan_requirements(requirements_path)
        conflicts = self._detect_conflicts(packages)
        summary = self._generate_summary(packages, conflicts)
        spdx_document = self._generate_spdx_document(packages)

        return ComplianceReport(
            packages=packages,
            conflicts=conflicts,
            spdx_document=spdx_document,
            summary=summary)

    def _detect_conflicts(self, packages):
        conflicts = []
        for i, pkg1 in enumerate(packages):
            for j, pkg2 in enumerate(packages):
                if i >= j:
                    continue

                compatibility = self.compatibility_checker.check_compatibility(
                    pkg1.license_type, pkg2.license_type
                )

                if compatibility != LicenseCompatibility.COMPATIBLE:
                    conflicts.append(LicenseConflict(
                        package1=pkg1.name,
                        package2=pkg2.name,
                        license1=pkg1.license_type,
                        license2=pkg2.license_type,
                        conflict_type=compatibility.value,
                        severity="high" if compatibility == LicenseCompatibility.INCOMPATIBLE else "medium",
                        description=self.compatibility_checker.get_compatibility_description(compatibility)
                    ))

        return conflicts

    def _generate_summary(self, packages, conflicts):
        license_counts = {}
        for pkg in packages:
            license_counts[pkg.license_type.value] = license_counts.get(pkg.license_type.value, 0) + 1

        return {
            'total_packages': len(packages),
            'unique_licenses': len(license_counts),
            'license_distribution': license_counts,
            'total_conflicts': len(conflicts),
            'incompatible_conflicts': len([c for c in conflicts if c.conflict_type == 'incompatible']),
            'restricted_conflicts': len([c for c in conflicts if c.conflict_type == 'restricted'])
        }

    def _generate_spdx_document(self, packages):
        spdx_lines = [
            "SPDXVersion: SPDX-2.3",
            "DataLicense: CC0-1.0",
            "SPDXID: SPDXRef-DOCUMENT",
            "DocumentName: BinMind-Binary-Analysis-Tool",
            "DocumentNamespace: https://github.com/binmind-project/binmind",
            "",
            "## Package Information"
        ]

        for pkg in packages:
            spdx_lines.append(f"PackageName: {pkg.name}")
            spdx_lines.append(f"SPDXID: SPDXRef-{pkg.name}")
            spdx_lines.append(f"PackageVersion: {pkg.version}")
            spdx_lines.append(f"PackageLicenseInfoFromFiles: {pkg.license_type.value}")
            spdx_lines.append("")

        spdx_lines.append("## License Information")
        spdx_lines.append("")
        spdx_lines.append("LicenseConcluded: MIT")
        spdx_lines.append("LicenseInfoInFile: MIT")

        return "\n".join(spdx_lines)

class GeneratedCodeLicenseChecker:

    ALLOWED_LICENSES = {
        LicenseType.MIT, LicenseType.BSD_2_CLAUSE, LicenseType.BSD_3_CLAUSE,
        LicenseType.APACHE_2_0, LicenseType.ISC
    }

    FORBIDDEN_LICENSES = {
        LicenseType.GPL_2_0, LicenseType.GPL_3_0,
        LicenseType.AGPL_3_0, LicenseType.PROPRIETARY
    }

    @classmethod
    def is_license_allowed(cls, license_type):
        if license_type in cls.FORBIDDEN_LICENSES:
            return False, f"License {license_type.value} is forbidden"
        if license_type in cls.ALLOWED_LICENSES:
            return True, f"License {license_type.value} is allowed"
        return True, f"License {license_type.value} requires manual review"

    @classmethod
    def check_generated_code_license(cls, output_path):
        try:
            with open(output_path, 'r', encoding='utf-8') as f:
                content = f.read(2000)

            if 'License' in content or 'LICENSE' in content or 'copyright' in content.lower():
                if 'GPL' in content or 'General Public License' in content:
                    logger.warning(f"Generated code may contain GPL license: {output_path}")
                    return False

            return True
        except Exception as e:
            logger.error(f"Failed to check generated code license: {e}")
            return False

def generate_compliance_report(requirements_path="requirements.txt", output_path=None):
    analyzer = ComplianceAnalyzer()
    report = analyzer.analyze(requirements_path)

    if output_path:
        report_data = {
            'summary': report.summary,
            'packages': [pkg.__dict__ for pkg in report.packages],
            'conflicts': [conflict.__dict__ for conflict in report.conflicts]
        }

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)

        logger.info(f"Compliance report saved to: {output_path}")

    return report

def check_license_compliance(package_name):
    scanner = LicenseScanner()
    pkg_info = scanner.scan_package(package_name)

    if not pkg_info:
        return {'success': False, 'error': f"Package {package_name} not found"}

    allowed, reason = GeneratedCodeLicenseChecker.is_license_allowed(pkg_info.license_type)

    return {
        'success': True,
        'package': pkg_info.name,
        'version': pkg_info.version,
        'license': pkg_info.license_type.value,
        'allowed': allowed,
        'reason': reason,
        'location': pkg_info.location
    }

_global_scanner = None

def get_license_scanner():
    global _global_scanner
    if _global_scanner is None:
        _global_scanner = LicenseScanner()
    return _global_scanner
