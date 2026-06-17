import os
import re
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any
from pathlib import Path

@dataclass
class LicenseInfo:
    name: str
    identifier: str
    spdx_id: Optional[str] = None
    is_copyleft: bool = False
    requires_attribution: bool = True
    compatible_licenses: List[str] = field(default_factory=list)
    prohibited_licenses: List[str] = field(default_factory=list)

@dataclass
class ComponentInfo:
    name: str
    version: Optional[str] = None
    license: Optional[LicenseInfo] = None
    source_url: Optional[str] = None
    local_path: Optional[str] = None
    is_optional: bool = False

@dataclass
class LicenseConflict:
    component1: str
    component2: str
    license1: str
    license2: str
    conflict_type: str
    severity: str

@dataclass
class ComplianceReport:
    components: List[ComponentInfo]
    conflicts: List[LicenseConflict]
    attribution_text: str
    summary: Dict[str, Any]

class LicenseDatabase:
    def __init__(self):
        self.licenses: Dict[str, LicenseInfo] = {}
        self._load_known_licenses()
    
    def _load_known_licenses(self):
        licenses_data = [
            {
                "name": "MIT License",
                "identifier": "mit",
                "spdx_id": "MIT",
                "is_copyleft": False,
                "requires_attribution": True,
                "compatible_licenses": ["apache-2.0", "bsd-2-clause", "bsd-3-clause", "mit", "isc"],
                "prohibited_licenses": []
            },
            {
                "name": "Apache License 2.0",
                "identifier": "apache-2.0",
                "spdx_id": "Apache-2.0",
                "is_copyleft": False,
                "requires_attribution": True,
                "compatible_licenses": ["mit", "bsd-2-clause", "bsd-3-clause", "apache-2.0"],
                "prohibited_licenses": ["gpl-3.0"]
            },
            {
                "name": "GNU General Public License v3",
                "identifier": "gpl-3.0",
                "spdx_id": "GPL-3.0",
                "is_copyleft": True,
                "requires_attribution": True,
                "compatible_licenses": ["gpl-3.0", "lgpl-3.0"],
                "prohibited_licenses": ["mit", "apache-2.0", "bsd-2-clause", "bsd-3-clause"]
            },
            {
                "name": "GNU Lesser General Public License v3",
                "identifier": "lgpl-3.0",
                "spdx_id": "LGPL-3.0",
                "is_copyleft": True,
                "requires_attribution": True,
                "compatible_licenses": ["gpl-3.0", "lgpl-3.0", "mit", "apache-2.0"],
                "prohibited_licenses": []
            },
            {
                "name": "BSD 2-Clause License",
                "identifier": "bsd-2-clause",
                "spdx_id": "BSD-2-Clause",
                "is_copyleft": False,
                "requires_attribution": True,
                "compatible_licenses": ["mit", "apache-2.0", "bsd-3-clause"],
                "prohibited_licenses": ["gpl-3.0"]
            },
            {
                "name": "BSD 3-Clause License",
                "identifier": "bsd-3-clause",
                "spdx_id": "BSD-3-Clause",
                "is_copyleft": False,
                "requires_attribution": True,
                "compatible_licenses": ["mit", "apache-2.0", "bsd-2-clause"],
                "prohibited_licenses": ["gpl-3.0"]
            },
            {
                "name": "ISC License",
                "identifier": "isc",
                "spdx_id": "ISC",
                "is_copyleft": False,
                "requires_attribution": True,
                "compatible_licenses": ["mit", "apache-2.0", "bsd-2-clause", "bsd-3-clause"],
                "prohibited_licenses": ["gpl-3.0"]
            },
            {
                "name": "Mozilla Public License 2.0",
                "identifier": "mpl-2.0",
                "spdx_id": "MPL-2.0",
                "is_copyleft": True,
                "requires_attribution": True,
                "compatible_licenses": ["mpl-2.0", "mit", "apache-2.0"],
                "prohibited_licenses": ["gpl-3.0"]
            }
        ]
        
        for lic in licenses_data:
            self.licenses[lic["identifier"]] = LicenseInfo(**lic)
    
    def get_license(self, identifier: str) -> Optional[LicenseInfo]:
        return self.licenses.get(identifier.lower(


class LicenseScanner:
    LICENSE_PATTERNS = {
        "mit": [
            r"MIT License",
            r"Permission is hereby granted, free of charge",
            r"Copyright \(c\) .* All rights reserved\."
        ],
        "apache-2.0": [
            r"Apache License",
            r"Version 2\.0, January 2004",
            r"http://www.apache.org/licenses/LICENSE-2\.0"
        ],
        "gpl-3.0": [
            r"GNU General Public License",
            r"Version 3, 29 June 2007",
            r"This program is free software: you can redistribute it and/or modify"
        ],
        "lgpl-3.0": [
            r"GNU Lesser General Public License",
            r"Version 3, 29 June 2007",
            r"This library is free software"
        ],
        "bsd-2-clause": [
            r"Redistribution and use in source and binary forms",
            r"provided that the following conditions are met:",
            r"Redistributions of source code must retain the above copyright"
        ],
        "bsd-3-clause": [
            r"Neither the name of the .* nor the names of its contributors",
            r"may be used to endorse or promote products derived from"
        ],
        "isc": [
            r"ISC License",
            r"Permission to use, copy, modify, and/or distribute this software"
        ],
        "mpl-2.0": [
            r"Mozilla Public License",
            r"Version 2\.0",
            r"https://www.mozilla.org/en-US/MPL/2\.0/"
        ]
    }
    
    def __init__(self):
        self.license_db = LicenseDatabase()
    
    def scan_file(self, file_path: str) -> Optional[LicenseInfo]:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read().lower()
            
            for license_id, patterns in self.LICENSE_PATTERNS.items():
                matches = sum(1 for pattern in patterns if re.search(pattern.lower(), content

                if matches >= len(patterns) * 0.6:
                    return self.license_db.get_license(license_id)
        except Exception:
            pass
        
        return None
    
    def scan_directory(self, directory: str, excluded_patterns: Optional[List[str]] = None) -> List[ComponentInfo]:
        excluded_patterns = excluded_patterns or []
        components: List[ComponentInfo] = []
        
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if not any(re.match(p, d) for p in excluded_patterns)]
            
            for filename in ['LICENSE', 'LICENSE.txt', 'LICENSE.md', 'COPYING', 'COPYRIGHT']:
                license_path = os.path.join(root, filename)
                if os.path.exists(license_path):
                    license_info = self.scan_file(license_path)
                    if license_info:
                        component_name = os.path.basename(root)
                        components.append(ComponentInfo(
                            name=component_name,
                            license=license_info,
                            local_path=root
                        

                        break
        
        return components

class LicenseComplianceChecker:
    def __init__(self):
        self.license_db = LicenseDatabase()
    
    def check_conflicts(self, components: List[ComponentInfo]) -> List[LicenseConflict]:
        conflicts: List[LicenseConflict] = []
        
        for i, comp1 in enumerate(components):
            for j, comp2 in enumerate(components[i+1:], i+1):
                if comp1.license and comp2.license:
                    lic1 = comp1.license
                    lic2 = comp2.license
                    
                    if lic1.identifier in lic2.prohibited_licenses or \
                       lic2.identifier in lic1.prohibited_licenses:
                        conflicts.append(LicenseConflict(
                            component1=comp1.name,
                            component2=comp2.name,
                            license1=lic1.name,
                            license2=lic2.name,
                            conflict_type="license_incompatibility",
                            severity="high"
                        

                    
                    if lic1.is_copyleft and not lic2.is_copyleft:
                        conflicts.append(LicenseConflict(
                            component1=comp1.name,
                            component2=comp2.name,
                            license1=lic1.name,
                            license2=lic2.name,
                            conflict_type="copyleft_encroachment",
                            severity="medium"
                        

        
        return conflicts
    
    def generate_attribution_text(self, components: List[ComponentInfo]) -> str:
        attribution_lines = ["Third-party components used in this project:\n"]
        
        for comp in components:
            if comp.license and comp.license.requires_attribution:
                line = f"- {comp.name}",
                if comp.version:
                    line += f" (version {comp.version})"
                line += f" - Licensed under {comp.license.name}",
                if comp.source_url:
                    line += f" ({comp.source_url})"
                attribution_lines.append(line)
        
        return "\n".join(attribution_lines)
    
    def generate_compliance_report(self, components: List[ComponentInfo]) -> ComplianceReport:
        conflicts = self.check_conflicts(components)
        
        summary = {
            "total_components": len(components),
            "components_with_license": sum(1 for c in components if c.license),
            "conflicts_found": len(conflicts),
            "copyleft_components": sum(1 for c in components if c.license and c.license.is_copyleft),
            "requires_attribution": sum(1 for c in components if c.license and c.license.requires_attribution)
        }
        
        return ComplianceReport(
            components=components,
            conflicts=conflicts,
            attribution_text=self.generate_attribution_text(components),
            summary=summary)
        


class ExploitCodeGenerator:
    def __init__(self):
        self.compliance_checker = LicenseComplianceChecker()
    
    def add_compliance_header(self, exploit_code: str, components: List[ComponentInfo]) -> str:
        report = self.compliance_checker.generate_compliance_report(components)
        
        header_lines = [
            "# Exploit Code Compliance Notice",
            "# ===================================",
            "# This exploit code may incorporate components from various libraries.",
            "# Please review the following license information before use.",
            "#",
            f"# Generated with {report.summary['total_components']} dependencies",
            f"# Conflicts detected: {report.summary['conflicts_found']}",
            "#",
            "# Dependencies:",
            "=" * 50
        ]
        
        for comp in components:
            if comp.license:
                header_lines.append(f"# - {comp.name}: {comp.license.name}")
        
        if report.conflicts:
            header_lines.append("#")
            header_lines.append("# WARNING: License conflicts detected:")
            for conflict in report.conflicts:
                header_lines.append(f"#   - {conflict.component1} ({conflict.license1}) conflicts with {conflict.component2} ({conflict.license2})")
        
        header_lines.append("#")
        header_lines.append("# USE AT YOUR OWN RISK.")
        header_lines.append("# ===================================")
        header_lines.append("")
        
        return "\n".join(header_lines) + exploit_code))))))))))