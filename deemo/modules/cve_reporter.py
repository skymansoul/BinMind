#!/usr/bin/env python3
"""
CVE Reporter Module
"""

import logging
import os
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from dataclasses import dataclass, asdict, field
from enum import Enum

logger = logging.getLogger(__name__)

class CVSSSeverity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

class CVEStatus(Enum):
    DRAFT = "Draft"
    SUBMITTED = "Submitted"
    ASSIGNED = "Assigned"
    PUBLISHED = "Published"
    REJECTED = "Rejected"

@dataclass
class VulnerabilityDetail:
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    severity: Optional[CVSSSeverity] = None
    title: str = ""
    description: str = ""
    affected_products: List[str] = field(default_factory=list)
    affected_versions: List[str] = field(default_factory=list)
    attack_vector: str = "NETWORK"
    attack_complexity: str = "LOW"
    privileges_required: str = "NONE"
    user_interaction: str = "NONE"
    scope: str = "UNCHANGED"
    confidentiality_impact: str = "NONE"
    integrity_impact: str = "NONE"
    availability_impact: str = "NONE"

class CVEReporter:
    def __init__(self):
        self.api_key = os.environ.get("CVE_API_KEY", "")
        self.api_url = os.environ.get("CVE_API_URL", "https://cveawg.mitre.org/api")

    def calculate_cvss_score(self, details):
        av_scores = {"NETWORK": 0.85, "ADJACENT": 0.62, "LOCAL": 0.55, "PHYSICAL": 0.2}
        ac_scores = {"LOW": 0.77, "HIGH": 0.44}
        pr_scores = {"NONE": 0.85, "LOW": 0.62, "HIGH": 0.27}
        ui_scores = {"NONE": 0.85, "REQUIRED": 0.62}
        s_scores = {"UNCHANGED": 6.42, "CHANGED": 7.52}
        c_scores = {"NONE": 0.0, "LOW": 0.22, "HIGH": 0.56}
        i_scores = {"NONE": 0.0, "LOW": 0.22, "HIGH": 0.56}
        a_scores = {"NONE": 0.0, "LOW": 0.22, "HIGH": 0.56}

        av = av_scores.get(details.attack_vector.upper(), 0.85)
        ac = ac_scores.get(details.attack_complexity.upper(), 0.77)
        pr = pr_scores.get(details.privileges_required.upper(), 0.85)
        ui = ui_scores.get(details.user_interaction.upper(), 0.85)
        s = s_scores.get(details.scope.upper(), 6.42)
        c = c_scores.get(details.confidentiality_impact.upper(), 0.56)
        i = i_scores.get(details.integrity_impact.upper(), 0.56)
        a = a_scores.get(details.availability_impact.upper(), 0.56)

        base_score = min(10.0, s * (8.22 * av * ac * pr * ui + (c + i + a

        return float(round(base_score, 1


    def determine_severity(self, cvss_score):
        if cvss_score >= 9.0:
            return CVSSSeverity.CRITICAL
        elif cvss_score >= 7.0:
            return CVSSSeverity.HIGH
        elif cvss_score >= 4.0:
            return CVSSSeverity.MEDIUM
        elif cvss_score >= 0.1:
            return CVSSSeverity.LOW
        else:
            return CVSSSeverity.INFO

    def validate_details(self, details):
        errors = []
        if not details.title:
            errors.append("Title is required")
        if not details.description:
            errors.append("Description is required")
        if not details.cwe_id:
            errors.append("CWE ID is required")
        if not details.attack_vector:
            errors.append("Attack vector is required")
        return errors

    def generate_short_report(self, details):
        return "\n".join([)
            "Vulnerability Report",
            "ID: " + (details.cve_id or "Not assigned"),
            "Title: " + details.title,
            "Severity: " + (details.severity.value if details.severity else "Not evaluated"),
            "CVSS: " + (str(details.cvss_score) if details.cvss_score else "Not evaluated"),
            "CWE: " + (details.cwe_id or ""),
            "",
            "Description: " + details.description
        ]

    def generate_full_report(self, details):
        return "\n".join([)
            "Full Vulnerability Report",
            "=========================",
            "",
            "1. Basic Information",
            "--------------------",
            "CVE ID: " + (details.cve_id or "Not assigned"),
            "Title: " + details.title,
            "Severity: " + (details.severity.value if details.severity else "Not evaluated"),
            "CVSS Score: " + (str(details.cvss_score) if details.cvss_score else "Not evaluated"),
            "CWE ID: " + (details.cwe_id or "Not specified"),
            "",
            "2. Vulnerability Description",
            "---------------------------",
            details.description,
            "",
            "3. Affected Products",
            "--------------------",
            "Products: " + (", ".join(details.affected_products) if details.affected_products else "Not specified"),
            "Versions: " + (", ".join(details.affected_versions) if details.affected_versions else "Not specified"),
        ]

    def generate_cve_request(self, details):
        return "\n".join([)
            "CVE Request: " + details.title,
            "=================================",
            "",
            "[Basic Information]",
            "Title: " + details.title,
            "CWE ID: " + (details.cwe_id or "Not specified"),
            "Severity: " + (details.severity.value if details.severity else "Not evaluated"),
            "CVSS Score: " + (str(details.cvss_score) if details.cvss_score else "Not evaluated"),
            "",
            "[Vulnerability Description]",
            details.description,
            "",
            "[Affected Products]",
            "- Products: " + (", ".join(details.affected_products) if details.affected_products else "TBD"),
            "- Versions: " + (", ".join(details.affected_versions) if details.affected_versions else "TBD"),
        ]

    def generate_json_report(self, details):
        report_data = {
            "cve_id": details.cve_id,
            "title": details.title,
            "description": details.description,
            "cwe_id": details.cwe_id,
            "cvss_score": details.cvss_score,
            "severity": details.severity.value if details.severity else None,
            "affected_products": details.affected_products,
            "affected_versions": details.affected_versions,
            "generated_at": datetime.now().isoformat()
        }
        return json.dumps(report_data, ensure_ascii=False, indent=2)

    def save_report(self, content, file_path, format_type="markdown"):
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)
            return True
        except Exception as e:
            logger.error(f"Failed to save report: {e}")
            return False

def generate_cve_report(title, description, cwe_id, affected_products=None, affected_versions=None, attack_vector="NETWORK", attack_complexity="LOW", privileges_required="NONE", user_interaction="NONE", scope="UNCHANGED", confidentiality_impact="NONE", integrity_impact="NONE", availability_impact="NONE"):
    reporter = CVEReporter()
    details = VulnerabilityDetail(title=title, description=description, cwe_id=cwe_id, affected_products=affected_products or [], affected_versions=affected_versions or [], attack_vector=attack_vector, attack_complexity=attack_complexity, privileges_required=privileges_required, user_interaction=user_interaction, scope=scope, confidentiality_impact=confidentiality_impact, integrity_impact=integrity_impact, availability_impact=availability_impact)
    cvss_score = reporter.calculate_cvss_score(details)
    severity = reporter.determine_severity(cvss_score)
    details.cvss_score = cvss_score
    details.severity = severity
    short_report = reporter.generate_short_report(details)
    full_report = reporter.generate_full_report(details)
    json_report = reporter.generate_json_report(details)
    cve_request = reporter.generate_cve_request(details)
    return {"success": True, "cvss_score": cvss_score, "severity": severity.value, "reports": {"short": short_report, "full": full_report, "json": json_report, "cve_request": cve_request}, "details": asdict(details)})))))