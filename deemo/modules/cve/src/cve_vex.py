# 2026-09-08 ~ 2026-09-10
# CycloneDX VEX (Vulnerability Exploitability eXchange) document generator.
# VEX is the standard way to communicate the exploitability status of
# vulnerabilities in a product — required by US EO 14028 for federal software.
#
# Takes SBOM match results (from cve_sbom_matcher or build_sbom_report) and
# generates a CycloneDX VEX JSON document. The VEX says, for each CVE matched
# against your SBOM, whether you're affected, not affected, investigating, or
# already fixed it.
#
# VEX spec: https://cyclonedx.org/capabilities/vex/
# Minimal profile — we generate the required fields, not the full CycloneDX VEX
# spec. Full VEX includes product tree, vulnerability analysis details, etc.
# This is the "just give me something valid" path.

import json
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

from .cve_models import CVEEntry, Severity

# VEX statuses per CycloneDX spec
VEX_AFFECTED = "affected"
VEX_NOT_AFFECTED = "not_affected"
VEX_UNDER_INVESTIGATION = "under_investigation"
VEX_FIXED = "fixed"

# justification labels for "not_affected" entries
_NOT_AFFECTED_JUSTIFICATIONS = {
    "component_not_present": "component_not_present",
    "vulnerable_code_not_present": "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path": "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary": "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist": "inline_mitigations_already_exist",
}


def make_vex_document(
    matches: List[Dict],
    product_name: str = "",
    product_version: str = "",
    author: str = "BinMind CVE Analyzer",
) -> Dict[str, Any]:
    """Generate a minimal CycloneDX VEX document from SBOM match results.

    matches: list of match dicts from build_sbom_report()['matches'].
      Each match should have at minimum: cve_id, component, component_version,
      severity, description. Additional fields (status, justification, action)
      are read if present.

    Returns a dict suitable for json.dump() as a CycloneDX VEX document.
    """
    bom_version = 1
    serial = str(uuid.uuid4())[:8]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    doc: Dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial}",
        "version": bom_version,
        "metadata": {
            "timestamp": now,
            "tools": [{
                "vendor": "BinMind",
                "name": "CVE Analyzer",
                "version": "1.0",
            }],
            "authors": [{"name": author}],
        },
    }

    if product_name:
        doc["metadata"]["component"] = {
            "type": "application",
            "name": product_name,
            "version": product_version or "unknown",
        }

    # build vulnerabilities list
    vulns: List[Dict] = []
    seen_cves: set = set()

    for m in matches:
        cve_id = m.get("cve_id", "")
        if not cve_id or cve_id in seen_cves:
            continue
        seen_cves.add(cve_id)

        comp_name = m.get("component", m.get("component_name", ""))
        comp_ver = m.get("component_version", m.get("version", ""))
        severity = m.get("severity", "UNKNOWN")
        desc = m.get("description", "")[:500]
        status = m.get("vex_status", m.get("status", VEX_AFFECTED))
        justification = m.get("vex_justification", m.get("justification", ""))
        action = m.get("vex_action", m.get("action", ""))
        cvss_score = m.get("cvss_score")
        epss_score = m.get("epss_score")

        # normalize status
        status = status.lower().replace(" ", "_")
        if status not in (VEX_AFFECTED, VEX_NOT_AFFECTED, VEX_UNDER_INVESTIGATION, VEX_FIXED):
            status = VEX_AFFECTED

        vuln_entry: Dict[str, Any] = {
            "id": cve_id,
            "source": {
                "name": "NVD",
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            },
            "ratings": [{
                "severity": severity.lower(),
            }],
            "description": desc,
            "affects": [{
                "ref": f"component:{comp_name}@{comp_ver}",
            }],
            "properties": [{
                "name": "vex:status",
                "value": status,
            }],
        }

        if cvss_score is not None:
            vuln_entry["ratings"][0]["score"] = cvss_score
            vuln_entry["ratings"][0]["method"] = "CVSSv3"

        if epss_score is not None:
            vuln_entry["properties"].append({
                "name": "epss:score",
                "value": str(epss_score),
            })

        # not_affected requires a justification
        if status == VEX_NOT_AFFECTED:
            just = justification or "vulnerable_code_not_present"
            vuln_entry["analysis"] = {
                "state": status,
                "detail": _get_justification_label(just),
            }
        elif status == VEX_UNDER_INVESTIGATION:
            vuln_entry["analysis"] = {
                "state": status,
                "detail": action or "Investigation in progress — no determination yet.",
            }
        elif status == VEX_FIXED:
            vuln_entry["analysis"] = {
                "state": "resolved",
                "detail": action or "Patched in a subsequent version.",
            }
        elif action:
            vuln_entry["properties"].append({
                "name": "vex:action",
                "value": action,
            })

        # add recommendation property based on severity
        if status == VEX_AFFECTED:
            recommendation = _severity_recommendation(severity)
            if recommendation:
                vuln_entry["properties"].append({
                    "name": "vex:recommendation",
                    "value": recommendation,
                })

        vulns.append(vuln_entry)

    doc["vulnerabilities"] = vulns
    return doc


def make_vex_from_report(
    report: Dict,
    product_name: str = "",
    product_version: str = "",
) -> Dict[str, Any]:
    """Generate VEX from a build_sbom_report() output dict.
    Thin wrapper — extracts 'matches' from the report."""
    matches = report.get("matches", [])
    # add VEX status from top_priorities
    priorities = report.get("top_priorities", [])
    priority_cves = {p["cve_id"]: p for p in priorities}

    return make_vex_document(matches, product_name, product_version)


def export_vex_json(
    matches: List[Dict],
    output_path: str,
    product_name: str = "",
    product_version: str = "",
) -> str:
    """Generate VEX and write to a JSON file. Returns the file path."""
    doc = make_vex_document(matches, product_name, product_version)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
    return output_path


# ---- helpers ----

def _get_justification_label(key: str) -> str:
    """Map a short justification key to the CycloneDX label."""
    if key in _NOT_AFFECTED_JUSTIFICATIONS:
        return _NOT_AFFECTED_JUSTIFICATIONS[key]
    return key  # pass through as-is


def _severity_recommendation(severity: str) -> str:
    """Generate a remediation recommendation based on severity."""
    s = severity.upper()
    if s == "CRITICAL":
        return "Apply patch immediately. Deploy within 24 hours."
    if s == "HIGH":
        return "Apply patch within 7 days. Monitor for active exploitation."
    if s == "MEDIUM":
        return "Apply patch within 30 days as part of regular update cycle."
    if s == "LOW":
        return "Apply patch at next maintenance window."
    return ""


# ---- mark match results with VEX status ----
# call this after running build_sbom_report to annotate matches
# with manual VEX decisions.

def annotate_vex_status(
    matches: List[Dict],
    decisions: Dict[str, str],
    justification: str = "",
    action: str = "",
) -> List[Dict]:
    """Apply VEX status decisions to a match list.

    decisions: dict of cve_id → status (affected/not_affected/under_investigation/fixed)
    justification: global justification for not_affected entries
    action: global action statement

    Modifies matches in place and also returns them (fluent-ish API)."""
    for m in matches:
        cid = m.get("cve_id", "")
        if cid in decisions:
            m["vex_status"] = decisions[cid]
            if justification:
                m["vex_justification"] = justification
            if action:
                m["vex_action"] = action
    return matches


# ---- auto-status: heuristic VEX decisions ----
# when you don't have manual decisions, this applies heuristics
# based on severity, epss score, and match confidence

def auto_vex_status(matches: List[Dict]) -> List[Dict]:
    """Automatically assign VEX statuses based on heuristics.

    Rules (order matters — first match wins):
      - epss_score > 0.1 AND severity >= HIGH → affected
      - severity == CRITICAL → affected
      - match_confidence < 0.6 → under_investigation
      - everything else → affected (conservative default)

    Override with annotate_vex_status() for manual decisions."""
    for m in matches:
        sev = (m.get("severity") or "").upper()
        epss = m.get("epss_score")
        conf = m.get("match_confidence", 0.0)

        if epss is not None and epss > 0.1 and sev in ("HIGH", "CRITICAL"):
            m["vex_status"] = VEX_AFFECTED
            m["vex_action"] = "Prioritize patching — high EPSS indicates active exploitation likelihood."
        elif sev == "CRITICAL":
            m["vex_status"] = VEX_AFFECTED
            m["vex_action"] = "Critical severity — patch immediately."
        elif conf < 0.6:
            m["vex_status"] = VEX_UNDER_INVESTIGATION
            m["vex_action"] = "Low confidence match — verify against your deployment before acting."
        else:
            m["vex_status"] = VEX_AFFECTED

    return matches
