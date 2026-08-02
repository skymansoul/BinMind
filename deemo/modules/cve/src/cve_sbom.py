# 2026-08-01
# cve_sbom.py — thin compat wrapper.
# Tests that were written before the rename (cve_sbom → cve_sbom_matcher)
# import from this module name. Rather than updating all test imports
# (break other feature branches), this re-exports from cve_sbom_matcher.
#
# NOT importing from cve_sbom_import — that's the SBOM *import* module
# (parse/generate SBOMs from project files). Different concern.

import json
import os
import re
from typing import Dict, List, Optional, Any

# re-export everything from the matcher
from .cve_sbom_matcher import (
    match_component,
    match_sbom,
    build_sbom_report,
    _norm_name,
    _token_overlap,
    _check_version_affected,
    _extract_fix,
    _kb_lookup,
)

# re-export purl translation tools
from .cve_purl_cpe import (
    purl_to_cpe,
    cpe_to_purl,
    parse_purl,
    propagate_risk,
    transitive_risk_report,
)

__all__ = [
    "match_component",
    "match_sbom",
    "build_sbom_report",
    "parse_purl",
    "import_sbom",
    "purl_to_cpe",
    "cpe_to_purl",
    "propagate_risk",
    "transitive_risk_report",
    "_norm_name",
    "_token_overlap",
    "_check_version_affected",
    "_extract_fix",
    "_kb_lookup",
]


# ---- purl parsing with patches ----

# npm scoped package pattern: @scope/name
_NPM_SCOPED_RE = re.compile(r"^@([^/]+)/(.+)$")

# Go module path: domain/org/repo or similar
_GO_MODULE_RE = re.compile(r"^([^/]+\.[^/]+)/(.+)$")


def parse_purl(purl_str: str) -> Optional[Dict]:
    """Parse a purl string, with patches for npm scoped packages and Go modules.
    This wraps the cve_purl_cpe.parse_purl but adds ecosystem-specific
    handling that the base parser intentionally omits (to keep the base
    parser clean for the PURL→CPE pipeline)."""

    if not purl_str or not purl_str.startswith("pkg:"):
        return None

    # delegate to the base parser
    from .cve_purl_cpe import parse_purl as _base_parse_purl

    result = _base_parse_purl(purl_str)
    if not result:
        return None

    eco = result.get("type", "")
    name = result.get("name", "")
    namespace = result.get("namespace", "")

    # npm scoped packages: ensure namespace is set
    if eco == "npm" and not namespace:
        m = _NPM_SCOPED_RE.match(name)
        if m:
            result["namespace"] = m.group(1)
            result["name"] = m.group(2)
        else:
            # also check the raw name field which might have @scope/name
            raw_name = result.get("raw", "")
            if raw_name:
                # try to extract from qualified purl path
                pass

    # Go modules: normalize module path
    if eco == "golang":
        # if there's a namespace but it looks like a full path, re-parse
        full_name = f"{namespace}/{name}" if namespace else name
        m = _GO_MODULE_RE.match(full_name)
        if m:
            result["namespace"] = m.group(1)
            result["name"] = m.group(2)

    return result


# ---- SBOM file import ----

def import_sbom(path: str) -> Dict:
    """Load an SBOM JSON file and return a normalized dict.
    Handles both CycloneDX and SPDX formats. The returned dict always
    has a 'components' key for downstream consumers."""

    if not os.path.exists(path):
        raise FileNotFoundError(f"SBOM file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        sbom = json.load(f)

    # normalize to a common format
    result = {
        "source_path": os.path.abspath(path),
        "format": "unknown",
        "components": [],
        "metadata": {},
    }

    # CycloneDX
    if "bomFormat" in sbom or "specVersion" in sbom:
        result["format"] = "cyclonedx"
        result["metadata"] = sbom.get("metadata", {})
        result["components"] = sbom.get("components", [])
        # also handle services (SaaSBOM)
        if "services" in sbom:
            for svc in sbom.get("services", []):
                svc["_type"] = "service"
                result["components"].append(svc)

    # SPDX
    elif "spdxVersion" in sbom or "SPDXID" in sbom:
        result["format"] = "spdx"
        result["metadata"] = {
            "name": sbom.get("name", ""),
            "spdxVersion": sbom.get("spdxVersion", ""),
            "creationInfo": sbom.get("creationInfo", {}),
        }
        # SPDX packages → components
        packages = sbom.get("packages", [])
        for pkg in packages:
            comp = {
                "name": pkg.get("name", ""),
                "version": pkg.get("versionInfo", ""),
                "purl": None,
                "cpe": None,
                "ecosystem": None,
            }
            # extract purl/cpe from externalRefs
            for ref in pkg.get("externalRefs", []):
                ref_type = ref.get("referenceType", "")
                ref_locator = ref.get("referenceLocator", "")
                if "purl" in ref_type and not comp["purl"]:
                    comp["purl"] = ref_locator
                if "cpe" in ref_type and not comp["cpe"]:
                    comp["cpe"] = ref_locator
            result["components"].append(comp)

    # Unknown/raw format — assume components key
    else:
        result["format"] = "raw"
        if isinstance(sbom, list):
            result["components"] = sbom
        else:
            result["components"] = sbom.get("components", sbom.get("packages", []))

    return result
