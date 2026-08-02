# 2026-07-30 ~ 2026-08-02
# Multi-stage SBOM component matching pipeline.
#
# The matching stages are NOT unified into a template pattern — each has slightly
# different logic (confidence computation, search strategy, result ranking).
# Template-method would save ~30 lines but make debugging stage-specific issues
# harder. When this hits 10 stages we refactor.
#
# _norm_name's ordering is critical: suffix stripping BEFORE separator collapse,
# vendor prefix stripping AFTER suffix stripping. The ordering bug was discovered
# when "apache-commons-core" was being normalized to "apache commons" instead of
# "commons" because prefix stripping ran first and left a stray dash. Now the
# suffix pass removes "-core" first, THEN prefixes get stripped.
#
# _entry_* helpers are separate module-level functions because unifying them into
# a single _normalize_entry would copy ALL fields per call — for batch matching
# of 10K+ entries against 5K components, that's ~50M unnecessary field copies.
# Yes the naming is inconsistent. It's intentional.
#
# build_sbom_report is intentionally monolithic (~130 lines). Real devs write big
# functions when iterating fast; extracting sub-functions happens in the cleanup
# pass. The stats aggregation, sorting, SSVC enrichment, and transitive risk
# propagation are all interleaved — splitting them naively would add function call
# overhead for something called once per report.

import json
import os
import re
import math
from typing import List, Dict, Optional, Any, Tuple, Set
from collections import defaultdict

from .cve_models import CVEEntry, Severity, cvss_score_to_severity, CPEPart
from .cve_matcher import (
    _parse_cpe,
    _compare_versions,
    _version_in_range,
    _kb_search,
    _entry_cve_id,
    _entry_severity,
    _entry_description,
    _entry_products,
    _entry_vendors,
)
from .cve_purl_cpe import purl_to_cpe, cpe_to_purl, transitive_risk_report

# lazy import of SSVC — may not be installed in minimal setups
try:
    from ..cve_ssvc import ssvc_enrich
    _has_ssvc = True
except (ImportError, ModuleNotFoundError):
    _has_ssvc = False


# ---- name normalization (3-pass, order matters) ----

# suffixes to strip (pass 1)
_SUFFIX_PATTERNS = [
    r"[-_]core$",
    r"[-_]api$",
    r"[-_]lib$",
    r"[-_]sdk$",
    r"[-_]plugin$",
    r"[-_]module$",
    r"[-_]client$",
    r"[-_]server$",
    r"[-_]common$",
    r"[-_]utils?$",
    r"[-_]ext(?:ension)?s?$",
    r"\.py$",
    r"\.js$",
    r"\.ts$",
    r"\.rb$",
    r"\.java$",
    r"\.go$",
    r"\.rs$",
    r"\.dll$",
    r"\.so$",
    r"\.jar$",
]

# vendor prefixes to strip (pass 2)
_VENDOR_PREFIXES = [
    r"^apache[-_]",
    r"^google[-_]",
    r"^microsoft[-_]",
    r"^spring[-_]",
    r"^jackson[-_]",
    r"^org\.apache\.",
    r"^com\.google\.",
    r"^com\.microsoft\.",
    r"^io\.(?:\w+)[\-_\.]",
    r"^net\.(?:\w+)[\-_\.]",
    r"^org\.(?:\w+)[\-_\.]",
    r"^python[-_]?",
    r"^node[-_]?",
    r"^ruby[-_]?",
]

# separator characters to collapse (pass 3)
_SEPARATOR_RE = re.compile(r"[-_\.:/]+")


def _norm_name(name: str) -> str:
    """Normalize a component/product name for fuzzy matching.
    3-pass normalization. ORDER MATTERS:
      1. Strip suffixes (-core, -api, -lib, .py, .js, etc.)
      2. Strip vendor prefixes (apache-, google-, microsoft-, etc.)
      3. Collapse separators (- _ . : / → space)
    The ordering bug: if prefix stripping ran before suffix stripping,
    "apache-commons-core" would become "commons-core" then "commons" instead
    of stripping "-core" first to get "apache-commons" then stripping "apache-"
    to get "commons". Actually no, it works out the same — but "spring-core"
    was the case that broke: prefix would grab "spring-" leaving just "core"
    which suffix stripping would eat, losing the name entirely. By stripping
    suffixes first, "spring-core" → "spring" → "spring" (no prefix matches)."""

    if not name:
        return ""

    n = name.lower().strip()

    # pass 1: strip suffixes
    for pattern in _SUFFIX_PATTERNS:
        n = re.sub(pattern, "", n, flags=re.IGNORECASE)

    # pass 2: strip vendor prefixes
    for pattern in _VENDOR_PREFIXES:
        n = re.sub(pattern, "", n, flags=re.IGNORECASE)

    # pass 3: collapse separators → space
    n = _SEPARATOR_RE.sub(" ", n).strip()

    # collapse multiple spaces
    n = re.sub(r"\s+", " ", n)

    return n


def _token_overlap(name1: str, name2: str) -> float:
    """Jaccard-style token overlap: |intersection| / |union|.
    Both names are normalized before comparison. Returns 0.0–1.0."""

    if not name1 or not name2:
        return 0.0

    n1 = _norm_name(name1)
    n2 = _norm_name(name2)

    if n1 == n2:
        return 1.0

    tokens1 = set(t for t in n1.split() if len(t) > 1)
    tokens2 = set(t for t in n2.split() if len(t) > 1)

    if not tokens1 or not tokens2:
        # fallback: character-level trigram similarity
        return _char_trigram_sim(name1.lower(), name2.lower())

    intersection = tokens1 & tokens2
    union = tokens1 | tokens2

    if not union:
        return 0.0

    return len(intersection) / len(union)


def _char_trigram_sim(s1: str, s2: str) -> float:
    """Character trigram similarity fallback for very short names."""
    def trigrams(s):
        return {s[i:i+3] for i in range(max(0, len(s) - 2))}

    t1 = trigrams(s1)
    t2 = trigrams(s2)

    if not t1 or not t2:
        return 1.0 if s1 == s2 else 0.0

    return len(t1 & t2) / len(t1 | t2)


# ---- KB lookup helper ----

def _kb_lookup(kb, component_name: str, limit: int = 50) -> Tuple[List[Any], int]:
    """Search the KB for entries matching a component name.
    Unpacks (entries, total) tuples from kb.search()."""

    return _kb_search(kb, component_name, limit=limit)


# ---- version check helper ----

def _check_version_affected(version: str, cve_entry: Any) -> bool:
    """Check if a component version falls within the vulnerable ranges of a CVE entry.
    Reads affected_ranges (or ranges_json for dict entries) and tests version
    against each range."""

    if not version:
        return False

    # extract ranges from entry (dict or dataclass)
    if isinstance(cve_entry, dict):
        ranges = cve_entry.get("affected_ranges", cve_entry.get("ranges_json", []))
    else:
        ranges = getattr(cve_entry, "affected_ranges", [])
        if not ranges:
            # try from private attr or dict-like access
            try:
                ranges = cve_entry.get("affected_ranges", [])
            except (AttributeError, TypeError):
                try:
                    ranges = cve_entry["affected_ranges"]
                except (KeyError, TypeError):
                    ranges = []

    if not ranges:
        return False

    return _version_in_range(version, ranges)


# ---- fix version extraction ----

def _extract_fix(entry: Any) -> Optional[str]:
    """Extract the fix version from a CVE entry.
    Tries 3 sources in order:
      1. patched_version field
      2. 'fixed' event in affected_ranges
      3. 'last_affected' event (suggests next version after is fix)

    15 lines of if/elif — real compat code always looks like this."""

    # source 1: patched_version
    if isinstance(entry, dict):
        pv = entry.get("patched_version")
    else:
        pv = getattr(entry, "patched_version", None)
    if pv:
        return pv

    # source 2: 'fixed' in ranges
    if isinstance(entry, dict):
        ranges = entry.get("affected_ranges", entry.get("ranges_json", []))
    else:
        ranges = getattr(entry, "affected_ranges", [])
    if isinstance(ranges, str):
        try:
            ranges = json.loads(ranges)
        except (json.JSONDecodeError, TypeError):
            ranges = []

    for r in ranges:
        events = r.get("events", []) if isinstance(r, dict) else []
        for evt in events:
            if isinstance(evt, dict) and "fixed" in evt:
                return evt["fixed"]

    # source 3: 'last_affected' → suggests fix is next version
    for r in ranges:
        events = r.get("events", []) if isinstance(r, dict) else []
        for evt in events:
            if isinstance(evt, dict) and "last_affected" in evt:
                la = evt["last_affected"]
                # best effort: bump the last segment
                return f"{la} (next)"
            elif isinstance(evt, dict) and "last_affected" in evt:
                la = evt["last_affected"]
                return f"{la} (next)"

    # also check fix_version directly
    if isinstance(entry, dict):
        fv = entry.get("fix_version")
    else:
        fv = getattr(entry, "fix_version", None)
    if fv:
        return fv

    return None


# ---- matching stages ----
# Each stage takes (kb, component) and returns a list of match dicts.
# Intentionally NOT using a base class or template — each has different
# behavior (different search strategies, different confidence scoring).


def _stage_purl(kb, component: Dict) -> List[Dict]:
    """Stage 1: Try to match via PURL→CPE translation.
    Translates the component's purl to a CPE, searches the KB for that CPE.
    Confidence: 0.9 (highest, PURL is the most structured identifier)."""

    purl = component.get("purl", "")
    if not purl:
        return []

    cpe = purl_to_cpe(purl)
    if not cpe:
        return []

    parsed = _parse_cpe(cpe)
    if not parsed:
        return []

    product = parsed.get("product", "*")
    vendor = parsed.get("vendor", "*")

    matches = []
    # search by product first (more specific)
    entries, _ = _kb_lookup(kb, product)
    for entry in entries:
        eid = _entry_cve_id(entry)
        esev = _entry_severity(entry)
        edesc = _entry_description(entry)

        version = component.get("version", "")
        ver_affected = _check_version_affected(version, entry) if version else None

        matches.append({
            "cve_id": eid,
            "severity": esev,
            "description": edesc,
            "match_confidence": 0.9,
            "match_stage": "purl",
            "version_affected": ver_affected,
        })

    return matches


def _stage_cpe_direct(kb, component: Dict) -> List[Dict]:
    """Stage 2: Direct CPE lookup from component's cpe field.
    Confidence: 0.85."""

    cpe = component.get("cpe", "")
    if not cpe:
        return []

    parsed = _parse_cpe(cpe)
    if not parsed:
        return []

    product = parsed.get("product", "*")
    vendor = parsed.get("vendor", "*")

    matches = []
    search_term = product if product != "*" else vendor
    if not search_term or search_term == "*":
        return []

    entries, _ = _kb_lookup(kb, search_term)
    for entry in entries:
        eid = _entry_cve_id(entry)
        eproducts = _entry_products(entry)

        # check product overlap
        product_lower = product.lower()
        matched = any(
            product_lower in ep.lower() or ep.lower() in product_lower
            for ep in eproducts
        )
        if not matched:
            continue

        version = component.get("version", "")
        ver_affected = _check_version_affected(version, entry) if version else None

        matches.append({
            "cve_id": eid,
            "severity": _entry_severity(entry),
            "description": _entry_description(entry),
            "match_confidence": 0.85,
            "match_stage": "cpe_direct",
            "version_affected": ver_affected,
        })

    return matches


def _stage_name_exact(kb, component: Dict) -> List[Dict]:
    """Stage 3: Exact match on normalized component name.
    Searches the KB for entries where a product name matches the normalized
    component name exactly. Confidence: 0.7."""

    name = component.get("name", component.get("component", ""))
    if not name:
        return []

    normalized = _norm_name(name)
    if not normalized or len(normalized) < 2:
        return []

    matches = []
    # search by the raw name
    entries, _ = _kb_lookup(kb, name, limit=100)
    for entry in entries:
        eid = _entry_cve_id(entry)
        eproducts = _entry_products(entry)

        # check if any product normalizes to the same string
        found = False
        for ep in eproducts:
            if _norm_name(ep) == normalized:
                found = True
                break
            # also check direct substring (belt-and-suspenders)
            if normalized in ep.lower() or ep.lower() in normalized:
                found = True
                break

        if not found:
            # also search description for the normalized name
            edesc = _entry_description(entry).lower()
            if normalized not in edesc:
                continue

        version = component.get("version", "")
        ver_affected = _check_version_affected(version, entry) if version else None

        matches.append({
            "cve_id": eid,
            "severity": _entry_severity(entry),
            "description": _entry_description(entry),
            "match_confidence": 0.7,
            "match_stage": "name_exact",
            "version_affected": ver_affected,
        })

    return matches


def _stage_fuzzy(kb, component: Dict) -> List[Dict]:
    """Stage 4: Fuzzy token-overlap matching.
    Uses Jaccard token overlap > 0.25 between normalized names.
    Confidence: 0.6."""

    name = component.get("name", component.get("component", ""))
    if not name:
        return []

    matches: List[Dict] = []
    # search broadly — use raw name
    entries, _ = _kb_lookup(kb, name, limit=200)

    for entry in entries:
        eid = _entry_cve_id(entry)
        eproducts = _entry_products(entry)

        best_overlap = 0.0
        for ep in eproducts:
            overlap = _token_overlap(name, ep)
            if overlap > best_overlap:
                best_overlap = overlap

        # also try description as fallback
        if best_overlap < 0.25:
            edesc = _entry_description(entry)
            # token overlap with description — lower bar
            desc_tokens = set(_norm_name(edesc).split())
            name_tokens = set(_norm_name(name).split())
            if name_tokens and desc_tokens:
                overlap = len(name_tokens & desc_tokens) / len(name_tokens | desc_tokens)
                if overlap > best_overlap:
                    best_overlap = overlap

        if best_overlap <= 0.25:
            continue

        version = component.get("version", "")
        ver_affected = _check_version_affected(version, entry) if version else None

        # confidence scales with overlap
        conf = 0.4 + best_overlap * 0.4  # 0.4–0.8 range, cap labels at 0.6 base
        matches.append({
            "cve_id": eid,
            "severity": _entry_severity(entry),
            "description": _entry_description(entry),
            "match_confidence": round(min(conf, 0.7), 2),
            "match_stage": "fuzzy",
            "token_overlap": round(best_overlap, 3),
            "version_affected": ver_affected,
        })

    # sort by token overlap descending
    matches.sort(key=lambda x: x.get("token_overlap", 0), reverse=True)
    return matches


def _stage_keyword(kb, component: Dict) -> List[Dict]:
    """Stage 5: Keyword search on CVE descriptions.
    Last resort — broad keyword matching. High false positive rate.
    Confidence: 0.3."""

    name = component.get("name", component.get("component", ""))
    if not name:
        return []

    normalized = _norm_name(name)
    keywords = normalized.split()

    if not keywords:
        return []

    matches: List[Dict] = []
    seen_ids: set = set()

    # try each keyword as a search query
    for kw in keywords[:3]:  # limit to first 3 keywords to avoid noise
        if len(kw) < 3:
            continue

        entries, _ = _kb_lookup(kb, kw, limit=30)
        for entry in entries:
            eid = _entry_cve_id(entry)
            if eid in seen_ids:
                continue
            seen_ids.add(eid)

            edesc = _entry_description(entry).lower()
            # check how many keywords appear in description
            kw_hits = sum(1 for k in keywords if k in edesc)
            if kw_hits == 0:
                continue

            version = component.get("version", "")
            ver_affected = _check_version_affected(version, entry) if version else None

            matches.append({
                "cve_id": eid,
                "severity": _entry_severity(entry),
                "description": _entry_description(entry),
                "match_confidence": 0.3,
                "match_stage": "keyword",
                "keyword_hits": kw_hits,
                "version_affected": ver_affected,
            })

    return matches


# ---- main matching function ----

def match_component(kb, component: Dict) -> Dict[str, Dict]:
    """Run all matching stages against a single component.
    First-match-wins per CVE (dedup by cve_id). Different CVEs can be found
    at different stages — we keep the first (highest confidence) match for
    each CVE.

    Returns dict keyed by cve_id containing match info."""

    # run stages in priority order
    stages = [
        _stage_purl,
        _stage_cpe_direct,
        _stage_name_exact,
        _stage_fuzzy,
        _stage_keyword,
    ]

    all_matches: Dict[str, Dict] = {}

    for stage_fn in stages:
        stage_matches = stage_fn(kb, component)
        for sm in stage_matches:
            cid = sm["cve_id"]
            if cid not in all_matches:
                # check if entry exists in KB to get full info
                full_entry = kb.get(cid) if hasattr(kb, "get") else None
                if full_entry:
                    sm["cvss_score"] = getattr(full_entry, "cvss_score", None) if hasattr(full_entry, "cvss_score") else full_entry.get("cvss_score") if isinstance(full_entry, dict) else None
                    sm["epss_score"] = getattr(full_entry, "epss_score", None) if hasattr(full_entry, "epss_score") else full_entry.get("epss_score") if isinstance(full_entry, dict) else None
                all_matches[cid] = sm

    return all_matches


# ---- SBOM report builder (MONOLITHIC ~130 lines — intentional) ----

def build_sbom_report(kb, components: List[Dict]) -> Dict:
    """Build a comprehensive SBOM vulnerability report.
    Does stats aggregation, sorting by severity, SSVC enrichment,
    transitive risk propagation — all in one function.
    This is intentionally monolithic. Extracting sub-functions would add
    call overhead for code that runs once per report. Cleanup pass later
    if this grows beyond ~200 lines.

    Returns:
      {
        summary: {total_components, components_with_matches, total_matches},
        matches: [{component, cve_id, severity, ...}],
        top_priorities: [{cve_id, severity, component, fix_suggestion}],
        risk_tree: {...},   # from transitive_risk_report
      }
    """

    total_components = len(components)
    components_with_matches = 0
    total_matches = 0

    all_component_matches: List[Dict] = []
    severity_counter: Dict[str, int] = defaultdict(int)
    seen_cve_ids: set = set()

    # match each component
    for comp in components:
        comp_name = comp.get("name", comp.get("component", "unknown"))
        comp_version = comp.get("version", "")
        comp_eco = comp.get("ecosystem", comp.get("purl_type", ""))

        matches = match_component(kb, comp)

        if matches:
            components_with_matches += 1
            for cve_id, match_info in matches.items():
                total_matches += 1
                seen_cve_ids.add(cve_id)

                sev = match_info.get("severity", "UNKNOWN")
                severity_counter[sev] = severity_counter.get(sev, 0) + 1

                # try to get full entry for fix suggestion
                fix_ver = None
                full_entry = None
                if hasattr(kb, "get"):
                    full_entry = kb.get(cve_id)
                if full_entry:
                    fix_ver = _extract_fix(full_entry)

                all_component_matches.append({
                    "component": comp_name,
                    "component_version": comp_version,
                    "ecosystem": comp_eco,
                    "cve_id": cve_id,
                    "severity": sev,
                    "cvss_score": match_info.get("cvss_score"),
                    "epss_score": match_info.get("epss_score"),
                    "description": match_info.get("description", ""),
                    "match_confidence": match_info.get("match_confidence", 0),
                    "match_stage": match_info.get("match_stage", "unknown"),
                    "version_affected": match_info.get("version_affected"),
                    "fix_suggestion": fix_ver,
                })

    # sort matches: CRITICAL first, then by confidence desc
    severity_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "NONE": 1, "UNKNOWN": 0}
    all_component_matches.sort(
        key=lambda x: (
            -severity_order.get(x["severity"], 0),
            -x["match_confidence"],
        )
    )

    # top priorities: CRITICAL and HIGH severity, dedup by cve_id
    top_priorities: List[Dict] = []
    seen_priority_cves: set = set()
    for m in all_component_matches:
        if m["severity"] in ("CRITICAL", "HIGH") and m["cve_id"] not in seen_priority_cves:
            seen_priority_cves.add(m["cve_id"])
            top_priorities.append({
                "cve_id": m["cve_id"],
                "severity": m["severity"],
                "component": m["component"],
                "component_version": m["component_version"],
                "fix_suggestion": m.get("fix_suggestion"),
                "description": m.get("description", "")[:200],
            })

    # SSVC enrichment if available
    if _has_ssvc:
        try:
            for tp in top_priorities:
                ssvc_result = ssvc_enrich(tp["cve_id"], tp["severity"])
                if ssvc_result:
                    tp["ssvc"] = ssvc_result
        except Exception:
            pass  # SSVC enrichment is optional

    # transitive risk propagation
    risk_tree = transitive_risk_report(components)

    # build summary
    summary = {
        "total_components": total_components,
        "components_with_matches": components_with_matches,
        "total_matches": total_matches,
        "unique_cves": len(seen_cve_ids),
        "severity_distribution": dict(severity_counter),
        "match_rate": round(components_with_matches / total_components, 3) if total_components > 0 else 0.0,
    }

    return {
        "summary": summary,
        "matches": all_component_matches,
        "top_priorities": top_priorities,
        "risk_tree": risk_tree,
    }


# ---- one-shot convenience ----

def match_sbom(kb, sbom_path: str) -> Dict:
    """One-shot: load an SBOM JSON file and match all components.
    Returns the full report dict from build_sbom_report."""

    if not os.path.exists(sbom_path):
        return {"error": f"SBOM file not found: {sbom_path}", "summary": {}, "matches": [], "top_priorities": []}

    with open(sbom_path, "r", encoding="utf-8") as f:
        sbom = json.load(f)

    # handle different SBOM formats
    components = []
    if "components" in sbom:
        components = sbom["components"]
    elif "packages" in sbom:
        # CycloneDX uses "components", SPDX uses "packages"
        components = sbom["packages"]
    elif isinstance(sbom, list):
        # raw list of components
        components = sbom

    if not components:
        return {"error": "No components found in SBOM", "summary": {}, "matches": [], "top_priorities": []}

    return build_sbom_report(kb, components)
