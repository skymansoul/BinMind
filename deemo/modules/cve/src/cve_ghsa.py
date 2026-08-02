# 2026-08-01 ~ 2026-08-25
# GitHub Security Advisory (GHSA) integration.
# GHSA entries complement NVD data — some advisories appear on GitHub days or
# weeks before the NVD publishes them. The merge logic picks the best description
# (longest non-empty) and combines references from both sources.
#
# The source_confidence field was originally AFTER the return statement in
# merge_entries() — classic error from editing near the end of a function.
# Moved it before return.
#
# Aug 24-25: finally implemented pagination via Link header parsing. the
# GitHub API returns at most 100 per page and we were silently truncating.
# also added description-based dedup for GHSA entries that don't have CVE IDs
# (GHSA-only advisories like GHSA-xxxx-xxxx-xxxx). these can now be fuzzy-matched
# against NVD entries by description overlap, not just CVE ID equality.

import json
import re
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple

from .cve_models import CVEEntry

# GHSA API base
_GHSA_API_BASE = "https://api.github.com/advisories"

# optional env var for github token (higher rate limit)
_GHSA_TOKEN = None
try:
    import os
    _GHSA_TOKEN = os.environ.get("GITHUB_TOKEN") or os.environ.get("GHSA_TOKEN")
except Exception:
    pass

# max pages to fetch — safety cap, real queries rarely go beyond page 20
_MAX_PAGES = 50

# delay between pages for rate limiting
# 60 req/hr unauthenticated → 1 req/min. with token: 5000/hr → 0.72s delay
_PAGE_DELAY = 1.0 if _GHSA_TOKEN is None else 0.8


# ---- GHSA-specific severity mapping ----
# GitHub uses their own levels — map to our Severity enum
_GHSA_SEVERITY_MAP = {
    "LOW": "LOW",
    "MODERATE": "MEDIUM",
    "HIGH": "HIGH",
    "CRITICAL": "CRITICAL",
    "NONE": "NONE",
}


@dataclass
class GHSAEntry:
    """GitHub Security Advisory entry — similar to CVEEntry but GHSA-specific fields."""
    ghsa_id: str
    cve_id: Optional[str] = None
    summary: str = ""
    description: str = ""
    severity: str = "UNKNOWN"
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    identifiers: List[Dict[str, str]] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    permalink: str = ""
    published_at: Optional[str] = None
    updated_at: Optional[str] = None
    withdrawn_at: Optional[str] = None
    vulnerabilities: List[Dict] = field(default_factory=list)
    ecosystem: str = ""
    package_name: str = ""
    source: str = "ghsa"
    source_confidence: float = 0.8  # GHSA is usually high quality but not authoritative

    @classmethod
    def from_ghsa_json(cls, data: Dict) -> "GHSAEntry":
        """Parse a GHSA API response dict into a GHSAEntry."""
        ghsa_id = data.get("ghsa_id", "")
        cve_id = data.get("cve_id") or None

        # GitHub advisory has both summary and description
        summary = data.get("summary", "") or ""
        description = data.get("description", "") or ""

        severity = _GHSA_SEVERITY_MAP.get(
            (data.get("severity") or "").upper(), "UNKNOWN"
        )

        cvss_score = None
        cvss_vector = None
        if data.get("cvss"):
            cvss_data = data["cvss"]
            cvss_score = cvss_data.get("score")
            cvss_vector = cvss_data.get("vector_string")

        identifiers = data.get("identifiers", [])

        references = []
        for ref in data.get("references", []):
            url = ref.get("url", "")
            if url:
                references.append(url)

        permalink = data.get("html_url", data.get("permalink", ""))
        published_at = data.get("published_at")
        updated_at = data.get("updated_at")
        withdrawn_at = data.get("withdrawn_at")

        vulnerabilities = data.get("vulnerabilities", [])

        # extract ecosystem/package from first vulnerability
        ecosystem = ""
        package_name = ""
        if vulnerabilities:
            vuln = vulnerabilities[0]
            pkg = vuln.get("package", {})
            ecosystem = pkg.get("ecosystem", "")
            package_name = pkg.get("name", "")

        return cls(
            ghsa_id=ghsa_id,
            cve_id=cve_id,
            summary=summary,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            identifiers=identifiers,
            references=references,
            permalink=permalink,
            published_at=published_at,
            updated_at=updated_at,
            withdrawn_at=withdrawn_at,
            vulnerabilities=vulnerabilities,
            ecosystem=ecosystem,
            package_name=package_name,
        )

    def to_cve_entry(self) -> Optional[CVEEntry]:
        """Convert to CVEEntry format. Returns None if no CVE ID."""
        if not self.cve_id:
            return None

        # prefer description over summary (description is usually more detailed)
        desc = self.description if self.description else self.summary

        return CVEEntry(
            cve_id=self.cve_id,
            description=desc,
            severity=self.severity,
            cvss_score=self.cvss_score,
            cvss_vector=self.cvss_vector,
            references=self.references,
            published_date=self.published_at,
            last_modified_date=self.updated_at,
            source="ghsa",
            source_confidence=self.source_confidence,
        )


# ---- internal: parse github link header (rfc 5988) ----
# github returns: <url>; rel="next", <url>; rel="last"
# we need to extract the "next" url to walk pages
_LINK_RE = re.compile(r'<([^>]+)>\s*;\s*rel="([^"]+)"')


def _parse_next_link(link_header: str) -> Optional[str]:
    """Extract 'next' URL from a GitHub Link header. Returns None if no next page."""
    if not link_header:
        return None
    parts = link_header.split(",")
    for part in parts:
        m = _LINK_RE.search(part.strip())
        if m and m.group(2) == "next":
            return m.group(1)
    return None


def _ghsa_request(url: str) -> Tuple[List[Dict], Optional[str]]:
    """Make a single GHSA API request. Returns (items_list, next_url_or_None).
    Uses GitHub token if available (higher rate limit)."""
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "BinMind-CVE/1.0",
    }
    if _GHSA_TOKEN:
        headers["Authorization"] = f"Bearer {_GHSA_TOKEN}"

    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        link_header = resp.headers.get("Link", "")
        next_url = _parse_next_link(link_header)

    items = data if isinstance(data, list) else []
    return items, next_url


# ---- search ----
def search_ghsa(
    query: str,
    ecosystem: Optional[str] = None,
    limit: int = 100,
    max_pages: int = _MAX_PAGES,
) -> List[GHSAEntry]:
    """Search the GitHub Advisory Database with full pagination.
    Walks Link headers to fetch all pages up to limit or max_pages.
    Respects rate limits with a delay between page requests.

    max_pages caps the number of pages to fetch — safety valve.
    limit is the total number of results desired (not per-page)."""
    params_parts = [f"type=reviewed"]

    if query:
        params_parts.append(f"q={urllib.request.quote(query)}")

    if ecosystem:
        params_parts.append(f"ecosystem={urllib.request.quote(ecosystem)}")

    # per_page is always 100 (api max), use limit to control total
    params_parts.append("per_page=100")

    base_url = f"{_GHSA_API_BASE}?{'&'.join(params_parts)}"
    results: List[GHSAEntry] = []
    current_url: Optional[str] = base_url
    pages_fetched = 0

    while current_url is not None and pages_fetched < max_pages:
        if pages_fetched > 0:
            time.sleep(_PAGE_DELAY)

        try:
            items, next_url = _ghsa_request(current_url)
        except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as e:
            print(f"[GHSA] request failed at page {pages_fetched + 1}: {e}")
            break

        for item in items:
            try:
                results.append(GHSAEntry.from_ghsa_json(item))
            except Exception:
                pass

        pages_fetched += 1
        current_url = next_url

        # stop if we have enough results
        if len(results) >= limit:
            break

    return results[:limit]


# ---- search_advisories: search + optional nvd dedup ----
# this is the main entry point for "find all advisories for ecosystem X
# and merge them with what we already have in the KB"

def search_and_dedup(
    kb,
    query: str,
    ecosystem: Optional[str] = None,
    limit: int = 200,
) -> Dict[str, Any]:
    """Search GHSA, then dedup against KB using CVE ID + description overlap.
    Returns:
      {merged: [...], ghsa_only: [...], nvd_only: [...], stats: {...}}

    GHSA entries that have a CVE ID are matched 1:1 with KB entries.
    GHSA entries WITHOUT a CVE ID are fuzzy-matched by description overlap
    (>0.6 Jaccard on normalized tokens). Unmatched GHSA-only entries go
    into ghsa_only for manual review.
    """
    ghsa_entries = search_ghsa(query, ecosystem=ecosystem, limit=limit)

    # get all KB entries matching the same query
    kb_entries, _ = kb.search(query=query, limit=limit) if hasattr(kb, 'search') else ([], 0)

    merged: List[Dict] = []
    ghsa_only: List[Dict] = []
    matched_kb_ids: set = set()

    # pass 1: match by CVE ID
    kb_by_cve: Dict[str, Any] = {}
    for e in kb_entries:
        cid = e.cve_id if hasattr(e, 'cve_id') else e.get('cve_id', '')
        if cid:
            kb_by_cve[cid] = e

    for ghsa in ghsa_entries:
        if ghsa.cve_id and ghsa.cve_id in kb_by_cve:
            nvd_entry = kb_by_cve[ghsa.cve_id]
            merged_entry = merge_entries(ghsa, nvd_entry)
            merged.append(merged_entry.to_dict())
            matched_kb_ids.add(ghsa.cve_id)
        else:
            ghsa_only.append({
                "ghsa_id": ghsa.ghsa_id,
                "cve_id": ghsa.cve_id,
                "summary": ghsa.summary,
                "description": (ghsa.description or ghsa.summary)[:300],
                "severity": ghsa.severity,
                "ecosystem": ghsa.ecosystem,
                "package": ghsa.package_name,
                "has_cve": ghsa.cve_id is not None,
                "permalink": ghsa.permalink,
            })

    # pass 2: for GHSA-only entries (no CVE ID), try description overlap
    # against unmatched KB entries. threshold tuned empirically.
    still_unmatched: List[Dict] = []
    for gonly in ghsa_only:
        if gonly["has_cve"]:
            still_unmatched.append(gonly)
            continue

        ghsa_desc = gonly["description"]
        best_score = 0.0
        best_kb_entry = None

        for kb_entry in kb_entries:
            cid = kb_entry.cve_id if hasattr(kb_entry, 'cve_id') else kb_entry.get('cve_id', '')
            if cid in matched_kb_ids:
                continue
            kb_desc = kb_entry.description if hasattr(kb_entry, 'description') else kb_entry.get('description', '')
            if not kb_desc:
                continue
            score = _desc_overlap(ghsa_desc, kb_desc)
            if score > best_score and score > 0.6:
                best_score = score
                best_kb_entry = kb_entry

        if best_kb_entry is not None:
            cid = best_kb_entry.cve_id if hasattr(best_kb_entry, 'cve_id') else best_kb_entry.get('cve_id', '')
            gonly["matched_cve"] = cid
            gonly["match_confidence"] = round(best_score, 3)
            matched_kb_ids.add(cid)
            still_unmatched.append(gonly)
        else:
            still_unmatched.append(gonly)

    # unmatched NVD entries
    nvd_only = [
        e.cve_id if hasattr(e, 'cve_id') else e.get('cve_id', '')
        for e in kb_entries
        if (e.cve_id if hasattr(e, 'cve_id') else e.get('cve_id', '')) not in matched_kb_ids
    ]

    return {
        "merged": merged,
        "ghsa_only": still_unmatched,
        "nvd_only": nvd_only,
        "stats": {
            "total_ghsa": len(ghsa_entries),
            "total_kb": len(kb_entries),
            "merged_count": len(merged),
            "ghsa_only_count": len(still_unmatched),
            "nvd_only_count": len(nvd_only),
        },
    }


# ---- description similarity for cross-source dedup ----
# simple token overlap — not as fancy as the sbom matcher's _norm_name
# but it doesn't need to be. we're comparing vulnerability descriptions,
# not package names.

def _desc_overlap(desc1: str, desc2: str) -> float:
    """Jaccard similarity on word tokens from two descriptions.
    Both are lowercased, split on non-alphanumeric, min 3 chars per token.
    Returns 0.0–1.0."""
    if not desc1 or not desc2:
        return 0.0

    def tokens(s: str) -> set:
        words = re.split(r'[^a-z0-9]+', s.lower())
        return {w for w in words if len(w) >= 3}

    t1 = tokens(desc1)
    t2 = tokens(desc2)
    if not t1 or not t2:
        return 0.0
    return len(t1 & t2) / len(t1 | t2)


# expose the raw paginated search under a different name
# so existing callers of search_ghsa aren't affected
fetch_ghsa_paginated = search_ghsa


# ---- merge logic ----
def merge_entries(ghsa_entry: GHSAEntry, nvd_entry: CVEEntry) -> CVEEntry:
    """Merge GHSA and NVD data into a single CVEEntry.
    Picks best description (longest non-empty), combines references.
    source_confidence is set BEFORE the return — was originally unreachable
    code after return, fixed by moving it up."""
    # pick best description
    # GHSA descriptions are often more detailed (with impact analysis)
    # but NVD descriptions are more standardized
    nvd_desc = nvd_entry.description or ""
    ghsa_desc = ghsa_entry.description or ghsa_entry.summary or ""

    if len(ghsa_desc) > len(nvd_desc):
        description = ghsa_desc
        desc_source = "ghsa"
    else:
        description = nvd_desc
        desc_source = "nvd"

    # combine references (dedup)
    refs = list(set(nvd_entry.references + ghsa_entry.references))

    # pick best CVSS — prefer NVD (more authoritative) unless missing
    score = nvd_entry.cvss_score or ghsa_entry.cvss_score
    vector = nvd_entry.cvss_vector or ghsa_entry.cvss_vector
    severity = nvd_entry.severity if nvd_entry.severity != "UNKNOWN" else ghsa_entry.severity

    # source_confidence: average of both sources, weighted toward NVD
    # was originally after return — unreachable. Fixed by moving here.
    source_confidence = (nvd_entry.source_confidence * 0.6 + ghsa_entry.source_confidence * 0.4)

    merged = CVEEntry(
        cve_id=nvd_entry.cve_id,
        description=description,
        severity=severity,
        cvss_score=score,
        cvss_vector=vector,
        exploitability_score=nvd_entry.exploitability_score,
        impact_score=nvd_entry.impact_score,
        products=nvd_entry.products,
        vendors=nvd_entry.vendors,
        cpe_matches=nvd_entry.cpe_matches,
        cwes=nvd_entry.cwes,
        published_date=nvd_entry.published_date or ghsa_entry.published_at,
        last_modified_date=nvd_entry.last_modified_date or ghsa_entry.updated_at,
        references=refs,
        epss_score=nvd_entry.epss_score,
        epss_percentile=nvd_entry.epss_percentile,
        source="nvd+ghsa",
        source_confidence=source_confidence,
    )
    return merged


def cross_source_coverage(
    nvd_entries: List[CVEEntry],
    ghsa_entries: List[GHSAEntry],
) -> Dict[str, Any]:
    """Quantify how much value GHSA adds on top of NVD alone.
    Returns {only_nvd, only_ghsa, both, coverage_pct}."""
    nvd_ids = {e.cve_id for e in nvd_entries}
    # GHSA entries may not have CVE IDs (some are GHSA-only)
    ghsa_cve_ids = {e.cve_id for e in ghsa_entries if e.cve_id}

    only_nvd = list(nvd_ids - ghsa_cve_ids)
    only_ghsa = list(ghsa_cve_ids - nvd_ids)
    both = list(nvd_ids & ghsa_cve_ids)

    total = len(nvd_ids | ghsa_cve_ids)
    coverage_pct = len(both) / total * 100 if total > 0 else 0.0

    return {
        "only_nvd": only_nvd,
        "only_ghsa": only_ghsa,
        "both": both,
        "total_unique": total,
        "coverage_pct": round(coverage_pct, 2),
    }


def merge_with_confidence(entries_list: List[CVEEntry]) -> List[CVEEntry]:
    """Annotate field provenance for debugging cross-source discrepancies.
    Each entry's source_confidence is set based on which fields were populated.
    This is useful when debugging why a merged entry picked one source's data
    over another's."""
    for entry in entries_list:
        # start with base confidence
        confidence = entry.source_confidence

        # if entry has NVD-quality metadata, boost confidence
        if entry.cvss_vector and entry.cvss_score is not None:
            confidence = max(confidence, 0.9)
        if entry.cwes:
            confidence = max(confidence, 0.85)
        if not entry.description:
            confidence = 0.3  # no description = low quality

        entry.source_confidence = min(confidence, 1.0)

    return entries_list
