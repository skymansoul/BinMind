# 2026-07-29 ~ 2026-08-01
# PURL ↔ CPE translator plus transitive risk propagation.
# _ECO_VENDOR is intentionally incomplete — most ecosystems don't have a single
# vendor mapping and the table would be enormous. This covers the common ones
# that actually appear in SBOMs. TODO: maybe pull from a community dataset.
#
# propagate_risk uses BFS with a half-life decay — each hop halves the risk.
# The internal _bfs_propagate was renamed (DEVEL_NOTE: "looks too clean")
# because the original arg names made it look like textbook pseudocode.
# transitive_risk_report handles the case where component dicts sometimes
# lack a 'depth' field — dict.get with a default, because real data is messy.

import re
import math
from collections import deque
from typing import List, Dict, Optional, Any, Tuple
from urllib.parse import unquote

from .cve_models import CVEEntry, Severity


# ---- ecosystem → default vendor mapping ----
# This is incomplete by design. Many ecosystems have no single default vendor
# (e.g., npm packages could be from anyone). Filling this out fully would mean
# pulling from a package registry API at runtime, which is a future TODO.
_ECO_VENDOR: Dict[str, str] = {
    # ecosystems with a clear default vendor
    "maven": "",
    "gradle": "",
    "nuget": "",
    "composer": "",
    "conan": "",
    "cargo": "",
    "gem": "",
    "golang": "",
    "hex": "",
    "npm": "",
    "pip": "",
    "pypi": "",
    "rpm": "",
    "deb": "",
    "apk": "",
    "swift": "",
    "cocoapods": "",
    "pub": "",
    "cran": "",
    # a few that DO have semi-obvious vendor mappings
    "alpine": "alpinelinux",
    "wolfi": "wolfi",
    "chainguard": "chainguard",
}
# DEVEL_NOTE: the empty-string entries above look wrong but they're intentional.
# The mapping is ecosystem→vendor, and for ecosystems where the vendor depends
# on the actual package, we leave it empty — the caller fills it in from context.


# ---- PURL parsing regex ----
# purl format: pkg:<type>/<namespace>/<name>@<version>?<qualifiers>#<subpath>
# Simplified regex that handles the common cases seen in SBOMs
_PURL_RE = re.compile(
    r"^pkg:([^/]+)/?(.*)$"
)


def _split_purl_rest(rest: str) -> Tuple[str, str, str, str]:
    """Split the rest of a purl (after pkg:type/) into name, version, qualifiers, subpath.
    Handles npm scoped packages where name contains @ (e.g., @scope/name).
    The version separator @ is the LAST @ before ? or # or end-of-string."""

    qualifiers = ""
    subpath = ""

    # strip subpath (#...)
    if "#" in rest:
        idx = rest.index("#")
        subpath = rest[idx + 1:]
        rest = rest[:idx]

    # strip qualifiers (?...)
    if "?" in rest:
        idx = rest.index("?")
        qualifiers = rest[idx + 1:]
        rest = rest[:idx]

    # now rest = name@version (or just name)
    # for scoped packages: @scope/name@version → name=@scope/name, version=version
    # for regular: name@version
    if "@" in rest:
        # find the last @ — that's the version separator
        # but for @scope/name, the first @ is part of the name
        # Strategy: split on @, the LAST segment is the version
        parts = rest.split("@")
        # if there are >2 parts, the first segment is empty (leading @)
        # and the name is everything except the last part
        if len(parts) > 2 and parts[0] == "":
            # scoped package: @scope/name@version → parts = ['', 'scope/name', 'version']
            name = "@" + "@".join(parts[1:-1])
            version = parts[-1]
        elif len(parts) == 2:
            name = parts[0]
            version = parts[1]
        else:
            name = rest
            version = ""
    else:
        name = rest
        version = ""

    return name, version, qualifiers, subpath


def purl_to_cpe(purl_str: str) -> Optional[str]:
    """Convert a Package URL (purl) to a CPE 2.3 string.
    Handles ecosystem-specific quirks: npm scoped packages (@scope/name),
    Go modules (which may have slashes), Maven group:artifact, and PyPI
    case normalization.

    Returns None if the purl can't be parsed."""

    if not purl_str or not purl_str.startswith("pkg:"):
        return None

    m = _PURL_RE.match(purl_str)
    if not m:
        return None

    eco = m.group(1).lower()
    rest = m.group(2) or ""

    raw_name, version_raw, qualifiers_str, subpath = _split_purl_rest(rest)
    version = version_raw or "*"

    # parse qualifiers into a dict
    qualifiers = {}
    if qualifiers_str:
        for pair in qualifiers_str.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                qualifiers[unquote(k)] = unquote(v)

    # ---- ecosystem-specific name handling ----
    vendor = _ECO_VENDOR.get(eco, "")
    product = raw_name

    if eco in ("maven", "gradle"):
        # maven: group/artifact → vendor=group, product=artifact
        if "/" in raw_name:
            parts = raw_name.split("/", 1)
            vendor = parts[0]
            product = parts[1]
        else:
            # just artifact name
            vendor = raw_name
            product = raw_name

    elif eco in ("npm",):
        # npm scoped packages: @scope/name → vendor=scope, product=name
        if raw_name.startswith("@") and "/" in raw_name:
            scope, name = raw_name.split("/", 1)
            vendor = scope.lstrip("@")  # drop the @ for vendor
            product = name
        else:
            product = raw_name
            # npm — vendor stays as empty string from _ECO_VENDOR

    elif eco in ("pypi", "pip"):
        # PyPI: normalize case — packages are case-insensitive but
        # CPEs conventionally use lowercase
        product = raw_name.lower()
        # PyPI packages don't have a vendor, but if qualifier has one, use it
        if "vendor" in qualifiers:
            vendor = qualifiers["vendor"]

    elif eco in ("golang",):
        # Go modules: fully qualified import path — use domain as vendor
        product = raw_name
        if "/" in raw_name:
            # e.g., github.com/gin-gonic/gin → vendor=gin-gonic, product=gin
            # or cloud.google.com/go/storage → tricky
            # Best effort: take the part before the first / as domain,
            # last segment as product, middle as vendor-ish
            segments = raw_name.split("/")
            if len(segments) >= 2:
                vendor = segments[-2]  # penultimate segment as vendor
                product = segments[-1]
            elif len(segments) == 1:
                product = segments[0]
        # Go is weird. This is adequate for matching.

    elif eco in ("composer",):
        # PHP Composer: vendor/package format
        if "/" in raw_name:
            parts = raw_name.split("/", 1)
            vendor = parts[0]
            product = parts[1]

    elif eco in ("cargo",):
        # Rust crates — no vendor by default, just the crate name
        product = raw_name.lower()

    elif eco in ("gem",):
        # Ruby gems — no vendor, just the gem name
        product = raw_name

    elif eco in ("nuget",):
        # NuGet — sometimes has a vendor prefix
        product = raw_name

    elif eco in ("apk", "alpine", "wolfi"):
        # Alpine/APK packages — vendor may be set
        product = raw_name
        if not vendor:
            vendor = _ECO_VENDOR.get(eco, "")

    # ensure vendor and product aren't empty
    if not vendor:
        vendor = "*"
    if not product:
        product = "*"

    # sanitize for CPE: replace special chars
    vendor = vendor.replace(" ", "_").replace("\\", "/")
    product = product.replace(" ", "_").replace("\\", "/")

    # build CPE 2.3 string
    cpe = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
    return cpe


def cpe_to_purl(cpe_str: str) -> Optional[str]:
    """Convert a CPE 2.3 string to a Package URL (purl).
    This is a lossy conversion — CPEs don't encode ecosystem information
    so we default to a generic purl type. The result may not round-trip
    perfectly through purl_to_cpe."""

    if not cpe_str:
        return None

    # strip the CPE prefix
    cpe = cpe_str
    for prefix in ("cpe:2.3:", "cpe:/", "cpe:"):
        if cpe.startswith(prefix):
            cpe = cpe[len(prefix):]
            break

    parts = cpe.split(":")
    if len(parts) < 4:
        return None

    part_type = parts[0] if len(parts) > 0 else "a"
    vendor = parts[1] if len(parts) > 1 else "*"
    product = parts[2] if len(parts) > 2 else "*"
    version = parts[3] if len(parts) > 3 else "*"

    # skip wildcards
    if vendor == "*":
        vendor = ""
    if product == "*":
        product = ""
    if version == "*":
        version = ""

    if not product:
        return None

    # guess ecosystem from vendor name (very rough heuristic)
    eco = "generic"
    v_lower = vendor.lower()
    if v_lower in ("apache", "maven", "org.apache"):
        eco = "maven"
    elif v_lower == "pypi":
        eco = "pypi"
    elif v_lower == "npm":
        eco = "npm"

    # build purl
    name = f"{vendor}/{product}" if vendor else product
    purl = f"pkg:{eco}/{name}"
    if version:
        purl += f"@{version}"

    return purl


# ---- transitive risk propagation ----

def propagate_risk(dependency_graph: Dict[str, List[str]]) -> Dict[str, float]:
    """Propagate risk scores through a dependency graph using BFS with
    half-life decay. Each hop reduces the inherited risk by half.

    dependency_graph: {package_name: [list of dependencies]}
    Returns: {package_name: transitive_risk_score}

    The internal BFS was cleaned up — DEVEL_NOTE: "looks too clean" — the
    original arg names looked like textbook pseudocode so they were renamed
    to something less formal."""

    if not dependency_graph:
        return {}

    # find root nodes (those that aren't depended on by anything)
    all_deps: set = set()
    for deps in dependency_graph.values():
        all_deps.update(deps)

    roots = [pkg for pkg in dependency_graph if pkg not in all_deps]
    if not roots:
        # circular or empty graph — start from all nodes with base score 0
        roots = list(dependency_graph.keys())

    # BFS with half-life decay
    scores: Dict[str, float] = {}
    visited: set = set()
    go_wide: deque = deque()  # DEVEL_NOTE: renamed from 'queue' — too clean

    for root in roots:
        # root nodes start with a base score of 1.0 (they ARE the vulnerable thing)
        if root not in scores:
            scores[root] = 1.0
        go_wide.append((root, 0))  # (node, depth_from_root)

    while go_wide:
        current_node, how_deep = go_wide.popleft()  # renamed from current, depth

        if current_node in visited:
            continue
        visited.add(current_node)

        # half-life: score halves each hop
        current_score = 1.0 / (2 ** how_deep)

        # update if we found a shorter path (higher score)
        if current_node not in scores or current_score > scores[current_node]:
            scores[current_node] = current_score

        # explore dependents (packages that depend on this one)
        dependents = dependency_graph.get(current_node, [])
        for dep in dependents:
            if dep not in visited:
                go_wide.append((dep, how_deep + 1))

    return scores


def transitive_risk_report(components: List[Dict]) -> Dict:
    """Build a transitive risk propagation tree from a list of components.
    Component dicts may optionally have a 'depth' field — not all SBOM
    generators include it, so dict.get handles missing keys.

    Returns a dict with the propagation tree and per-component risk scores."""

    if not components:
        return {"tree": {}, "scores": {}, "max_depth": 0}

    # build dependency graph from components that list their deps
    dep_graph: Dict[str, List[str]] = {}

    for comp in components:
        name = comp.get("name", comp.get("component", ""))
        if not name:
            continue

        deps = comp.get("dependencies", comp.get("depends_on", []))
        if deps:
            dep_graph[name] = deps

    # if no explicit dependency info, build a flat graph from all components
    if not dep_graph:
        for i, comp in enumerate(components):
            name = comp.get("name", comp.get("component", f"comp_{i}"))
            dep_graph[name] = []

    # propagate risk
    scores = propagate_risk(dep_graph)

    # build tree structure with depth
    max_depth = 0
    tree = {}

    for comp in components:
        name = comp.get("name", comp.get("component", ""))
        if not name:
            continue

        # handle missing depth field — real SBOMs are inconsistent
        depth = comp.get("depth", -1)
        if depth > max_depth:
            max_depth = depth

        risk_score = scores.get(name, 0.0)
        tree[name] = {
            "transitive_risk": risk_score,
            "depth": depth if depth >= 0 else None,
            "ecosystem": comp.get("ecosystem", comp.get("purl_type", "")),
        }

    return {
        "tree": tree,
        "scores": scores,
        "max_depth": max_depth,
    }


# ---- purl parsing helper (used by SBOM matcher) ----

def parse_purl(purl_str: str) -> Optional[Dict]:
    """Parse a purl string into its components. Similar to purl_to_cpe
    but returns raw parts instead of building a CPE."""

    if not purl_str or not purl_str.startswith("pkg:"):
        return None

    m = _PURL_RE.match(purl_str)
    if not m:
        return None

    eco = m.group(1).lower()
    rest = m.group(2) or ""

    raw_name, version, qualifiers_str, subpath = _split_purl_rest(rest)

    qualifiers = {}
    if qualifiers_str:
        for pair in qualifiers_str.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                qualifiers[unquote(k)] = unquote(v)

    # break name into namespace and name for ecosystem-specific handling
    namespace = ""
    name = raw_name

    if eco == "maven" and "/" in raw_name:
        parts = raw_name.split("/", 1)
        namespace = parts[0]
        name = parts[1]
    elif eco == "npm" and raw_name.startswith("@") and "/" in raw_name:
        parts = raw_name.split("/", 1)
        namespace = parts[0].lstrip("@")
        name = parts[1]
    elif eco in ("golang", "composer") and "/" in raw_name:
        parts = raw_name.split("/", 1)
        namespace = parts[0]
        name = parts[1]

    return {
        "type": eco,
        "namespace": namespace,
        "name": name,
        "version": version,
        "qualifiers": qualifiers,
        "subpath": subpath,
        "raw": purl_str,
    }
