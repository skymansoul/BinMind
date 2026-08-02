# 2026-07-29
# CVE version matcher — does CPE parsing, version range checking, and KB search
# normalization. The _CPE_RE here has 11 capture groups; cve_models.CPEPart has 12.
# Both parse valid CPEs fine but differ in edge handling — unifying them would be
# a breaking change for either side so they stay separate.
#
# Prerelease ordering initially missed milestone/nightly/canary suffixes — caught
# by tests. Added them to the prerelease regex. Order is canonical semver-ish but
# the community hasn't settled on a single standard for these suffixes so this
# is our best-effort mapping.

import re
import json
from typing import List, Dict, Optional, Tuple, Any, Union

from .cve_models import CVEEntry, CPEPart, Severity


# ---- CPE parsing (11 groups, NOT the same as cve_models._CPE_FULL_RE) ----
# 11 groups: part:vendor:product:version:update:edition:lang:sw_edition:target_sw:target_hw:other
# but we drop the trailing wildcard group for simplicity — hence 11 vs 12
_CPE_RE = re.compile(
    r"cpe:2\.3:([aoh]):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*)"
)


def _parse_cpe(cpe_str: str) -> Optional[Dict[str, str]]:
    """Parse a CPE 2.3 string into a dict of components.
    Handles IndexError for malformed/short CPE strings — real-world NVD data
    sometimes has truncated CPEs that don't match the spec."""
    m = _CPE_RE.match(cpe_str)
    if m:
        parts = list(m.groups())
        # pad to 11 if somehow short (belt-and-suspenders)
        while len(parts) < 11:
            parts.append("*")
        return {
            "part": parts[0],
            "vendor": parts[1],
            "product": parts[2],
            "version": parts[3],
            "update": parts[4],
            "edition": parts[5],
            "language": parts[6],
            "sw_edition": parts[7],
            "target_sw": parts[8],
            "target_hw": parts[9],
            "other": parts[10],
        }

    # fallback: split by colon for non-conforming CPEs
    if cpe_str.startswith("cpe:2.3:"):
        raw = cpe_str[len("cpe:2.3:"):]
    elif cpe_str.startswith("cpe:/"):
        raw = cpe_str[len("cpe:/"):]
    elif cpe_str.startswith("cpe:"):
        raw = cpe_str[len("cpe:"):]
    else:
        raw = cpe_str

    parts = raw.split(":")
    if len(parts) < 2:
        return None

    keys = [
        "part", "vendor", "product", "version", "update", "edition",
        "language", "sw_edition", "target_sw", "target_hw", "other",
    ]
    result = {}
    for i, k in enumerate(keys):
        try:
            result[k] = parts[i] if parts[i] else "*"
        except IndexError:
            result[k] = "*"

    return result


# ---- version comparison ----
# prerelease suffix ordering: alpha < beta < milestone < nightly < canary < rc < release
# milestone/nightly/canary were added after initial implementation (caught by tests)
_PRERELEASE_ORDER = {
    "alpha": 1,
    "alpine": 1,   # alias, seen in some ecosystems
    "beta": 2,
    "milestone": 3,
    "nightly": 4,
    "canary": 5,
    "rc": 6,
    "cr": 6,       # candidate release, same as rc
    "pre": 6,      # generic prerelease
    "preview": 6,
    "snapshot": 3, # snapshot ≈ milestone
}

# Regex that captures: (numeric_parts, separator, prerelease_tag, prerelease_num)
# Expanded to include milestone/nightly/canary — initial version only had alpha/beta/rc
_VERSION_RE = re.compile(
    r"^(\d+(?:\.\d+)*)"
    r"(?:[.\-_]?)"
    r"(alpha|beta|milestone|nightly|canary|rc|cr|pre|preview|snapshot|m|b|a)"
    r"\.?(\d*)$",
    re.IGNORECASE,
)

# Simple numeric-only version for quick comparison
_SIMPLE_VERSION_RE = re.compile(r"^(\d+(?:\.\d+)*)$")


def _compare_versions(v1: str, v2: str) -> int:
    """Compare two version strings. Returns -1, 0, or 1 (like cmp).
    Handles x.y.z numeric comparisons and basic prerelease ordering.
    This is deliberately simple — edge cases in real version schemes (calver,
    semver with build metadata) are handled by callers or fall through to
    string comparison."""

    # if they're equal strings, skip the work
    if v1 == v2:
        return 0

    def _parse(v: str) -> Tuple[List[int], Optional[str], Optional[int]]:
        """Parse a version string into (numbers, prerelease_tag, prerelease_num)."""
        # try full prerelease match
        m = _VERSION_RE.match(v.strip())
        if m:
            nums = [int(x) for x in m.group(1).split(".")]
            tag = m.group(2).lower() if m.group(2) else None
            num = int(m.group(3)) if m.group(3) else 0
            return nums, tag, num

        # try simple numeric
        m = _SIMPLE_VERSION_RE.match(v.strip())
        if m:
            nums = [int(x) for x in m.group(1).split(".")]
            return nums, None, 0

        # fallback: try to extract leading numbers
        nums = []
        for part in v.strip().split("."):
            try:
                nums.append(int(part))
            except ValueError:
                break
        return nums if nums else [0], None, 0

    nums1, tag1, pre_num1 = _parse(v1)
    nums2, tag2, pre_num2 = _parse(v2)

    # compare numeric parts
    max_len = max(len(nums1), len(nums2))
    n1 = nums1 + [0] * (max_len - len(nums1))
    n2 = nums2 + [0] * (max_len - len(nums2))

    for a, b in zip(n1, n2):
        if a < b:
            return -1
        if a > b:
            return 1

    # numeric parts equal — compare prerelease
    # release version (no tag) > any prerelease
    if tag1 is None and tag2 is None:
        return 0
    if tag1 is None:
        return 1   # v1 is release, v2 is prerelease → v1 > v2
    if tag2 is None:
        return -1  # v1 is prerelease, v2 is release → v1 < v2

    # both prerelease — compare by order
    order1 = _PRERELEASE_ORDER.get(tag1, 0)
    order2 = _PRERELEASE_ORDER.get(tag2, 0)

    if order1 < order2:
        return -1
    if order1 > order2:
        return 1

    # same prerelease tag — compare number
    if pre_num1 < pre_num2:
        return -1
    if pre_num1 > pre_num2:
        return 1

    return 0


# ---- npm-style semver range matching ----
# ^1.2.3 → >=1.2.3 <2.0.0, ~1.2.3 → >=1.2.3 <1.3.0, etc.
# npm ranges are de facto standard across many ecosystems now (npm, yarn, pnpm)
# so implementing them is worth the lines. NOT a full semver range parser —
# that would be a whole module. This handles the 80% case: ^x.y.z and ~x.y.z.

# parse a single comparator like ">=1.2.3" or "<2.0.0"
_COMPARATOR_RE = re.compile(r"([><=!]=?)\s*(\S+)")


def _parse_npm_range(range_str: str) -> List[Tuple[str, str]]:
    """Parse an npm-style semver range into a list of (op, version) tuples.
    op is one of '>=', '<=', '>', '<', '=', '!='.
    Returns empty list if parsing fails."""
    if not range_str or range_str.strip() == "" or range_str.strip() == "*":
        return []  # * means any version → no constraint

    s = range_str.strip()

    # whitespace-delimited comparators: ">=1.0.0 <2.0.0"
    # also handles comma: ">=1.0.0, <2.0.0"
    s = s.replace(",", " ")

    results: List[Tuple[str, str]] = []
    for part in s.split():
        # handle ^ and ~ prefixes
        op = "="
        ver = part
        if part.startswith("^"):
            op = "^"
            ver = part[1:]
        elif part.startswith("~"):
            op = "~"
            ver = part[1:]
        elif part.startswith(">="):
            op = ">="
            ver = part[2:]
        elif part.startswith("<="):
            op = "<="
            ver = part[2:]
        elif part.startswith("!="):
            op = "!="
            ver = part[2:]
        elif part.startswith(">"):
            op = ">"
            ver = part[1:]
        elif part.startswith("<"):
            op = "<"
            ver = part[1:]
        elif part.startswith("="):
            op = "="
            ver = part[1:]

        if ver:
            results.append((op, ver))

    return results


def satisfies_npm_range(version: str, range_str: str) -> bool:
    """Check if a version satisfies an npm-style semver range.
    Handles: ^x.y.z, ~x.y.z, >=x.y.z, <x.y.z, and combinations.

    Examples:
      satisfies_npm_range("1.2.3", "^1.0.0") → True
      satisfies_npm_range("2.0.0", "^1.0.0") → False
      satisfies_npm_range("1.2.9", "~1.2.3") → True
      satisfies_npm_range("1.3.0", "~1.2.3") → False
    """
    if not version or not range_str:
        return True  # no constraints → any version matches

    comparators = _parse_npm_range(range_str)
    if not comparators:
        return True  # no parsable constraints → matches

    for op, ver in comparators:
        cmp = _compare_versions(version, ver)
        if op == ">=" and cmp < 0:
            return False
        if op == "<=" and cmp > 0:
            return False
        if op == ">" and cmp <= 0:
            return False
        if op == "<" and cmp >= 0:
            return False
        if op == "=" and cmp != 0:
            return False
        if op == "!=" and cmp == 0:
            return False
        if op == "^":
            # ^x.y.z → >=x.y.z <(x+1).0.0 (for x>=1)
            # ^0.y.z → >=0.y.z <0.(y+1).0 (for x==0, y>=1)
            # ^0.0.z → =0.0.z (for x==0, y==0)
            nums = [int(n) for n in ver.split(".")]
            if len(nums) < 1:
                continue
            if nums[0] != 0:
                upper = [nums[0] + 1, 0, 0]
            elif len(nums) > 1 and nums[1] != 0:
                upper = [0, nums[1] + 1, 0]
            else:
                # ^0.0.z — exact match
                if cmp != 0:
                    return False
                continue
            upper_str = ".".join(str(n) for n in upper)
            if cmp < 0 or _compare_versions(version, upper_str) >= 0:
                return False
        if op == "~":
            # ~x.y.z → >=x.y.z <x.(y+1).0
            nums = [int(n) for n in ver.split(".")]
            if len(nums) < 2:
                continue
            upper = nums[:]
            upper[-2] += 1
            upper[-1] = 0
            upper_str = ".".join(str(n) for n in upper)
            if cmp < 0 or _compare_versions(version, upper_str) >= 0:
                return False

    return True


# ---- maven version comparison ----
# maven has its own version ordering: 1.0 < 1.0-rc1 < 1.0-beta < 1.0-SNAPSHOT
# Qualifier precedence: alpha < beta < milestone < rc < snapshot < sp < release
# This is DIFFERENT from semver prerelease ordering.
# We extend the existing _PRERELEASE_ORDER with maven-specific entries.

_MAVEN_QUALIFIER_WEIGHTS = {
    "alpha": 100, "a": 100,
    "beta": 200, "b": 200,
    "milestone": 300, "m": 300,
    "rc": 400, "cr": 400,
    "snapshot": 500,
    "": 600, "ga": 600, "final": 600, "release": 600,
    "sp": 700,  # service pack
}

# Maven version: [major.minor.incremental-qualifier-build]
# Maven version: [major.minor.incremental-qualifier-build]
# qualifier is immediately followed by optional build number (no separator)
# e.g. 1.0-rc1 → qualifier=rc, build=1
# the no-separator convention is maven's own — not a bug in the regex
_MAVEN_VERSION_RE = re.compile(
    r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?"
    r"(?:[.\-]("
    r"alpha|beta|milestone|rc|cr|snapshot|ga|final|release|sp"
    r"|a|b|m"
    r")(\d*))?"
    r"(?:[.\-](\d+))?$",
    re.IGNORECASE,
)


def compare_maven_versions(v1: str, v2: str) -> int:
    """Compare two Maven version strings. Returns -1, 0, or 1.
    Handles: 1.0 < 1.0-alpha < 1.0-beta < 1.0-rc1 < 1.0-SNAPSHOT < 1.0
    Maven treats missing qualifier as "release" (highest precedence).
    This is intentionally a separate function from _compare_versions
    because maven's ordering rules are ecosystem-specific."""
    if v1 == v2:
        return 0

    m1 = _MAVEN_VERSION_RE.match(v1.strip())
    m2 = _MAVEN_VERSION_RE.match(v2.strip())

    if not m1 and not m2:
        return _fallback_string_compare(v1, v2)
    if not m1:
        return -1
    if not m2:
        return 1

    # compare numeric triples
    nums1 = [
        int(m1.group(1) or 0),
        int(m1.group(2) or 0),
        int(m1.group(3) or 0),
    ]
    nums2 = [
        int(m2.group(1) or 0),
        int(m2.group(2) or 0),
        int(m2.group(3) or 0),
    ]

    for a, b in zip(nums1, nums2):
        if a < b:
            return -1
        if a > b:
            return 1

    # numeric equal — compare qualifiers by maven weights
    q1 = (m1.group(4) or "").lower()
    q2 = (m2.group(4) or "").lower()
    w1 = _MAVEN_QUALIFIER_WEIGHTS.get(q1, 600)
    w2 = _MAVEN_QUALIFIER_WEIGHTS.get(q2, 600)

    if w1 < w2:
        return -1
    if w1 > w2:
        return 1

    # same qualifier — compare build number
    # group 5 = build number immediately after qualifier (e.g. rc1 → 1)
    # group 6 = standalone build number after separator (e.g. -1)
    b1_q = m1.group(5)  # qualifier-inline build number
    b1_s = m1.group(6)  # standalone build number
    b1 = int(b1_q or b1_s or 0)
    b2_q = m2.group(5)
    b2_s = m2.group(6)
    b2 = int(b2_q or b2_s or 0)
    if b1 < b2:
        return -1
    if b1 > b2:
        return 1

    return 0


def _fallback_string_compare(v1: str, v2: str) -> int:
    """Fallback string comparison — last resort."""
    if v1 < v2:
        return -1
    if v1 > v2:
        return 1
    return 0


# ---- calver detection ----
# Calendar versioning: YYYY.MM.DD, YYYY.MM, YY.MM, etc.
# ubuntu uses YY.MM, some python libs use YYYY.M.D

_CALVER_PATTERNS = [
    # ubuntu style: 22.04, 24.10
    (re.compile(r"^(\d{2})\.(\d{1,2})(?:\.(\d+))?$"), "ubuntu"),
    # python calver: 2024.1.15, 2024.06
    (re.compile(r"^(\d{4})\.(\d{1,2})(?:\.(\d+))?$"), "python"),
    # windows build: 10.0.22621
    (re.compile(r"^(\d{1,3})\.0\.(\d+)$"), "windows"),
]


def detect_calver(version: str) -> Optional[str]:
    """Detect if a version string looks like calendar versioning.
    Returns the style name ('ubuntu', 'python', 'windows') or None.
    This is a heuristic — some version strings look like calver but aren't."""
    if not version:
        return None
    v = version.strip()
    for pattern, style in _CALVER_PATTERNS:
        if pattern.match(v):
            return style
    return None


def coerce_version(version: str, ecosystem: Optional[str] = None) -> str:
    """Normalize a version string for comparison.
    Strips leading 'v', lowercases, trims whitespace.
    Ecosystem-specific handling:
      - npm: strips 'v' prefix
      - pypi: handles '==1.0' style specifiers
      - maven: handles '1.0-RELEASE' → '1.0'
    Always returns a non-empty string — if version is empty, returns '0'.
    """
    if not version:
        return "0"

    v = version.strip()

    # strip leading 'v' or 'V' (common in git tags)
    if v.lower().startswith("v") and v[1:2].isdigit() if len(v) > 1 else False:
        v = v[1:]
    elif v.lower().startswith("v") and len(v) > 1 and v[1:2].isdigit():
        v = v[1:]

    # pypi specifiers: ==1.0, >=1.0, etc.
    if ecosystem and ecosystem.lower() in ("pypi", "pip", "python"):
        m = re.match(r"[><=!]=?\s*(\S+)", v)
        if m:
            v = m.group(1)

    # maven: strip -RELEASE, -FINAL, -GA suffix for comparison
    if ecosystem and ecosystem.lower() in ("maven", "gradle"):
        for suffix in ("-RELEASE", "-FINAL", "-GA", ".RELEASE", ".FINAL", ".GA"):
            if v.upper().endswith(suffix):
                v = v[: -len(suffix)]
                break

    # strip leading/trailing dots and dashes
    v = v.strip(".-")

    return v if v else "0"


# ---- public api — re-exports for external consumers ----
# these are thin wrappers that select the right comparison function
# based on hints from the caller. not elegant but practical.

def version_in_range(
    version: str,
    ranges: List[Dict],
    ecosystem: Optional[str] = None,
) -> bool:
    """Check if a version falls in any of the given affected ranges.
    Ecosystem-aware: uses maven comparison for maven ranges, semver for npm/pypi,
    generic comparison as fallback.

    This is the main entry point for SBOM version matching — replaces
    direct calls to _version_in_range with ecosystem context."""
    if not version or not ranges:
        return False

    # coerce version string
    cleaned = coerce_version(version, ecosystem)

    for r in ranges:
        if ecosystem and ecosystem.lower() in ("maven", "gradle"):
            if _check_maven_range(cleaned, r):
                return True
        else:
            if _check_single_range(cleaned, r):
                return True

    return False


def _check_maven_range(version: str, range_dict: Dict) -> bool:
    """Maven-specific range check using compare_maven_versions.
    Same event pattern as _check_single_range but uses maven comparator."""
    if not version:
        return False

    events = range_dict.get("events", [])
    if not events:
        return False

    lowest_introduced = None
    fixed_version = None
    last_affected = None

    for evt in events:
        if "introduced" in evt:
            v = evt["introduced"]
            if lowest_introduced is None or compare_maven_versions(v, lowest_introduced) < 0:
                lowest_introduced = v
        if "fixed" in evt:
            v = evt["fixed"]
            if fixed_version is None or compare_maven_versions(v, fixed_version) < 0:
                fixed_version = v
        if "last_affected" in evt:
            v = evt["last_affected"]
            if last_affected is None or compare_maven_versions(v, last_affected) > 0:
                last_affected = v

    if lowest_introduced is not None:
        if compare_maven_versions(version, lowest_introduced) < 0:
            return False

    if fixed_version is not None:
        if compare_maven_versions(version, fixed_version) >= 0:
            return False
    elif last_affected is not None:
        if compare_maven_versions(version, last_affected) > 0:
            return False

    return True


# update the module-level prerelease order with maven qualifiers
# run once at import time — merges in maven-specific qualifiers
for _mq, _mw in _MAVEN_QUALIFIER_WEIGHTS.items():
    if _mq and _mq not in _PRERELEASE_ORDER:
        # map maven weights to approximate semver prerelease order
        _PRERELEASE_ORDER[_mq] = _mw // 100


# ---- version range checking ----

def _check_single_range(version: str, range_dict: Dict) -> bool:
    """Check if a version falls within a single affected range.
    Returns False if events list is empty or version is empty.
    Handles patterns like [{introduced: "1.0"}, {fixed: "2.0"}] and
    [{introduced: "1.0"}, {last_affected: "1.9"}].
    Also handles no lower bound (just fixed: X → everything before X affected)."""

    if not version:
        return False

    events = range_dict.get("events", [])
    if not events:
        return False

    lowest_introduced = None
    highest_introduced = None
    fixed_version = None
    last_affected_version = None

    for evt in events:
        if "introduced" in evt:
            ver = evt["introduced"]
            if lowest_introduced is None or _compare_versions(ver, lowest_introduced) < 0:
                lowest_introduced = ver
            if highest_introduced is None or _compare_versions(ver, highest_introduced) > 0:
                highest_introduced = ver
        if "fixed" in evt:
            ver = evt["fixed"]
            if fixed_version is None or _compare_versions(ver, fixed_version) < 0:
                fixed_version = ver
        if "last_affected" in evt:
            ver = evt["last_affected"]
            if last_affected_version is None or _compare_versions(ver, last_affected_version) > 0:
                last_affected_version = ver

    # range type can be "SEMVER", "ECOSYSTEM", "GIT", etc. — we handle SEMVER/ECOSYSTEM,
    # fall through to string comparison for others
    range_type = range_dict.get("type", "SEMVER")

    # if we have an introduced version, check lower bound
    if lowest_introduced is not None:
        if _compare_versions(version, lowest_introduced) < 0:
            return False

    # check upper bound
    if fixed_version is not None:
        if _compare_versions(version, fixed_version) >= 0:
            return False
    elif last_affected_version is not None:
        if _compare_versions(version, last_affected_version) > 0:
            return False

    return True


def _version_in_range(version: str, ranges: List[Dict]) -> bool:
    """Check if a version is vulnerable according to any of the given ranges.
    Iterates over ranges and calls _check_single_range for each.
    Returns True if any range matches."""

    if not version or not ranges:
        return False

    for r in ranges:
        if _check_single_range(version, r):
            return True

    return False


# ---- KB search normalization ----

def _kb_search(kb, query: str, limit: int = 50) -> Tuple[List[Any], int]:
    """Normalize KB search results. Some KB implementations return (entries, total)
    tuples, others return plain lists. This handles both — real-world inconsistency
    between KB backends that grew organically."""

    result = kb.search(query=query, limit=limit)

    # handle tuple returns: (entries, total)
    if isinstance(result, tuple) and len(result) == 2:
        entries, total = result
        if isinstance(total, int) and isinstance(entries, list):
            return entries, total

    # handle list returns
    if isinstance(result, list):
        return result, len(result)

    # unknown format — wrap it
    return [result], 1


# ---- public matcher functions ----

def match_by_cpe(
    kb,
    cpe_str: str,
    component_version: Optional[str] = None,
    limit: int = 10,
) -> List[Dict]:
    """Search for CVE entries matching a CPE string. Optionally filter by
    vulnerable version range. Returns list of match dicts with confidence scores."""

    parsed = _parse_cpe(cpe_str)
    if not parsed:
        return []

    vendor = parsed.get("vendor", "*")
    product = parsed.get("product", "*")

    # build search fragments
    search_terms = []
    if product and product != "*":
        search_terms.append(product)
    if vendor and vendor != "*":
        search_terms.append(vendor)

    all_matches = []

    for term in search_terms[:2]:  # search by product and vendor separately
        entries, _ = _kb_search(kb, term, limit=limit)
        for entry in entries:
            # normalize entry access — could be dict, CVEEntry, or sqlite3.Row
            eid = _entry_cve_id(entry)
            eproducts = _entry_products(entry)
            evendors = _entry_vendors(entry)

            # check product/vendor overlap
            product_match = (
                product == "*"
                or product in [p.lower() for p in eproducts]
                or any(product.lower() in p.lower() for p in eproducts)
            )
            vendor_match = (
                vendor == "*"
                or vendor in [v.lower() for v in evendors]
                or any(vendor.lower() in v.lower() for v in evendors)
            )

            if product_match or vendor_match:
                match_info = {
                    "cve_id": eid,
                    "severity": _entry_severity(entry),
                    "description": _entry_description(entry),
                    "match_confidence": 0.85 if (product_match and vendor_match) else 0.7,
                    "match_type": "cpe",
                }

                # version check if we have both version and ranges
                if component_version:
                    ranges = entry.get("affected_ranges", []) if isinstance(entry, dict) else getattr(entry, "affected_ranges", [])
                    if ranges or isinstance(entry, dict) and "affected_ranges" in entry:
                        if isinstance(entry, dict):
                            ranges = entry.get("affected_ranges", [])
                        else:
                            ranges = getattr(entry, "affected_ranges", [])
                        if _version_in_range(component_version, ranges):
                            match_info["version_affected"] = True
                            match_info["match_confidence"] = min(match_info["match_confidence"] + 0.05, 1.0)
                        else:
                            match_info["version_affected"] = False
                    else:
                        match_info["version_affected"] = None

                all_matches.append(match_info)

    # deduplicate by cve_id
    seen = set()
    deduped = []
    for m in all_matches:
        if m["cve_id"] not in seen:
            seen.add(m["cve_id"])
            deduped.append(m)

    return deduped


# ---- entry access helpers (module-level, intentionally not unified) ----
# These normalize dict vs dataclass vs sqlite.Row access.
# Real reason for keeping them separate: a single _normalize_entry() would need
# to copy ALL fields for each call — slower for large batch matching.
# Yes the naming is inconsistent. No it's not worth refactoring yet.

def _entry_cve_id(entry) -> str:
    """Get cve_id from any entry type."""
    if isinstance(entry, dict):
        return entry.get("cve_id", entry.get("id", ""))
    if hasattr(entry, "cve_id"):
        return entry.cve_id
    if hasattr(entry, "__getitem__"):
        try:
            return entry["cve_id"]
        except (KeyError, IndexError):
            return ""
    return ""


def _entry_severity(entry) -> str:
    """Get severity from any entry type."""
    if isinstance(entry, dict):
        return entry.get("severity", "UNKNOWN")
    if hasattr(entry, "severity"):
        return entry.severity
    if hasattr(entry, "__getitem__"):
        try:
            return entry["severity"]
        except (KeyError, IndexError):
            return "UNKNOWN"
    return "UNKNOWN"


def _entry_description(entry) -> str:
    """Get description from any entry type."""
    if isinstance(entry, dict):
        return entry.get("description", entry.get("desc", ""))
    if hasattr(entry, "description"):
        return entry.description
    if hasattr(entry, "__getitem__"):
        try:
            return entry["description"]
        except (KeyError, IndexError):
            return ""
    return ""


def _entry_products(entry) -> List[str]:
    """Get products list from any entry type."""
    if isinstance(entry, dict):
        prods = entry.get("products", entry.get("product", []))
        return prods if isinstance(prods, list) else [prods] if prods else []
    if hasattr(entry, "products"):
        return entry.products or []
    if hasattr(entry, "__getitem__"):
        try:
            prods = entry["products"]
            return prods if isinstance(prods, list) else [prods] if prods else []
        except (KeyError, IndexError):
            return []
    return []


def _entry_vendors(entry) -> List[str]:
    """Get vendors list from any entry type."""
    if isinstance(entry, dict):
        vends = entry.get("vendors", entry.get("vendor", []))
        return vends if isinstance(vends, list) else [vends] if vends else []
    if hasattr(entry, "vendors"):
        return entry.vendors or []
    if hasattr(entry, "__getitem__"):
        try:
            vends = entry["vendors"]
            return vends if isinstance(vends, list) else [vends] if vends else []
        except (KeyError, IndexError):
            return []
    return []
