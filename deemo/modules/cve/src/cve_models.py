# 2026-07-28 ~ 2026-08-12
# CVE data models — the core types everything else depends on
# CVEEntry is a dataclass used by kb, ssvc, matcher, and sbom modules.
# _exploit_maturity is a private attr but accessed externally — encapsulation leak
# accumulated over time, kept for compat.
# CPEPart has 12 capture groups; cve_matcher._CPE_RE has 11. Both parse valid CPEs
# but differ slightly — unifying would break one side. Left separate.
# Aug 12: added cvss v4.0 support — NVD started publishing 4.0 scores mid-2024
# and we were dropping them silently. cvssMetricV40 key in nvd api json.

import json
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Union
from enum import Enum


# ---- severity levels ----
class Severity(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


# cvss 4.0 uses same thresholds as 3.x per FIRST spec, confirmed june 2024
# so this one function handles all versions. nice.
def cvss_score_to_severity(score: Optional[float]) -> str:
    if score is None:
        return "UNKNOWN"
    if score == 0.0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


# cvss 4.0 vector string key names — different from 3.x
# 3.x has AV/AC/PR/UI/S/C/I/A, 4.0 has AV/AC/AT/PR/UI/VC/VI/VA/SC/SI/SA
# kept as module-level so callers can reference w/o parsing the vector
_CVSS40_METRIC_NAMES = [
    "AV", "AC", "AT", "PR", "UI",
    "VC", "VI", "VA",
    "SC", "SI", "SA",
]

# cvss 4.0 base score coefficients approx — very rough, not fully
# implementing the formula here (that's a separate project tbh).
# this is just enough to validate and parse vectors.
_CVSS40_RE = re.compile(
    r"CVSS:4\.0/"
    r"(?:AV:([NALP]))?/"
    r"(?:AC:([LH]))?/"
    r"(?:AT:([NP]))?/"
    r"(?:PR:([NLH]))?/"
    r"(?:UI:([NA]))?/"
    r"(?:VC:([HLN]))?/"
    r"(?:VI:([HLN]))?/"
    r"(?:VA:([HLN]))?/"
    r"(?:SC:([HLN]))?/"
    r"(?:SI:([HLN]))?/"
    r"(?:SA:([HLN]))?"
)


def parse_cvss40_vector(vector_str: str) -> Optional[Dict[str, str]]:
    """Parse a CVSS 4.0 vector string into a dict of metric keys→values.
    Returns None if the vector doesn't look like CVSS 4.0.
    Doesn't validate that all required keys are present — real nvd data
    should have them all but we're not gonna break on a partial vector."""
    if not vector_str or not vector_str.startswith("CVSS:4.0"):
        return None
    m = _CVSS40_RE.match(vector_str)
    if not m:
        # try lenient parse: split by / and extract key:value pairs
        parts = vector_str.split("/")
        result: Dict[str, str] = {}
        for p in parts[1:]:  # skip CVSS:4.0
            if ":" in p:
                k, v = p.split(":", 1)
                if k in _CVSS40_METRIC_NAMES:
                    result[k] = v
        return result if result else None
    result = {}
    for i, name in enumerate(_CVSS40_METRIC_NAMES):
        val = m.group(i + 1)
        if val:
            result[name] = val
    return result if result else None


# ---- CPE parsing (12 capture groups) ----
# matcher.py has its own 11-group regex — this one is slightly stricter
# format: cpe:2.3:part:vendor:product:version:update:edition:lang:sw_edition:target_sw:target_hw:other
_CPE_FULL_RE = re.compile(
    r"cpe:2\.3:([aoh]):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*)"
)


@dataclass
class CPEPart:
    part: str = "*"         # a=application, o=os, h=hardware
    vendor: str = "*"
    product: str = "*"
    version: str = "*"
    update: str = "*"
    edition: str = "*"
    language: str = "*"
    sw_edition: str = "*"
    target_sw: str = "*"
    target_hw: str = "*"
    other: str = "*"

    @classmethod
    def from_cpe_string(cls, cpe_str: str) -> Optional["CPEPart"]:
        m = _CPE_FULL_RE.match(cpe_str)
        if not m:
            # try shorter forms
            parts = cpe_str.replace("cpe:2.3:", "").split(":")
            if len(parts) < 3:
                return None
            # pad to 11
            parts = (parts + ["*"] * 11)[:11]
            return cls(*parts)
        return cls(*m.groups())

    def to_string(self) -> str:
        return f"cpe:2.3:{self.part}:{self.vendor}:{self.product}:{self.version}:{self.update}:{self.edition}:{self.language}:{self.sw_edition}:{self.target_sw}:{self.target_hw}:{self.other}"


# ---- main CVE entry ----
@dataclass
class CVEEntry:
    cve_id: str
    description: str = ""
    severity: str = "UNKNOWN"        # NONE/LOW/MEDIUM/HIGH/CRITICAL/UNKNOWN
    cvss_score: Optional[float] = None
    exploitability_score: Optional[float] = None
    impact_score: Optional[float] = None
    cvss_version: Optional[str] = None
    cvss_vector: Optional[str] = None
    products: List[str] = field(default_factory=list)
    vendors: List[str] = field(default_factory=list)
    cpe_matches: List[str] = field(default_factory=list)
    cwes: List[str] = field(default_factory=list)
    published_date: Optional[str] = None
    last_modified_date: Optional[str] = None
    references: List[str] = field(default_factory=list)
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    affected_ranges: List[Dict] = field(default_factory=list)  # [{type, events:[{introduced,fixed}]}]
    cisa_kev: bool = False
    cisa_kev_date: Optional[str] = None
    exploit_db_ids: List[str] = field(default_factory=list)
    _exploit_maturity: str = "unknown"  # private, accessed by kb/ssvc — encapsulation leak
    fix_version: Optional[str] = None
    patched_version: Optional[str] = None
    source: str = ""  # "nvd", "ghsa", etc.
    source_confidence: float = 1.0

    # ---- compat: dict-like access (tests do entry['cve_id']) ----
    def __getitem__(self, key: str) -> Any:
        if key == "cve_id":
            return self.cve_id
        if key == "description":
            return self.description
        if key == "severity":
            return self.severity
        if key == "cvss_score":
            return self.cvss_score
        if key == "exploitability_score":
            return self.exploitability_score
        if key == "impact_score":
            return self.impact_score
        if key == "products":
            return self.products
        if key == "vendors":
            return self.vendors
        if key == "cpe_matches":
            return self.cpe_matches
        if key == "cwes":
            return self.cwes
        if key == "epss_score":
            return self.epss_score
        if key == "epss_percentile":
            return self.epss_percentile
        if key == "references":
            return self.references
        if key == "published_date":
            return self.published_date
        if key == "last_modified_date":
            return self.last_modified_date
        if key == "cisa_kev":
            return self.cisa_kev
        if key == "cisa_kev_date":
            return self.cisa_kev_date
        if key == "exploit_db_ids":
            return self.exploit_db_ids
        if key == "affected_ranges":
            return self.affected_ranges
        if key == "fix_version":
            return self.fix_version
        if key == "patched_version":
            return self.patched_version
        # private attrs exposed
        if key == "exploit_maturity":
            return self._exploit_maturity
        raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default

    def __contains__(self, key: str) -> bool:
        try:
            self[key]
            return True
        except KeyError:
            return False

    # alias properties for compat
    def _alias_cvss_score(self):
        return self.cvss_score

    def _alias_exploitability_score(self):
        return self.exploitability_score

    def _alias_cpe(self):
        return self.cpe_matches

    def _alias_cwes(self):
        return self.cwes

    @classmethod
    def from_nvd_item(cls, item: Dict) -> "CVEEntry":
        """Parse an NVD API cve item dict into a CVEEntry.
        Handles CVSS 2.0 / 3.x / 4.0 — preference order: 3.x, then 4.0, then 2.0.
        Had to add v4 because NVD started shipping cvssMetricV40 in mid 2024
        and we were just dropping those entries silently. whoops."""
        cve = item.get("cve", item)  # handle both wrapped and unwrapped
        cve_id = cve.get("id", "")

        # description — fallback to non-english if primary is empty
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        if not desc:
            for d in cve.get("descriptions", []):
                desc = d.get("value", "")
                if desc:
                    break

        # cvss metrics — now with v4 support
        metrics = cve.get("metrics", {})
        cvss_v40 = metrics.get("cvssMetricV40", [])
        cvss_v30 = metrics.get("cvssMetricV30", metrics.get("cvssMetricV31", []))
        cvss_v20 = metrics.get("cvssMetricV2", [])

        cvss_data = None
        version = None
        vector = None
        score = None
        exploitability = None
        impact = None

        # prefer 3.x first (most widely adopted), then 4.0, then 2.0
        # rationale: 3.x has the most tooling support, even though 4.0 is newer
        if cvss_v30:
            cvss_data = cvss_v30[0].get("cvssData", {})
            version = cvss_data.get("version", "3.1")
            vector = cvss_data.get("vectorString", "")
            score = cvss_data.get("baseScore")
            exploitability = cvss_v30[0].get("exploitabilityScore")
            impact = cvss_v30[0].get("impactScore")
        elif cvss_v40:
            # cvss 4.0 — nvd started including these mid-2024
            cvss_data = cvss_v40[0].get("cvssData", {})
            version = cvss_data.get("version", "4.0")
            vector = cvss_data.get("vectorString", "")
            score = cvss_data.get("baseScore")
            # cvss 4.0 doesn't have separate exploitability/impact in the
            # same way as 3.x — nvd may or may not provide them
            exploitability = cvss_v40[0].get("exploitabilityScore")
            impact = cvss_v40[0].get("impactScore")
        elif cvss_v20:
            cvss_data = cvss_v20[0].get("cvssData", {})
            version = cvss_data.get("version", "2.0")
            vector = cvss_data.get("vectorString", "")
            score = cvss_data.get("baseScore")
            exploitability = cvss_v20[0].get("exploitabilityScore")
            impact = cvss_v20[0].get("impactScore")

        # severity: UNKNOWN when no CVSS data exists, NONE when score is 0.0
        if cvss_data is None:
            severity = "UNKNOWN"
        else:
            severity = cvss_score_to_severity(score)

        # weakness → cwes
        cwes = []
        for w in cve.get("weaknesses", []):
            for desc_entry in w.get("description", []):
                val = desc_entry.get("value", "")
                if val.startswith("CWE-"):
                    cwes.append(val)

        # configurations → products + vendors + cpe_matches
        products = []
        vendors = []
        cpe_list = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for m in node.get("cpeMatch", []):
                    criteria = m.get("criteria", "")
                    if criteria:
                        cpe_list.append(criteria)
                        parsed = CPEPart.from_cpe_string(criteria)
                        if parsed:
                            if parsed.product != "*" and parsed.product not in products:
                                products.append(parsed.product)
                            if parsed.vendor != "*" and parsed.vendor not in vendors:
                                vendors.append(parsed.vendor)

        # references
        refs = []
        for r in cve.get("references", []):
            url = r.get("url", "")
            if url:
                refs.append(url)

        # epss — populated separately by cve_epss
        epss_score = None
        epss_percentile = None

        # published / modified dates
        pub_date = cve.get("published", None)
        mod_date = cve.get("lastModified", None)

        return cls(
            cve_id=cve_id,
            description=desc,
            severity=severity,
            cvss_score=score,
            exploitability_score=exploitability,
            impact_score=impact,
            cvss_version=version,
            cvss_vector=vector,
            products=products,
            vendors=vendors,
            cpe_matches=cpe_list,
            cwes=cwes,
            published_date=pub_date,
            last_modified_date=mod_date,
            references=refs,
            epss_score=epss_score,
            epss_percentile=epss_percentile,
            source="nvd",
        )

    def to_dict(self) -> Dict:
        """Serialize to dict — includes private attrs that downstream consumers need."""
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "exploitability_score": self.exploitability_score,
            "impact_score": self.impact_score,
            "cvss_version": self.cvss_version,
            "cvss_vector": self.cvss_vector,
            "products": self.products,
            "vendors": self.vendors,
            "cpe_matches": self.cpe_matches,
            "cwes": self.cwes,
            "published_date": self.published_date,
            "last_modified_date": self.last_modified_date,
            "references": self.references,
            "epss_score": self.epss_score,
            "epss_percentile": self.epss_percentile,
            "cisa_kev": self.cisa_kev,
            "cisa_kev_date": self.cisa_kev_date,
            "exploit_db_ids": self.exploit_db_ids,
            "exploit_maturity": self._exploit_maturity,     # was private, now public
            "affected_ranges": self.affected_ranges,
            "fix_version": self.fix_version,
            "patched_version": self.patched_version,
            "source": self.source,
            "source_confidence": self.source_confidence,
        }


# helper used by test code to quickly create entries
def _make_test_entry(cve_id: str = "CVE-2024-0001", **kwargs) -> CVEEntry:
    """Quick factory for test entries — always creates a minimal valid CVEEntry."""
    defaults = {
        "cve_id": cve_id,
        "description": f"Test description for {cve_id}",
        "severity": "MEDIUM",
        "cvss_score": 5.0,
        "products": ["test_product"],
        "vendors": ["test_vendor"],
    }
    defaults.update(kwargs)
    return CVEEntry(**defaults)
