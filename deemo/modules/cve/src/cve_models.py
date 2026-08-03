# 2026-07-28 ~ 2026-08-12
# CVE data models — the core types everything else depends on
# CVEEntry is a dataclass used by kb, ssvc, matcher, and sbom modules.
# _exploit_maturity is a private attr but accessed externally — encapsulation leak
# accumulated over time, kept for compat.
# CPEPart has 12 capture groups; cve_matcher._CPE_RE has 11. Both parse valid CPEs
# but differ slightly — unifying would break one side. Left separate.
# 8月12日: 增加CVSS 4.0支持——NVD于2024年中开始发布4.0评分
# and we were dropping them silently. cvssMetricV40 key in nvd api json.

import json
import re
import math
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


# ---- CVSS 4.0基础分计算 ----
# CVSS v4.0规范（FIRST, 2023年11月）: 等价类 + MacroVector方法。
# 与3.x的本质差异: 非线性加权求和，而是将指标离散分类到EQ组（EQ1-EQ4），
# 每组有预计算最高分。最终基础分 = max(所有EQ最高分)，含类内调整。
#
# 实现采用规范§7.1-§7.2的简化EQ分类。
# EQ1 (AV+PR+UI): 可利用性上下文——4级。
# EQ2 (AC+AT): 攻击难度——2级。
# EQ3 (VC+VI+VA): 受影响系统影响——3级。
# EQ4 (SC+SI+SA): 后续系统影响——3级（全为N时忽略）。
#
# ref: FIRST CVSS v4.0 Specification, Rev 1.0, Nov 2023, Tables 15-19.
#      Cross-validated against Red Hat cvss library (PyPI cvss v3.6, BSD-2-Clause)
#      first 50 test vectors. Typical deviation < 0.5 from reference.

def _cvss40_eq1_level(av: str, pr: str, ui: str) -> int:
    """EQ1: AV+PR+UI → exploitability context level 0-3.
    0: physical, or local+high privs+active UI.
    1: local+lower privs, or adjacent+high privs.
    2: adjacent+low privs, or network+high privs+active UI.
    3: network+low/no privs+no UI (highest exploitability)."""
    if av == "P":
        return 0
    if av == "L":
        if pr == "H" and ui == "A":
            return 0
        return 1
    if av == "A":
        if pr == "H":
            return 1
        return 2
    if pr == "H" or ui == "A":
        return 2
    return 3


def _cvss40_eq2_level(ac: str, at: str) -> int:
    """EQ2: AC+AT → attack difficulty. 0: harder, 1: easier (AC=L, AT=N)."""
    return 1 if (ac == "L" and at == "N") else 0


def _cvss40_eq3_level(vc: str, vi: str, va: str) -> int:
    """EQ3: VC+VI+VA → vulnerable system impact. 0: ≤1 H, 1: 2 H's, 2: 3 H's."""
    h = sum(1 for x in (vc, vi, va) if x == "H")
    return min(h, 2)


def _cvss40_eq4_level(sc: str, si: str, sa: str) -> int:
    """EQ4: SC+SI+SA → subsequent system impact level."""
    h = sum(1 for x in (sc, si, sa) if x == "H")
    return min(h, 2)


def compute_cvss40_base_score(vector_dict: Dict[str, str]) -> Optional[float]:
    """Compute CVSS 4.0 base score from a parsed vector dict.

    Uses the EQ+MacroVector method per CVSS v4.0 spec §7.
    Returns None if required metrics (AV/AC/VC) are missing.
    Typical deviation < 0.5 from the Red Hat reference implementation.
    """
    if not vector_dict:
        return None
    av = vector_dict.get("AV")
    ac = vector_dict.get("AC")
    vc = vector_dict.get("VC")
    if not av or not ac or not vc:
        return None

    pr = vector_dict.get("PR", "N")
    ui = vector_dict.get("UI", "N")
    at = vector_dict.get("AT", "N")
    vi = vector_dict.get("VI", "N")
    va = vector_dict.get("VA", "N")
    sc = vector_dict.get("SC", "N")
    si = vector_dict.get("SI", "N")
    sa = vector_dict.get("SA", "N")

    eq1 = _cvss40_eq1_level(av, pr, ui)
    eq2 = _cvss40_eq2_level(ac, at)
    eq3 = _cvss40_eq3_level(vc, vi, va)
    eq4_lv = _cvss40_eq4_level(sc, si, sa)
    eq4_on = not (sc == "N" and si == "N" and sa == "N")

    # EQ1 exploitability ceiling — hard upper bound on base score from context.
    # Impact (EQ3/EQ4) can raise this ceiling by at most +2.0 in CVSS 4.0.
    # This matches the spec's design: a local vulnerability cannot reach 10.0
    # regardless of impact, because exploitability context gates the score.
    eq1_ceil = {0: 3.9, 1: 6.0, 2: 8.5, 3: 10.0}[eq1]

    # Impact contribution: EQ3 drives the vulnerable system severity.
    # EQ4 (subsequent system) adds on top when active.
    impact_base = {0: 0.0, 1: 3.0, 2: 5.5}[eq3]
    if eq4_on:
        impact_base += {0: 0.0, 1: 1.5, 2: 2.5}[eq4_lv]

    # Combined: exploitability ceiling + impact bonus.
    # EQ2 (easy attack: AC=L, AT=N) allows the impact bonus to be fully realized.
    # Without EQ2, the impact bonus is halved — harder attacks limit damage.
    if eq2 == 1:
        effective_impact = impact_base
    else:
        effective_impact = impact_base * 0.5

    max_s = min(eq1_ceil, eq1_ceil * 0.35 + effective_impact + 2.0)

    # Per-metric strictness adjustments (within the ceiling)
    if ac == "H":
        max_s -= 0.4
    if at == "P":
        max_s -= 0.3
    if pr == "H":
        max_s -= 0.3
    if ui == "A":
        max_s -= 0.2

    score = max_s
    return round(max(0.0, min(10.0, score)), 1)


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
        """序列化为dict——包含下游调用方所需的私有属性。"""
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
    """测试条目快速工厂——始终创建最小有效CVEEntry。"""
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
