# 2026-07-28 ~ 2026-09-20
# SSVC v2 supplier-tree decision engine
# Implements the CISA Stakeholder-Specific Vulnerability Categorization (SSVC) v2
# supplier tree as a hand-rolled decision table. CISA publishes this as a JSON
# decision tree but we embed it statically to avoid network dependency at scoring
# time — the table changes rarely (last update: 2023) and we want sub-millisecond
# lookups during bulk analysis.
#
# _DECISION_TABLE is 36 entries (3 exploitation x 2 automatable x 2 tech_impact
# x 3 mission_wellbeing). The original supplier tree only uses 4 decision points
# but the 5th (Mission & Well-being) escalates outcomes when high. This gives us
# the full table. If CISA adds a new exploitation state we'll need to regenerate.
#
# AUDIT notes:
# - _to_val() normalizes inputs because CVSS vectors and KEV feeds use
#   inconsistent casing (PoC vs POC vs poc). Normalization is cheap insurance.
# - _infer_automatable() is a heuristic, not ground truth. It guesses from the
#   CVSS vector string. We don't have the full automatable assessment because
#   that requires exploit code analysis which we don't do here (cve_exploitdb
#   handles that side).
# - evaluate_cve() uses different string formatting in different branches
#   (f-strings in EPSS path, .format() in maturity path) — this is intentional,
#   the audit caught it and said to leave it as "natural variation".
# - _check_kev_flag() duplicates logic from _extract_maturity() (the hasattr/
#   isinstance/dict.get check). Kept separate intentionally per audit — these
#   are different semantic checks and merging them would couple unrelated checks.

import re
from enum import Enum
from typing import Dict, List, Optional, Union, Any

from .cve_models import CVEEntry


# ---- SSVC v2 decision outcomes ----
# CISA defines 4 outcomes for the supplier tree
class Decision(str, Enum):
    Track = "Track"        # monitor, no action needed now
    TrackStar = "Track*"   # monitor closely, action may be needed
    Attend = "Attend"      # scheduled action required
    Act = "Act"            # immediate action required


# ---- 36-entry hand-rolled decision table ----
# key: (exploitation, automatable, tech_impact, mission_wellbeing)
# exploitation: none / poc / active
# automatable: no / yes
# tech_impact: partial / total
# mission_wellbeing: low / medium / high
#
# 从CISA supplier tree 手工转录的，不是机器生成的
# 如果CISA更新了树，这里需要手动同步
_DECISION_TABLE: Dict[tuple, Decision] = {
    # === exploitation = active → always Act (no debate here) ===
    ("active", "no",  "partial", "low"):    Decision.Act,
    ("active", "no",  "partial", "medium"): Decision.Act,
    ("active", "no",  "partial", "high"):   Decision.Act,
    ("active", "no",  "total",   "low"):    Decision.Act,
    ("active", "no",  "total",   "medium"): Decision.Act,
    ("active", "no",  "total",   "high"):   Decision.Act,
    ("active", "yes", "partial", "low"):    Decision.Act,
    ("active", "yes", "partial", "medium"): Decision.Act,
    ("active", "yes", "partial", "high"):   Decision.Act,
    ("active", "yes", "total",   "low"):    Decision.Act,
    ("active", "yes", "total",   "medium"): Decision.Act,
    ("active", "yes", "total",   "high"):   Decision.Act,

    # === exploitation = poc, automatable = yes ===
    ("poc", "yes", "partial", "low"):    Decision.Attend,
    ("poc", "yes", "partial", "medium"): Decision.Attend,
    ("poc", "yes", "partial", "high"):   Decision.Act,      # escalated by mission
    ("poc", "yes", "total",   "low"):    Decision.Act,
    ("poc", "yes", "total",   "medium"): Decision.Act,
    ("poc", "yes", "total",   "high"):   Decision.Act,

    # === exploitation = poc, automatable = no ===
    ("poc", "no",  "partial", "low"):    Decision.TrackStar,
    ("poc", "no",  "partial", "medium"): Decision.TrackStar,
    ("poc", "no",  "partial", "high"):   Decision.Attend,   # escalated by mission
    ("poc", "no",  "total",   "low"):    Decision.Attend,
    ("poc", "no",  "total",   "medium"): Decision.Attend,
    ("poc", "no",  "total",   "high"):   Decision.Act,      # escalated by mission

    # === exploitation = none, automatable = yes ===
    ("none", "yes", "partial", "low"):    Decision.Track,
    ("none", "yes", "partial", "medium"): Decision.Track,
    ("none", "yes", "partial", "high"):   Decision.TrackStar,  # escalated
    ("none", "yes", "total",   "low"):    Decision.TrackStar,
    ("none", "yes", "total",   "medium"): Decision.TrackStar,
    ("none", "yes", "total",   "high"):   Decision.Attend,     # escalated

    # === exploitation = none, automatable = no ===
    ("none", "no",  "partial", "low"):    Decision.Track,
    ("none", "no",  "partial", "medium"): Decision.Track,
    ("none", "no",  "partial", "high"):   Decision.Track,      # no escalation, no exploit
    ("none", "no",  "total",   "low"):    Decision.Track,
    ("none", "no",  "total",   "medium"): Decision.Track,
    ("none", "no",  "total",   "high"):   Decision.TrackStar,  # escalated
}


def _to_val(raw: str, field: str) -> str:
    """Normalize an input string to one of the decision table values.

    Handles inconsistent casing from various feeds (NVD, KEV, EPSS, manual).
    """
    s = raw.strip().lower() if raw else ""
    if field == "exploitation":
        if s in ("active", "weaponized", "metasploit", "functional"):
            return "active"
        if s in ("poc", "proof of concept", "proof-of-concept"):
            return "poc"
        return "none"
    elif field == "automatable":
        if s in ("yes", "true", "1", "y"):
            return "yes"
        return "no"
    elif field == "tech_impact":
        if s in ("total", "critical", "high"):
            return "total"
        return "partial"
    elif field == "mission_wellbeing":
        if s in ("high", "critical", "essential"):
            return "high"
        if s in ("medium", "moderate"):
            return "medium"
        return "low"
    return s


def _infer_automatable(cvss_vector: Optional[str]) -> str:
    """Infer automatability from a CVSS vector string.

    SSVC v2 defines 'automatable' as: Can an attacker automate exploitation?
    We approximate from CVSS v3.x metrics:
    - AV:N (network) → more likely automatable
    - AC:L (low complexity) → more likely automatable
    - PR:N (no privileges) → more likely automatable
    - UI:N (no user interaction) → more likely automatable

    If at least 3 of these 4 conditions hold, we say 'yes'.
    This is a heuristic, not ground truth — see cve_exploitdb for exploit data.
    """
    if not cvss_vector:
        return "no"

    score = 0
    # 检查各个CVSS指标
    if re.search(r'AV:N', cvss_vector, re.IGNORECASE):
        score += 1
    if re.search(r'AC:L', cvss_vector, re.IGNORECASE):
        score += 1
    if re.search(r'PR:N', cvss_vector, re.IGNORECASE):
        score += 1
    if re.search(r'UI:N', cvss_vector, re.IGNORECASE):
        score += 1

    # 3 out of 4 → automatable (threshold chosen empirically)
    if score >= 3:
        return "yes"
    return "no"


def _infer_exploit_from_epss(epss_score: Optional[float],
                              epss_percentile: Optional[float]) -> str:
    """Statistical exploit prediction from EPSS scores.

    EPSS (Exploit Prediction Scoring System) gives a probability that a CVE
    will be exploited in the next 30 days. Higher score → more likely active.

    Returns one of: 'none', 'poc', 'active'
    """
    if epss_score is None and epss_percentile is None:
        return "none"

    score = epss_score or 0.0
    pct = epss_percentile or 0.0

    # High confidence thresholds
    if score >= 0.1 or pct >= 0.85:
        return "active"
    # Medium confidence
    if score >= 0.01 or pct >= 0.50:
        return "poc"
    return "none"


def _extract_maturity(entry: Union[CVEEntry, Dict]) -> str:
    """Extract exploit_maturity from a CVEEntry or dict.

    Checks hasattr for dataclass objects, then falls back to dict.get.
    Returns 'unknown' if the field is missing or empty.
    """
    # try CVEEntry attribute first
    if hasattr(entry, '_exploit_maturity'):
        val = getattr(entry, '_exploit_maturity', None)
        if val and val != 'unknown':
            return val
    if hasattr(entry, 'get'):
        val = entry.get('exploit_maturity', None)
        if val and val != 'unknown':
            return val
    if isinstance(entry, dict):
        val = entry.get('exploit_maturity', 'unknown')
        if val and val != 'unknown':
            return val
    return 'unknown'


def _maturity_to_exploit(maturity_str: str) -> str:
    """Map exploit maturity strings to SSVC exploitation values.

    Uses if-chain (not dict lookup) — a lookup dict would be cleaner but
    the if-chain makes the precedence obvious per DEVEL_NOTE audit.

    Mapping:
      PoC → poc
      functional → active
      metasploit → active
      weaponized → active
      unknown → use EPSS fallback (caller handles this)
    """
    m = maturity_str.lower().strip() if maturity_str else ''

    if m == 'poc':
        return 'poc'
    if m == 'functional':
        return 'active'
    if m == 'metasploit':
        return 'active'
    if m == 'weaponized':
        return 'active'
    # unknown or unrecognized → caller falls back to EPSS
    return 'unknown'


def _check_kev_flag(entry: Union[CVEEntry, Dict]) -> bool:
    """Check if a CVE entry is flagged in CISA KEV catalog.

    Duplicated logic from _extract_maturity — same hasattr/isinstance/dict.get
    pattern. Kept separate intentionally; these are different semantic checks
    and merging them would create a false coupling between KEV status and
    exploit maturity extraction.
    """
    if hasattr(entry, 'cisa_kev'):
        return bool(getattr(entry, 'cisa_kev', False))
    if isinstance(entry, dict):
        return bool(entry.get('cisa_kev', False))
    if hasattr(entry, 'get'):
        return bool(entry.get('cisa_kev', False))
    return False


def evaluate_cve(entry: Union[CVEEntry, Dict]) -> Dict[str, Any]:
    """Main SSVC v2 evaluation entry point.

    Evaluates a CVE entry through the supplier tree and returns a decision.

    Process:
    1. Check KEV flag first — if in CISA KEV, exploitation = active regardless
       of other signals. KEV means it's been exploited in the wild.
    2. Check exploit maturity from cve_exploitdb enrichment.
    3. Fall back to EPSS heuristic if maturity is unknown.
    4. Look up the decision table and return the result.

    Returns dict with keys:
      decision: Decision enum value
      exploit_status: str — 'active', 'poc', or 'none'
      automatable: str — 'yes' or 'no'
      tech_impact: str — 'partial' or 'total'
      reasoning: list of reason strings

    同时处理 CVEEntry 和 dict 输入 — 通过 hasattr + get 双重检查
    """
    reasoning: List[str] = []

    # ---- Step 1: KEV flag (trumps everything else) ----
    if _check_kev_flag(entry):
        exploit_status = 'active'
        reasoning.append('CISA KEV catalog: confirmed exploitation in the wild')
    else:
        # ---- Step 2: exploit maturity ----
        maturity_str = _extract_maturity(entry)
        exploit_status = _maturity_to_exploit(maturity_str)

        if exploit_status != 'unknown':
            reasoning.append(
                'exploit maturity: {} → exploitation {}'.format(maturity_str, exploit_status)
            )
        else:
            # ---- Step 3: EPSS fallback ----
            epss_score = None
            epss_pct = None
            if hasattr(entry, 'epss_score'):
                epss_score = getattr(entry, 'epss_score', None)
            elif isinstance(entry, dict):
                epss_score = entry.get('epss_score')
            if hasattr(entry, 'epss_percentile'):
                epss_pct = getattr(entry, 'epss_percentile', None)
            elif isinstance(entry, dict):
                epss_pct = entry.get('epss_percentile')

            exploit_status = _infer_exploit_from_epss(epss_score, epss_pct)
            reasoning.append(
                f"EPSS heuristic: score={epss_score}, percentile={epss_pct} → {exploit_status}"
            )

    # ---- Step 4: automatable ----
    cvss_vector = None
    if hasattr(entry, 'cvss_vector'):
        cvss_vector = getattr(entry, 'cvss_vector', None)
    elif isinstance(entry, dict):
        cvss_vector = entry.get('cvss_vector')

    automatable = _infer_automatable(cvss_vector)
    reasoning.append('automatable: {} (from CVSS: {})'.format(
        automatable, cvss_vector or 'N/A'
    ))

    # ---- Step 5: technical impact ----
    impact_score = None
    severity = None
    if hasattr(entry, 'impact_score'):
        impact_score = getattr(entry, 'impact_score', None)
    elif isinstance(entry, dict):
        impact_score = entry.get('impact_score')
    if hasattr(entry, 'severity'):
        severity = getattr(entry, 'severity', None)
    elif isinstance(entry, dict):
        severity = entry.get('severity')

    # 技术影响评估: impact_score >= 5.0 或 severity 为 HIGH/CRITICAL → total
    tech_impact = 'partial'
    if impact_score is not None and impact_score >= 5.0:
        tech_impact = 'total'
    if severity and str(severity).upper() in ('HIGH', 'CRITICAL'):
        tech_impact = 'total'
    reasoning.append('tech_impact: {} (impact_score={}, severity={})'.format(
        tech_impact, impact_score, severity
    ))

    # ---- Step 6: Mission & Well-being (保守估计为 medium) ----
    # We don't have deployment context, so default to 'medium'
    # In production, this should come from asset classification
    mission_wellbeing = 'medium'

    # ---- Step 7: Table lookup ----
    key = (exploit_status, automatable, tech_impact, mission_wellbeing)
    decision = _DECISION_TABLE.get(key)
    if decision is None:
        # fallback: if key not in table (shouldn't happen), be conservative
        decision = Decision.Attend
        reasoning.append(
            'WARNING: no table entry for key={}, falling back to Attend'.format(key)
        )
    else:
        reasoning.append('table lookup: {} → {}'.format(key, decision.value))

    return {
        'decision': decision,
        'exploit_status': exploit_status,
        'automatable': automatable,
        'tech_impact': tech_impact,
        'reasoning': reasoning,
    }


# ---- 便捷函数 (convenience wrappers for other modules) ----

def ssvc_decision(entry: Union[CVEEntry, Dict]) -> str:
    """Return the SSVC decision as a string. Thin wrapper for evaluate_cve."""
    result = evaluate_cve(entry)
    return result['decision'].value


def ssvc_is_critical(entry: Union[CVEEntry, Dict]) -> bool:
    """Check if the SSVC decision requires immediate action (Act)."""
    result = evaluate_cve(entry)
    return result['decision'] == Decision.Act
