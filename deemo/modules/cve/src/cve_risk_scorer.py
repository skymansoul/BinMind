# 2026-09-22 ~ 2026-09-24
# Temporal CVE Risk Scoring — combines EPSS, SSVC, KEV, and exploit maturity
# into a single 0-100 score that reflects "how worried should I be right now?"
#
# CVSS is static (set at disclosure, rarely changes). EPSS is a 30-day forward
# prediction but doesn't account for patch availability. SSVC gives a decision
# category but not a numeric rank. KEV says "this is exploited in the wild" but
# not how urgently. Exploit maturity tells you if a PoC exists but not the weaponization level.
#
# This module unifies them into a temporal score with:
#   - Base: CVSS score (0-10 → 0-50)
#   - EPSS multiplier: higher EPSS → score boost (0-30)
#   - SSVC decision weighting: Act=+20, Attend=+10, Track*=+5, Track=+0
#   - KEV bonus: +15 if in CISA KEV catalog
#   - Exploit maturity bonus: weaponized=+15, metasploit=+12, functional=+8, poc=+5
#   - Temporal decay: score decays over time if a fix is available
#
# Final score is clamped to 0-100.

import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any, Union

from .cve_models import CVEEntry, Severity

# ---- scoring weights ----
# these are tuned empirically based on observing ~1000 real CVEs.
# adjust if you have better calibration data.

_CVSS_MAX_CONTRIBUTION = 50   # max points from CVSS base score
_EPSS_MAX_CONTRIBUTION = 30   # max points from EPSS percentile
_SSVC_WEIGHTS = {
    "Act": 20, "act": 20,
    "Attend": 10, "attend": 10,
    "TrackStar": 5, "track*": 5, "trackstar": 5,
    "Track": 0, "track": 0,
}
_KEV_BONUS = 15               # flat bonus for CISA KEV presence
_EXPLOIT_MATURITY_BONUS = {
    "weaponized": 15,
    "metasploit": 12,
    "functional": 8,
    "poc": 5,
    "proof_of_concept": 5,
    "unknown": 0,
}

# temporal decay: score drops by this fraction per day after fix publication
# higher values = faster decay. 0.005 means ~half score after 140 days.
_DECAY_RATE_PER_DAY = 0.005
# cap: score won't drop below this fraction of original
_MIN_SCORE_FRACTION = 0.2


def compute_risk_score(
    entry: Union[CVEEntry, Dict],
    ssvc_decision: Optional[str] = None,
    days_since_fix: Optional[float] = None,
) -> Dict[str, Any]:
    """Compute a unified temporal risk score for a CVE entry.

    entry: CVEEntry or dict with cvss_score, epss_score, epss_percentile,
           cisa_kev, exploit_maturity, fix_version, patched_version.
    ssvc_decision: pre-computed SSVC decision string (Act/Attend/Track*/Track).
                   If None, SSVC contribution is skipped.
    days_since_fix: days since a fix was published. If None, no temporal decay.

    Returns dict with:
      score, breakdown, label (LOW/MEDIUM/HIGH/CRITICAL)
    """
    # ---- extract fields ----
    cvss = _get_num(entry, "cvss_score") or 0.0
    epss = _get_num(entry, "epss_score") or 0.0
    epss_pct = _get_num(entry, "epss_percentile") or 0.0
    cisa_kev = _get_bool(entry, "cisa_kev")
    maturity = _get_str(entry, "exploit_maturity", "unknown")
    has_fix = bool(
        _get_str(entry, "fix_version") or _get_str(entry, "patched_version")
    )

    breakdown = {}
    total = 0.0

    # ---- 1. CVSS base ----
    # linear mapping: 0 → 0, 10 → _CVSS_MAX_CONTRIBUTION
    cvss_contrib = (cvss / 10.0) * _CVSS_MAX_CONTRIBUTION
    breakdown["cvss_contribution"] = round(cvss_contrib, 1)
    total += cvss_contrib

    # ---- 2. EPSS ----
    # use the higher of raw EPSS score or percentile-norm'd value
    epss_effective = max(epss, epss_pct)
    epss_contrib = epss_effective * _EPSS_MAX_CONTRIBUTION
    breakdown["epss_contribution"] = round(epss_contrib, 1)
    total += epss_contrib

    # ---- 3. SSVC decision ----
    ssvc_contrib = 0.0
    if ssvc_decision is not None:
        ssvc_contrib = _SSVC_WEIGHTS.get(ssvc_decision, 0)
    breakdown["ssvc_contribution"] = ssvc_contrib
    total += ssvc_contrib

    # ---- 4. KEV bonus ----
    kev_contrib = _KEV_BONUS if cisa_kev else 0.0
    breakdown["kev_contribution"] = kev_contrib
    total += kev_contrib

    # ---- 5. Exploit maturity ----
    mat_key = maturity.lower().strip().replace(" ", "_")
    maturity_contrib = _EXPLOIT_MATURITY_BONUS.get(mat_key, 0)
    breakdown["maturity_contribution"] = maturity_contrib
    total += maturity_contrib

    # ---- 6. Temporal decay ----
    decay_factor = 1.0
    if days_since_fix is not None and days_since_fix > 0 and has_fix:
        decay_factor = max(
            _MIN_SCORE_FRACTION,
            1.0 - _DECAY_RATE_PER_DAY * days_since_fix,
        )
    breakdown["decay_factor"] = round(decay_factor, 3)
    total *= decay_factor

    # clamp
    total = max(0.0, min(100.0, total))
    score = round(total, 1)

    # label
    if score >= 75:
        label = "CRITICAL"
    elif score >= 50:
        label = "HIGH"
    elif score >= 25:
        label = "MEDIUM"
    else:
        label = "LOW"

    return {
        "score": score,
        "label": label,
        "breakdown": breakdown,
    }


def batch_risk_scores(
    entries: List[Union[CVEEntry, Dict]],
    ssvc_decisions: Optional[Dict[str, str]] = None,
) -> List[Dict[str, Any]]:
    """Compute risk scores for a batch of entries.
    ssvc_decisions: optional dict of cve_id → ssvc_decision.

    Returns list of {cve_id, score, label, breakdown} sorted by score desc."""
    results = []
    for entry in entries:
        cid = _get_str(entry, "cve_id")
        ssvc = ssvc_decisions.get(cid) if ssvc_decisions else None

        # estimate days since fix from published_date if available
        days_since_fix = None
        pub_date = _get_str(entry, "published_date")
        if pub_date and _get_str(entry, "fix_version"):
            try:
                # handle ISO date strings
                pub_dt = datetime.fromisoformat(pub_date.replace("Z", "+00:00"))
                now = datetime.now(timezone.utc)
                days_since_fix = (now - pub_dt).total_seconds() / 86400
            except (ValueError, TypeError):
                pass

        result = compute_risk_score(entry, ssvc_decision=ssvc, days_since_fix=days_since_fix)
        result["cve_id"] = cid
        results.append(result)

    results.sort(key=lambda x: x["score"], reverse=True)
    return results


def risk_summary(scores: List[Dict]) -> Dict[str, Any]:
    """Aggregate risk scores into a summary.
    Returns {total, by_label: {CRITICAL: n, HIGH: n, ...}, avg_score, top_5, ...}"""
    if not scores:
        return {"total": 0, "by_label": {}, "avg_score": 0.0, "top_cves": []}

    by_label: Dict[str, int] = {}
    total_score = 0.0

    for s in scores:
        lbl = s.get("label", "LOW")
        by_label[lbl] = by_label.get(lbl, 0) + 1
        total_score += s.get("score", 0.0)

    top_5 = [
        {"cve_id": s["cve_id"], "score": s["score"], "label": s["label"]}
        for s in scores[:5]
    ]

    return {
        "total": len(scores),
        "by_label": by_label,
        "avg_score": round(total_score / len(scores), 1),
        "top_cves": top_5,
    }


# ---- helper: extract estimated days since fix ----

def estimate_days_since_fix(entry) -> Optional[float]:
    """Heuristic estimate of days since a fix became available.
    Uses published_date as a proxy — when NVD publishes, the fix is usually known.
    Returns days (float) or None if can't determine."""
    pub = _get_str(entry, "published_date")
    has_fix = _get_str(entry, "fix_version") or _get_str(entry, "patched_version")
    if not pub or not has_fix:
        return None
    try:
        pub_dt = datetime.fromisoformat(pub.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        return (now - pub_dt).total_seconds() / 86400
    except (ValueError, TypeError):
        return None


# ---- field access helpers ----

def _get_num(entry, field: str) -> Optional[float]:
    if hasattr(entry, field):
        return getattr(entry, field)
    if isinstance(entry, dict):
        return entry.get(field)
    return None


def _get_str(entry, field: str, default: str = "") -> str:
    if hasattr(entry, field):
        return str(getattr(entry, field) or default)
    if isinstance(entry, dict):
        return str(entry.get(field, default))
    return default


def _get_bool(entry, field: str) -> bool:
    if hasattr(entry, field):
        return bool(getattr(entry, field))
    if isinstance(entry, dict):
        return bool(entry.get(field, False))
    return False
