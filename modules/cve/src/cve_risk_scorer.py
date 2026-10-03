# 时态CVE风险评分——将EPSS、SSVC、KEV与exploit成熟度合并为0-100分，
# 反映"此刻应多担忧？"
#
# CVSS为静态（披露时确定，鲜有变更）。EPSS为30天前向预测但不考虑补丁可用性。
# SSVC给出决策类别但无数值排名。KEV表示"野外利用中"但不指示紧迫度。
# Exploit成熟度告知PoC是否存在但不包含武器化级别。
#
# 本模块将其统一为时态评分:
# 基础: CVSS评分 (0-10 → 0-50)
# EPSS乘数: EPSS越高 → 评分提升 (0-30)
#   - SSVC决策加权: Act=+20, Attend=+10, Track*=+5, Track=+0
# KEV加成: 若在CISA KEV目录中 +15
#   - Exploit成熟度加成: weaponized=+15, metasploit=+12, functional=+8, poc=+5
# 时态衰减: 若有可用修复，评分随时间衰减
#
# 最终评分截断至0-100。

import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any, Union

from .cve_models import CVEEntry, Severity

# 评分权重
# 基于观察约1000个真实CVE的经验调参。
# 若有更好校准数据可调整。

_CVSS_MAX_CONTRIBUTION = 50   # CVSS基础分最大贡献
_EPSS_MAX_CONTRIBUTION = 30   # EPSS百分位最大贡献
_SSVC_WEIGHTS = {
    "Act": 20, "act": 20,
    "Attend": 10, "attend": 10,
    "TrackStar": 5, "track*": 5, "trackstar": 5,
    "Track": 0, "track": 0,
}
_KEV_BONUS = 15               # CISA KEV存在时的固定加成
_EXPLOIT_MATURITY_BONUS = {
    "weaponized": 15,
    "metasploit": 12,
    "functional": 8,
    "poc": 5,
    "proof_of_concept": 5,
    "unknown": 0,
}

# 时态衰减: 修复发布后每天评分衰减比例
# 值越高衰减越快。0.005意味着约140天后评分减半。
_DECAY_RATE_PER_DAY = 0.005
# 下限: 评分不低于原始值的此比例
_MIN_SCORE_FRACTION = 0.2


def compute_risk_score(
    entry: Union[CVEEntry, Dict],
    ssvc_decision: Optional[str] = None,
    days_since_fix: Optional[float] = None,
) -> Dict[str, Any]:
    """计算CVE条目的统一时态风险评分。

    entry: CVEEntry或含cvss_score, epss_score, epss_percentile,
           cisa_kev, exploit_maturity, fix_version, patched_version的字典。
    ssvc_decision: 预计算的SSVC决策字符串（Act/Attend/Track*/Track）。
                   为None时跳过SSVC贡献。
    days_since_fix: 修复发布以来的天数。为None时不应用时态衰减。

    返回含score, breakdown, label（LOW/MEDIUM/HIGH/CRITICAL）的字典。
    """
# 提取字段
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

# 1. CVSS基础
    # 线性映射: 0 → 0, 10 → _CVSS_MAX_CONTRIBUTION
    cvss_contrib = (cvss / 10.0) * _CVSS_MAX_CONTRIBUTION
    breakdown["cvss_contribution"] = round(cvss_contrib, 1)
    total += cvss_contrib

# 2. EPSS
    # 取原始EPSS评分与百分位归一化值中的较高者
    epss_effective = max(epss, epss_pct)
    epss_contrib = epss_effective * _EPSS_MAX_CONTRIBUTION
    breakdown["epss_contribution"] = round(epss_contrib, 1)
    total += epss_contrib

# 3. SSVC决策
    ssvc_contrib = 0.0
    if ssvc_decision is not None:
        ssvc_contrib = _SSVC_WEIGHTS.get(ssvc_decision, 0)
    breakdown["ssvc_contribution"] = ssvc_contrib
    total += ssvc_contrib

# 4. KEV加成
    kev_contrib = _KEV_BONUS if cisa_kev else 0.0
    breakdown["kev_contribution"] = kev_contrib
    total += kev_contrib

# 5. Exploit成熟度
    mat_key = maturity.lower().strip().replace(" ", "_")
    maturity_contrib = _EXPLOIT_MATURITY_BONUS.get(mat_key, 0)
    breakdown["maturity_contribution"] = maturity_contrib
    total += maturity_contrib

# 6. 时态衰减
    decay_factor = 1.0
    if days_since_fix is not None and days_since_fix > 0 and has_fix:
        decay_factor = max(
            _MIN_SCORE_FRACTION,
            1.0 - _DECAY_RATE_PER_DAY * days_since_fix,
        )
    breakdown["decay_factor"] = round(decay_factor, 3)
    total *= decay_factor

    # 截断
    total = max(0.0, min(100.0, total))
    score = round(total, 1)

    # 标签
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
    """批量计算风险评分。
    ssvc_decisions: 可选 cve_id → ssvc_decision字典。

    返回按评分降序排列的 {cve_id, score, label, breakdown} 列表。"""
    results = []
    for entry in entries:
        cid = _get_str(entry, "cve_id")
        ssvc = ssvc_decisions.get(cid) if ssvc_decisions else None

        # 若published_date可用则估算修复以来的天数
        days_since_fix = None
        pub_date = _get_str(entry, "published_date")
        if pub_date and _get_str(entry, "fix_version"):
            try:
                # 处理ISO日期字符串
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
    """将风险评分聚合为摘要。
    返回 {total, by_label: {CRITICAL: n, HIGH: n, ...}, avg_score, top_5, ...}"""
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


# 辅助: 估算修复以来的天数

def estimate_days_since_fix(entry) -> Optional[float]:
    """启发式估算修复可用以来的天数。
    以published_date为代理——NVD发布时通常已知修复。
    返回天数（浮点数）或无法确定时返回None。"""
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


# 字段访问辅助

from ._internal_helpers import _get_str, _get_num, _get_bool


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
