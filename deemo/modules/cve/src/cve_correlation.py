# ~ 2026-10-19
# 跨部署 CVE 关联 - 当有多个不同服务/部署的 SBOM 时，
# 查找交集和爆炸半径。
#
# 用例: 运行 5 个微服务，各有独立 SBOM。将各 SBOM 与 CVE KB 匹配后，
# 得到 5 个匹配列表。哪些 CVE 影响全部 5 个服务？哪些仅影响一个？
# 每个 CVE 的爆炸半径是多少？
#
# 本模块接收多个匹配结果集（来自 build_sbom_report 或 match_sbom），
# 计算跨部署统计。

from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple, Any


def correlate_deployments(
    deployment_matches: Dict[str, List[Dict]],
) -> Dict[str, Any]:
    """跨多个部署关联 CVE 匹配。

    deployment_matches: deployment_name → 匹配 dict 列表的映射。
      每个匹配 dict 至少需包含: cve_id, severity, component。
      （build_sbom_report()['matches'] 可直接使用。）

    返回 {
      deployments: {name: {cve_count, component_count, top_cves}},
      intersection: {所有部署中均存在的 cve_ids},
      union: {所有部署中唯一的 cve_ids 全集},
      blast_radius: [{cve_id, deployment_count, severity, ...}] 按半径降序,
      by_severity: {CRITICAL: {intersection: [...], per_deployment: {...}}},
      uniqueness: {cve_id: [所在部署列表]} 仅单部署 CVE,
    }
    """
    if not deployment_matches:
        return {"error": "no deployments provided", "deployments": {}}

    # 各部署统计
    dep_stats: Dict[str, Dict] = {}
    dep_cve_sets: Dict[str, Set[str]] = {}
    all_cves: Set[str] = set()

    for dep_name, matches in deployment_matches.items():
        cve_ids: Set[str] = set()
        components: Set[str] = set()
        sev_counts: Dict[str, int] = defaultdict(int)

        for m in matches:
            cid = m.get("cve_id", "")
            comp = m.get("component", m.get("component_name", ""))
            sev = m.get("severity", "UNKNOWN")
            if cid:
                cve_ids.add(cid)
                all_cves.add(cid)
                sev_counts[sev] = sev_counts.get(sev, 0) + 1
            if comp:
                components.add(comp)

        dep_cve_sets[dep_name] = cve_ids
        top = sorted(
            [m for m in matches if m.get("severity") in ("CRITICAL", "HIGH")],
            key=lambda x: x.get("cvss_score") or 0,
            reverse=True,
        )[:5]

        dep_stats[dep_name] = {
            "cve_count": len(cve_ids),
            "component_count": len(components),
            "severity_distribution": dict(sev_counts),
            "top_critical": [
                {"cve_id": t.get("cve_id"), "severity": t.get("severity"),
                 "cvss_score": t.get("cvss_score"), "component": t.get("component")}
                for t in top
            ],
        }

    # 交集: 所有部署中均存在的 CVE
    dep_names = list(dep_cve_sets.keys())
    if dep_names:
        intersection = dep_cve_sets[dep_names[0]].copy()
        for name in dep_names[1:]:
            intersection &= dep_cve_sets[name]
    else:
        intersection = set()

    # 爆炸半径: 每个 CVE 影响的部署数
    cve_to_deps: Dict[str, List[str]] = defaultdict(list)
    for dep_name, cves in dep_cve_sets.items():
        for cid in cves:
            cve_to_deps[cid].append(dep_name)

    blast_radius: List[Dict] = []
    for cid, deps in cve_to_deps.items():
        # 在所有部署中取最高严重程度
        max_sev = "UNKNOWN"
        max_score = None
        sev_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "NONE": 1, "UNKNOWN": 0}
        for dep in deps:
            for m in deployment_matches.get(dep, []):
                if m.get("cve_id") == cid:
                    s = m.get("severity", "UNKNOWN")
                    if sev_order.get(s, 0) > sev_order.get(max_sev, 0):
                        max_sev = s
                        max_score = m.get("cvss_score")

        blast_radius.append({
            "cve_id": cid,
            "deployment_count": len(deps),
            "deployments": deps,
            "total_deployments": len(dep_names),
            "blast_pct": round(len(deps) / len(dep_names) * 100, 1) if dep_names else 0,
            "max_severity": max_sev,
            "max_cvss_score": max_score,
            "in_intersection": cid in intersection,
        })

    blast_radius.sort(key=lambda x: (x["deployment_count"], sev_order.get(x["max_severity"], 0)), reverse=True)

    # 按严重程度分组
    by_severity: Dict[str, Dict] = {}
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        sev_cves = {cid for cid, br in zip(
            [b["cve_id"] for b in blast_radius],
            blast_radius,
        ) if br.get("max_severity") == sev} if False else set()
        # 正确重建
        sev_cves = set()
        sev_per_dep: Dict[str, int] = defaultdict(int)
        for br in blast_radius:
            if br["max_severity"] == sev:
                sev_cves.add(br["cve_id"])
                for dep in br["deployments"]:
                    sev_per_dep[dep] += 1

        by_severity[sev] = {
            "total": len(sev_cves),
            "in_intersection": len(sev_cves & intersection),
            "per_deployment": dict(sev_per_dep),
        }

    # 唯一性: 仅出现在一个部署中的 CVE
    uniqueness = {
        cid: deps for cid, deps in cve_to_deps.items() if len(deps) == 1
    }

    return {
        "deployments": dep_stats,
        "intersection": sorted(intersection),
        "intersection_count": len(intersection),
        "union_count": len(all_cves),
        "blast_radius": blast_radius,
        "by_severity": by_severity,
        "unique_to_deployment": uniqueness,
        "unique_count": len(uniqueness),
        "overlap_matrix": _build_overlap_matrix(dep_cve_sets),
    }


def _build_overlap_matrix(dep_cve_sets: Dict[str, Set[str]]) -> List[Dict]:
    """构建部署间两两重叠矩阵。"""
    names = sorted(dep_cve_sets.keys())
    matrix: List[Dict] = []
    for i, name_a in enumerate(names):
        for j, name_b in enumerate(names):
            if i >= j:
                continue
            set_a = dep_cve_sets[name_a]
            set_b = dep_cve_sets[name_b]
            overlap = set_a & set_b
            union = set_a | set_b
            matrix.append({
                "deployment_a": name_a,
                "deployment_b": name_b,
                "overlap_count": len(overlap),
                "jaccard": round(len(overlap) / len(union), 3) if union else 0.0,
                "a_only": len(set_a - set_b),
                "b_only": len(set_b - set_a),
            })
    return matrix


def find_common_cves(
    *match_lists: List[Dict],
) -> List[str]:
    """查找所有给定匹配列表中均存在的 CVE ID。
    便捷包装，覆盖常见场景。"""
    if not match_lists:
        return []

    common = {m.get("cve_id", "") for m in match_lists[0] if m.get("cve_id")}
    for ml in match_lists[1:]:
        ids = {m.get("cve_id", "") for m in ml if m.get("cve_id")}
        common &= ids
        if not common:
            break

    return sorted(common)


def blast_radius_summary(correlation: Dict) -> str:
    """人类可读的爆炸半径摘要。"""
    br = correlation.get("blast_radius", [])
    if not br:
        return "No CVEs to correlate."

    total_deployments = len(correlation.get("deployments", {}))
    intersection = correlation.get("intersection_count", 0)
    union = correlation.get("union_count", 0)

    lines = [
        f"{union} unique CVEs across {total_deployments} deployments",
        f"{intersection} CVEs affect ALL deployments (intersection)",
    ]

    # 爆炸半径 top 3
    top3 = [b for b in br if b["deployment_count"] > 1][:3]
    if top3:
        lines.append("Top blast radius CVEs:")
        for b in top3:
            lines.append(
                f"  {b['cve_id']} ({b['max_severity']}): "
                f"affects {b['deployment_count']}/{b['total_deployments']} "
                f"deployments ({b['blast_pct']}%)"
            )

    return "\n".join(lines)
