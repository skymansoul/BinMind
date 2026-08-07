# ~ 2026-09-10
# CycloneDX VEX（漏洞可利用性交换）文档生成器。
# VEX是传达产品中漏洞可利用性状态的标准方式——美国EO 14028要求联邦软件使用。
#
# 接收SBOM匹配结果（来自cve_sbom_matcher或build_sbom_report），
# 生成CycloneDX VEX JSON文档。对每个匹配到的CVE，VEX说明是否受影响、
# 不受影响、调查中或已修复。
#
# VEX规范: https://cyclonedx.org/capabilities/vex/
# 最小配置文件——生成必需字段，非完整CycloneDX VEX规范。
# 完整VEX包括产品树、漏洞分析详情等。此为"先给我有效输出"路径。

import json
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

from .cve_models import CVEEntry, Severity

# 按CycloneDX规范的VEX状态
VEX_AFFECTED = "affected"
VEX_NOT_AFFECTED = "not_affected"
VEX_UNDER_INVESTIGATION = "under_investigation"
VEX_FIXED = "fixed"

# "not_affected"条目的理由标签
_NOT_AFFECTED_JUSTIFICATIONS = {
    "component_not_present": "component_not_present",
    "vulnerable_code_not_present": "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path": "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary": "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist": "inline_mitigations_already_exist",
}


def make_vex_document(
    matches: List[Dict],
    product_name: str = "",
    product_version: str = "",
    author: str = "BinMind CVE Analyzer",
) -> Dict[str, Any]:
    """从SBOM匹配结果生成最小CycloneDX VEX文档。

    matches: 来自build_sbom_report()['matches']的匹配字典列表。
      每个匹配至少需含: cve_id, component, component_version,
      severity, description。附加字段（status, justification, action）
      若存在则读取。

    返回适合json.dump()的CycloneDX VEX文档字典。
    """
    bom_version = 1
    serial = str(uuid.uuid4())[:8]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    doc: Dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial}",
        "version": bom_version,
        "metadata": {
            "timestamp": now,
            "tools": [{
                "vendor": "BinMind",
                "name": "CVE Analyzer",
                "version": "1.0",
            }],
            "authors": [{"name": author}],
        },
    }

    if product_name:
        doc["metadata"]["component"] = {
            "type": "application",
            "name": product_name,
            "version": product_version or "unknown",
        }

    # 构建漏洞列表
    vulns: List[Dict] = []
    seen_cves: set = set()

    for m in matches:
        cve_id = m.get("cve_id", "")
        if not cve_id or cve_id in seen_cves:
            continue
        seen_cves.add(cve_id)

        comp_name = m.get("component", m.get("component_name", ""))
        comp_ver = m.get("component_version", m.get("version", ""))
        severity = m.get("severity", "UNKNOWN")
        desc = m.get("description", "")[:500]
        status = m.get("vex_status", m.get("status", VEX_AFFECTED))
        justification = m.get("vex_justification", m.get("justification", ""))
        action = m.get("vex_action", m.get("action", ""))
        cvss_score = m.get("cvss_score")
        epss_score = m.get("epss_score")

        # 规范化状态
        status = status.lower().replace(" ", "_")
        if status not in (VEX_AFFECTED, VEX_NOT_AFFECTED, VEX_UNDER_INVESTIGATION, VEX_FIXED):
            status = VEX_AFFECTED

        vuln_entry: Dict[str, Any] = {
            "id": cve_id,
            "source": {
                "name": "NVD",
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            },
            "ratings": [{
                "severity": severity.lower(),
            }],
            "description": desc,
            "affects": [{
                "ref": f"component:{comp_name}@{comp_ver}",
            }],
            "properties": [{
                "name": "vex:status",
                "value": status,
            }],
        }

        if cvss_score is not None:
            vuln_entry["ratings"][0]["score"] = cvss_score
            vuln_entry["ratings"][0]["method"] = "CVSSv3"

        if epss_score is not None:
            vuln_entry["properties"].append({
                "name": "epss:score",
                "value": str(epss_score),
            })

        # not_affected需要理由
        if status == VEX_NOT_AFFECTED:
            just = justification or "vulnerable_code_not_present"
            vuln_entry["analysis"] = {
                "state": status,
                "detail": _get_justification_label(just),
            }
        elif status == VEX_UNDER_INVESTIGATION:
            vuln_entry["analysis"] = {
                "state": status,
                "detail": action or "Investigation in progress — no determination yet.",
            }
        elif status == VEX_FIXED:
            vuln_entry["analysis"] = {
                "state": "resolved",
                "detail": action or "Patched in a subsequent version.",
            }
        elif action:
            vuln_entry["properties"].append({
                "name": "vex:action",
                "value": action,
            })

        # 按严重度添加修复建议属性
        if status == VEX_AFFECTED:
            recommendation = _severity_recommendation(severity)
            if recommendation:
                vuln_entry["properties"].append({
                    "name": "vex:recommendation",
                    "value": recommendation,
                })

        vulns.append(vuln_entry)

    doc["vulnerabilities"] = vulns
    return doc


def make_vex_from_report(
    report: Dict,
    product_name: str = "",
    product_version: str = "",
) -> Dict[str, Any]:
    """从build_sbom_report()输出字典生成VEX。
    薄包装——从报告中提取'matches'。"""
    matches = report.get("matches", [])
    # 从top_priorities添加VEX状态
    priorities = report.get("top_priorities", [])
    priority_cves = {p["cve_id"]: p for p in priorities}

    return make_vex_document(matches, product_name, product_version)


def export_vex_json(
    matches: List[Dict],
    output_path: str,
    product_name: str = "",
    product_version: str = "",
) -> str:
    """生成VEX并写入JSON文件。返回文件路径。"""
    doc = make_vex_document(matches, product_name, product_version)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
    return output_path


# 辅助函数

def _get_justification_label(key: str) -> str:
    """将简短理由键映射到CycloneDX标签。"""
    if key in _NOT_AFFECTED_JUSTIFICATIONS:
        return _NOT_AFFECTED_JUSTIFICATIONS[key]
    return key  # 原样透传


def _severity_recommendation(severity: str) -> str:
    """按严重度生成修复建议。"""
    s = severity.upper()
    if s == "CRITICAL":
        return "Apply patch immediately. Deploy within 24 hours."
    if s == "HIGH":
        return "Apply patch within 7 days. Monitor for active exploitation."
    if s == "MEDIUM":
        return "Apply patch within 30 days as part of regular update cycle."
    if s == "LOW":
        return "Apply patch at next maintenance window."
    return ""


# 为匹配结果标记VEX状态
# 在运行build_sbom_report后调用以用人工VEX决策标注匹配项。

def annotate_vex_status(
    matches: List[Dict],
    decisions: Dict[str, str],
    justification: str = "",
    action: str = "",
) -> List[Dict]:
    """对匹配列表应用VEX状态决策。

    decisions: cve_id → status字典（affected/not_affected/under_investigation/fixed）
    justification: not_affected条目的全局理由
    action: 全局行动声明

    原地修改匹配项并返回（链式API风格）。"""
    for m in matches:
        cid = m.get("cve_id", "")
        if cid in decisions:
            m["vex_status"] = decisions[cid]
            if justification:
                m["vex_justification"] = justification
            if action:
                m["vex_action"] = action
    return matches


# 自动状态: 启发式VEX决策
# 当无人工决策时，基于严重度、EPSS评分和匹配置信度应用启发式规则

def auto_vex_status(matches: List[Dict]) -> List[Dict]:
    """基于启发式规则自动分配VEX状态。

    规则（按顺序——首次匹配即胜出）:
      - epss_score > 0.1 且 severity >= HIGH → affected
      - severity == CRITICAL → affected
      - match_confidence < 0.6 → under_investigation
      - 其他均 → affected（保守默认）

    使用annotate_vex_status()覆盖人工决策。"""
    for m in matches:
        sev = (m.get("severity") or "").upper()
        epss = m.get("epss_score")
        conf = m.get("match_confidence", 0.0)

        if epss is not None and epss > 0.1 and sev in ("HIGH", "CRITICAL"):
            m["vex_status"] = VEX_AFFECTED
            m["vex_action"] = "Prioritize patching — high EPSS indicates active exploitation likelihood."
        elif sev == "CRITICAL":
            m["vex_status"] = VEX_AFFECTED
            m["vex_action"] = "Critical severity — patch immediately."
        elif conf < 0.6:
            m["vex_status"] = VEX_UNDER_INVESTIGATION
            m["vex_action"] = "Low confidence match — verify against your deployment before acting."
        else:
            m["vex_status"] = VEX_AFFECTED

    return matches
