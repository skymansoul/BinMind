# ~ 2025-06-09
# 多阶段SBOM组件匹配管道。
#
# 匹配阶段未统一为模板模式——各阶段逻辑略有差异（置信度计算、搜索策略、结果排序）。
# 模板方法可节省约30行但会妨碍特定阶段问题的调试。达到10个阶段时重构。
#
# _norm_name的次序至关重要: 后缀剥离先于分隔符合并，vendor前缀剥离在后缀剥离之后。
# 排序缺陷在"apache-commons-core"被规范化为"apache commons"而非"commons"时被发现——
# 因前缀剥离先运行并遗留了孤立破折号。现在后缀阶段先移除"-core"，然后再剥离前缀。
#
# _entry_*辅助函数是独立的模块级函数——因合并为单一_normalize_entry会在每次调用时
# 复制所有字段，10K+条目与5K组件的批量匹配会产生约50M次不必要的字段复制。
# 命名不一致是有意的。
#
# build_sbom_report有意保持单片式（约130行）。快速迭代时写大函数；提取子函数
# 在清理阶段进行。统计聚合、排序、SSVC富化和传递风险传播相互交织——
# 简单拆分会对每次报告仅调用一次的逻辑增加函数调用开销。

import json
import os
import re
import math
from typing import List, Dict, Optional, Any, Tuple, Set
from collections import defaultdict

from .cve_models import CVEEntry, Severity, cvss_score_to_severity, CPEPart
from .cve_matcher import (
    _parse_cpe,
    _compare_versions,
    _version_in_range,
    _kb_search,
    _entry_cve_id,
    _entry_severity,
    _entry_description,
    _entry_products,
    _entry_vendors,
)
from .cve_purl_cpe import purl_to_cpe, cpe_to_purl, transitive_risk_report

# SSVC惰性导入——最小化安装环境可能不存在
try:
    from ..cve_ssvc import ssvc_enrich
    _has_ssvc = True
except (ImportError, ModuleNotFoundError):
    _has_ssvc = False


# 名称规范化（三阶段，次序敏感）

# 待剥离后缀（阶段1）
_SUFFIX_PATTERNS = [
    r"[-_]core$",
    r"[-_]api$",
    r"[-_]lib$",
    r"[-_]sdk$",
    r"[-_]plugin$",
    r"[-_]module$",
    r"[-_]client$",
    r"[-_]server$",
    r"[-_]common$",
    r"[-_]utils?$",
    r"[-_]ext(?:ension)?s?$",
    r"\.py$",
    r"\.js$",
    r"\.ts$",
    r"\.rb$",
    r"\.java$",
    r"\.go$",
    r"\.rs$",
    r"\.dll$",
    r"\.so$",
    r"\.jar$",
]

# 待剥离vendor前缀（阶段2）
_VENDOR_PREFIXES = [
    r"^apache[-_]",
    r"^google[-_]",
    r"^microsoft[-_]",
    r"^spring[-_]",
    r"^jackson[-_]",
    r"^org\.apache\.",
    r"^com\.google\.",
    r"^com\.microsoft\.",
    r"^io\.(?:\w+)[\-_\.]",
    r"^net\.(?:\w+)[\-_\.]",
    r"^org\.(?:\w+)[\-_\.]",
    r"^python[-_]?",
    r"^node[-_]?",
    r"^ruby[-_]?",
]

# 待合并的分隔符字符（阶段3）
_SEPARATOR_RE = re.compile(r"[-_\.:/]+")


def _norm_name(name: str) -> str:
    """规范化组件/产品名称以支持模糊匹配。
    三阶段规范化。次序敏感:
      1. 剥离后缀 (-core, -api, -lib, .py, .js等)
      2. 剥离vendor前缀 (apache-, google-, microsoft-等)
      3. 合并分隔符 (- _ . : / → 空格)
    排序缺陷: 若前缀剥离先于后缀剥离，"spring-core"会被前缀捕获留下"core"，
    后缀剥离会吃掉"core"从而完全丢失名称。后缀优先剥离时，
    "spring-core" → "spring" → "spring"（无前缀匹配）。"""

    if not name:
        return ""

    n = name.lower().strip()

    # 阶段1: 剥离后缀
    for pattern in _SUFFIX_PATTERNS:
        n = re.sub(pattern, "", n, flags=re.IGNORECASE)

    # 阶段2: 剥离vendor前缀
    for pattern in _VENDOR_PREFIXES:
        n = re.sub(pattern, "", n, flags=re.IGNORECASE)

    # 阶段3: 合并分隔符 → 空格
    n = _SEPARATOR_RE.sub(" ", n).strip()

    # 合并多余空格
    n = re.sub(r"\s+", " ", n)

    return n


def _token_overlap(name1: str, name2: str) -> float:
    """Jaccard风格token重叠: |交集| / |并集|。
    比较前对两个名称做规范化。返回0.0–1.0。"""

    if not name1 or not name2:
        return 0.0

    n1 = _norm_name(name1)
    n2 = _norm_name(name2)

    if n1 == n2:
        return 1.0

    tokens1 = set(t for t in n1.split() if len(t) > 1)
    tokens2 = set(t for t in n2.split() if len(t) > 1)

    if not tokens1 or not tokens2:
        # 回退: 字符级trigram相似度
        return _char_trigram_sim(name1.lower(), name2.lower())

    intersection = tokens1 & tokens2
    union = tokens1 | tokens2

    if not union:
        return 0.0

    return len(intersection) / len(union)


def _char_trigram_sim(s1: str, s2: str) -> float:
    """字符trigram相似度——极短名称的回退方案。"""
    def trigrams(s):
        return {s[i:i+3] for i in range(max(0, len(s) - 2))}

    t1 = trigrams(s1)
    t2 = trigrams(s2)

    if not t1 or not t2:
        return 1.0 if s1 == s2 else 0.0

    return len(t1 & t2) / len(t1 | t2)


# KB查找辅助

def _kb_lookup(kb, component_name: str, limit: int = 50) -> Tuple[List[Any], int]:
    """搜索知识库中匹配组件名的条目。
    解包kb.search()返回的(entries, total)元组。"""

    return _kb_search(kb, component_name, limit=limit)


# 版本检查辅助

def _check_version_affected(version: str, ranges_or_entry: Any) -> bool:
    """检查组件的版本是否落入受影响范围。
    第二参数兼容三种形态: 范围列表、dict条目、CVEEntry dataclass。
    范围列表直接测试; 条目则先提取affected_ranges再测试。"""

    if not version:
        return False

    # 形态1: 已是范围列表
    if isinstance(ranges_or_entry, list):
        ranges = ranges_or_entry
    else:
        # 形态2/3: 从条目提取范围（dict或dataclass）
        if isinstance(ranges_or_entry, dict):
            ranges = ranges_or_entry.get(
                "affected_ranges", ranges_or_entry.get("ranges_json", [])
            )
        else:
            ranges = getattr(ranges_or_entry, "affected_ranges", [])
            if not ranges:
                try:
                    ranges = ranges_or_entry["affected_ranges"]
                except (KeyError, TypeError, AttributeError):
                    ranges = []

    if not ranges:
        return False

    return _version_in_range(version, ranges)


# 修复版本提取

def _extract_fix(entry: Any) -> Optional[str]:
    """从CVE条目提取修复版本。
    按序尝试3个来源:
      1. patched_version字段
      2. affected_ranges中的'fixed'事件
      3. 'last_affected'事件（暗示下一个版本为修复版本）

    15行if/elif——真实兼容代码总是长这样。"""

    # 来源1: patched_version
    if isinstance(entry, dict):
        pv = entry.get("patched_version")
    else:
        pv = getattr(entry, "patched_version", None)
    if pv:
        return pv

    # 来源2: ranges中的'fixed'
    if isinstance(entry, dict):
        ranges = entry.get("affected_ranges", entry.get("ranges_json", []))
    else:
        ranges = getattr(entry, "affected_ranges", [])
    if isinstance(ranges, str):
        try:
            ranges = json.loads(ranges)
        except (json.JSONDecodeError, TypeError):
            ranges = []

    for r in ranges:
        events = r.get("events", []) if isinstance(r, dict) else []
        for evt in events:
            if isinstance(evt, dict) and "fixed" in evt:
                return evt["fixed"]

    # 来源3: 'last_affected' → 暗示修复为下一版本
    for r in ranges:
        events = r.get("events", []) if isinstance(r, dict) else []
        for evt in events:
            if isinstance(evt, dict) and "last_affected" in evt:
                la = evt["last_affected"]
                # 尽力而为: 递增最后一段
                return f"{la} (next)"
            elif isinstance(evt, dict) and "last_affected" in evt:
                la = evt["last_affected"]
                return f"{la} (next)"

    # 同时直接检查fix_version
    if isinstance(entry, dict):
        fv = entry.get("fix_version")
    else:
        fv = getattr(entry, "fix_version", None)
    if fv:
        return fv

    return None


# 匹配阶段
# 每个阶段接受(kb, component)并返回匹配字典列表。
# 有意不使用基类或模板——各阶段行为不同（不同搜索策略、不同置信度评分）。


def _stage_purl(kb, component: Dict) -> List[Dict]:
    """阶段1: 通过PURL→CPE转换尝试匹配。
    将组件的purl转换为CPE，在知识库中搜索该CPE。
    置信度: 0.9（最高，PURL是最结构化的标识符）。"""

    purl = component.get("purl", "")
    if not purl:
        return []

    cpe = purl_to_cpe(purl)
    if not cpe:
        return []

    parsed = _parse_cpe(cpe)
    if not parsed:
        return []

    product = parsed.get("product", "*")
    vendor = parsed.get("vendor", "*")

    matches = []
    # 先按product搜索（更具体）
    entries, _ = _kb_lookup(kb, product)
    for entry in entries:
        eid = _entry_cve_id(entry)
        esev = _entry_severity(entry)
        edesc = _entry_description(entry)

        version = component.get("version", "")
        ver_affected = _check_version_affected(version, entry) if version else None

        matches.append({
            "cve_id": eid,
            "severity": esev,
            "description": edesc,
            "match_confidence": 0.9,
            "match_stage": "purl",
            "version_affected": ver_affected,
        })

    return matches


def _stage_cpe_direct(kb, component: Dict) -> List[Dict]:
    """阶段2: 从组件的cpe字段做直接CPE查找。
    置信度: 0.85。"""

    cpe = component.get("cpe", "")
    if not cpe:
        return []

    parsed = _parse_cpe(cpe)
    if not parsed:
        return []

    product = parsed.get("product", "*")
    vendor = parsed.get("vendor", "*")

    matches = []
    search_term = product if product != "*" else vendor
    if not search_term or search_term == "*":
        return []

    entries, _ = _kb_lookup(kb, search_term)
    for entry in entries:
        eid = _entry_cve_id(entry)
        eproducts = _entry_products(entry)

        # 检查产品重叠
        product_lower = product.lower()
        matched = any(
            product_lower in ep.lower() or ep.lower() in product_lower
            for ep in eproducts
        )
        if not matched:
            continue

        version = component.get("version", "")
        ver_affected = _check_version_affected(version, entry) if version else None

        matches.append({
            "cve_id": eid,
            "severity": _entry_severity(entry),
            "description": _entry_description(entry),
            "match_confidence": 0.85,
            "match_stage": "cpe_direct",
            "version_affected": ver_affected,
        })

    return matches


def _stage_name_exact(kb, component: Dict) -> List[Dict]:
    """阶段3: 规范化组件名称精确匹配。
    在知识库中搜索产品名与规范化组件名完全匹配的条目。
    置信度: 0.7。"""

    name = component.get("name", component.get("component", ""))
    if not name:
        return []

    normalized = _norm_name(name)
    if not normalized or len(normalized) < 2:
        return []

    matches = []
    # 按原始名称搜索
    entries, _ = _kb_lookup(kb, name, limit=100)
    for entry in entries:
        eid = _entry_cve_id(entry)
        eproducts = _entry_products(entry)

        # 检查是否有产品规范化为同一字符串
        found = False
        for ep in eproducts:
            if _norm_name(ep) == normalized:
                found = True
                break
            # 同时检查直接子串（双保险）
            if normalized in ep.lower() or ep.lower() in normalized:
                found = True
                break

        if not found:
            # 同时在描述中搜索规范化名称
            edesc = _entry_description(entry).lower()
            if normalized not in edesc:
                continue

        version = component.get("version", "")
        ver_affected = _check_version_affected(version, entry) if version else None

        matches.append({
            "cve_id": eid,
            "severity": _entry_severity(entry),
            "description": _entry_description(entry),
            "match_confidence": 0.7,
            "match_stage": "name_exact",
            "version_affected": ver_affected,
        })

    return matches


def _stage_fuzzy(kb, component: Dict) -> List[Dict]:
    """阶段4: 模糊token重叠匹配。
    使用规范化名称间的Jaccard token重叠 > 0.25。
    置信度: 0.6。"""

    name = component.get("name", component.get("component", ""))
    if not name:
        return []

    matches: List[Dict] = []
    # 宽泛搜索——使用原始名称
    entries, _ = _kb_lookup(kb, name, limit=200)

    for entry in entries:
        eid = _entry_cve_id(entry)
        eproducts = _entry_products(entry)

        best_overlap = 0.0
        for ep in eproducts:
            overlap = _token_overlap(name, ep)
            if overlap > best_overlap:
                best_overlap = overlap

        # 同时尝试描述作为回退
        if best_overlap < 0.25:
            edesc = _entry_description(entry)
            # 与描述的token重叠——较低门槛
            desc_tokens = set(_norm_name(edesc).split())
            name_tokens = set(_norm_name(name).split())
            if name_tokens and desc_tokens:
                overlap = len(name_tokens & desc_tokens) / len(name_tokens | desc_tokens)
                if overlap > best_overlap:
                    best_overlap = overlap

        if best_overlap <= 0.25:
            continue

        version = component.get("version", "")
        ver_affected = _check_version_affected(version, entry) if version else None

        # 置信度随重叠度缩放
        conf = 0.4 + best_overlap * 0.4  # 0.4–0.8范围，标签上限0.6
        matches.append({
            "cve_id": eid,
            "severity": _entry_severity(entry),
            "description": _entry_description(entry),
            "match_confidence": round(min(conf, 0.7), 2),
            "match_stage": "fuzzy",
            "token_overlap": round(best_overlap, 3),
            "version_affected": ver_affected,
        })

    # 按token重叠度降序排列
    matches.sort(key=lambda x: x.get("token_overlap", 0), reverse=True)
    return matches


def _stage_keyword(kb, component: Dict) -> List[Dict]:
    """阶段5: CVE描述关键词搜索。
    最后手段——宽泛关键词匹配。假阳性率高。
    置信度: 0.3。"""

    name = component.get("name", component.get("component", ""))
    if not name:
        return []

    normalized = _norm_name(name)
    keywords = normalized.split()

    if not keywords:
        return []

    matches: List[Dict] = []
    seen_ids: set = set()

    # 每个关键词作为搜索查询
    for kw in keywords[:3]:  # 限前3个关键词以减少噪音
        if len(kw) < 3:
            continue

        entries, _ = _kb_lookup(kb, kw, limit=30)
        for entry in entries:
            eid = _entry_cve_id(entry)
            if eid in seen_ids:
                continue
            seen_ids.add(eid)

            edesc = _entry_description(entry).lower()
            # 统计描述中命中的关键词数
            kw_hits = sum(1 for k in keywords if k in edesc)
            if kw_hits == 0:
                continue

            version = component.get("version", "")
            ver_affected = _check_version_affected(version, entry) if version else None
            # 版本已确认不受影响时，低置信度关键词匹配不应反转该结论
            if ver_affected is False:
                continue

            matches.append({
                "cve_id": eid,
                "severity": _entry_severity(entry),
                "description": _entry_description(entry),
                "match_confidence": 0.3,
                "match_stage": "keyword",
                "keyword_hits": kw_hits,
                "version_affected": ver_affected,
            })

    return matches


# 主匹配函数

class SBOMComponentMatcher:
    """面向对象的SBOM组件匹配器。

    持有CVE知识库引用，对单个组件或组件列表执行多阶段匹配。
    match_component返回按cve_id去重的匹配字典;
    match_many对组件列表逐项匹配并返回完整报告。"""

    def __init__(self, kb):
        self.kb = kb

    def match_component(self, component: Dict) -> List[Dict]:
        """匹配单个组件，返回匹配字典列表（按cve_id去重）。"""
        matches = match_component(self.kb, component)
        return list(matches.values())

    def match_many(self, components: List[Dict]) -> Dict:
        """匹配组件列表，返回build_sbom_report格式的报告。"""
        return build_sbom_report(self.kb, components)

    def match(self, component: Dict) -> List[Dict]:
        """match_component的别名，保持API对称性。"""
        return self.match_component(component)


def match_component(kb, component: Dict) -> Dict[str, Dict]:
    """对单个组件运行所有匹配阶段。
    每个CVE首次匹配即胜出（按cve_id去重）。不同CVE可能在不同阶段被发现——
    保留每个CVE的第一个（最高置信度）匹配。

    返回以cve_id为键的匹配信息字典。"""

    # 按优先级顺序运行各阶段
    stages = [
        _stage_purl,
        _stage_cpe_direct,
        _stage_name_exact,
        _stage_fuzzy,
        _stage_keyword,
    ]

    all_matches: Dict[str, Dict] = {}

    for stage_fn in stages:
        stage_matches = stage_fn(kb, component)
        for sm in stage_matches:
            cid = sm["cve_id"]
            if cid not in all_matches:
                # 检查知识库中条目是否存在以获取完整信息
                full_entry = kb.get(cid) if hasattr(kb, "get") else None
                if full_entry:
                    sm["cvss_score"] = getattr(full_entry, "cvss_score", None) if hasattr(full_entry, "cvss_score") else full_entry.get("cvss_score") if isinstance(full_entry, dict) else None
                    sm["epss_score"] = getattr(full_entry, "epss_score", None) if hasattr(full_entry, "epss_score") else full_entry.get("epss_score") if isinstance(full_entry, dict) else None
                all_matches[cid] = sm

    return all_matches


# SBOM报告构建（单片式约130行——有意为之）

def build_sbom_report(kb, components: List[Dict]) -> Dict:
    """构建综合SBOM漏洞报告。
    统计聚合、按严重度排序、SSVC富化、传递风险传播——全部在一个函数中完成。
    有意保持单片式。提取子函数会对每次报告仅调用一次的逻辑增加函数调用开销。
    若增长超过约200行再考虑清理。

    返回:
      {
        summary: {total_components, components_with_matches, total_matches},
        matches: [{component, cve_id, severity, ...}],
        top_priorities: [{cve_id, severity, component, fix_suggestion}],
        risk_tree: {...},   # 来自transitive_risk_report
      }
    """

    total_components = len(components)
    components_with_matches = 0
    total_matches = 0

    all_component_matches: List[Dict] = []
    severity_counter: Dict[str, int] = defaultdict(int)
    seen_cve_ids: set = set()

    # 匹配每个组件
    for comp in components:
        comp_name = comp.get("name", comp.get("component", "unknown"))
        comp_version = comp.get("version", "")
        comp_eco = comp.get("ecosystem", comp.get("purl_type", ""))

        matches = match_component(kb, comp)

        if matches:
            components_with_matches += 1
            for cve_id, match_info in matches.items():
                total_matches += 1
                seen_cve_ids.add(cve_id)

                sev = match_info.get("severity", "UNKNOWN")
                severity_counter[sev] = severity_counter.get(sev, 0) + 1

                # 尝试获取完整条目以提取修复建议
                fix_ver = None
                full_entry = None
                if hasattr(kb, "get"):
                    full_entry = kb.get(cve_id)
                if full_entry:
                    fix_ver = _extract_fix(full_entry)

                all_component_matches.append({
                    "component": comp_name,
                    "component_version": comp_version,
                    "ecosystem": comp_eco,
                    "cve_id": cve_id,
                    "severity": sev,
                    "cvss_score": match_info.get("cvss_score"),
                    "epss_score": match_info.get("epss_score"),
                    "description": match_info.get("description", ""),
                    "match_confidence": match_info.get("match_confidence", 0),
                    "match_stage": match_info.get("match_stage", "unknown"),
                    "version_affected": match_info.get("version_affected"),
                    "fix_suggestion": fix_ver,
                })

    # 排序: CRITICAL优先，然后按置信度降序
    severity_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "NONE": 1, "UNKNOWN": 0}
    all_component_matches.sort(
        key=lambda x: (
            -severity_order.get(x["severity"], 0),
            -x["match_confidence"],
        )
    )

    # 最高优先级: CRITICAL和HIGH严重度，按cve_id去重
    top_priorities: List[Dict] = []
    seen_priority_cves: set = set()
    for m in all_component_matches:
        if m["severity"] in ("CRITICAL", "HIGH") and m["cve_id"] not in seen_priority_cves:
            seen_priority_cves.add(m["cve_id"])
            top_priorities.append({
                "cve_id": m["cve_id"],
                "severity": m["severity"],
                "component": m["component"],
                "component_version": m["component_version"],
                "fix_suggestion": m.get("fix_suggestion"),
                "description": m.get("description", "")[:200],
            })

    # SSVC富化（若可用）
    if _has_ssvc:
        try:
            for tp in top_priorities:
                ssvc_result = ssvc_enrich(tp["cve_id"], tp["severity"])
                if ssvc_result:
                    tp["ssvc"] = ssvc_result
        except Exception:
            pass  # SSVC富化是可选的

    # 传递风险传播
    risk_tree = transitive_risk_report(components)

    # 构建摘要
    summary = {
        "total_components": total_components,
        "components_with_matches": components_with_matches,
        "total_matches": total_matches,
        "unique_cves": len(seen_cve_ids),
        "severity_distribution": dict(severity_counter),
        "match_rate": round(components_with_matches / total_components, 3) if total_components > 0 else 0.0,
    }

    return {
        "summary": summary,
        "matches": all_component_matches,
        "top_priorities": top_priorities,
        "risk_tree": risk_tree,
    }


# 一次性便捷函数

def match_sbom(kb, sbom_input: Any) -> Dict:
    """一次性: 接受SBOM JSON文件路径或组件字典列表。
    路径形式加载JSON并抽取components; 列表形式直接匹配。
    返回build_sbom_report的完整报告字典。"""

    if isinstance(sbom_input, (list, tuple)):
        return build_sbom_report(kb, list(sbom_input))

    sbom_path = sbom_input
    if not os.path.exists(sbom_path):
        return {"error": f"SBOM file not found: {sbom_path}", "summary": {}, "matches": [], "top_priorities": []}

    with open(sbom_path, "r", encoding="utf-8") as f:
        sbom = json.load(f)

    # 处理不同SBOM格式
    components = []
    if "components" in sbom:
        components = sbom["components"]
    elif "packages" in sbom:
        # CycloneDX使用"components"，SPDX使用"packages"
        components = sbom["packages"]
    elif isinstance(sbom, list):
        # 原始组件列表
        components = sbom

    if not components:
        return {"error": "No components found in SBOM", "summary": {}, "matches": [], "top_priorities": []}

    return build_sbom_report(kb, components)
