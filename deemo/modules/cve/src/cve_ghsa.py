# ~ 2026-08-25
# GitHub Security Advisory (GHSA) 集成。
# GHSA 条目补充 NVD 数据 — 部分公告在 GitHub 上比 NVD 发布早数天到数周。
# 合并逻辑选取最佳描述（最长非空）并合并两源的参考链接。
#
# source_confidence 字段原先在 merge_entries() 的 return 语句之后 —
# 函数末尾编辑的典型错误。已移至 return 之前。
#
# 8月24-25日: 最终通过 Link header 解析实现了分页。GitHub API 每页最多
# 返回 100 条，之前静默截断。同时为无 CVE ID 的 GHSA 条目
# (如 GHSA-xxxx-xxxx-xxxx) 增加了基于描述的重复检测。这些条目现可
# 通过描述重叠而非仅 CVE ID 相等与 NVD 条目模糊匹配。

import json
import re
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple

from .cve_models import CVEEntry

# GHSA API 基础地址
_GHSA_API_BASE = "https://api.github.com/advisories"

# 可选环境变量用于 github token (更高速率限制)
_GHSA_TOKEN = None
try:
    import os
    _GHSA_TOKEN = os.environ.get("GITHUB_TOKEN") or os.environ.get("GHSA_TOKEN")
except Exception:
    pass

# 最大页数 — 安全上限，实际查询很少超过 20 页
_MAX_PAGES = 50

# 页面间延迟用于速率限制
# 无认证 60 次/小时 → 1 次/分钟。有 token: 5000/小时 → 0.72s 延迟
_PAGE_DELAY = 1.0 if _GHSA_TOKEN is None else 0.8


# GHSA 特定严重程度映射
# GitHub 使用自己的等级 — 映射到我们的 Severity 枚举
_GHSA_SEVERITY_MAP = {
    "LOW": "LOW",
    "MODERATE": "MEDIUM",
    "HIGH": "HIGH",
    "CRITICAL": "CRITICAL",
    "NONE": "NONE",
}


@dataclass
class GHSAEntry:
    """GitHub Security Advisory 条目 — 类似 CVEEntry 但含 GHSA 特定字段。"""
    ghsa_id: str
    cve_id: Optional[str] = None
    summary: str = ""
    description: str = ""
    severity: str = "UNKNOWN"
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    identifiers: List[Dict[str, str]] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    permalink: str = ""
    published_at: Optional[str] = None
    updated_at: Optional[str] = None
    withdrawn_at: Optional[str] = None
    vulnerabilities: List[Dict] = field(default_factory=list)
    ecosystem: str = ""
    package_name: str = ""
    source: str = "ghsa"
    source_confidence: float = 0.8  # GHSA 通常质量高但非权威来源

    @classmethod
    def from_ghsa_json(cls, data: Dict) -> "GHSAEntry":
        """解析 GHSA API 响应 dict 为 GHSAEntry。"""
        ghsa_id = data.get("ghsa_id", "")
        cve_id = data.get("cve_id") or None

        # GitHub advisory 同时有 summary 和 description
        summary = data.get("summary", "") or ""
        description = data.get("description", "") or ""

        severity = _GHSA_SEVERITY_MAP.get(
            (data.get("severity") or "").upper(), "UNKNOWN"
        )

        cvss_score = None
        cvss_vector = None
        if data.get("cvss"):
            cvss_data = data["cvss"]
            cvss_score = cvss_data.get("score")
            cvss_vector = cvss_data.get("vector_string")

        identifiers = data.get("identifiers", [])

        references = []
        for ref in data.get("references", []):
            url = ref.get("url", "")
            if url:
                references.append(url)

        permalink = data.get("html_url", data.get("permalink", ""))
        published_at = data.get("published_at")
        updated_at = data.get("updated_at")
        withdrawn_at = data.get("withdrawn_at")

        vulnerabilities = data.get("vulnerabilities", [])

        # 从首个 vulnerability 提取 ecosystem/package
        ecosystem = ""
        package_name = ""
        if vulnerabilities:
            vuln = vulnerabilities[0]
            pkg = vuln.get("package", {})
            ecosystem = pkg.get("ecosystem", "")
            package_name = pkg.get("name", "")

        return cls(
            ghsa_id=ghsa_id,
            cve_id=cve_id,
            summary=summary,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            identifiers=identifiers,
            references=references,
            permalink=permalink,
            published_at=published_at,
            updated_at=updated_at,
            withdrawn_at=withdrawn_at,
            vulnerabilities=vulnerabilities,
            ecosystem=ecosystem,
            package_name=package_name,
        )

    def to_cve_entry(self) -> Optional[CVEEntry]:
        """转换为 CVEEntry 格式。无 CVE ID 时返回 None。"""
        if not self.cve_id:
            return None

        # 优先 description 而非 summary（description 通常更详细）
        desc = self.description if self.description else self.summary

        return CVEEntry(
            cve_id=self.cve_id,
            description=desc,
            severity=self.severity,
            cvss_score=self.cvss_score,
            cvss_vector=self.cvss_vector,
            references=self.references,
            published_date=self.published_at,
            last_modified_date=self.updated_at,
            source="ghsa",
            source_confidence=self.source_confidence,
        )


# 内部: 解析 github link header (RFC 5988)
# github 返回: <url>; rel="next", <url>; rel="last"
# 需提取 "next" url 以遍历页面
_LINK_RE = re.compile(r'<([^>]+)>\s*;\s*rel="([^"]+)"')


def _parse_next_link(link_header: str) -> Optional[str]:
    """从 GitHub Link header 提取 'next' URL。无下一页时返回 None。"""
    if not link_header:
        return None
    parts = link_header.split(",")
    for part in parts:
        m = _LINK_RE.search(part.strip())
        if m and m.group(2) == "next":
            return m.group(1)
    return None


def _ghsa_request(url: str) -> Tuple[List[Dict], Optional[str]]:
    """单次 GHSA API 请求。返回 (items_list, next_url_or_None)。
    若可用则使用 GitHub token (更高速率限制)。"""
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "BinMind-CVE/1.0",
    }
    if _GHSA_TOKEN:
        headers["Authorization"] = f"Bearer {_GHSA_TOKEN}"

    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        link_header = resp.headers.get("Link", "")
        next_url = _parse_next_link(link_header)

    items = data if isinstance(data, list) else []
    return items, next_url


# 搜索
def search_ghsa(
    query: str,
    ecosystem: Optional[str] = None,
    limit: int = 100,
    max_pages: int = _MAX_PAGES,
) -> List[GHSAEntry]:
    """搜索 GitHub Advisory Database，含完整分页。
    遍历 Link headers 获取所有页面，直到 limit 或 max_pages。
    页面间延迟以遵守速率限制。

    max_pages 限制获取页数 — 安全阀。
    limit 是期望的结果总数（非每页数）。"""
    params_parts = [f"type=reviewed"]

    if query:
        params_parts.append(f"q={urllib.request.quote(query)}")

    if ecosystem:
        params_parts.append(f"ecosystem={urllib.request.quote(ecosystem)}")

    # per_page 始终为 100 (API 最大值)，使用 limit 控制总数
    params_parts.append("per_page=100")

    base_url = f"{_GHSA_API_BASE}?{'&'.join(params_parts)}"
    results: List[GHSAEntry] = []
    current_url: Optional[str] = base_url
    pages_fetched = 0

    while current_url is not None and pages_fetched < max_pages:
        if pages_fetched > 0:
            time.sleep(_PAGE_DELAY)

        try:
            items, next_url = _ghsa_request(current_url)
        except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as e:
            print(f"[GHSA] request failed at page {pages_fetched + 1}: {e}")
            break

        for item in items:
            try:
                results.append(GHSAEntry.from_ghsa_json(item))
            except Exception:
                pass

        pages_fetched += 1
        current_url = next_url

        # 结果足够时停止
        if len(results) >= limit:
            break

    return results[:limit]


# search_advisories: 搜索 + 可选 NVD 去重
# 主要入口: "查找生态系统 X 的所有公告并与 KB 已有数据合并"

def search_and_dedup(
    kb,
    query: str,
    ecosystem: Optional[str] = None,
    limit: int = 200,
) -> Dict[str, Any]:
    """搜索 GHSA，然后通过 CVE ID + 描述重叠与 KB 去重。
    返回:
      {merged: [...], ghsa_only: [...], nvd_only: [...], stats: {...}}

    有 CVE ID 的 GHSA 条目与 KB 条目 1:1 匹配。
    无 CVE ID 的 GHSA 条目通过描述重叠模糊匹配
    (归一化 token 的 Jaccard > 0.6)。未匹配的 GHSA 专有条目
    放入 ghsa_only 供人工审核。
    """
    ghsa_entries = search_ghsa(query, ecosystem=ecosystem, limit=limit)

    # 获取匹配同一查询的所有 KB 条目
    kb_entries, _ = kb.search(query=query, limit=limit) if hasattr(kb, 'search') else ([], 0)

    merged: List[Dict] = []
    ghsa_only: List[Dict] = []
    matched_kb_ids: set = set()

    # 第一遍: 按 CVE ID 匹配
    kb_by_cve: Dict[str, Any] = {}
    for e in kb_entries:
        cid = e.cve_id if hasattr(e, 'cve_id') else e.get('cve_id', '')
        if cid:
            kb_by_cve[cid] = e

    for ghsa in ghsa_entries:
        if ghsa.cve_id and ghsa.cve_id in kb_by_cve:
            nvd_entry = kb_by_cve[ghsa.cve_id]
            merged_entry = merge_entries(ghsa, nvd_entry)
            merged.append(merged_entry.to_dict())
            matched_kb_ids.add(ghsa.cve_id)
        else:
            ghsa_only.append({
                "ghsa_id": ghsa.ghsa_id,
                "cve_id": ghsa.cve_id,
                "summary": ghsa.summary,
                "description": (ghsa.description or ghsa.summary)[:300],
                "severity": ghsa.severity,
                "ecosystem": ghsa.ecosystem,
                "package": ghsa.package_name,
                "has_cve": ghsa.cve_id is not None,
                "permalink": ghsa.permalink,
            })

    # 第二遍: GHSA 专有条目 (无 CVE ID)，对未匹配的 KB 条目
    # 尝试描述重叠。阈值经验调参。
    still_unmatched: List[Dict] = []
    for gonly in ghsa_only:
        if gonly["has_cve"]:
            still_unmatched.append(gonly)
            continue

        ghsa_desc = gonly["description"]
        best_score = 0.0
        best_kb_entry = None

        for kb_entry in kb_entries:
            cid = kb_entry.cve_id if hasattr(kb_entry, 'cve_id') else kb_entry.get('cve_id', '')
            if cid in matched_kb_ids:
                continue
            kb_desc = kb_entry.description if hasattr(kb_entry, 'description') else kb_entry.get('description', '')
            if not kb_desc:
                continue
            score = _desc_overlap(ghsa_desc, kb_desc)
            if score > best_score and score > 0.6:
                best_score = score
                best_kb_entry = kb_entry

        if best_kb_entry is not None:
            cid = best_kb_entry.cve_id if hasattr(best_kb_entry, 'cve_id') else best_kb_entry.get('cve_id', '')
            gonly["matched_cve"] = cid
            gonly["match_confidence"] = round(best_score, 3)
            matched_kb_ids.add(cid)
            still_unmatched.append(gonly)
        else:
            still_unmatched.append(gonly)

    # 未匹配的 NVD 条目
    nvd_only = [
        e.cve_id if hasattr(e, 'cve_id') else e.get('cve_id', '')
        for e in kb_entries
        if (e.cve_id if hasattr(e, 'cve_id') else e.get('cve_id', '')) not in matched_kb_ids
    ]

    return {
        "merged": merged,
        "ghsa_only": still_unmatched,
        "nvd_only": nvd_only,
        "stats": {
            "total_ghsa": len(ghsa_entries),
            "total_kb": len(kb_entries),
            "merged_count": len(merged),
            "ghsa_only_count": len(still_unmatched),
            "nvd_only_count": len(nvd_only),
        },
    }


# 跨源去重的描述相似度
# 简单的 token 重叠 — 不如 SBOM 匹配器的 _norm_name 精细
# 但无需那么精细。正在比较漏洞描述而非包名。

def _desc_overlap(desc1: str, desc2: str) -> float:
    """两个描述词 token 的 Jaccard 相似度。
    均转小写，按非字母数字分割，每 token 至少 3 字符。
    返回 0.0–1.0。"""
    if not desc1 or not desc2:
        return 0.0

    def tokens(s: str) -> set:
        words = re.split(r'[^a-z0-9]+', s.lower())
        return {w for w in words if len(w) >= 3}

    t1 = tokens(desc1)
    t2 = tokens(desc2)
    if not t1 or not t2:
        return 0.0
    return len(t1 & t2) / len(t1 | t2)


# 以不同名称暴露原始分页搜索
# 使 search_ghsa 的现有调用方不受影响
fetch_ghsa_paginated = search_ghsa


# 合并逻辑
def merge_entries(ghsa_entry: GHSAEntry, nvd_entry: CVEEntry) -> CVEEntry:
    """将 GHSA 和 NVD 数据合并为单个 CVEEntry。
    选取最佳描述（最长非空），合并参考链接。
    source_confidence 在 return 之前设置 — 原本在 return 之后，
    为不可达代码，修复为前移。"""
    # 选取最佳描述
    # GHSA 描述通常更详细（含影响分析）
    # 但 NVD 描述更标准化
    nvd_desc = nvd_entry.description or ""
    ghsa_desc = ghsa_entry.description or ghsa_entry.summary or ""

    if len(ghsa_desc) > len(nvd_desc):
        description = ghsa_desc
        desc_source = "ghsa"
    else:
        description = nvd_desc
        desc_source = "nvd"

    # 合并参考链接 (去重)
    refs = list(set(nvd_entry.references + ghsa_entry.references))

    # 选取最佳 CVSS — 优先 NVD (更权威)，除非缺失
    score = nvd_entry.cvss_score or ghsa_entry.cvss_score
    vector = nvd_entry.cvss_vector or ghsa_entry.cvss_vector
    severity = nvd_entry.severity if nvd_entry.severity != "UNKNOWN" else ghsa_entry.severity

    # source_confidence: 两源平均，偏向 NVD
    # 原本在 return 之后 — 不可达。修复为移动到此处。
    source_confidence = (nvd_entry.source_confidence * 0.6 + ghsa_entry.source_confidence * 0.4)

    merged = CVEEntry(
        cve_id=nvd_entry.cve_id,
        description=description,
        severity=severity,
        cvss_score=score,
        cvss_vector=vector,
        exploitability_score=nvd_entry.exploitability_score,
        impact_score=nvd_entry.impact_score,
        products=nvd_entry.products,
        vendors=nvd_entry.vendors,
        cpe_matches=nvd_entry.cpe_matches,
        cwes=nvd_entry.cwes,
        published_date=nvd_entry.published_date or ghsa_entry.published_at,
        last_modified_date=nvd_entry.last_modified_date or ghsa_entry.updated_at,
        references=refs,
        epss_score=nvd_entry.epss_score,
        epss_percentile=nvd_entry.epss_percentile,
        source="nvd+ghsa",
        source_confidence=source_confidence,
    )
    return merged


def cross_source_coverage(
    nvd_entries: List[CVEEntry],
    ghsa_entries: List[GHSAEntry],
) -> Dict[str, Any]:
    """量化 GHSA 在 NVD 基础上的增量价值。
    返回 {only_nvd, only_ghsa, both, coverage_pct}。"""
    nvd_ids = {e.cve_id for e in nvd_entries}
    # GHSA 条目可能无 CVE ID (部分为 GHSA 专有)
    ghsa_cve_ids = {e.cve_id for e in ghsa_entries if e.cve_id}

    only_nvd = list(nvd_ids - ghsa_cve_ids)
    only_ghsa = list(ghsa_cve_ids - nvd_ids)
    both = list(nvd_ids & ghsa_cve_ids)

    total = len(nvd_ids | ghsa_cve_ids)
    coverage_pct = len(both) / total * 100 if total > 0 else 0.0

    return {
        "only_nvd": only_nvd,
        "only_ghsa": only_ghsa,
        "both": both,
        "total_unique": total,
        "coverage_pct": round(coverage_pct, 2),
    }


def merge_with_confidence(entries_list: List[CVEEntry]) -> List[CVEEntry]:
    """为调试跨源差异标注字段来源。
    每个条目的 source_confidence 根据填充的字段设置。
    在调试合并条目为何选取某源而非另一源的数据时有帮助。"""
    for entry in entries_list:
        # 从基础置信度开始
        confidence = entry.source_confidence

        # 若条目有 NVD 质量的元数据，提升置信度
        if entry.cvss_vector and entry.cvss_score is not None:
            confidence = max(confidence, 0.9)
        if entry.cwes:
            confidence = max(confidence, 0.85)
        if not entry.description:
            confidence = 0.3  # 无描述 = 低质量

        entry.source_confidence = min(confidence, 1.0)

    return entries_list
