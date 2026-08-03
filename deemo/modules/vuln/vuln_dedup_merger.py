# CRDT风格多源漏洞归并引擎
# 三趟匹配链：CVE ID精确 → 函数名+类型 → 地址邻近(±8字节容差)
# 冲突按字段优先级规则消解，产出归一化合并结果

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Set
from enum import Enum
import re


class MatchConfidence(str, Enum):
    EXACT = "exact"     # CVE ID完全一致
    HIGH = "high"       # 函数名+漏洞类型一致
    MEDIUM = "medium"   # 地址邻近匹配
    NONE = "none"


@dataclass
class MergedFinding:
    """归并后的单条漏洞记录"""
    cve_id: str = ""
    vuln_type: str = ""
    function_name: str = ""
    address: int = 0
    severity: str = ""
    cvss_score: float = 0.0
    description: str = ""
    file_path: str = ""
    line_number: int = 0
    sources: List[str] = field(default_factory=list)  # 数据来源标识
    source_data: Dict[str, Dict] = field(default_factory=dict)
    match_confidence: str = "none"


@dataclass
class MergeConflict:
    """归并冲突——同漏洞多源描述不一致"""
    field: str
    values: Dict[str, Any]  # source → value
    resolved_value: Any
    resolution_method: str  # 消解策略标识


@dataclass
class MergeResult:
    """多源归并完整输出"""
    merged: List[MergedFinding] = field(default_factory=list)
    conflicts: List[MergeConflict] = field(default_factory=list)
    stats: Dict[str, int] = field(default_factory=dict)
    unmatched: Dict[str, List[Dict]] = field(default_factory=dict)
    total_input: int = 0


# 字段置信度优先级——IDA函数名更可靠，Ghidra类型推断更强
_FIELD_PRECEDENCE = {
    "function_name": ["ida", "ghidra", "r2"],
    "severity": ["ghidra", "ida", "r2"],
    "cvss_score": ["ghidra", "ida", "r2"],
    "description": ["ghidra", "ida", "r2"],
    "vuln_type": ["ghidra", "ida", "r2"],
    "address": ["ida", "ghidra", "r2"],
    "file_path": ["ghidra", "ida", "r2"],
    "line_number": ["ghidra", "ida", "r2"],
    "cve_id": ["ghidra", "ida", "r2"],
}


class VulnDedupMerger:
    """多源漏洞发现归并器。

    核心入口:
        merge_from_sources(ghidra_findings, ida_findings, r2_findings) → MergeResult
        执行三趟匹配+CRDT字段归并，消除多工具分析重复。
    """

    def __init__(self, address_tolerance: int = 8):
        self.address_tolerance = address_tolerance
        self._conflicts: List[MergeConflict] = []

    # 字段规范化——统一各工具输出的异构格式
    @staticmethod
    def _norm(finding: Dict) -> Dict:
        nf = dict(finding)
        nf.setdefault("cve_id", "")
        nf.setdefault("vuln_type", "")
        nf.setdefault("function_name", "")
        nf.setdefault("severity", "")
        nf.setdefault("cvss_score", 0.0)
        addr = nf.get("address", nf.get("addr", nf.get("offset", 0)))
        try:
            nf["address"] = int(addr, 16) if isinstance(addr, str) and addr.startswith("0x") else int(addr)
        except (ValueError, TypeError):
            nf["address"] = 0
        return nf

    # ==== 三趟匹配链路 ====

    def _round1_cve_id(self, sources: Dict[str, List[Dict]]) -> Tuple[
            List[List[Tuple[str, int]]], Set[Tuple[str, str, int]]]:
        """第一趟：CVE ID精确匹配——CID非空的finding按相同CID归组"""
        groups: Dict[str, List[Tuple[str, int]]] = {}
        for src, findings in sources.items():
            for i, f in enumerate(findings):
                nf = self._norm(f)
                cid = nf.get("cve_id", "")
                if cid:
                    groups.setdefault(cid, []).append((src, i))
        matched: Set[Tuple[str, str, int]] = set()
        result = []
        for cid, members in groups.items():
            if len(set(s for s, _ in members)) > 1:
                result.append(members)
                for m in members:
                    matched.add((m[0], cid, m[1]))
        return result, matched

    def _round2_func_type(self, sources: Dict[str, List[Dict]],
                          matched: Set[Tuple[str, str, int]]) -> List[List[Tuple[str, int]]]:
        """第二趟：函数名+漏洞类型匹配——同函数同类型视为同一漏洞"""
        remaining = {}
        for src, findings in sources.items():
            for i, f in enumerate(findings):
                if (src, f.get("cve_id", ""), i) not in matched:
                    remaining.setdefault(src, {})[i] = self._norm(f)

        groups: Dict[Tuple[str, str], List[Tuple[str, int]]] = {}
        for src, idx_map in remaining.items():
            for idx, nf in idx_map.items():
                key = (nf.get("function_name", "").lower().strip(),
                       nf.get("vuln_type", "").lower().strip())
                if key[0] and key[1]:
                    groups.setdefault(key, []).append((src, idx))

        result = []
        for key, members in groups.items():
            srcs = {s for s, _ in members}
            if len(srcs) > 1:
                result.append(members)
        return result

    def _round3_addr_proximity(self, sources: Dict[str, List[Dict]],
                               matched: Set[Tuple]) -> List[List[Tuple[str, int]]]:
        """第三趟：地址邻近匹配——±8字节容差内归为同源"""
        remaining = {}
        for src, findings in sources.items():
            for i, f in enumerate(findings):
                cid = f.get("cve_id", "")
                key = (src, cid, i)
                already = False
                for m in matched:
                    if m[0] == src and m[2] == i:
                        already = True
                        break
                if not already:
                    remaining.setdefault(src, {})[i] = self._norm(f)

        addr_list: List[Tuple[str, int, Dict]] = []
        for src, idx_map in remaining.items():
            for idx, nf in idx_map.items():
                if nf["address"] > 0:
                    addr_list.append((src, idx, nf))

        # 地址距离聚类
        groups = []
        used = set()
        tol = self.address_tolerance
        for i, (src_a, idx_a, nf_a) in enumerate(addr_list):
            if i in used:
                continue
            cluster = [(src_a, idx_a)]
            used.add(i)
            for j, (src_b, idx_b, nf_b) in enumerate(addr_list):
                if j in used or src_a == src_b:
                    continue
                if abs(nf_a["address"] - nf_b["address"]) <= tol:
                    cluster.append((src_b, idx_b))
                    used.add(j)
            if len(set(s for s, _ in cluster)) > 1:
                groups.append(cluster)
        return groups

    # ==== 字段级归并 ====

    def _merge_fields(self, entries: List[Tuple[str, Dict]]) -> Tuple[Dict, List[MergeConflict]]:
        """CRDT风格字段归并——按来源优先级选取最可信值"""
        result = {}
        conflicts = []
        fields_to_merge = ["function_name", "severity", "cvss_score",
                           "description", "vuln_type", "address", "file_path",
                           "line_number", "cve_id"]

        for field in fields_to_merge:
            vals: Dict[str, Any] = {}
            for src, entry in entries:
                v = entry.get(field)
                if v is not None and v != "" and v != 0.0:
                    vals[src] = v
            if len(vals) <= 1:
                result[field] = next(iter(vals.values()), entry.get(field)) if vals else next((e.get(field) for _, e in entries), "")
                continue
            unique_vals = set(str(v) for v in vals.values())
            if len(unique_vals) == 1:
                result[field] = next(iter(vals.values()))
                continue
            precedence = _FIELD_PRECEDENCE.get(field, ["ghidra", "ida", "r2"])
            resolved = None
            method = "first_seen"
            for src in precedence:
                if src in vals:
                    resolved = vals[src]
                    method = f"precedence({src})"
                    break
            if resolved is None:
                resolved = next(iter(vals.values()))
            conflicts.append(MergeConflict(
                field=field, values=vals, resolved_value=resolved,
                resolution_method=method))
            result[field] = resolved

        return result, conflicts

    # ==== 主入口 ====

    def merge_from_sources(self, ghidra_findings: List[Dict] = None,
                           ida_findings: List[Dict] = None,
                           r2_findings: List[Dict] = None,
                           **extra_sources) -> MergeResult:
        """多源漏洞发现归并。

        用法:
            merger = VulnDedupMerger()
            result = merger.merge_from_sources(
                ghidra_findings=ghidra_results,
                ida_findings=ida_results,
                r2_findings=r2_results,
            )

        返回MergeResult，含merged列表、conflicts列表及统计信息。
        """
        sources = {}
        if ghidra_findings:
            sources["ghidra"] = ghidra_findings
        if ida_findings:
            sources["ida"] = ida_findings
        if r2_findings:
            sources["r2"] = r2_findings
        sources.update(extra_sources)

        total = sum(len(v) for v in sources.values())
        self._conflicts = []

        # 全部规范化
        normed: Dict[str, List[Dict]] = {}
        for src, f_list in sources.items():
            normed[src] = [self._norm(f) for f in f_list]

        # 三趟匹配
        r1_groups, r1_matched = self._round1_cve_id(normed)
        r2_groups = self._round2_func_type(normed, r1_matched)
        r3_groups = self._round3_addr_proximity(normed, set())

        all_groups = r1_groups + r2_groups + r3_groups

        # 构建归并记录
        merged = []
        seen_keys: Set[Tuple] = set()  # 每个(source, idx)仅归入一组

        for group in all_groups:
            entries = []
            srcs = set()
            for src, idx in group:
                seen_keys.add((src, idx))
                entries.append((src, normed[src][idx]))
                srcs.add(src)
            merged_fields, confs = self._merge_fields(entries)
            mf = MergedFinding(
                cve_id=merged_fields.get("cve_id", ""),
                vuln_type=merged_fields.get("vuln_type", ""),
                function_name=merged_fields.get("function_name", ""),
                address=merged_fields.get("address", 0),
                severity=merged_fields.get("severity", ""),
                cvss_score=merged_fields.get("cvss_score", 0.0),
                description=merged_fields.get("description", ""),
                file_path=merged_fields.get("file_path", ""),
                line_number=merged_fields.get("line_number", 0),
                sources=list(srcs),
                source_data={s: normed[s][i] for s, i in group},
                match_confidence="exact" if group in r1_groups else ("high" if group in r2_groups else "medium"),
            )
            merged.append(mf)

        # 未匹配的孤立发现
        unmatched: Dict[str, List[Dict]] = {}
        for src, f_list in normed.items():
            for i, f in enumerate(f_list):
                if (src, i) not in seen_keys:
                    unmatched.setdefault(src, []).append(f)

        stats = {
            "total_input": total,
            "merged": len(merged),
            "conflicts": len(self._conflicts),
            "unmatched": sum(len(v) for v in unmatched.values()),
            "match_rounds": {"r1_cve_id": len(r1_groups),
                             "r2_func_type": len(r2_groups),
                             "r3_addr_prox": len(r3_groups)},
        }

        return MergeResult(
            merged=merged,
            conflicts=self._conflicts,
            stats=stats,
            unmatched=unmatched,
            total_input=total,
        )

    def merge_two_lists(self, list_a: List[Dict], list_b: List[Dict]) -> MergeResult:
        """双列表快速归并"""
        return self.merge_from_sources(ida_findings=list_a, ghidra_findings=list_b)
