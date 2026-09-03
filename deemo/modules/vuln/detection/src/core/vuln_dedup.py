# 合并去重模块——混合哈希聚类+CRDT多源合并，统一DeduplicationStrategy Enum
# 边界条件: 空输入直接返回空DeduplicationResult/MergeResult

import hashlib
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import deque

from deemo.modules.vuln.detection.src.logger import get_logger

_log = get_logger("vuln_detection.dedup")


class DeduplicationStrategy(str, Enum):
    DATAFLOW = "dataflow"
    SYNTAX = "syntax"
    SEMANTIC = "semantic"
    HYBRID = "hybrid"


class ClusterSimilarity(str, Enum):
    EXACT = "exact"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class MatchConfidence(str, Enum):
    EXACT = "exact"
    HIGH = "high"
    MEDIUM = "medium"
    NONE = "none"


# 混合哈希去重——VulnerabilitySignature/Cluster/Result

@dataclass
class VulnerabilitySignature:
    vulnerability_type: str
    function_name: str
    dataflow_hash: str
    syntax_hash: str
    semantic_features: List[str] = field(default_factory=list)
    address: int = 0
    severity: str = "unknown"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vulnerability_type": self.vulnerability_type,
            "function_name": self.function_name,
            "dataflow_hash": self.dataflow_hash,
            "syntax_hash": self.syntax_hash,
            "semantic_features": self.semantic_features,
            "address": hex(self.address),
            "severity": self.severity,
        }


@dataclass
class VulnerabilityCluster:
    cluster_id: str
    representative: VulnerabilitySignature
    members: List[VulnerabilitySignature] = field(default_factory=list)
    similarity: str = "medium"
    nCount: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "representative": self.representative.to_dict(),
            "members": [m.to_dict() for m in self.members],
            "similarity": self.similarity,
            "nCount": self.nCount,
        }

    size = property(lambda self: self.nCount)


@dataclass
class DeduplicationResult:
    clusters: List[VulnerabilityCluster] = field(default_factory=list)
    unique_count: int = 0
    total_count: int = 0
    deduplicated_count: int = 0
    strategy: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "clusters": [c.to_dict() for c in self.clusters],
            "unique_count": self.unique_count,
            "total_count": self.total_count,
            "deduplicated_count": self.deduplicated_count,
            "strategy": self.strategy,
        }


# CRDT多源合并——MergedFinding/MergeConflict/MergeResult

@dataclass
class MergedFinding:
    cve_id: str = ""
    vuln_type: str = ""
    function_name: str = ""
    address: int = 0
    severity: str = ""
    cvss_score: float = 0.0
    description: str = ""
    file_path: str = ""
    line_number: int = 0
    sources: List[str] = field(default_factory=list)
    source_data: Dict[str, Dict] = field(default_factory=dict)
    match_confidence: str = "none"


@dataclass
class MergeConflict:
    field: str
    values: Dict[str, Any]
    resolved_value: Any
    resolution_method: str


@dataclass
class MergeResult:
    merged: List[MergedFinding] = field(default_factory=list)
    conflicts: List[MergeConflict] = field(default_factory=list)
    stats: Dict[str, int] = field(default_factory=dict)
    unmatched: Dict[str, List[Dict]] = field(default_factory=dict)
    total_input: int = 0


# 字段优先级——不同工具对同一字段可靠性不同
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


# VulnDeduplicator——混合哈希聚类

class VulnDeduplicator:
    """混合去重器——三路哈希+Jaccard语义相似度+加权评分"""

    def __init__(self, strategy: str = "hybrid"):
        self.strategy = strategy
        self.similarity_thresholds = {
            "dataflow": 0.85, "syntax": 0.80,
            "semantic": 0.70, "hybrid": 0.75,
        }

    def deduplicate(self, vulnerabilities: List[Dict[str, Any]]) -> DeduplicationResult:
        if not vulnerabilities:
            return DeduplicationResult(strategy=str(self.strategy))
        signatures = self._create_signatures(vulnerabilities)
        if self.strategy == "dataflow":
            clusters = self._cluster_by_dataflow(signatures)
        elif self.strategy == "syntax":
            clusters = self._cluster_by_syntax(signatures)
        elif self.strategy == "semantic":
            clusters = self._cluster_by_semantic(signatures)
        else:
            clusters = self._cluster_hybrid(signatures)
        return DeduplicationResult(
            clusters=clusters, unique_count=len(clusters),
            total_count=len(vulnerabilities),
            deduplicated_count=len(vulnerabilities) - len(clusters),
            strategy=str(self.strategy),
        )

    def _create_signatures(self, vulns: List[Dict[str, Any]]) -> List[VulnerabilitySignature]:
        sigs = []
        for vuln in vulns:
            df = self._compute_dataflow_hash(vuln)
            sy = self._compute_syntax_hash(vuln)
            se = self._extract_semantic_features(vuln)
            sigs.append(VulnerabilitySignature(
                vulnerability_type=vuln.get("vulnerability_type", "unknown"),
                function_name=vuln.get("function_name", ""),
                dataflow_hash=df, syntax_hash=sy,
                semantic_features=se,
                address=vuln.get("address", 0),
                severity=vuln.get("severity", "unknown"),
            ))
        return sigs

    def _compute_dataflow_hash(self, vuln: Dict[str, Any]) -> str:
        els = [str(vuln.get(k, "")) for k in ("source", "sink", "path", "taint_flow")]
        return hashlib.md5("|".join(els).encode()).hexdigest()

    def _compute_syntax_hash(self, vuln: Dict[str, Any]) -> str:
        els = [str(vuln.get(k, "")) for k in ("pseudocode", "function_name", "vulnerability_type")]
        return hashlib.md5("|".join(els).encode()).hexdigest()

    def _extract_semantic_features(self, vuln: Dict[str, Any]) -> List[str]:
        feats = []
        if vuln.get("vulnerability_type"):
            feats.append(f"type:{vuln['vulnerability_type']}")
        if vuln.get("severity"):
            feats.append(f"severity:{vuln['severity']}")
        if vuln.get("function_name"):
            feats.append(f"func:{vuln['function_name']}")
        if vuln.get("requires_user_interaction"):
            feats.append(f"interaction:{vuln['requires_user_interaction']}")
        if vuln.get("network_accessible"):
            feats.append(f"network:{vuln['network_accessible']}")
        return feats

    def _cluster_by_dataflow(self, sigs: List[VulnerabilitySignature]) -> List[VulnerabilityCluster]:
        clusters = []
        seen = set()
        for sig in sigs:
            if sig.dataflow_hash not in seen:
                clusters.append(VulnerabilityCluster(
                    cluster_id=f"df_{sig.dataflow_hash[:8]}",
                    representative=sig, members=[sig],
                    similarity=ClusterSimilarity.EXACT.value, nCount=1))
                seen.add(sig.dataflow_hash)
            else:
                for cl in clusters:
                    if cl.representative.dataflow_hash == sig.dataflow_hash:
                        cl.members.append(sig)
                        cl.nCount += 1
                        break
        return clusters

    def _cluster_by_syntax(self, sigs: List[VulnerabilitySignature]) -> List[VulnerabilityCluster]:
        clusters = []
        for sig in sigs:
            matched = False
            for cl in clusters:
                sim = self._calc_syntax_sim(sig, cl.representative)
                if sim >= self.similarity_thresholds["syntax"]:
                    cl.members.append(sig); cl.nCount += 1
                    if sim >= 0.95: cl.similarity = ClusterSimilarity.EXACT.value
                    elif sim >= 0.85 and cl.similarity != ClusterSimilarity.EXACT.value:
                        cl.similarity = ClusterSimilarity.HIGH.value
                    matched = True; break
            if not matched:
                clusters.append(VulnerabilityCluster(
                    cluster_id=f"syn_{hash(sig.syntax_hash) % 10000}",
                    representative=sig, members=[sig],
                    similarity=ClusterSimilarity.EXACT.value, nCount=1))
        return clusters

    def _calc_syntax_sim(self, a: VulnerabilitySignature, b: VulnerabilitySignature) -> float:
        if a.syntax_hash == b.syntax_hash: return 1.0
        score = 0.0
        if a.vulnerability_type == b.vulnerability_type: score += 0.5
        if a.function_name == b.function_name: score += 0.5
        return score

    def _cluster_by_semantic(self, sigs: List[VulnerabilitySignature]) -> List[VulnerabilityCluster]:
        clusters = []
        for sig in sigs:
            matched = False
            for cl in clusters:
                sim = self._calc_semantic_sim(sig, cl.representative)
                if sim >= self.similarity_thresholds["semantic"]:
                    cl.members.append(sig); cl.nCount += 1
                    if sim >= 0.9: cl.similarity = ClusterSimilarity.HIGH.value
                    matched = True; break
            if not matched:
                clusters.append(VulnerabilityCluster(
                    cluster_id=f"sem_{hash(tuple(sig.semantic_features)) % 10000}",
                    representative=sig, members=[sig],
                    similarity=ClusterSimilarity.EXACT.value, nCount=1))
        return clusters

    def _calc_semantic_sim(self, a: VulnerabilitySignature, b: VulnerabilitySignature) -> float:
        s1, s2 = set(a.semantic_features), set(b.semantic_features)
        u = s1 | s2
        return len(s1 & s2) / len(u) if u else 0.0

    def _cluster_hybrid(self, sigs: List[VulnerabilitySignature]) -> List[VulnerabilityCluster]:
        clusters = []
        for sig in sigs:
            matched = False
            for cl in clusters:
                df_sim = 1.0 if sig.dataflow_hash == cl.representative.dataflow_hash else 0.0
                syn_sim = self._calc_syntax_sim(sig, cl.representative)
                sem_sim = self._calc_semantic_sim(sig, cl.representative)
                weighted = df_sim * 0.4 + syn_sim * 0.3 + sem_sim * 0.3
                if weighted >= self.similarity_thresholds["hybrid"]:
                    cl.members.append(sig); cl.nCount += 1
                    if weighted >= 0.95: cl.similarity = ClusterSimilarity.EXACT.value
                    elif weighted >= 0.85 and cl.similarity != ClusterSimilarity.EXACT.value:
                        cl.similarity = ClusterSimilarity.HIGH.value
                    elif weighted >= 0.75 and cl.similarity not in (
                            ClusterSimilarity.EXACT.value, ClusterSimilarity.HIGH.value):
                        cl.similarity = ClusterSimilarity.MEDIUM.value
                    matched = True; break
            if not matched:
                clusters.append(VulnerabilityCluster(
                    cluster_id=f"hyb_{hash(sig.dataflow_hash + sig.syntax_hash) % 10000}",
                    representative=sig, members=[sig],
                    similarity=ClusterSimilarity.EXACT.value, nCount=1))
        return clusters


# VulnDedupMerger——CRDT多源合并

class VulnDedupMerger:
    """多源漏洞发现合并器。

    三趟匹配: CVE ID精确 → 函数名+类型 → 地址邻近(±8字节)
    冲突解决按字段优先级选取。
    """

    def __init__(self, address_tolerance: int = 8):
        self.address_tolerance = address_tolerance
        self._conflicts: List[MergeConflict] = []

    @staticmethod
    def _norm(finding: Dict) -> Dict:
        nf = dict(finding)
        nf.setdefault("cve_id", ""); nf.setdefault("vuln_type", "")
        nf.setdefault("function_name", ""); nf.setdefault("severity", "")
        nf.setdefault("cvss_score", 0.0)
        addr = nf.get("address", nf.get("addr", nf.get("offset", 0)))
        try:
            nf["address"] = int(addr, 16) if isinstance(addr, str) and addr.startswith("0x") else int(addr)
        except (ValueError, TypeError):
            nf["address"] = 0
        return nf

    def _round1_cve_id(self, sources: Dict[str, List[Dict]]) -> Tuple[
            List[List[Tuple[str, int]]], Set[Tuple[str, str, int]]]:
        groups: Dict[str, List[Tuple[str, int]]] = {}
        for src, findings in sources.items():
            for i, f in enumerate(findings):
                nf = self._norm(f)
                cid = nf.get("cve_id", "")
                if cid: groups.setdefault(cid, []).append((src, i))
        matched: Set[Tuple[str, str, int]] = set()
        result = []
        for cid, members in groups.items():
            if len({s for s, _ in members}) > 1:
                result.append(members)
                for m in members: matched.add((m[0], cid, m[1]))
        return result, matched

    def _round2_func_type(self, sources: Dict[str, List[Dict]],
                          matched: Set[Tuple[str, str, int]]) -> List[List[Tuple[str, int]]]:
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
                if key[0] and key[1]: groups.setdefault(key, []).append((src, idx))
        return [members for members in groups.values()
                if len({s for s, _ in members}) > 1]

    def _round3_addr_proximity(self, sources: Dict[str, List[Dict]],
                               matched: Set[Tuple]) -> List[List[Tuple[str, int]]]:
        remaining = {}
        for src, findings in sources.items():
            for i, f in enumerate(findings):
                cid = f.get("cve_id", "")
                if not any(m[0] == src and m[2] == i for m in matched):
                    remaining.setdefault(src, {})[i] = self._norm(f)
        addr_list: List[Tuple[str, int, Dict]] = []
        for src, idx_map in remaining.items():
            for idx, nf in idx_map.items():
                if nf["address"] > 0: addr_list.append((src, idx, nf))
        groups = []; used = set(); tol = self.address_tolerance
        for i, (sa, ia, na) in enumerate(addr_list):
            if i in used: continue
            cluster = [(sa, ia)]; used.add(i)
            for j, (sb, ib, nb) in enumerate(addr_list):
                if j in used or sa == sb: continue
                if abs(na["address"] - nb["address"]) <= tol:
                    cluster.append((sb, ib)); used.add(j)
            if len({s for s, _ in cluster}) > 1: groups.append(cluster)
        return groups

    def _merge_fields(self, entries: List[Tuple[str, Dict]]) -> Tuple[Dict, List[MergeConflict]]:
        result = {}; conflicts = []
        fields = ["function_name", "severity", "cvss_score",
                  "description", "vuln_type", "address",
                  "file_path", "line_number", "cve_id"]
        for field in fields:
            vals: Dict[str, Any] = {}
            for src, entry in entries:
                v = entry.get(field)
                if v is not None and v != "" and v != 0.0: vals[src] = v
            if len(vals) <= 1:
                result[field] = next(iter(vals.values())) if vals else \
                    next((e.get(field, "") for _, e in entries), "")
                continue
            unique_vals = {str(v) for v in vals.values()}
            if len(unique_vals) == 1:
                result[field] = next(iter(vals.values())); continue
            precedence = _FIELD_PRECEDENCE.get(field, ["ghidra", "ida", "r2"])
            resolved = None; method = "first_seen"
            for src in precedence:
                if src in vals: resolved = vals[src]; method = f"precedence({src})"; break
            if resolved is None: resolved = next(iter(vals.values()))
            conflicts.append(MergeConflict(
                field=field, values=vals, resolved_value=resolved,
                resolution_method=method))
            result[field] = resolved
        return result, conflicts

    def merge_from_sources(self, ghidra_findings: List[Dict] = None,
                           ida_findings: List[Dict] = None,
                           r2_findings: List[Dict] = None,
                           **extra_sources) -> MergeResult:
        sources = {}
        if ghidra_findings: sources["ghidra"] = ghidra_findings
        if ida_findings: sources["ida"] = ida_findings
        if r2_findings: sources["r2"] = r2_findings
        sources.update(extra_sources)

        total = sum(len(v) for v in sources.values())
        if total == 0:
            return MergeResult(total_input=0)

        self._conflicts = []
        normed: Dict[str, List[Dict]] = {}
        for src, fl in sources.items():
            normed[src] = [self._norm(f) for f in fl]

        r1_groups, r1_matched = self._round1_cve_id(normed)
        r2_groups = self._round2_func_type(normed, r1_matched)
        r3_groups = self._round3_addr_proximity(normed, set())

        all_groups = r1_groups + r2_groups + r3_groups
        merged = []; seen_keys: Set[Tuple] = set()

        for group in all_groups:
            entries = []; srcs = set()
            for src, idx in group:
                seen_keys.add((src, idx))
                entries.append((src, normed[src][idx])); srcs.add(src)
            mf_data, confs = self._merge_fields(entries)
            confidence = ("exact" if group in r1_groups
                          else ("high" if group in r2_groups else "medium"))
            mf = MergedFinding(
                cve_id=mf_data.get("cve_id", ""),
                vuln_type=mf_data.get("vuln_type", ""),
                function_name=mf_data.get("function_name", ""),
                address=mf_data.get("address", 0),
                severity=mf_data.get("severity", ""),
                cvss_score=mf_data.get("cvss_score", 0.0),
                description=mf_data.get("description", ""),
                file_path=mf_data.get("file_path", ""),
                line_number=mf_data.get("line_number", 0),
                sources=list(srcs),
                source_data={s: normed[s][i] for s, i in group},
                match_confidence=confidence)
            merged.append(mf)

        unmatched: Dict[str, List[Dict]] = {}
        for src, fl in normed.items():
            for i, f in enumerate(fl):
                if (src, i) not in seen_keys:
                    unmatched.setdefault(src, []).append(f)

        stats = {
            "total_input": total, "merged": len(merged),
            "conflicts": len(self._conflicts),
            "unmatched": sum(len(v) for v in unmatched.values()),
            "match_rounds": {"r1_cve_id": len(r1_groups),
                             "r2_func_type": len(r2_groups),
                             "r3_addr_prox": len(r3_groups)},
        }
        return MergeResult(
            merged=merged, conflicts=self._conflicts,
            stats=stats, unmatched=unmatched, total_input=total)

    def merge_two_lists(self, list_a: List[Dict], list_b: List[Dict]) -> MergeResult:
        return self.merge_from_sources(ida_findings=list_a, ghidra_findings=list_b)


# 便捷函数

def deduplicate_vulnerabilities(vulns: List[Dict[str, Any]],
                                strategy: str = "hybrid") -> DeduplicationResult:
    dedup = VulnDeduplicator(strategy)
    return dedup.deduplicate(vulns)


def merge_from_sources(**sources) -> MergeResult:
    merger = VulnDedupMerger()
    return merger.merge_from_sources(**sources)
