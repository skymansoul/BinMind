import logging
import hashlib
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger(__name__)


class VulnSignature:
    __slots__ = ('func_name', 'vuln_type', 'address', 'constraint_hash', 'source_analyzer',)

    def __init__(self, func_name, vuln_type, address=0, constraint_hash="", source_analyzer=""):
        self.func_name = func_name
        self.vuln_type = vuln_type
        self.address = address
        self.constraint_hash = constraint_hash
        self.source_analyzer = source_analyzer

    @property
    def fingerprint(self) -> str:
        raw = f"{self.func_name}:{self.vuln_type}:{self.address}:{self.constraint_hash}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

@dataclass
class MergedVuln:
    vuln_id: str = ""
    vuln_type: str = ""
    func_name: str = ""
    severity: str = ""
    confidence: float = 0.0
    duplicate_count: int = 1
    source_analyzers: list = field(default_factory=list)
    original_reports: list = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'vuln_id': self.vuln_id,
            'vuln_type': self.vuln_type,
            'func_name': self.func_name,
            'severity': self.severity,
            'confidence': self.confidence,
            'duplicate_count': self.duplicate_count,
            'source_analyzers': self.source_analyzers
        }

class VulnDedupMerger:
    """基于指纹的漏洞去重引擎, 按signature hash分组, 每簇选取最高置信度代表。"""

    def __init__(self, similarity_threshold: float = 0.7):
        self.threshold = similarity_threshold
        self._signatures: Dict[str, List[VulnSignature]] = defaultdict(list)
        self._counter = 0

    def _next_id(self) -> str:
        self._counter += 1
        return f"VULN-{self._counter:06d}"

    def make_signature(self, vuln: Dict[str, Any]) -> VulnSignature:
        return VulnSignature(
            func_name=vuln.get('func_name', 'unknown'),
            vuln_type=vuln.get('vuln_type', 'generic'),
            address=vuln.get('address', 0),
            constraint_hash=vuln.get('constraint_hash', ''),
            source_analyzer=vuln.get('source', 'unknown'))

    def deduplicate(self, vulns: List[Dict[str, Any]]) -> List[MergedVuln]:
        sig_groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for v in vulns:
            sig = self.make_signature(v)
            sig_groups[sig.fingerprint].append(v)

        merged = []
        for fp, group in sig_groups.items():
            best = max(group, key=lambda v: v.get('confidence', 0.0))
            merged.append(MergedVuln(
                vuln_id=self._next_id(),
                vuln_type=best.get('vuln_type', 'unknown'),
                func_name=best.get('func_name', 'unknown'),
                severity=best.get('severity', 'medium'),
                confidence=round(max(v.get('confidence', 0.0) for v in group), 2),
                duplicate_count=len(group),
                source_analyzers=list(set(
                    v.get('source', 'unknown') for v in group)),
                original_reports=group))
        return merged

    def analyze(self, vulnerabilities: Optional[List[Dict[str, Any]]] = None,
                        **kwargs) -> Dict[str, Any]:
        if not vulnerabilities:
            return {'success': True, 'total_raw': 0, 'unique': 0, 'duplicates': 0}

        raw_count = len(vulnerabilities)
        merged = self.deduplicate(vulnerabilities)
        duplicates = raw_count - len(merged)

        return {
            'success': True,
            'total_raw': raw_count,
            'unique': len(merged),
            'duplicates_removed': duplicates,
            'dedup_ratio': round(duplicates / max(1, raw_count) * 100, 1),
            'merged_vulns': [m.to_dict() for m in merged[:50]],
            'top_duplicates': sorted(
                [{'func_name': m.func_name, 'nCount': m.duplicate_count,
                  'source_analyzers': m.source_analyzers} for m in merged
                 if m.duplicate_count > 1],
                key=lambda x: x['nCount'], reverse=True)[:10]
        }

def dedup_vulnerabilities(vulnerabilities: List[Dict[str, Any]],
                           **kwargs) -> Dict[str, Any]:
    merger = VulnDedupMerger()
    return merger.analyze(vulnerabilities=vulnerabilities)

__all__ = ["VulnDedupMerger", "VulnSignature", "MergedVuln", "dedup_vulnerabilities"]
