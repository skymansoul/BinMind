from enum import StrEnum
import logging
import os
import json
import re
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger(__name__)

class FindingPriority(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class KeyFinding:
    title: Any = None
    description: str = ""
    priority: Any = None
    location: Any = None
    cwe_id: Any = None
    confidence: float = 0.0
    evidence: Any = None
    score: float = 0.0

class ReverseNote:
    __slots__ = ('title', 'summary', 'findings', 'binary_path', 'author', 'timestamp', 'tags',)

    def __init__(self, title, summary, findings, binary_path, author="auto_reverser", timestamp=0.0, tags=None):
        self.title = title
        self.summary = summary
        self.findings = findings
        self.binary_path = binary_path
        self.author = author
        self.timestamp = timestamp
        self.tags = tags

    def to_markdown(self) -> str:
        lines = [
            f"# {self.title}",
            "",
            f"**Binary**: `{self.binary_path}`  ",
            f"**Author**: {self.author}  ",
            f"**Generated**: {self.timestamp}  ",
            "",
            "## TL;DR",
            "",
            self.summary,
            "",
            "## Key Findings",
            ""
        ]
        for i, f in enumerate(self.findings, 1):
            lines.append(f"### {i}. [{f.priority.value.upper()}] {f.title}")
            lines.append("")
            lines.append(f"- **Location**: `{f.location}`")
            if f.cwe_id:
                lines.append(f"- **CWE**: {f.cwe_id}")
            lines.append(f"- **Confidence**: {f.confidence:.2f}")
            lines.append("")
            lines.append(f.description)
            if f.evidence:
                lines.append("")
                lines.append("**Evidence**:")
                for ev in f.evidence[:5]:
                    lines.append(f"- `{ev}`")
            lines.append("")
        if self.tags:
            lines.append("## Tags")
            lines.append("")
            lines.append(", ".join(f"`{t}`" for t in self.tags))
        return "\n".join(lines)

class FindingScorer:
    """加权评分模型：严重度 × 可达性 × 公开利用 × CVSS × 关键词密度。"""

    SEVERITY_WEIGHT = {
        "critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1
    }

    KEYWORD_HIGH = {"system", "execve", "popen", "format", "strcpy", "gets"}
    KEYWORD_MED = {"malloc", "free", "memcpy", "sprintf"}

    def score(self, finding_dict: Dict[str, Any]) -> float:
        score = 0.0
        sev = finding_dict.get('severity', 'low').lower()
        score += self.SEVERITY_WEIGHT.get(sev, 1)
        if finding_dict.get('reachable', False):
            score += 3
        if finding_dict.get('public_exploit', False):
            score += 5
        if finding_dict.get('cvss', 0) >= 9:
            score += 5
        elif finding_dict.get('cvss', 0) >= 7:
            score += 3
        text = json.dumps(finding_dict, ensure_ascii=False).lower()
        for kw in self.KEYWORD_HIGH:
            if kw in text:
                score += 1.5
        for kw in self.KEYWORD_MED:
            if kw in text:
                score += 0.5
        return score

class KeyFindingsExtractor:
    """根据综合严重度评分提取 Top-K 安全发现。"""

    def __init__(self, top_k: int = 5):
        self.top_k = top_k
        self.scorer = FindingScorer()

    def extract(self, analysis_result: Dict[str, Any]) -> List[KeyFinding]:
        candidates: List[Tuple[float, KeyFinding]] = []
        vulns = analysis_result.get('vulnerabilities', [])
        for v in vulns:
            f = self._to_finding(v)
            score = self.scorer.score(v)
            f.score = score
            candidates.append((score, f))
        candidates.sort(key=lambda x: x[0], reverse=True)
        selected: List[KeyFinding] = []
        seen_types: Set[str] = set()
        for score, f in candidates:
            if f.cwe_id in seen_types and len(selected) < self.top_k:
                if sum(1 for s in selected if s.cwe_id == f.cwe_id) < 2:
                    selected.append(f)
                    seen_types.add(f.cwe_id)
            else:
                if len(selected) < self.top_k:
                    selected.append(f)
                    seen_types.add(f.cwe_id)
        if len(selected) < self.top_k:
            for score, f in candidates:
                if f not in selected and len(selected) < self.top_k:
                    selected.append(f)
        return selected

    def _to_finding(self, v: Dict[str, Any]) -> KeyFinding:
        sev = v.get('severity', 'low').lower()
        try:
            priority = FindingPriority(sev)
        except ValueError:
            priority = FindingPriority.INFO
        return KeyFinding(
            title=v.get('title') or v.get('vuln_type', 'Unknown'),
            description=v.get('description', ''),
            priority=priority,
            location=v.get('location', 'unknown'),
            cwe_id=v.get('cwe_id', ''),
            confidence=float(v.get('confidence', 0.5)),
            evidence=v.get('evidence', [])
        )

class ReverseNoteGenerator:
    """中文逆向分析摘要生成器 — 从分析结果生成结构化笔记。"""

    def __init__(self, author: str = "auto_reverser"):
        self.author = author
        self.extractor = KeyFindingsExtractor()

    def _generate_summary(self, findings: List[KeyFinding],
                          analysis: Dict[str, Any]) -> str:
        if not findings:
            return "未发现明显高危问题, binary整体安全态势良好。"
        lines = []
        crit = sum(1 for f in findings if f.priority == FindingPriority.CRITICAL)
        high = sum(1 for f in findings if f.priority == FindingPriority.HIGH)
        if crit > 0:
            lines.append(f"发现 {crit} 个严重漏洞")
        if high > 0:
            lines.append(f"、{high} 个高危漏洞")
        if analysis.get('binary_type'):
            lines.append(f"。该 {analysis['binary_type']} binary")
        else:
            lines.append("。该binary")
        caps = set()
        for f in findings:
            if "information disclosure" in f.title or "format" in f.title.lower():
                caps.add("information disclosure能力")
            if "控制" in f.title or "hijack" in f.title.lower():
                caps.add("control flow劫持原语")
            if "heap" in f.title or "heap" in f.title.lower():
                caps.add("heap操作原语")
        if caps:
            lines.append(f"存在 {', '.join(caps)} 风险")
        lines.append("。")
        return "".join(lines)

    def generate(self, analysis_result: Dict[str, Any],
                 binary_path: str,
                 title: Optional[str] = None) -> ReverseNote:
        findings = self.extractor.extract(analysis_result)
        import time
        if title is None:
            title = f"逆向笔记: {os.path.basename(binary_path)}"
        summary = self._generate_summary(findings, analysis_result)
        return ReverseNote(
            title=title,
            summary=summary,
            findings=findings,
            binary_path=binary_path,
            author=self.author,
            timestamp=time.time(),
            tags=[f.vuln_type for f in findings if f.vuln_type][:5]
        )

def generate_reverse_note(analysis_result: Dict[str, Any],
                          binary_path: str,
                          title: Optional[str] = None) -> Dict[str, Any]:
    """便捷入口：从原始分析结果生成逆向笔记字典。"""
    g = ReverseNoteGenerator()
    note = g.generate(analysis_result, binary_path, title)
    return {
        'success': True,
        'note': {
            'title': note.title,
            'summary': note.summary,
            'findings': [
                {
                    'title': f.title,
                    'description': f.description,
                    'priority': f.priority.value,
                    'location': f.location,
                    'cwe_id': f.cwe_id,
                    'confidence': f.confidence,
                    'score': f.score
                }
                for f in note.findings
            ],
            'tags': note.tags,
            'timestamp': note.timestamp,
            'markdown': note.to_markdown()
        }
    }
