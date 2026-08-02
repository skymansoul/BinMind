"""关键发现提取器 — 加权评分 + Top-K 选择 + 逆向笔记生成。"""
from enum import StrEnum
import logging
import os
import json
import re
import time
from typing import Dict, Any, List, Optional, Tuple, Set
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
    title: str = ""
    description: str = ""
    priority: FindingPriority = FindingPriority.INFO
    location: str = ""
    cwe_id: str = ""
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    score: float = 0.0
    vuln_type: str = ""  # 原始漏洞类型标签，用于标签聚合


class ReverseNote:
    """逆向分析笔记 — 结构化 Markdown 输出。"""
    __slots__ = ('title', 'summary', 'findings', 'binary_path',
                 'author', 'timestamp', 'tags')

    def __init__(self, title, summary, findings, binary_path,
                 author="auto_reverser", timestamp=0.0, tags=None):
        self.title = title
        self.summary = summary
        self.findings = findings
        self.binary_path = binary_path
        self.author = author
        self.timestamp = timestamp
        self.tags = tags or []

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
            prio = f.priority.value if hasattr(f.priority, 'value') else str(f.priority)
            lines.append(f"### {i}. [{prio.upper()}] {f.title}")
            lines.append("")
            lines.append(f"- **Location**: `{f.location}`")
            if f.cwe_id:
                lines.append(f"- **CWE**: {f.cwe_id}")
            lines.append(f"- **Confidence**: {f.confidence:.2f}")
            lines.append(f"- **Score**: {f.score:.1f}")
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
    """加权评分模型：严重度 × 可达性 × 公开利用 × CVSS × 关键词密度。

    每项权重由领域经验确定，非机器学习参数：
    - 公开利用 (public_exploit) 权重最高，因为 Exploit-DB/野外样本
      的存在直接证明了漏洞的可利用性。
    - CVSS >= 9 与 public_exploit 等效，>= 7 为中等加成。
    """

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
    """根据综合严重度评分提取 Top-K 安全发现。

    去重策略：同一 CWE ID 最多保留 2 条，避免单一类型漏洞
    挤占 Top-K 名额。当 CWE 未知时按标题字符串相似度去重。
    增强：跨发现关联评分 — 若多个漏洞存在于同一函数或具备
    互补利用路径（如 info leak + buffer overflow），则组合评分
    超出简单加和，反映复合利用的实际风险。
    """

    # 已知互补 CWE 对：(CWE_A, CWE_B) 共存时每发现额外 +2 关联分
    _CORRELATED_CWE_PAIRS: set[tuple[str, str]] = {
        ("CWE-134", "CWE-121"),  # format string + stack overflow
        ("CWE-134", "CWE-122"),  # format string + heap overflow
        ("CWE-125", "CWE-787"),  # OOB read + OOB write
        ("CWE-416", "CWE-787"),  # UAF + OOB write
        ("CWE-476", "CWE-787"),  # NULL deref + OOB write
        ("CWE-200", "CWE-119"),  # info disclosure + memory corruption
    }

    def __init__(self, top_k: int = 5):
        self.top_k = top_k
        self.scorer = FindingScorer()

    def _compute_correlation_bonus(self, cwe_a: str, cwe_b: str) -> float:
        """检查两个 CWE 是否构成已知互补对。"""
        pair = (cwe_a, cwe_b)
        rev = (cwe_b, cwe_a)
        if pair in self._CORRELATED_CWE_PAIRS or rev in self._CORRELATED_CWE_PAIRS:
            return 2.0
        return 0.0

    def extract(self, analysis_result: Dict[str, Any]) -> List[KeyFinding]:
        candidates: List[Tuple[float, KeyFinding]] = []
        vulns = analysis_result.get('vulnerabilities', [])
        for v in vulns:
            f = self._to_finding(v)
            score = self.scorer.score(v)
            f.score = score
            candidates.append((score, f))
        candidates.sort(key=lambda x: x[0], reverse=True)

        # 跨发现关联：对每对候选检查互补 CWE 关系
        all_cwes = [(i, c[1].cwe_id) for i, c in enumerate(candidates) if c[1].cwe_id]
        for a_idx, a_cwe in all_cwes:
            for b_idx, b_cwe in all_cwes:
                if b_idx <= a_idx:
                    continue
                bonus = self._compute_correlation_bonus(a_cwe, b_cwe)
                if bonus > 0:
                    score_a, fa = candidates[a_idx]
                    score_b, fb = candidates[b_idx]
                    candidates[a_idx] = (score_a + bonus, fa)
                    candidates[b_idx] = (score_b + bonus, fb)

        candidates.sort(key=lambda x: x[0], reverse=True)
        selected: List[KeyFinding] = []
        seen_cwes: Set[str] = set()

        for score, f in candidates:
            if not f.cwe_id:
                dedup_key = f.title[:30].lower()
            else:
                dedup_key = f.cwe_id

            if dedup_key in seen_cwes:
                same_cwe_count = sum(1 for s in selected
                                     if (s.cwe_id and s.cwe_id == dedup_key)
                                     or (not s.cwe_id and s.title[:30].lower() == dedup_key))
                if same_cwe_count >= 2:
                    continue

            if len(selected) < self.top_k:
                selected.append(f)
                seen_cwes.add(dedup_key)

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
            evidence=v.get('evidence', []),
            vuln_type=v.get('vuln_type', ''),
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
            if "information disclosure" in f.title.lower() or "format" in f.title.lower():
                caps.add("information disclosure能力")
            if "控制" in f.title or "hijack" in f.title.lower():
                caps.add("control flow劫持原语")
            if "heap" in f.title.lower():
                caps.add("heap操作原语")
        if caps:
            lines.append(f"存在 {', '.join(caps)} 风险")
        lines.append("。")
        return "".join(lines)

    def generate(self, analysis_result: Dict[str, Any],
                 binary_path: str,
                 title: Optional[str] = None) -> ReverseNote:
        findings = self.extractor.extract(analysis_result)
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
            tags=[getattr(f, 'vuln_type', '') for f in findings if getattr(f, 'vuln_type', '')][:5]
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
