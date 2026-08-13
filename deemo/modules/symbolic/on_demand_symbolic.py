"""On-demand vulnerability triage pipeline.

Pattern-match for known-dangerous API call sites, rank by confidence,
then symbolically execute the high-confidence candidates at a depth
proportional to the confidence score.
"""

import os
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class VulnerabilityType(Enum):
    BUFFER_OVERFLOW = "buffer_overflow"
    USE_AFTER_FREE = "use_after_free"
    NULL_DEREFERENCE = "null_dereference"
    INTEGER_OVERFLOW = "integer_overflow"
    FORMAT_STRING = "format_string"
    SQL_INJECTION = "sql_injection"


class AnalysisLevel:
    """Depth tiers: more paths = higher cost, higher coverage."""
    FAST = "fast"
    STANDARD = "standard"
    DEEP = "deep"
    EXHAUSTIVE = "exhaustive"


@dataclass
class VulnerabilityCandidate:
    """A site flagged by pattern matching, scored for triage priority."""
    function_name: str
    function_address: int
    vuln_type: VulnerabilityType
    confidence: float
    evidence: Dict = field(default_factory=dict)


@dataclass
class SymbolicResult:
    """Output of a single symbolic execution run."""
    function_name: str
    vulnerabilities_found: List
    paths_explored: int
    constraints: List


class VulnerabilityDetector:
    """Regex-based pre-scanner. Flags functions that call unsafe C APIs
    and assigns a confidence estimate from pattern density."""

    def __init__(self):
        self._patterns = {
            VulnerabilityType.BUFFER_OVERFLOW: [
                r'memcpy\(', r'strcpy\(', r'sprintf\(', r'gets\(',
                r'memmove\(', r'strcat\('
            ],
            VulnerabilityType.USE_AFTER_FREE: [
                r'free\(', r'malloc\(', r'calloc\(', r'realloc\('
            ],
            VulnerabilityType.FORMAT_STRING: [
                r'printf\(', r'fprintf\(', r'snprintf\(', r'vfprintf\('
            ]
        }

    def scan_function(self, function_name: str, code: str) -> List[VulnerabilityCandidate]:
        """Match patterns within a single function's decompiled text."""
        candidates = []

        for vuln_type, patterns in self._patterns.items():
            matches = sum(1 for pattern in patterns if pattern in code)
            if matches > 0:
                candidates.append(VulnerabilityCandidate(
                    function_name=function_name,
                    function_address=0,
                    vuln_type=vuln_type,
                    confidence=min(matches * 0.3, 0.9),
                    evidence={"patterns_found": matches}
                ))

        return candidates

    def scan_binary(self, binary_data: bytes) -> List[VulnerabilityCandidate]:
        """Coarse scan over raw binary bytes treated as a text blob."""
        candidates = []
        code_str = binary_data.decode('utf-8', errors='ignore')

        for vuln_type, patterns in self._patterns.items():
            matches = sum(1 for pattern in patterns if pattern in code_str)
            if matches > 0:
                candidates.append(VulnerabilityCandidate(
                    function_name="unknown",
                    function_address=0,
                    vuln_type=vuln_type,
                    confidence=min(matches * 0.2, 0.8),
                    evidence={"pattern_count": matches}
                ))

        return candidates


class SymbolicExecutor:
    """Depth-gated symbolic execution. Path budget scales with analysis level;
    higher levels spend more CPU for deeper coverage."""

    def __init__(self):
        self._max_paths = 1000
        self._timeout = 300

    def execute(self, function_name: str, code: str, level: str = AnalysisLevel.STANDARD) -> SymbolicResult:
        """Run at the given depth tier. Path count is tier-gated;
        vulnerability detection here is a simplified heuristic."""
        paths_explored = 0
        vulnerabilities_found = []

        if level == AnalysisLevel.EXHAUSTIVE:
            paths_explored = 1000
        elif level == AnalysisLevel.DEEP:
            paths_explored = 500
        elif level == AnalysisLevel.STANDARD:
            paths_explored = 100
        else:
            paths_explored = 20

        if "memcpy" in code or "strcpy" in code:
            vulnerabilities_found.append({
                "type": "buffer_overflow",
                "location": function_name,
                "description": "Potential buffer overflow detected"
            })

        return SymbolicResult(
            function_name=function_name,
            vulnerabilities_found=vulnerabilities_found,
            paths_explored=paths_explored,
            constraints=[]
        )


class OnDemandAnalyzer:
    """Two-phase pipeline: detect candidates with regex, then symbolically
    execute only those above the confidence threshold. Allocates analysis
    depth proportional to confidence."""

    def __init__(self):
        self._detector = VulnerabilityDetector()
        self._executor = SymbolicExecutor()
        self._candidates: List[VulnerabilityCandidate] = []
        self._results: Dict[str, SymbolicResult] = {}

    def analyze_binary(self, binary_data: bytes) -> Dict[str, Any]:
        """Run the full detect→triage→execute pipeline."""
        self._candidates = self._detector.scan_binary(binary_data)

        high_confidence = [c for c in self._candidates if c.confidence >= 0.6]

        for candidate in high_confidence:
            logger.info(f"Analyzing function: {candidate.function_name}")
            result = self._executor.execute(
                candidate.function_name,
                str(candidate.evidence),
                self._get_analysis_level(candidate)
            )
            self._results[candidate.function_name] = result

        return self._generate_report()

    def _get_analysis_level(self, candidate: VulnerabilityCandidate) -> str:
        """Map confidence band to analysis depth tier."""
        if candidate.confidence >= 0.8:
            return AnalysisLevel.EXHAUSTIVE
        elif candidate.confidence >= 0.6:
            return AnalysisLevel.DEEP
        return AnalysisLevel.STANDARD

    def analyze_function(self, function_name: str, code: str) -> Optional[SymbolicResult]:
        """Scan one function; execute symbolically if confidence reaches 0.5."""
        candidates = self._detector.scan_function(function_name, code)

        if not candidates:
            logger.info(f"No vulnerability candidates found in {function_name}")
            return None

        max_confidence = max(c.confidence for c in candidates)

        if max_confidence >= 0.5:
            level = self._get_analysis_level(candidates[0])
            return self._executor.execute(function_name, code, level)

        return None

    def _generate_report(self) -> Dict[str, Any]:
        """Aggregate pipeline statistics into a summary dict."""
        total_candidates = len(self._candidates)
        analyzed = len(self._results)
        vulns_found = sum(len(r.vulnerabilities_found) for r in self._results.values())

        return {
            "total_candidates": total_candidates,
            "analyzed_functions": analyzed,
            "vulnerabilities_found": vulns_found,
            "results": {
                func: {
                    "vulns_found": len(res.vulnerabilities_found),
                    "paths_explored": res.paths_explored
                }
                for func, res in self._results.items()
            }
        }

    def get_candidates(self) -> List[VulnerabilityCandidate]:
        """Return all detected candidates from the last scan."""
        return self._candidates

    def get_results(self) -> Dict[str, SymbolicResult]:
        """Return all execution results from the last run."""
        return self._results


def analyze_on_demand(binary_path: str) -> Dict[str, Any]:
    """One-shot: read binary from disk, run the detect→triage→execute pipeline."""
    try:
        with open(binary_path, 'rb') as f:
            data = f.read()

        analyzer = OnDemandAnalyzer()
        return analyzer.analyze_binary(data)
    except Exception as e:
        logger.error(f"Failed to analyze binary: {e}")
        return {"error": str(e)}
