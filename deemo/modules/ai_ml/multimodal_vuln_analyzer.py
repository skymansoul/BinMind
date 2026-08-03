#!/usr/bin/env python3
# Multimodal vulnerability analyzer — weighted evidence fusion across analysis modalities.
# evidence fusion with modality weights; consensus 检测; contradiction resolution.

import logging as _logging
from collections import defaultdict as _defaultdict
from typing import Dict, Any, List, Optional, Tuple

__dbg = _logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Analysis Modality
# ---------------------------------------------------------------------------

class AnalysisModality:
    """Labels for distinct analysis modalities."""

    STATIC = "static_analysis"
    DYNAMIC = "dynamic_analysis"
    SYMBOLIC = "symbolic_execution"
    ML_PREDICTION = "ml_prediction"
    FUZZING = "fuzzing"
    FORMAL = "formal_verification"
    MANUAL = "manual_review"
    NETWORK = "network_analysis"
    BINARY_DIFFING = "binary_diffing"
    TAINT_TRACKING = "taint_tracking"

    ALL_MODALITIES = [
        STATIC, DYNAMIC, SYMBOLIC, ML_PREDICTION, FUZZING,
        FORMAL, MANUAL, NETWORK, BINARY_DIFFING, TAINT_TRACKING,
    ]

    @classmethod
    def is_valid(cls, modality: str) -> bool:
        return modality in cls.ALL_MODALITIES

    @classmethod
    def default_weight(cls, modality: str) -> float:
        weights = {
            cls.SYMBOLIC: 1.0,
            cls.FORMAL: 0.9,
            cls.MANUAL: 0.95,
            cls.DYNAMIC: 0.85,
            cls.FUZZING: 0.8,
            cls.TAINT_TRACKING: 0.75,
            cls.STATIC: 0.7,
            cls.BINARY_DIFFING: 0.65,
            cls.NETWORK: 0.6,
            cls.ML_PREDICTION: 0.5,
        }
        return weights.get(modality, 0.5)


# ---------------------------------------------------------------------------
# Modal Result
# ---------------------------------------------------------------------------

class ModalResult:
    """A single finding from one analysis modality."""

    __slots__ = ('m_modality', 'm_vuln_type', 'm_confidence', 'm_severity',
                 'm_evidence', 'm_false_positive_rate', 'm_location',
                 'm_timestamp', 'm_metadata')

    def __init__(self, modality, vuln_type, confidence, severity,
                 evidence="", false_positive_rate=0.2, location="",
                 metadata=None):
        self.m_modality = modality
        self.m_vuln_type = vuln_type
        self.m_confidence = float(confidence) if confidence is not None else 0.0
        self.m_severity = severity
        self.m_evidence = evidence
        self.m_false_positive_rate = float(false_positive_rate) if false_positive_rate is not None else 0.2
        self.m_location = location
        import time as _time
        self.m_timestamp = _time.time()
        self.m_metadata = dict(metadata) if metadata else {}

    def weighted_confidence(self, weight: float) -> float:
        return self.m_confidence * weight * (1.0 - self.m_false_positive_rate)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "modality": self.m_modality,
            "vuln_type": self.m_vuln_type,
            "confidence": round(self.m_confidence, 4),
            "severity": self.m_severity,
            "evidence": self.m_evidence[:200],
            "false_positive_rate": self.m_false_positive_rate,
            "location": self.m_location,
        }

    def __repr__(self):
        return (f"<ModalResult {self.m_modality}:{self.m_vuln_type} "
                f"conf={self.m_confidence:.2f} sev={self.m_severity}>")


# ---------------------------------------------------------------------------
# Fused Vulnerability
# ---------------------------------------------------------------------------

class FusedVuln:
    """Result of fusing multiple ModalResult instances."""

    __slots__ = ('m_vuln_id', 'm_vuln_type', 'm_modalities', 'm_fused_confidence',
                 'm_severity', 'm_is_consensus', 'm_contradictory',
                 'm_supporting_count', 'm_opposing_count', 'm_details')

    def __init__(self, vuln_id, vuln_type, modalities, fused_confidence,
                 severity, is_consensus, contradictory=False):
        self.m_vuln_id = vuln_id
        self.m_vuln_type = vuln_type
        self.m_modalities = modalities if modalities else []
        self.m_fused_confidence = fused_confidence
        self.m_severity = severity
        self.m_is_consensus = is_consensus
        self.m_contradictory = contradictory
        self.m_supporting_count = 0
        self.m_opposing_count = 0
        self.m_details: Dict[str, Any] = {}

    def compute_support(self, threshold=0.5):
        supporting = 0
        opposing = 0
        mi = 0
        while mi < len(self.m_modalities):
            if self.m_modalities[mi].m_confidence >= threshold:
                supporting += 1
            else:
                opposing += 1
            mi += 1
        self.m_supporting_count = supporting
        self.m_opposing_count = opposing

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vuln_id": self.m_vuln_id,
            "vuln_type": self.m_vuln_type,
            "modality_count": len(self.m_modalities),
            "fused_confidence": round(self.m_fused_confidence, 4),
            "severity": self.m_severity,
            "is_consensus": self.m_is_consensus,
            "contradictory": self.m_contradictory,
            "supporting": self.m_supporting_count,
            "opposing": self.m_opposing_count,
        }

    def __repr__(self):
        return (f"<FusedVuln {self.m_vuln_id} type={self.m_vuln_type} "
                f"conf={self.m_fused_confidence:.2f} consensus={self.m_is_consensus}>")


# ---------------------------------------------------------------------------
# Evidence Fusion Engine
# ---------------------------------------------------------------------------

class EvidenceFusion:
    """Fuses multiple modal results into a single confidence score using
    modality-specific weights and false-positive-rate penalization.
    """

    __slots__ = ('m_modality_weights', 'm_consensus_threshold',
                 'm_contradiction_threshold')

    def __init__(self, modality_weights=None, consensus_threshold=0.5,
                 contradiction_threshold=0.3):
        self.m_modality_weights = dict(modality_weights) if modality_weights else {}
        self.m_consensus_threshold = consensus_threshold
        self.m_contradiction_threshold = contradiction_threshold

    def _weight_for(self, modality: str) -> float:
        if modality in self.m_modality_weights:
            return self.m_modality_weights[modality]
        return AnalysisModality.default_weight(modality)

    def fuse(self, results: List[ModalResult]) -> FusedVuln:
        if not results:
            return FusedVuln(
                vuln_id="NONE", vuln_type="none", modalities=[],
                fused_confidence=0.0, severity="info", is_consensus=False,
            )

        total_weight = 0.0
        weighted_confidence = 0.0
        severity_counts: Dict[str, int] = _defaultdict(int)

        ri = 0
        while ri < len(results):
            result = results[ri]
            w = self._weight_for(result.m_modality)
            total_weight += w
            weighted_confidence += result.weighted_confidence(w)
            severity_counts[result.m_severity] += 1
            ri += 1

        fused_conf = weighted_confidence / max(0.01, total_weight)
        fused_conf = min(1.0, max(0.0, fused_conf))

        # Most common vuln type
        type_counts: Dict[str, float] = _defaultdict(float)
        ri = 0
        while ri < len(results):
            type_counts[results[ri].m_vuln_type] += results[ri].m_confidence
            ri += 1
        vuln_type = max(type_counts, key=lambda k: type_counts[k]) if type_counts else "unknown"

        # Most common severity
        severity = max(severity_counts, key=lambda k: severity_counts[k]) if severity_counts else "info"

        # Consensus: at least 2 modalities with confidence > threshold
        high_conf_count = 0
        ri = 0
        while ri < len(results):
            if results[ri].m_confidence > self.m_consensus_threshold:
                high_conf_count += 1
            ri += 1
        is_consensus = high_conf_count >= 2

        # Contradiction: different vuln types with high confidence
        vuln_types = set()
        ri = 0
        while ri < len(results):
            if results[ri].m_confidence > self.m_contradiction_threshold:
                vuln_types.add(results[ri].m_vuln_type)
            ri += 1
        has_contradiction = len(vuln_types) > 1 and len(results) > 1

        fused = FusedVuln(
            vuln_id=f"FUSED-{vuln_type}",
            vuln_type=vuln_type,
            modalities=list(results),
            fused_confidence=round(fused_conf, 4),
            severity=severity,
            is_consensus=is_consensus,
            contradictory=has_contradiction,
        )
        fused.compute_support(self.m_consensus_threshold)
        return fused

    def fuse_multi(self, grouped_results: Dict[str, List[ModalResult]]) -> List[FusedVuln]:
        fused_list: List[FusedVuln] = []
        keys = list(grouped_results.keys())
        ki = 0
        while ki < len(keys):
            vuln_type = keys[ki]
            results = grouped_results[vuln_type]
            fused = self.fuse(results)
            fused_list.append(fused)
            ki += 1
        return fused_list


# ---------------------------------------------------------------------------
# Multimodal Vulnerability Analyzer
# ---------------------------------------------------------------------------

class MultimodalVulnAnalyzer:
    """Orchestrates multimodal vulnerability analysis with evidence fusion.

    Accepts results from multiple analysis modalities (static, dynamic,
    symbolic, ML, fuzzing, etc.) and fuses them into consensus scores.
    """

    __slots__ = ('m_fusion', 'm_modal_results', 'm_fused',
                 'm_history', 'm_config')

    def __init__(self, modality_weights=None, consensus_threshold=0.5):
        self.m_fusion = EvidenceFusion(
            modality_weights=modality_weights,
            consensus_threshold=consensus_threshold,
        )
        self.m_modal_results: Dict[str, List[ModalResult]] = _defaultdict(list)
        self.m_fused: List[FusedVuln] = []
        self.m_history: List[Dict[str, Any]] = []
        self.m_config: Dict[str, Any] = {}

    def add_modal_result(self, vuln_type: str, modality: str, confidence: float,
                         severity: str, evidence: str = "", fpr: float = 0.2,
                         location: str = "", metadata: Dict[str, Any] = None):
        if not AnalysisModality.is_valid(modality):
            __dbg.warning("Unknown modality '%s', using STATIC", modality)
            modality = AnalysisModality.STATIC

        result = ModalResult(
            modality=modality,
            vuln_type=vuln_type,
            confidence=confidence,
            severity=severity,
            evidence=evidence,
            false_positive_rate=fpr,
            location=location,
            metadata=metadata,
        )
        self.m_modal_results[vuln_type].append(result)
        return result

    def add_results_batch(self, results: List[Dict[str, Any]]):
        ri = 0
        while ri < len(results):
            r = results[ri]
            self.add_modal_result(
                vuln_type=r.get("vuln_type", "unknown"),
                modality=r.get("modality", AnalysisModality.STATIC),
                confidence=r.get("confidence", 0.0),
                severity=r.get("severity", "info"),
                evidence=r.get("evidence", ""),
                fpr=r.get("false_positive_rate", 0.2),
                location=r.get("location", ""),
                metadata=r.get("metadata"),
            )
            ri += 1

    def analyze(self, modal_results: Optional[List[Dict[str, Any]]] = None,
                **kwargs) -> Dict[str, Any]:
        if modal_results:
            self.add_results_batch(modal_results)

        vuln_counts: Dict[str, Dict[str, Any]] = {}
        self.m_fused = []

        keys = list(self.m_modal_results.keys())
        ki = 0
        while ki < len(keys):
            vuln_type = keys[ki]
            results = self.m_modal_results[vuln_type]
            fused = self.m_fusion.fuse(results)
            self.m_fused.append(fused)
            vuln_counts[vuln_type] = {
                "modal_count": len(results),
                "fused_confidence": fused.m_fused_confidence,
                "is_consensus": fused.m_is_consensus,
                "contradictory": fused.m_contradictory,
                "severity": fused.m_severity,
            }
            ki += 1

        # Summary
        consensus_vulns = [f.to_dict() for f in self.m_fused if f.m_is_consensus and not f.m_contradictory]
        contradictory_vulns = [f.to_dict() for f in self.m_fused if f.m_contradictory]
        high_confidence = [f.to_dict() for f in self.m_fused if f.m_fused_confidence > 0.7]

        recommendations: List[str] = []
        if contradictory_vulns:
            recommendations.append(
                "Manual review required for contradictory findings across modalities"
            )
            recommendations.append(
                f"{len(contradictory_vulns)} vulnerability types exhibit inter-modal "
                "conflict; consider appending symbolic execution pass for resolution"
            )
        if high_confidence:
            recommendations.append(
                f"{len(high_confidence)} vulnerabilities have high confidence (>0.7) "
                "and should be prioritized for remediation"
            )

        result = {
            "success": True,
            "total_vuln_types": len(vuln_counts),
            "vulnerabilities": vuln_counts,
            "consensus_vulns": consensus_vulns,
            "contradictory_vulns": contradictory_vulns,
            "high_confidence_vulns": len(high_confidence),
            "confidence_threshold": self.m_fusion.m_consensus_threshold,
            "recommendations": recommendations,
            "fused_details": [f.to_dict() for f in self.m_fused],
        }

        self.m_history.append({
            "timestamp": _import_time(),
            "vuln_count": len(vuln_counts),
            "consensus_count": len(consensus_vulns),
        })

        return result

    def get_consensus_findings(self) -> List[FusedVuln]:
        return [f for f in self.m_fused if f.m_is_consensus and not f.m_contradictory]

    def get_high_confidence_findings(self, threshold=0.7) -> List[FusedVuln]:
        return [f for f in self.m_fused if f.m_fused_confidence >= threshold]

    def get_contradictory_findings(self) -> List[FusedVuln]:
        return [f for f in self.m_fused if f.m_contradictory]

    def reset(self):
        self.m_modal_results.clear()
        self.m_fused.clear()
        self.m_history.clear()

    def get_statistics(self) -> Dict[str, Any]:
        total_modals = sum(len(v) for v in self.m_modal_results.values())
        return {
            "total_modal_results": total_modals,
            "unique_vuln_types": len(self.m_modal_results),
            "fused_count": len(self.m_fused),
            "consensus_count": len(self.get_consensus_findings()),
            "contradiction_count": len(self.get_contradictory_findings()),
        }


def _import_time():
    import time
    return time.time()


# ---------------------------------------------------------------------------
# Convenience
# ---------------------------------------------------------------------------

def analyze_multimodal(modal_results: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
    analyzer = MultimodalVulnAnalyzer()
    return analyzer.analyze(modal_results=modal_results)


__all__ = [
    "MultimodalVulnAnalyzer", "EvidenceFusion", "ModalResult",
    "FusedVuln", "AnalysisModality", "analyze_multimodal",
]
