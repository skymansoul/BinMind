import logging
import re
import ast
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple, Set

# from core.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

logger = logging.getLogger(__name__)

DEFAULT_SCORE = 60.0


class ValidationStatus(Enum):
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    NOT_APPLICABLE = "not_applicable"

class ValidationCategory(Enum):
    SYNTAX = "syntax"
    CFG = "cfg"
    TYPES = "types"
    SEMANTIC = "semantic"
    BEHAVIOR = "behavior"


@dataclass
class CFGNode:
    node_id: str
    address: int
    instructions: list = field(default_factory=list)
    predecessors: list = field(default_factory=list)
    successors: list = field(default_factory=list)


@dataclass
class CFGGraph:
    function_name: str
    function_address: int
    entry_node_id: str
    nodes: Dict[str, CFGNode]
    edges: List[Tuple]


@dataclass
class ValidationFinding:
    category: ValidationCategory
    status: ValidationStatus
    message: str
    details: dict = field(default_factory=dict)
    score_impact: float = 0.0


@dataclass
class ValidationReport:
    function_name: str
    function_address: int
    overall_score: float
    status: ValidationStatus
    findings: List[ValidationFinding]
    category_scores: Dict[str, float]
    recommendations: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


class DecompilerValidator:
    """
    Decompiler output validator.

    Core functions:
    1. validate_syntax -- check if decompiled code passes syntax analysis
    2. compare_cfg -- compare original CFG with decompiled CFG
    3. validate_types -- type consistency check
    4. semantic_equivalence_score -- semantic equivalence scoring
    5. generate_validation_report -- comprehensive validation report
    """

    WEIGHTS = {
        ValidationCategory.SYNTAX: 0.25,
        ValidationCategory.CFG: 0.30,
        ValidationCategory.TYPES: 0.20,
        ValidationCategory.SEMANTIC: 0.25,
    }

    def __init__(self):
        self._findings: List[ValidationFinding] = []
        self._strict_mode: bool = False

    def validate_syntax(self, code: str,
                          language: str = "c") -> List[ValidationFinding]:
        findings: List[ValidationFinding] = []

        if not code or not code.strip():
            findings.append(ValidationFinding(
                category=ValidationCategory.SYNTAX,
                status=ValidationStatus.FAIL,
                message="Decompiled code is empty",
                score_impact=-25.0
            ))
            return findings

        bracket_ok, bracket_msg = self._check_bracket_balance(code)
        if not bracket_ok:
            findings.append(ValidationFinding(
                category=ValidationCategory.SYNTAX,
                status=ValidationStatus.FAIL,
                message=f"Bracket mismatch: {bracket_msg}",
                details={"unmatched": bracket_msg},
                score_impact=-10.0
            ))
        else:
            findings.append(ValidationFinding(
                category=ValidationCategory.SYNTAX,
                status=ValidationStatus.PASS,
                message="Bracket balance correct",
                score_impact=5.0
            ))

        if language in ("c", "c-like"):
            findings.extend(self._check_semicolons(code))

        if language == "python":
            findings.extend(self._try_ast_parse(code))

        if language in ("c", "c-like"):
            findings.extend(self._check_c_patterns(code))

        return findings

    @staticmethod
    def _check_bracket_balance(code: str) -> Tuple[bool, str]:
        pairs = {"(": ")", "{": "}", "[": "]"}
        closing = {v: k for k, v in pairs.items()}
        stack: List[Tuple[str, int]] = []
        for i, ch in enumerate(code):
            if ch in pairs:
                stack.append((ch, i))
            elif ch in closing:
                if not stack:
                    return False, f"Extra '{ch}' at position {i}"
                last_open, last_pos = stack.pop()
                if pairs[last_open] != ch:
                    return False, (f"'{last_open}' at {last_pos} "
                                   f"incorrectly closed by '{ch}' at {i}")
        if stack:
            unmatched = ", ".join(f"'{c}' at {p}" for c, p in stack)
            return False, f"Unclosed: {unmatched}"
        return True, ""

    @staticmethod
    def _check_semicolons(code: str) -> List[ValidationFinding]:
        findings: List[ValidationFinding] = []
        lines = code.split('\n')
        suspicious = 0
        for line in lines:
            stripped = line.strip()
            if stripped and not stripped.startswith(('//', '#', '/*', '*')):
                if stripped.endswith(('{', '}', ')', ';')):
                    continue
                if len(stripped) > 10 and not stripped.endswith(';'):
                    suspicious += 1
        if suspicious > 0:
            findings.append(ValidationFinding(
                category=ValidationCategory.SYNTAX,
                status=(ValidationStatus.WARNING if suspicious <= 3
                        else ValidationStatus.FAIL),
                message=f"Found {suspicious} lines possibly missing semicolons",
                details={"suspicious_lines": suspicious},
                score_impact=max(-suspicious * 2.0, -100.0)
            ))
        else:
            findings.append(ValidationFinding(
                category=ValidationCategory.SYNTAX,
                status=ValidationStatus.PASS,
                message="Semicolon usage normal",
                score_impact=2.0
            ))
        return findings

    @staticmethod
    def _try_ast_parse(code: str) -> List[ValidationFinding]:
        try:
            ast.parse(code)
            return [ValidationFinding(
                category=ValidationCategory.SYNTAX,
                status=ValidationStatus.PASS,
                message="Python AST parse passed",
                score_impact=10.0
            )]
        except SyntaxError as e:
            return [ValidationFinding(
                category=ValidationCategory.SYNTAX,
                status=ValidationStatus.FAIL,
                message=f"Python syntax error: {e.msg} (line {e.lineno})",
                details={"line": e.lineno, "offset": e.offset, "msg": e.msg},
                score_impact=-15.0
            )]

    @staticmethod
    def _check_c_patterns(code: str) -> List[ValidationFinding]:
        findings: List[ValidationFinding] = []
        gibberish = re.findall(r'\b[a-zA-Z_]\w{30,}\b', code)
        if gibberish:
            findings.append(ValidationFinding(
                category=ValidationCategory.SYNTAX,
                status=ValidationStatus.WARNING,
                message=f"Found {len(gibberish)} excessively long identifiers",
                details={"gibberish_examples": gibberish[:5]},
                score_impact=max(-len(gibberish) * 1.5, -10.0)
            ))
        return findings

    def compare_cfg(self, original_cfg: CFGGraph,
                      decompiled_cfg: CFGGraph) -> List[ValidationFinding]:
        findings: List[ValidationFinding] = []
        orig_n = len(original_cfg.nodes)
        dec_n = len(decompiled_cfg.nodes)
        orig_e = len(original_cfg.edges)
        dec_e = len(decompiled_cfg.edges)

        if orig_n == 0:
            findings.append(ValidationFinding(
                category=ValidationCategory.CFG,
                status=ValidationStatus.FAIL,
                message="Original CFG has no nodes",
                score_impact=-20.0
            ))
            return findings

        node_ratio = dec_n / max(1, orig_n)
        if node_ratio >= 0.9:
            findings.append(ValidationFinding(
                category=ValidationCategory.CFG,
                status=ValidationStatus.PASS,
                message=f"Node count matches: orig={orig_n}, dec={dec_n}, ratio={node_ratio:.2f}",
                details={"original_nodes": orig_n, "decompiled_nodes": dec_n,
                         "ratio": node_ratio},
                score_impact=10.0
            ))
        elif node_ratio >= 0.5:
            findings.append(ValidationFinding(
                category=ValidationCategory.CFG,
                status=ValidationStatus.WARNING,
                message=f"Node count partial match: ratio={node_ratio:.2f}",
                details={"original_nodes": orig_n, "decompiled_nodes": dec_n,
                         "ratio": node_ratio},
                score_impact=-5.0
            ))
        else:
            findings.append(ValidationFinding(
                category=ValidationCategory.CFG,
                status=ValidationStatus.FAIL,
                message=f"Node count severe mismatch: ratio={node_ratio:.2f}",
                details={"original_nodes": orig_n, "decompiled_nodes": dec_n,
                         "ratio": node_ratio},
                score_impact=-15.0
            ))

        if orig_e > 0:
            edge_ratio = dec_e / orig_e
            findings.append(ValidationFinding(
                category=ValidationCategory.CFG,
                status=(ValidationStatus.PASS if edge_ratio >= 0.8
                        else ValidationStatus.WARNING),
                message=f"Edge count match: orig={orig_e}, dec={dec_e}, ratio={edge_ratio:.2f}",
                details={"original_edges": orig_e, "decompiled_edges": dec_e,
                         "ratio": edge_ratio},
                score_impact=8.0 if edge_ratio >= 0.8 else -6.0
            ))

        orig_deg = self._compute_degree_distribution(original_cfg)
        dec_deg = self._compute_degree_distribution(decompiled_cfg)
        deg_sim = self._jaccard_similarity(
            set(orig_deg.keys()), set(dec_deg.keys())
        )
        findings.append(ValidationFinding(
            category=ValidationCategory.CFG,
            status=(ValidationStatus.PASS if deg_sim > 0.7
                    else ValidationStatus.WARNING),
            message=f"Degree distribution Jaccard similarity: {deg_sim:.2f}",
            details={"similarity": deg_sim, "orig_degrees": orig_deg,
                     "dec_degrees": dec_deg},
            score_impact=deg_sim * 6.0 - 2.0
        ))

        return findings

    @staticmethod
    def _compute_degree_distribution(cfg: CFGGraph) -> Dict[int, int]:
        dist: Dict[int, int] = {}
        for node in cfg.nodes.values():
            deg = len(node.successors) + len(node.predecessors)
            dist[deg] = dist.get(deg, 0) + 1
        return dist

    def validate_types(self, decompiled_code: str,
                         type_annotations: Optional[Dict[str, str]] = None
                         ) -> List[ValidationFinding]:
        findings: List[ValidationFinding] = []
        annotations = type_annotations or {}

        inconsistencies = self._detect_type_inconsistencies(
            decompiled_code, annotations
        )
        if inconsistencies:
            findings.append(ValidationFinding(
                category=ValidationCategory.TYPES,
                status=ValidationStatus.WARNING,
                message=f"Detected {len(inconsistencies)} potential type inconsistencies",
                details={"inconsistencies": inconsistencies[:10]},
                score_impact=-len(inconsistencies) * 2.0
            ))
        else:
            findings.append(ValidationFinding(
                category=ValidationCategory.TYPES,
                status=ValidationStatus.PASS,
                message="No obvious type inconsistencies detected",
                score_impact=5.0
            ))

        ptr_misuse = self._check_pointer_misuse(decompiled_code)
        if ptr_misuse:
            findings.append(ValidationFinding(
                category=ValidationCategory.TYPES,
                status=ValidationStatus.WARNING,
                message=f"Pointer/integer mixing: {len(ptr_misuse)} sites",
                details={"examples": ptr_misuse[:5]},
                score_impact=max(-len(ptr_misuse) * 3.0, -10.0)
            ))

        if annotations:
            findings.extend(self._validate_annotations(decompiled_code,
                                                         annotations))

        return findings

    @staticmethod
    def _detect_type_inconsistencies(code: str,
                                       annotations: Dict[str, str]) -> List[str]:
        issues: List[str] = []
        for i, line in enumerate(code.split('\n')):
            stripped = line.strip()
            if re.search(r'=\s*\(void\s*\*\s*\)', stripped):
                issues.append(f"Line {i+1}: void* cast")
            if re.search(r'=\s*\(unsigned\s+int\s*\)\s*-\d+', stripped):
                issues.append(f"Line {i+1}: signed->unsigned conversion")
            if re.search(r'=\s*\(int(32_t)?\s*\)', stripped):
                issues.append(f"Line {i+1}: possible truncation cast")
        return issues

    @staticmethod
    def _check_pointer_misuse(code: str) -> List[str]:
        issues = []
        for i, line in enumerate(code.split('\n')):
            if re.search(r'\*\s*\(\s*\w+\s*\+\s*\d+\s*\)', line):
                issues.append(f"Line {i+1}: suspicious pointer arithmetic")
        return issues

    @staticmethod
    def _validate_annotations(code: str,
                                annotations: Dict[str, str]
                                ) -> List[ValidationFinding]:
        findings = []
        for var_name, expected_type in annotations.items():
            if var_name not in code:
                findings.append(ValidationFinding(
                    category=ValidationCategory.TYPES,
                    status=ValidationStatus.WARNING,
                    message=f"Variable '{var_name}' not found in decompiled code",
                    details={"var": var_name, "expected_type": expected_type},
                    score_impact=-2.0
                ))
        return findings

    def semantic_equivalence_score(self, original_code: str,
                                     decompiled_code: str,
                                     test_inputs: Optional[List[Dict[str, Any]]] = None
                                     ) -> Tuple[float, List[ValidationFinding]]:
        findings: List[ValidationFinding] = []
        scores: List[float] = []

        sym_score, sym_finding = self._symbol_preservation_score(
            original_code, decompiled_code
        )
        scores.append(sym_score)
        findings.append(sym_finding)

        str_score, str_finding = self._string_constants_score(
            original_code, decompiled_code
        )
        scores.append(str_score)
        findings.append(str_finding)

        struct_score, struct_finding = self._structure_similarity(
            original_code, decompiled_code
        )
        scores.append(struct_score)
        findings.append(struct_finding)

        call_score, call_finding = self._function_call_preservation(
            original_code, decompiled_code
        )
        scores.append(call_score)
        findings.append(call_finding)

        SEMANTIC_WEIGHTS = [0.30, 0.20, 0.25, 0.25]
        final = sum(s * w for s, w in zip(scores, SEMANTIC_WEIGHTS))
        return round(final, 2), findings

    @staticmethod
    def _symbol_preservation_score(original: str, decompiled: str
                                     ) -> Tuple[float, ValidationFinding]:
        orig_syms = set(re.findall(r'\b([a-zA-Z_]\w{2,})\b', original))
        dec_syms = set(re.findall(r'\b([a-zA-Z_]\w{2,})\b', decompiled))
        if not orig_syms:
            return 50.0, ValidationFinding(
                category=ValidationCategory.SEMANTIC,
                status=ValidationStatus.NOT_APPLICABLE,
                message="Original code has no named symbols", score_impact=0.0
            )
        intersection = orig_syms & dec_syms
        ratio = len(intersection) / len(orig_syms)
        status = (ValidationStatus.PASS if ratio > 0.7 else
                  (ValidationStatus.WARNING if ratio > 0.3 else
                   ValidationStatus.FAIL))
        return ratio * 100, ValidationFinding(
            category=ValidationCategory.SEMANTIC,
            status=status,
            message=f"Symbol retention rate: {ratio:.0%} ({len(intersection)}/{len(orig_syms)})",
            details={"retained": len(intersection), "total": len(orig_syms)},
            score_impact=ratio * 20.0 - 10.0
        )

    @staticmethod
    def _string_constants_score(original: str, decompiled: str
                                  ) -> Tuple[float, ValidationFinding]:
        orig_strs = set(re.findall(r'"([^"]*)"', original))
        dec_strs = set(re.findall(r'"([^"]*)"', decompiled))
        if not orig_strs:
            return 60.0, ValidationFinding(
                category=ValidationCategory.SEMANTIC,
                status=ValidationStatus.NOT_APPLICABLE,
                message="Original code has no string constants", score_impact=0.0
            )
        ratio = len(orig_strs & dec_strs) / len(orig_strs)
        return ratio * 100, ValidationFinding(
            category=ValidationCategory.SEMANTIC,
            status=(ValidationStatus.PASS if ratio > 0.8
                    else ValidationStatus.WARNING),
            message=f"String constant match rate: {ratio:.0%}",
            details={"matched": len(orig_strs & dec_strs),
                     "total": len(orig_strs)},
            score_impact=ratio * 15.0 - 5.0
        )

    @staticmethod
    def _structure_similarity(original: str, decompiled: str
                                ) -> Tuple[float, ValidationFinding]:
        keywords = ["if", "else", "for", "while", "do", "switch",
                    "case", "return", "break", "continue", "goto"]
        orig_cnt = {kw: len(re.findall(rf'\b{kw}\b', original, re.IGNORECASE))
                    for kw in keywords}
        dec_cnt = {kw: len(re.findall(rf'\b{kw}\b', decompiled, re.IGNORECASE))
                   for kw in keywords}
        dot = sum(orig_cnt[k] * dec_cnt[k] for k in keywords)
        orig_n = (sum(v**2 for v in orig_cnt.values())) ** 0.5
        dec_n = (sum(v**2 for v in dec_cnt.values())) ** 0.5
        if orig_n == 0:
            return 50.0, ValidationFinding(
                category=ValidationCategory.SEMANTIC,
                status=ValidationStatus.NOT_APPLICABLE,
                message="Cannot compute structure similarity", score_impact=0.0
            )
        cosine = dot / (orig_n * dec_n + 1e-9)
        status = (ValidationStatus.PASS if cosine > 0.8 else
                  (ValidationStatus.WARNING if cosine > 0.5 else
                   ValidationStatus.FAIL))
        return cosine * 100, ValidationFinding(
            category=ValidationCategory.SEMANTIC,
            status=status,
            message=f"Structure similarity (cosine): {cosine:.2f}",
            details={"cosine_similarity": cosine},
            score_impact=cosine * 18.0 - 6.0
        )

    @staticmethod
    def _function_call_preservation(original: str, decompiled: str
                                      ) -> Tuple[float, ValidationFinding]:
        orig_calls = set(re.findall(r'\b([a-zA-Z_]\w+)\s*\(', original))
        dec_calls = set(re.findall(r'\b([a-zA-Z_]\w+)\s*\(', decompiled))
        if not orig_calls:
            return 60.0, ValidationFinding(
                category=ValidationCategory.SEMANTIC,
                status=ValidationStatus.NOT_APPLICABLE,
                message="No function calls detected", score_impact=0.0
            )
        ratio = len(orig_calls & dec_calls) / len(orig_calls)
        status = (ValidationStatus.PASS if ratio > 0.7
                  else ValidationStatus.WARNING)
        return ratio * 100, ValidationFinding(
            category=ValidationCategory.SEMANTIC,
            status=status,
            message=f"Function call retention rate: {ratio:.0%}",
            details={"retained": len(orig_calls & dec_calls),
                     "total": len(orig_calls)},
            score_impact=ratio * 15.0 - 5.0
        )

    def generate_validation_report(self,
                                     decompiled_code: str,
                                     original_cfg: Optional[CFGGraph] = None,
                                     decompiled_cfg: Optional[CFGGraph] = None,
                                     original_code: Optional[str] = None,
                                     type_annotations: Optional[Dict[str, str]] = None
                                     ) -> ValidationReport:
        all_findings: List[ValidationFinding] = []
        cat_scores: Dict[str, float] = {}

        syntax_findings = self.validate_syntax(decompiled_code)
        all_findings.extend(syntax_findings)
        cat_scores["syntax"] = self._compute_category_score(syntax_findings)

        if original_cfg and decompiled_cfg:
            cfg_findings = self.compare_cfg(original_cfg, decompiled_cfg)
            all_findings.extend(cfg_findings)
            cat_scores["cfg"] = self._compute_category_score(cfg_findings)
        else:
            cat_scores["cfg"] = 50.0

        type_findings = self.validate_types(decompiled_code, type_annotations)
        all_findings.extend(type_findings)
        cat_scores["types"] = self._compute_category_score(type_findings)

        if original_code:
            sem_score, sem_findings = self.semantic_equivalence_score(
                original_code, decompiled_code
            )
            all_findings.extend(sem_findings)
            cat_scores["semantic"] = sem_score
        else:
            cat_scores["semantic"] = 50.0

        overall = sum(
            cat_scores.get(cat.value, 50) * w
            for cat, w in self.WEIGHTS.items()
        )

        status = (ValidationStatus.PASS if overall >= 80 else
                  (ValidationStatus.WARNING if overall >= 50 else
                   ValidationStatus.FAIL))

        recommendations = self._generate_recommendations(all_findings)

        return ValidationReport(
            function_name="unknown", function_address=0,
            overall_score=round(overall, 2), status=status,
            findings=all_findings, category_scores=cat_scores,
            recommendations=recommendations,
            metadata={"strict_mode": self._strict_mode,
                      "weights": {k.value: v for k, v in self.WEIGHTS.items()}}
        )

    @staticmethod
    def _compute_category_score(findings: List[ValidationFinding]) -> float:
        if not findings:
            return DEFAULT_SCORE
        base = DEFAULT_SCORE
        for f in findings:
            base += f.score_impact
        return min(max(base, 0.0), 100.0)

    @staticmethod
    def _generate_recommendations(findings: List[ValidationFinding]) -> List[str]:
        recs = []
        has_fail = any(f.status == ValidationStatus.FAIL for f in findings)
        has_warn = any(f.status == ValidationStatus.WARNING for f in findings)
        if has_fail:
            recs.append("Critical: check decompiler version and input binary integrity")
        if has_warn:
            recs.append("Warnings present: recommend manual review of decompiled output")
        if any(f.category == ValidationCategory.SYNTAX and
               f.status == ValidationStatus.FAIL for f in findings):
            recs.append("Syntax errors: decompiled output may be incomplete, try adjusting decompiler options")
        if any(f.category == ValidationCategory.CFG and
               f.status == ValidationStatus.FAIL for f in findings):
            recs.append("CFG mismatch: obfuscation or indirect jumps may not be correctly resolved")
        if not recs:
            recs.append("Decompiled output quality is good, recommend functional validation")
        return recs

    @staticmethod
    def _jaccard_similarity(set_a: Set, set_b: Set) -> float:
        union = len(set_a | set_b)
        if union == 0:
            return 1.0
        return len(set_a & set_b) / union

    def set_strict_mode(self, strict: bool) -> None:
        self._strict_mode = strict

    def analyze(self, **kwargs) -> Dict[str, Any]:
        action = kwargs.get("action", "report")

        try:
            if action == "syntax":
                code = kwargs.get("code", "")
                lang = kwargs.get("language", "c")
                findings = self.validate_syntax(code, lang)
                return {
                    "success": True,
                    "findings": [
                        {"category": f.category.value,
                         "status": f.status.value,
                         "message": f.message,
                         "score_impact": f.score_impact}
                        for f in findings
                    ],
                    "score": self._compute_category_score(findings)
                }

            elif action == "cfg":
                orig = self._parse_cfg(kwargs.get("original_cfg"))
                dec = self._parse_cfg(kwargs.get("decompiled_cfg"))
                if not orig or not dec:
                    return {"success": False,
                            "error": "original_cfg and decompiled_cfg required"}
                findings = self.compare_cfg(orig, dec)
                return {
                    "success": True,
                    "findings": [
                        {"category": f.category.value,
                         "status": f.status.value,
                         "message": f.message,
                         "score_impact": f.score_impact}
                        for f in findings
                    ],
                    "score": self._compute_category_score(findings)
                }

            elif action == "types":
                code = kwargs.get("code", "")
                annotations = kwargs.get("type_annotations")
                findings = self.validate_types(code, annotations)
                return {
                    "success": True,
                    "findings": [
                        {"category": f.category.value,
                         "status": f.status.value,
                         "message": f.message,
                         "score_impact": f.score_impact}
                        for f in findings
                    ],
                    "score": self._compute_category_score(findings)
                }

            elif action == "semantic":
                code = kwargs.get("code", "")
                original = kwargs.get("original_code", "")
                if not code or not original:
                    return {"success": False,
                            "error": "code and original_code required"}
                score, findings = self.semantic_equivalence_score(original, code)
                return {
                    "success": True,
                    "score": score,
                    "findings": [
                        {"category": f.category.value,
                         "status": f.status.value,
                         "message": f.message,
                         "score_impact": f.score_impact}
                        for f in findings
                    ]
                }

            elif action == "report":
                code = kwargs.get("code", "")
                if not code:
                    return {"success": False, "error": "code is required"}
                orig_cfg = self._parse_cfg(kwargs.get("original_cfg"))
                dec_cfg = self._parse_cfg(kwargs.get("decompiled_cfg"))
                original = kwargs.get("original_code", "")
                report = self.generate_validation_report(
                    code,
                    original_cfg=orig_cfg,
                    decompiled_cfg=dec_cfg,
                    original_code=original if original else None,
                    type_annotations=kwargs.get("type_annotations")
                )
                return {
                    "success": True,
                    "report": {
                        "overall_score": report.overall_score,
                        "status": report.status.value,
                        "category_scores": report.category_scores,
                        "findings_count": len(report.findings),
                        "recommendations": report.recommendations,
                        "findings": [
                            {"category": f.category.value,
                             "status": f.status.value,
                             "message": f.message}
                            for f in report.findings[:20]
                        ]
                    }
                }

            else:
                return {"success": False,
                        "error": f"Unsupported action: {action}"}

        except Exception as e:
            logger.error(f"Decompiler validation failed: {e}", exc_info=True)
            return {"success": False, "error": str(e)}

    def _parse_cfg(self, cfg_data: Any) -> Optional[CFGGraph]:
        if not cfg_data:
            return None
        if isinstance(cfg_data, CFGGraph):
            return cfg_data
        if isinstance(cfg_data, dict):
            nodes = {}
            for n in cfg_data.get("nodes", []):
                node = CFGNode(
                    node_id=n.get("node_id", ""),
                    address=n.get("address", 0),
                    instructions=n.get("instructions", []),
                    predecessors=n.get("predecessors", []),
                    successors=n.get("successors", [])
                )
                nodes[node.node_id] = node
            edges = [tuple(e) for e in cfg_data.get("edges", [])]
            return CFGGraph(
                function_name=cfg_data.get("function_name", ""),
                function_address=cfg_data.get("function_address", 0),
                entry_node_id=cfg_data.get("entry_node_id", ""),
                nodes=nodes, edges=edges
            )
        return None


__all__ = ["DecompilerValidator", "ValidationReport", "ValidationFinding",
           "ValidationStatus", "ValidationCategory", "CFGGraph", "CFGNode"]
