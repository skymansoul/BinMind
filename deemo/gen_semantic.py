import os

content = '''# -*- coding: utf-8 -*-
"""Variable-Level Semantic Role Labeling"""
import os
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Any, Optional, Tuple, Set
from pathlib import Path

class SemanticRole(Enum):
    LOOP_COUNTER = "loop_counter"
    BUFFER_POINTER = "buffer_pointer"
    BUFFER_LENGTH = "buffer_length"
    CHECKSUM_VALUE = "checksum_value"
    RETURN_VALUE = "return_value"
    TEMPORARY = "temporary"
    CONSTANT = "constant"
    POINTER = "pointer"
    COUNTER = "counter"
    FLAG = "flag"
    UNKNOWN = "unknown"

@dataclass
class VariableInfo:
    name: str
    type: str
    definition_location: int
    usage_locations: List[int] = field(default_factory=list)
    operations: List[str] = field(default_factory=list)
    role: SemanticRole = SemanticRole.UNKNOWN
    confidence: float = 0.0

@dataclass
class FunctionVariableAnalysis:
    function_name: str
    variables: List[VariableInfo] = field(default_factory=list)
    call_graph_edges: List[Tuple[str, str]] = field(default_factory=list)

class VariableUsagePattern:
    def __init__(self):
        self.patterns = {
            SemanticRole.LOOP_COUNTER: [
                {"op": "add", "count": 2, "context": ["cmp", "jmp"]},
                {"op": "sub", "count": 1, "context": ["cmp", "jge"]},
                {"op": "inc", "count": 1, "context": ["cmp", "jne"]},
                {"op": "dec", "count": 1, "context": ["cmp", "jnz"]}
            ],
            SemanticRole.BUFFER_POINTER: [
                {"op": "mov", "count": 1, "context": ["lea", "offset"]},
                {"op": "add", "count": 1, "context": ["reg", "size"]},
                {"op": "mov", "count": 1, "context": ["deref", "byte"]}
            ],
            SemanticRole.BUFFER_LENGTH: [
                {"op": "mov", "count": 1, "context": ["const", "large"]},
                {"op": "cmp", "count": 2, "context": ["ptr", "length"]},
                {"op": "sub", "count": 1, "context": ["length", "index"]}
            ],
            SemanticRole.CHECKSUM_VALUE: [
                {"op": "xor", "count": 3, "context": ["byte", "accum"]},
                {"op": "add", "count": 2, "context": ["byte", "sum"]},
                {"op": "rol", "count": 1, "context": ["byte", "rotate"]}
            ],
            SemanticRole.FLAG: [
                {"op": "and", "count": 1, "context": ["mask", "bit"]},
                {"op": "or", "count": 1, "context": ["set", "bit"]},
                {"op": "test", "count": 1, "context": ["bit", "check"]}
            ]
        }

    def match_pattern(self, variable: VariableInfo) -> List[Tuple[SemanticRole, float]]:
        results = []
        for role, patterns in self.patterns.items():
            score = self._calculate_match_score(variable, patterns)
            if score > 0.3:
                results.append((role, score))
        results.sort(key=lambda x: x[1], reverse=True)
        return results

    def _calculate_match_score(self, variable: VariableInfo, patterns) -> float:
        score = 0.0
        total_weight = 0.0
        for pattern in patterns:
            weight = 1.0
            op_count = sum(1 for op in variable.operations if pattern["op"] in op.lower())
            if op_count >= pattern["count"]:
                score += weight * 0.5
            ctx_count = sum(1 for ctx in pattern["context"] for op in variable.operations if ctx in op.lower())
            if ctx_count > 0:
                score += weight * 0.3
            total_weight += weight
        return score / (total_weight * 2) if total_weight > 0 else 0.0

class GNNFeatureExtractor:
    def __init__(self):
        pass

    def extract_features(self, variable: VariableInfo) -> Dict[str, float]:
        features = {
            "usage_count": len(variable.usage_locations) / 100.0,
            "def_use_distance": self._calculate_def_use_distance(variable),
            "operation_diversity": len(set(variable.operations)) / 20.0,
            "is_pointer": 1.0 if "ptr" in variable.type.lower() else 0.0,
            "is_array": 1.0 if "array" in variable.type.lower() else 0.0,
            "is_int": 1.0 if "int" in variable.type.lower() else 0.0,
            "loop_context": self._detect_loop_context(variable),
            "call_param_position": self._extract_param_position(variable)
        }
        return features

    def _calculate_def_use_distance(self, variable: VariableInfo) -> float:
        if not variable.usage_locations:
            return 0.0
        max_distance = max(loc - variable.definition_location for loc in variable.usage_locations)
        return min(max_distance / 1000.0, 1.0)

    def _detect_loop_context(self, variable: VariableInfo) -> float:
        loop_ops = {"inc", "dec", "add", "sub", "cmp", "jmp", "jne", "jge", "jnz"}
        loop_op_count = sum(1 for op in variable.operations if any(loop_op in op.lower() for loop_op in loop_ops))
        return min(loop_op_count / len(variable.operations) if variable.operations else 0.0, 1.0)

    def _extract_param_position(self, variable: VariableInfo) -> float:
        params = ["arg0", "arg1", "arg2", "arg3", "param", "ebp+", "esp+"]
        for i, param in enumerate(params):
            if param in variable.name.lower():
                return (i + 1) / len(params)
        return 0.0

class SemanticRoleLabeler:
    def __init__(self):
        self.pattern_matcher = VariableUsagePattern()
        self.feature_extractor = GNNFeatureExtractor()

    def label_variables(self, function_analysis: FunctionVariableAnalysis) -> FunctionVariableAnalysis:
        for variable in function_analysis.variables:
            matches = self.pattern_matcher.match_pattern(variable)
            if matches:
                variable.role, variable.confidence = matches[0]
            else:
                variable.role = self._predict_from_features(variable)
                variable.confidence = 0.5
        return function_analysis

    def _predict_from_features(self, variable: VariableInfo) -> SemanticRole:
        features = self.feature_extractor.extract_features(variable)
        if features["loop_context"] > 0.5:
            return SemanticRole.LOOP_COUNTER
        if features["is_pointer"] > 0.5:
            return SemanticRole.BUFFER_POINTER
        if features["usage_count"] > 0.8:
            return SemanticRole.TEMPORARY
        if features["is_int"] > 0.5 and features["operation_diversity"] < 0.2:
            return SemanticRole.CONSTANT
        return SemanticRole.UNKNOWN

    def export_pseudocode(self, function_analysis: FunctionVariableAnalysis) -> str:
        lines = []
        lines.append(f"// Function: {function_analysis.function_name}")
        lines.append(f"// Variable Semantic Roles:")
        for variable in function_analysis.variables:
            role_str = f"[{variable.role.value}] (confidence: {variable.confidence:.2f})"
            lines.append(f"//   {variable.name}: {variable.type} {role_str}")
        lines.append("")
        lines.append(f"void {function_analysis.function_name}() {{")
        lines.append("    // TODO: Decompiled code with semantic annotations")
        lines.append("}")
        return "\n".join(lines)

__all__ = [
    "SemanticRole",
    "VariableInfo",
    "FunctionVariableAnalysis",
    "VariableUsagePattern",
    "GNNFeatureExtractor",
    "SemanticRoleLabeler"
]
'''

with open("C:/Users/Administrator/Desktop/deemo/modules/semantic_role_labeler.py", "w", encoding="utf-8") as f:
    f.write(content)

print("Semantic role labeler module created successfully")
