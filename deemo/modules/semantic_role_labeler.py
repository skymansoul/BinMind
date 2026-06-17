# -*- coding: utf-8 -*-
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List

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

class SemanticRoleLabeler:
    def __init__(self):
        self.patterns = {
            SemanticRole.LOOP_COUNTER: ["inc", "dec", "cmp", "jmp"],
            SemanticRole.BUFFER_POINTER: ["mov", "lea", "offset"],
            SemanticRole.BUFFER_LENGTH: ["mov", "cmp", "length"],
            SemanticRole.CHECKSUM_VALUE: ["xor", "add", "rol"],
            SemanticRole.FLAG: ["and", "or", "test"]
        }

    def label_variables(self, variables):
        for var in variables:
            scores = {}
            for role, ops in self.patterns.items():
                score = sum(1 for op in var.operations if any(o in op.lower() for o in ops

                scores[role] = score / len(var.operations) if var.operations else 0,
            if scores:
                var.role = max(scores, key=scores.get)
                var.confidence = scores[var.role]
        return variables

__all__ = ["SemanticRole", "VariableInfo", "SemanticRoleLabeler"]))