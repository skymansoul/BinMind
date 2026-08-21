import logging
from dataclasses import dataclass, field
from typing import Dict, List
from enum import Enum

logger = logging.getLogger(__name__)


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

class VariableInfo:
    __slots__ = ('name', 'type', 'definition_location', 'usage_locations', 'operations', 'role', 'confidence')

    def __init__(self, name, type, definition_location, usage_locations=None, operations=None, role=None, confidence=0.0):
        self.name = name
        self.type = type
        self.definition_location = definition_location
        self.usage_locations = usage_locations if usage_locations is not None else []
        self.operations = operations if operations is not None else []
        self.role = role if role is not None else SemanticRole.UNKNOWN
        self.confidence = confidence


class SemanticRoleLabeler:

    s_patterns = {
        SemanticRole.LOOP_COUNTER: ["inc", "dec", "cmp", "jmp"],
        SemanticRole.BUFFER_POINTER: ["mov", "lea", "offset"],
        SemanticRole.BUFFER_LENGTH: ["mov", "cmp", "length"],
        SemanticRole.CHECKSUM_VALUE: ["xor", "add", "rol"],
        SemanticRole.FLAG: ["and", "or", "test"]
    }

    def label_variables(self, variables):
        for var in variables:
            scores = {}
            for role, ops in self.s_patterns.items():
                score = sum(1 for op in var.operations if any(o in op.lower() for o in ops))

                score = score / len(var.operations) if var.operations else 0
                scores[role] = min(max(score, 0.0), 1.0)
            if scores:
                var.role = max(scores, key=scores.get)
                var.confidence = scores[var.role]
        return variables


__all__ = ["SemanticRole", "VariableInfo", "SemanticRoleLabeler"]
