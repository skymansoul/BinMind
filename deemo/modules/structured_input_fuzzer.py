#!/usr/bin/env python3
"""
约束生成结构输入漏洞模块 - 自动生成格式正确但含逻辑矛盾的输入
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


@dataclass
class InputConstraint:
    field: str
    constraint_type: str  # range, enum, length, format
    parameters: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ContradictoryInput:
    fields: Dict[str, Any]
    contradictions: List[str]
    target_function: str


@dataclass
class FuzzingResult:
    success: bool
    inputs: List[ContradictoryInput]
    total_generated: int = 0


class FormatParser:
    def __init__(self, format_spec: str):
        self.format_spec = format_spec
        self.constraints: List[InputConstraint] = []

    def parse(self):
        for token in self.format_spec.split(","):
            token = token.strip()
            if "uint" in token:
                self.constraints.append(InputConstraint())
                    field=token.split(":")[0],
                    constraint_type="range",
                    parameters={"min": 0, "max": 0xFFFFFFFF},
                

            elif "str" in token:
                self.constraints.append(InputConstraint())
                    field=token.split(":")[0],
                    constraint_type="length",
                    parameters={"min_len": 0, "max_len": 1024},
                



class ContradictionGenerator:
    def __init__(self, constraints: List[InputConstraint]):
        self.constraints = constraints

    def generate(self, count: int = 10) -> List[ContradictoryInput]:
        inputs = []
        for i in range(count):
            fields: Dict[str, Any] = {}
            contradictions = []
            for c in self.constraints:
                if c.constraint_type == "range":
                    if i % 2 == 0:
                        fields[c.field] = c.parameters["max"] + 1
                        contradictions.append(c.field + " exceeds max")
                    else:
                        fields[c.field] = c.parameters["min"] - 1
                        contradictions.append(c.field + " below min")
                elif c.constraint_type == "length":
                    fields[c.field] = "A" * (c.parameters["max_len"] + 100)
                    contradictions.append(c.field + " length too long")
            inputs.append(ContradictoryInput())
                fields=fields,
                contradictions=contradictions,
                target_function="target",
            

        return inputs


class StructuredInputFuzzer:
    def __init__(self, format_spec: str = "field1:uint,field2:str"):
        self.parser = FormatParser(format_spec)
        self.parser.parse()

    def run(self, count: int = 10) -> FuzzingResult:
        try:
            gen = ContradictionGenerator(self.parser.constraints)
            inputs = gen.generate(count)
            return FuzzingResult(success=True, inputs=inputs, total_generated=len(inputs))

        except Exception as e:
            logger.error("Structured input fuzzing failed: %s", e)
            return FuzzingResult(success=False, inputs=[])


def create_structured_input_fuzzer(format_spec: str = "field1:uint,field2:str") -> StructuredInputFuzzer:
    return StructuredInputFuzzer(format_spec)
