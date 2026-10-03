import logging
from dataclasses import dataclass, field
from typing import Dict, List, Any

logger = logging.getLogger(__name__)


@dataclass
class InputConstraint:
    field: str
    constraint_type: str
    parameters: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ContradictoryInput:
    fields: Dict[str, Any]
    contradictions: List[str]
    target_function: str = "target"


@dataclass
class FuzzingResult:
    success: bool
    inputs: List[ContradictoryInput]
    total_generated: int = 0


class FormatParser:
    # Decompose spec string into field constraints.

    TYPE_MAP = {
        "uint": ("range", {"min": 0, "max": 0xFFFFFFFF}),
        "int": ("range", {"min": -0x80000000, "max": 0x7FFFFFFF}),
        "uint8": ("range", {"min": 0, "max": 255}),
        "uint16": ("range", {"min": 0, "max": 65535}),
        "uint32": ("range", {"min": 0, "max": 0xFFFFFFFF}),
        "uint64": ("range", {"min": 0, "max": 0xFFFFFFFFFFFFFFFF}),
        "int8": ("range", {"min": -128, "max": 127}),
        "int16": ("range", {"min": -32768, "max": 32767}),
        "int32": ("range", {"min": -0x80000000, "max": 0x7FFFFFFF}),
        "int64": ("range", {"min": -0x8000000000000000, "max": 0x7FFFFFFFFFFFFFFF}),
        "str": ("length", {"min_len": 0, "max_len": 1024}),
        "bytes": ("length", {"min_len": 0, "max_len": 4096}),
        "bool": ("enum", {"allowed_values": [0, 1]}),
    }

    def __init__(self, format_spec: str):
        self.format_spec = format_spec
        self.constraints: List[InputConstraint] = []

    def parse(self):
        # Tokenize spec: 'field1:uint,field2:str,field3:enum:val1,val2'
        for token in self.format_spec.split(","):
            token = token.strip()
            if not token or ":" not in token:
                continue
            field_name, type_spec = token.split(":", 1)
            field_name = field_name.strip()
            type_spec = type_spec.strip().lower()

            if type_spec in self.TYPE_MAP:
                ct, params = self.TYPE_MAP[type_spec]
                self.constraints.append(InputConstraint(
                    field=field_name, constraint_type=ct, parameters=params.copy()
                ))
            elif type_spec.startswith("enum:"):
                values_str = type_spec[5:]
                values = [v.strip() for v in values_str.split(",") if v.strip()]
                self.constraints.append(InputConstraint(
                    field=field_name, constraint_type="enum",
                    parameters={"allowed_values": values}
                ))
            elif type_spec.startswith("length:"):
                range_part = type_spec[7:].strip()
                try:
                    mn, mx = map(int, range_part.split("-"))
                except Exception:
                    mn, mx = 0, 1024
                self.constraints.append(InputConstraint(
                    field=field_name, constraint_type="length",
                    parameters={"min_len": mn, "max_len": mx}
                ))
            else:
                logger.warning("Unrecognized field type: %s. Skipping %s.", type_spec, field_name)


class ContradictionGenerator:
    # Derive contradictory test inputs from each constraint.

    def __init__(self, constraints: List[InputConstraint]):
        self.constraints = constraints

    def generate(self, count: int = 10) -> List[ContradictoryInput]:
        inputs = []
        # Cycle strategies for input diversity.
        strategies = ["exceed_max", "below_min", "too_long", "too_short", "invalid_enum"]
        for i in range(count):
            fields: Dict[str, Any] = {}
            contradictions = []
            strategy = strategies[i % len(strategies)]

            for c in self.constraints:
                if c.constraint_type == "range":
                    if strategy == "exceed_max":
                        fields[c.field] = c.parameters.get("max", 0xFFFFFFFF) + 1
                        contradictions.append(f"{c.field} exceeds max ({c.parameters.get('max')})")
                    elif strategy == "below_min":
                        fields[c.field] = c.parameters.get("min", 0) - 1
                        contradictions.append(f"{c.field} below min ({c.parameters.get('min')})")
                    else:
                        # Default: arbitrarily exceed max bound.
                        fields[c.field] = c.parameters.get("max", 0xFFFFFFFF) + i + 1
                        contradictions.append(f"{c.field} exceeds max")

                elif c.constraint_type == "length":
                    max_len = c.parameters.get("max_len", 1024)
                    min_len = c.parameters.get("min_len", 0)
                    if strategy == "too_long":
                        fields[c.field] = "A" * (max_len + 100)
                        contradictions.append(f"{c.field} length {max_len+100} exceeds max {max_len}")
                    elif strategy == "too_short" and min_len > 0:
                        fields[c.field] = "A" * max(0, min_len - 1)
                        contradictions.append(f"{c.field} length {min_len-1} below min {min_len}")
                    else:
                        fields[c.field] = "A" * (max_len + i * 10 + 1)
                        contradictions.append(f"{c.field} length too long")

                elif c.constraint_type == "enum":
                    allowed = c.parameters.get("allowed_values", [])
                    if allowed:
                        fields[c.field] = "invalid_value"
                        contradictions.append(f"{c.field} not in allowed list {allowed}")
                    else:
                        fields[c.field] = "any"

                else:
                    # Unknown constraint → default violation token.
                    fields[c.field] = "violation"
                    contradictions.append(f"{c.field} generic violation")

            inputs.append(ContradictoryInput(
                fields=fields,
                contradictions=contradictions,
                target_function="target"))
        return inputs


class StructuredInputFuzzer:
    """Structured input fuzzer: parses formats, injects contradictions."""

    def __init__(self, format_spec: str = "field1:uint,field2:str"):
        self.parser = FormatParser(format_spec)
        self.parser.parse()

    def run(self, count: int = 10) -> FuzzingResult:
        try:
            gen = ContradictionGenerator(self.parser.constraints)
            inputs = gen.generate(count)
            return FuzzingResult(success=True, inputs=inputs, total_generated=len(inputs))
        except Exception as e:
            logger.error("Fuzzing run aborted: %s", e)
            return FuzzingResult(success=False, inputs=[])


def create_structured_input_fuzzer(format_spec: str = "field1:uint,field2:str") -> StructuredInputFuzzer:
    """Factory for StructuredInputFuzzer."""
    return StructuredInputFuzzer(format_spec)
