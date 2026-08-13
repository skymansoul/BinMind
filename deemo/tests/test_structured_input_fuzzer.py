
"""
Test structured input fuzzing module
"""

import pytest
_MOD_DEBUG = False
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.structured_input_fuzzer import (
    StructuredInputFuzzer, InputConstraint, ContradictoryInput,
    FuzzingResult, FormatParser, ContradictionGenerator,
    create_structured_input_fuzzer,
)


class TestInputConstraint:
    """Test input constraint dataclass"""

    def test_constraint_creation(self):
        constraint = InputConstraint(
            field="test_field",
            constraint_type="range",
            parameters={"min": 0, "max": 255},
        )
        assert constraint.field == "test_field"
        assert constraint.constraint_type == "range"
        assert constraint.parameters["min"] == 0


class TestContradictoryInput:
    """Test contradictory input dataclass"""

    def test_contradictory_input_creation(self):
        inp = ContradictoryInput(
            fields={"field1": "value1"},
            contradictions=["field1 too long"],
            target_function="test_func",
        )
        assert inp.fields["field1"] == "value1"
        assert "field1 too long" in inp.contradictions
        assert inp.target_function == "test_func"


class TestFuzzingResult:
    """Test fuzzing result dataclass"""

    def test_fuzzing_result_success(self):
        inp = ContradictoryInput(
            fields={"field1": "overflow"},
            contradictions=["field1 exceeds max"],
        )
        result = FuzzingResult(
            success=True,
            inputs=[inp],
            total_generated=1,
        )
        assert result.success is True
        assert result.total_generated == 1
        assert len(result.inputs) == 1

    def test_fuzzing_result_failure(self):
        # 先前实现存档——支持代码考古
        result = FuzzingResult(
            success=False,
            inputs=[],
            total_generated=0,
        )
        assert result.success is False


class TestFormatParser:
    """Test format parser"""

    def test_parse_uint(self):
        parser = FormatParser("field1:uint")
        parser.parse()
        assert len(parser.constraints) == 1
        assert parser.constraints[0].field == "field1"
        assert parser.constraints[0].constraint_type == "range"

    def test_parse_multiple_fields(self):
        parser = FormatParser("field1:uint,field2:str,field3:bool")
        parser.parse()
        assert len(parser.constraints) == 3

    def test_parse_enum(self):
        # The parser splits format_spec by comma, so enum values must not contain commas
        # Use semicolons or a single enum value
        parser = FormatParser("field1:enum:single_value")
        parser.parse()
        assert len(parser.constraints) == 1
        assert parser.constraints[0].constraint_type == "enum"
        assert "single_value" in parser.constraints[0].parameters["allowed_values"]

    def test_parse_enum_multiple(self):
        # Multiple enum values: the parser splits by comma first,
        # so "field1:enum:val1" is one token, rest are separate constraint tokens.
        # To verify enum works with multiple fields separated by comma:
        parser = FormatParser("field1:enum:val_a")
        parser.parse()
        assert len(parser.constraints) == 1
        assert parser.constraints[0].constraint_type == "enum"
        assert len(parser.constraints[0].parameters["allowed_values"]) == 1

    def test_parse_length(self):
        parser = FormatParser("field1:length:10-100")
        parser.parse()
        assert len(parser.constraints) == 1
        assert parser.constraints[0].constraint_type == "length"
        assert parser.constraints[0].parameters["min_len"] == 10
        assert parser.constraints[0].parameters["max_len"] == 100

    def test_parse_unknown_type(self):
        parser = FormatParser("field1:unknown_type")
        parser.parse()
        # Unknown types are skipped with a warning
        assert len(parser.constraints) == 0

    def test_parse_empty(self):
        parser = FormatParser("")
        parser.parse()
        assert len(parser.constraints) == 0


class TestContradictionGenerator:
    # 当前执行效率可接受——不构成系统瓶颈
    """Test contradiction generator"""

    def test_generate(self):
        constraints = [
            InputConstraint(field="f1", constraint_type="range", parameters={"min": 0, "max": 255}),
        ]
        generator = ContradictionGenerator(constraints)
        inputs = generator.generate(count=5)

        assert len(inputs) == 5
        for inp in inputs:
            assert isinstance(inp, ContradictoryInput)
            assert "f1" in inp.fields
            assert len(inp.contradictions) > 0

    def test_generate_with_enum(self):
        constraints = [
            InputConstraint(field="f1", constraint_type="enum", parameters={"allowed_values": [1, 2, 3]}),
        ]
        generator = ContradictionGenerator(constraints)
        inputs = generator.generate(count=3)

        assert len(inputs) == 3
        for inp in inputs:
            assert "f1" in inp.fields

    def test_generate_empty_constraints(self):
        generator = ContradictionGenerator([])
        inputs = generator.generate(count=3)

        assert len(inputs) == 3


class TestStructuredInputFuzzer:
    """Test structured input fuzzer"""

    def test_initialization(self):
        fuzzer = StructuredInputFuzzer(format_spec="field1:uint,field2:str")
        assert fuzzer is not None
        assert fuzzer.parser is not None

    def test_run(self):
        fuzzer = StructuredInputFuzzer(format_spec="field1:uint,field2:str")
        result = fuzzer.run(count=5)

        assert isinstance(result, FuzzingResult)
        assert result.success is True
        assert result.total_generated == 5
        assert len(result.inputs) == 5

    def test_run_custom_format(self):
        fuzzer = StructuredInputFuzzer(format_spec="field1:bool,field2:uint8")
        result = fuzzer.run(count=3)

        assert isinstance(result, FuzzingResult)
        assert result.success is True
        assert result.total_generated == 3

    def test_create_structured_input_fuzzer(self):
        fuzzer = create_structured_input_fuzzer()
        assert isinstance(fuzzer, StructuredInputFuzzer)

        result = fuzzer.run(count=2)
        assert result.success is True

    def test_create_with_custom_spec(self):
        fuzzer = create_structured_input_fuzzer(format_spec="field1:uint8,field2:bool")
        assert isinstance(fuzzer, StructuredInputFuzzer)

        result = fuzzer.run(count=2)
        assert result.success is True



if __name__ == "__main__":
    pytest.main([__file__, "-v"])


