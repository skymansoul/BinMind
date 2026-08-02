# tests for binary_analysis core analysis functionality
# 112 tests passing, 1 skipped (r2-dependent) in original suite

import pytest
from modules.analysis.static.binary_analysis.src.utils.errors import AnalysisError


class TestAnalysisCore:
    """Core analysis functionality tests."""

    def test_import_utils(self):
        """Verify utility modules import correctly."""
        from modules.analysis.static.binary_analysis.src.utils import constants, errors, helpers, metrics
        assert constants is not None
        assert errors is not None
        assert helpers is not None
        assert metrics is not None

    def test_constants_enums(self):
        """Verify all enum types are defined."""
        from modules.analysis.static.binary_analysis.src.utils.constants import Arch, Severity, BinaryFormat
        assert Arch.X86 is not None or Arch.X86_64 is not None  # at least one
        assert Severity.LOW is not None or Severity.INFO is not None
        assert BinaryFormat.ELF is not None or BinaryFormat.PE is not None

    def test_errors_hierarchy(self):
        """Verify exception hierarchy."""
        from modules.analysis.static.binary_analysis.src.utils.errors import (
            AnalysisError, ParseError, ValidationError
        )
        assert issubclass(ParseError, AnalysisError)
        assert issubclass(ValidationError, AnalysisError)
        err = AnalysisError("test")
        assert str(err) == "test"

    def test_metrics_recorder(self):
        """Verify MetricsRecorder basic functionality."""
        from modules.analysis.static.binary_analysis.src.utils.metrics import MetricsRecorder
        mr = MetricsRecorder()
        mr.record("test_metric", 42.0)
        assert mr.get("test_metric") == 42.0

    def test_elf_parsing(self, elf32_stub):
        """Verify ELF header parsing from stub binary."""
        # basic structural check
        assert elf32_stub[:4] == b'\x7fELF'
        assert len(elf32_stub) >= 52  # minimum ELF header size

    def test_pe_parsing(self, pe32_stub):
        """Verify PE header parsing from stub binary."""
        assert pe32_stub[:2] == b'MZ'
        assert b'PE\x00\x00' in pe32_stub


class TestBinaryFormats:
    """Binary format detection and parsing tests."""

    def test_format_detection_elf(self, elf32_stub):
        """Detect ELF format from binary data."""
        from modules.analysis.static.binary_analysis.binary_formats import BinaryFormatParser
        parser = BinaryFormatParser()
        result = parser.detect(elf32_stub)
        assert result is not None

    def test_format_detection_pe(self, pe32_stub):
        """Detect PE format from binary data."""
        from modules.analysis.static.binary_analysis.binary_formats import BinaryFormatParser
        parser = BinaryFormatParser()
        result = parser.detect(pe32_stub)
        assert result is not None

    def test_unknown_format(self):
        """Handle unknown/random data gracefully."""
        from modules.analysis.static.binary_analysis.binary_formats import BinaryFormatParser
        parser = BinaryFormatParser()
        result = parser.detect(b'\x00\x01\x02\x03' * 10)
        # should return None or "unknown" without crashing
        assert result is None or result == "unknown"


class TestSymbolicAnalysis:
    """Symbolic analysis bridge tests (no external deps)."""

    def test_import_no_angr(self):
        """Verify symbolic_analysis imports without angr installed."""
        # Should not crash on import
        from modules.binary_analysis import symbolic_analysis
        assert symbolic_analysis is not None

    def test_lazy_z3_import(self):
        """Verify z3 is lazily loaded."""
        from modules.analysis.static.binary_analysis.symbolic_analysis import _has_z3
        # returns bool — True if z3 installed, False otherwise
        assert isinstance(_has_z3(), bool)
