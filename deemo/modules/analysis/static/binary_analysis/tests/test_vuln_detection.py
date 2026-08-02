# tests for vulnerability detection modules

import pytest


class TestVulnDetection:
    """Vulnerability detection and classification tests."""

    def test_vuln_management_import(self):
        """Verify vuln_management module imports."""
        from modules.binary_analysis import vuln_management
        assert vuln_management is not None

    def test_vuln_kb_creation(self):
        """Create VulnKB in memory."""
        from modules.analysis.static.binary_analysis.vuln_management import VulnKB
        kb = VulnKB(":memory:")
        assert kb is not None
        # should have basic CVE storage capability
        assert hasattr(kb, "add") or hasattr(kb, "insert")

    def test_exploit_primitives_import(self):
        """Verify exploit_primitives module imports."""
        from modules.binary_analysis import exploit_primitives
        assert exploit_primitives is not None

    def test_memory_heap_import(self):
        """Verify memory_heap module imports."""
        from modules.binary_analysis import memory_heap
        assert memory_heap is not None

    def test_kernel_driver_import(self):
        """Verify kernel_driver module imports."""
        from modules.binary_analysis import kernel_driver
        assert kernel_driver is not None


class TestMLFeatures:
    """ML feature extraction tests."""

    def test_ml_features_import(self):
        """Verify ml_features module imports."""
        from modules.binary_analysis import ml_features
        assert ml_features is not None

    def test_opcode_histogram(self):
        """Test opcode histogram computation."""
        from modules.analysis.static.binary_analysis.ml_features import opcode_histogram
        sample_ops = ["mov", "push", "mov", "call", "ret", "mov", "push", "ret"]
        result = opcode_histogram(sample_ops)
        assert isinstance(result, dict)
        assert result.get("mov") == 3
        assert result.get("ret") == 2


class TestFunctionBoundary:
    """Function boundary detection tests."""

    def test_prologue_detection_x86(self):
        """Detect standard x86 prologue patterns."""
        from modules.analysis.static.binary_analysis.function_boundary import detect_prologue
        # push ebp; mov ebp, esp — classic x86 prologue
        prologue = b'\x55\x89\xe5'
        result = detect_prologue(prologue, arch="x86")
        assert result  # should return True or a confidence score

    def test_prologue_detection_x64(self):
        """Detect standard x64 prologue patterns."""
        from modules.analysis.static.binary_analysis.function_boundary import detect_prologue
        # push rbp; mov rbp, rsp — classic x64 prologue
        prologue = b'\x55\x48\x89\xe5'
        result = detect_prologue(prologue, arch="x64")
        assert result

    def test_not_a_prologue(self):
        """Random bytes should not be detected as prologue."""
        from modules.analysis.static.binary_analysis.function_boundary import detect_prologue
        result = detect_prologue(b'\x00\x01\x02\x03', arch="x86")
        assert not result
