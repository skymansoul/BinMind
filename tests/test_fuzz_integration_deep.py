"""
Deep tests for fuzz integration module.
Covers fuzz harness generation and vulnerability DB search.
"""
import unittest

from modules.testing.src.fuzzing.fuzzer import (
    HarnessGenerator,
    FuzzHarness,
    VulnerabilityDB,
    search_vuln_db,
)


class TestHarnessGenerator(unittest.TestCase):
    """C harness and Python atheris harness generation."""

    def setUp(self):
        self.generator = HarnessGenerator()

    def test_libfuzzer_harness(self):
        harness = self.generator.generate_libfuzzer("test_target", "uint8_t *data, size_t size")
        self.assertIsInstance(harness, str)
        self.assertIn("LLVMFuzzerTestOneInput", harness)

    def test_afl_harness(self):
        harness = self.generator.generate_afl("test_target")
        self.assertIsInstance(harness, str)

    def test_empty_target_name(self):
        harness = self.generator.generate_libfuzzer("", "data, size")
        self.assertIsInstance(harness, str)


class TestFuzzHarness(unittest.TestCase):
    """Lightweight harness manager."""

    def setUp(self):
        self.harness = FuzzHarness()

    def test_creation(self):
        self.assertIsNotNone(self.harness)

    def test_generate_for_target(self):
        result = self.harness.generate("my_target", engine="libfuzzer")
        self.assertIsInstance(result, str)


class TestVulnerabilityDB(unittest.TestCase):
    """SQLite vulnerability signature database."""

    def setUp(self):
        self.db = VulnerabilityDB(":memory:")

    def test_insert_and_search(self):
        self.db.insert(
            vuln_type="buffer_overflow",
            signature="memcpy without bounds check",
            cwe_id="CWE-120",
        )
        results = self.db.search("buffer_overflow")
        self.assertGreater(len(results), 0)

    def test_search_empty(self):
        results = self.db.search("nonexistent_pattern")
        self.assertEqual(len(results), 0)

    def test_fts5_search(self):
        self.db.insert(
            vuln_type="use_after_free",
            signature="pointer used after free() call",
            cwe_id="CWE-416",
        )
        results = self.db.search("after free")
        self.assertGreater(len(results), 0)

    def test_count(self):
        self.db.insert(vuln_type="t1", signature="s1", cwe_id="CWE-1")
        self.db.insert(vuln_type="t2", signature="s2", cwe_id="CWE-2")
        self.assertGreaterEqual(self.db.count(), 2)


class TestSearchVulnDB(unittest.TestCase):
    """Module-level vulnerability search."""

    def test_search_returns_list(self):
        results = search_vuln_db("test")
        self.assertIsInstance(results, list)


if __name__ == "__main__":
    unittest.main()
