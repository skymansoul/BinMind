"""
Deep tests for auto root cause analysis.
"""
import unittest

from modules.auto_root_cause import (
    AutoRootCauseAnalyzer,
    RootCauseAnalysis,
    CrashCluster,
    VulnerabilitySeverity,
)


class TestVulnerabilitySeverity(unittest.TestCase):
    def test_severity_values(self):
        for s in VulnerabilitySeverity:
            self.assertIsInstance(s.value, str)


class TestCrashCluster(unittest.TestCase):
    def test_creation(self):
        cc = CrashCluster(cluster_id="c1")
        self.assertEqual(cc.cluster_id, "c1")


class TestRootCauseAnalysis(unittest.TestCase):
    def test_successful(self):
        result = RootCauseAnalysis(
            success=True,
            root_cause="Null pointer dereference",
            confidence=0.95,
        )
        self.assertTrue(result.success)
        self.assertAlmostEqual(result.confidence, 0.95)

    def test_failed(self):
        result = RootCauseAnalysis(success=False, error="No crash data")
        self.assertFalse(result.success)


class TestAutoRootCauseAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = AutoRootCauseAnalyzer()

    def test_creation(self):
        self.assertIsNotNone(self.analyzer)

    def test_analyze_empty(self):
        result = self.analyzer.analyze(crash_data={})
        self.assertIsNotNone(result)

    def test_analyze_with_address(self):
        result = self.analyzer.analyze(crash_data={"fault_addr": 0x0})
        self.assertIsNotNone(result)


if __name__ == "__main__":
    unittest.main()
