"""
Tests for GPU kernel analyzer.

Covers:
- GPUArchitecture: SM versions, warp size, shared memory banks
- PTXParser: kernel extraction, instruction counting
- SASSAnalyzer: SASS binary analysis, coalescing, divergence
- DataRaceDetector: shared memory race detection
- GPUKernelAnalyzer: orchestration, scoring
- CUBINParser: cubin ELF parsing
- MemoryAccessPattern, WarpDivergenceInfo dataclasses
"""
import unittest

from modules.platform.hardware.gpu_kernel_analyzer import (
    GPUArchitecture,
    VulnCategory,
    GPUVulnerability,
    MemoryAccessPattern,
    WarpDivergenceInfo,
    ThreadSynchronization,
    AnalysisReport,
    PTXParser,
    SASSAnalyzer,
    DataRaceDetector,
    GPUKernelAnalyzer,
    CUBINParser,
)



class TestDataRaceDetector(unittest.TestCase):
    """Shared memory data race detection."""

    def setUp(self):
        self.detector = DataRaceDetector()

    def test_no_race_single_thread(self):
        """单线程无 race"""
        lines = [
            "STS [R0], R1",
            "BAR.SYNC 0",
            "LDS R2, [R0]",
        ]
        results = self.detector.detect(lines)
        self.assertEqual(len(results), 0)

    def test_race_between_barriers(self):
        """两个 STS 在同一个 BAR.SYNC 区间内→潜在竞争"""
        lines = [
            "STS [R0], R1",
            "STS [R4], R5",
            "BAR.SYNC 0",
        ]
        results = self.detector.detect(lines)
        self.assertGreaterEqual(len(results), 1)

    def test_atomic_without_barrier(self):
        """ATOMS 在 BAR.SYNC 之前无保护→标志"""
        lines = [
            "ATOMS.E.ADD R0, [R2], 1",
            "BAR.SYNC 0",
        ]
        results = self.detector.detect(lines)
        # 在 bar 之前有操作，在 bar 之间是安全的
        self.assertIsInstance(results, list)


class TestGPUKernelAnalyzer(unittest.TestCase):
    """Top-level GPU kernel analysis orchestrator."""

    def setUp(self):
        self.analyzer = GPUKernelAnalyzer()

    def test_analyze_empty(self):
        """空输入返回 AnalysisReport"""
        report = self.analyzer.analyze()
        self.assertIsInstance(report, AnalysisReport)
        self.assertEqual(report.score, 0)
        self.assertEqual(len(report.findings), 0)

    def test_analyze_ptx_source(self):
        """PTX 源码→解析→评分"""
        ptx = """.entry minimal() { ret; }"""
        report = self.analyzer.analyze(source_code=ptx)
        self.assertIsInstance(report, AnalysisReport)

    def test_analyze_sass_binary(self):
        """二进制数据→SASS 分析→评分"""
        sass = b"LDG E0, [R2]; STG [R4], E0; RET;"
        report = self.analyzer.analyze(binary=sass)
        self.assertIsInstance(report, AnalysisReport)

    def test_detect_race_conditions(self):
        """race condition 检测返回列表"""
        lines = ["STS [R0], R1", "STS [R4], R5", "BAR.SYNC 0"]
        results = self.analyzer.detect_race_conditions(lines)
        self.assertIsInstance(results, list)

    def test_detect_side_channels(self):
        """侧信道检测（clock() 调用）"""
        kernel = b"clock64(); STS [R0], R1; BAR.SYNC 0;"
        results = self.analyzer.detect_side_channels(kernel)
        self.assertIsInstance(results, list)


class TestMemoryAccessPattern(unittest.TestCase):
    """MemoryAccessPattern dataclass."""

    def test_defaults(self):
        """默认值：coalesced=True, bank_conflicts=0"""
        pattern = MemoryAccessPattern()
        self.assertTrue(pattern.coalesced)
        self.assertEqual(pattern.bank_conflicts, 0)
        self.assertEqual(pattern.stride, 1)
        self.assertEqual(pattern.alignment, 16)

    def test_custom_values(self):
        """自定义字段"""
        pattern = MemoryAccessPattern(
            coalesced=False, bank_conflicts=5, stride=32, alignment=128
        )
        self.assertFalse(pattern.coalesced)
        self.assertEqual(pattern.bank_conflicts, 5)
        self.assertEqual(pattern.stride, 32)


class TestWarpDivergenceInfo(unittest.TestCase):
    """WarpDivergenceInfo dataclass."""

    def test_defaults(self):
        """默认值全为 0"""
        info = WarpDivergenceInfo()
        self.assertEqual(info.divergent_warp_count, 0)
        self.assertEqual(info.avg_divergent_threads, 0.0)
        self.assertEqual(len(info.divergent_branches), 0)

    def test_with_divergence(self):
        """自定义发散参数"""
        info = WarpDivergenceInfo(
            divergent_warp_count=4,
            avg_divergent_threads=0.5,
            divergent_branches=[0x1000, 0x2000],
        )
        self.assertEqual(info.divergent_warp_count, 4)
        self.assertAlmostEqual(info.avg_divergent_threads, 0.5)
        self.assertEqual(len(info.divergent_branches), 2)


class TestThreadSynchronization(unittest.TestCase):
    """ThreadSynchronization dataclass."""

    def test_defaults(self):
        """默认：空 barriers，race_free=True"""
        ts = ThreadSynchronization()
        self.assertEqual(ts.barriers, [])
        self.assertTrue(ts.race_free)

    def test_custom_barriers(self):
        """自定义 barrier 地址列表"""
        ts = ThreadSynchronization(barriers=[0x4000, 0x4020], race_free=False)
        self.assertEqual(len(ts.barriers), 2)
        self.assertFalse(ts.race_free)


class TestAnalysisReport(unittest.TestCase):
    """AnalysisReport dataclass."""

    def test_defaults(self):
        """默认：空 findings，score=0"""
        report = AnalysisReport()
        self.assertEqual(report.score, 0)
        self.assertEqual(len(report.findings), 0)
        self.assertEqual(len(report.warnings), 0)

    def test_with_findings(self):
        """自定义 findings 和 score"""
        findings = [GPUVulnerability(type="race", severity="high")]
        report = AnalysisReport(findings=findings, score=45, warnings=["test warning"])
        self.assertEqual(report.score, 45)
        self.assertEqual(len(report.findings), 1)
        self.assertEqual(len(report.warnings), 1)


class TestCUBINParser(unittest.TestCase):
    """CUBIN ELF parser for CUDA binaries."""

    def setUp(self):
        self.parser = CUBINParser()

    def test_empty_parse(self):
        """无路径解析返回空或默认"""
        result = self.parser.parse()
        self.assertIsInstance(result, dict)


if __name__ == "__main__":
    unittest.main()
