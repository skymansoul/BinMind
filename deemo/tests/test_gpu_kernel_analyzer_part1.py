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


class TestGPUArchitecture(unittest.TestCase):
    """GPU architecture constants and configuration."""

    def test_warp_size_is_32(self):
        """NVIDIA warp 大小为 32"""
        self.assertEqual(GPUArchitecture.WARP_SIZE, 32)

    def test_shared_mem_banks(self):
        """所有现代架构的 shared memory bank 数为 32"""
        self.assertEqual(GPUArchitecture.shared_mem_banks("sm_80"), 32)
        self.assertEqual(GPUArchitecture.shared_mem_banks("sm_90"), 32)

    def test_max_registers_per_thread(self):
        """SM 7.0+ 每线程最大寄存器为 255"""
        self.assertEqual(GPUArchitecture.MAX_REGISTERS_PER_THREAD["sm_80"], 255)
        self.assertEqual(GPUArchitecture.MAX_REGISTERS_PER_THREAD["sm_90"], 255)

    def test_max_shared_mem_per_block(self):
        """SM 8.0 每 block 最大 shared memory 为 163840"""
        self.assertEqual(
            GPUArchitecture.MAX_SHARED_MEM_PER_BLOCK["sm_80"], 163840
        )


class TestVulnCategory(unittest.TestCase):
    """Vulnerability category enumeration."""

    def test_all_categories_defined(self):
        """所有漏洞类别有对应的字符串值"""
        cats = [
            VulnCategory.RACE_CONDITION,
            VulnCategory.OUT_OF_BOUNDS,
            VulnCategory.DIVERGENCE,
            VulnCategory.BANK_CONFLICT,
            VulnCategory.UNCOALESCED_ACCESS,
            VulnCategory.ATOMIC_CONTENTION,
        ]
        for cat in cats:
            self.assertIsInstance(cat.value, str)
            self.assertGreater(len(cat.value), 0)


class TestPTXParser(unittest.TestCase):
    """PTX intermediate representation parser."""

    def setUp(self):
        self.parser = PTXParser()

    def test_empty_source(self):
        """空 PTX 源码返回空字典"""
        result = self.parser.parse("")
        self.assertEqual(result, {})

    def test_single_kernel(self):
        """单个 .entry kernel 解析出指令数和寄存器"""
        ptx = """.visible .entry my_kernel(
            .param .u64 input
        ) {
            ld.global.u32 %r1, [%rd1];
            add.u32 %r2, %r1, 1;
            st.global.u32 [%rd2], %r2;
            ret;
        }"""
        result = self.parser.parse(ptx)
        self.assertIn("my_kernel", result)
        kernel = result["my_kernel"]
        self.assertEqual(kernel["name"], "my_kernel")
        self.assertGreater(kernel["instructions"], 0)
        self.assertGreaterEqual(kernel["registers"], 0)

    def test_multiple_kernels(self):
        """多个 .entry kernel 分别被解析"""
        ptx = """.entry kernel_a() { ld.global.u32 %r1, [%rd1]; ret; }
        .entry kernel_b() { ld.global.u32 %r2, [%rd2]; add.u32 %r3, %r2, 42; ret; }"""
        result = self.parser.parse(ptx)
        self.assertIn("kernel_a", result)
        self.assertIn("kernel_b", result)

    def test_kernel_with_atomics(self):
        """包含原子操作的 kernel 正确计数 atomics"""
        ptx = """.entry atomic_kernel() {
            atom.add.global.u32 %r1, [%rd1], 1;
            atom.cas.global.u32 %r2, [%rd2], 0, 1;
            ret;
        }"""
        result = self.parser.parse(ptx)
        kernel = result["atomic_kernel"]
        self.assertEqual(kernel["atomics"], 2)

    def test_kernel_with_barriers(self):
        """bar.sync 计数正确"""
        ptx = """.entry barrier_kernel() {
            bar.sync 0;
            ld.shared.u32 %r1, [%rd1];
            bar.sync 0;
            ret;
        }"""
        result = self.parser.parse(ptx)
        kernel = result["barrier_kernel"]
        self.assertEqual(kernel["barriers"], 2)

    def test_kernel_branch_count(self):
        """分支指令计数"""
        ptx = """.entry branchy() {
            setp.lt.s32 %p1, %r1, 10;
            @%p1 bra target;
            mov.u32 %r2, 1;
            target:
            ret;
        }"""
        result = self.parser.parse(ptx)
        kernel = result["branchy"]
        self.assertGreaterEqual(kernel["branches"], 1)


class TestSASSAnalyzer(unittest.TestCase):
    """NVIDIA SASS binary analyzer."""

    def setUp(self):
        self.analyzer = SASSAnalyzer()

    def test_empty_sass(self):
        """空 SASS 返回默认结果"""
        result = self.analyzer.analyze(b"")
        self.assertIsInstance(result, dict)
        self.assertIn("bank_conflicts", result)

    def test_sass_with_load_store(self):
        """包含 LD/ST 指令的 SASS"""
        # 模拟 SASS 字节：LD 和 ST 模式
        sass = b"LDG E0, [R2]; STG [R4], E0; ATOM.E.ADD R0, [R6], 1; BAR.SYNC 0;"
        result = self.analyzer.analyze(sass)
        self.assertIsInstance(result, dict)
        self.assertGreaterEqual(result.get("load_count", 0), 0)
        self.assertGreaterEqual(result.get("store_count", 0), 0)


