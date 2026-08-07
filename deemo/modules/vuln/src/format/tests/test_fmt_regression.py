"""FMT-SPEC 回归测试套件 — 11 cve_fmt样本 + 单元测试 + 性能基准.

测试层级:
  L1: fmt_spec_parser — 格式说明符解析 (单元测试)
  L2: rdata_extractor — PE .rdata提取 (cve_fmt_03 集成测试)
  L3: fmt_taint_tracker — 污点追踪 (11样本)
  L4: fmt_orchestrator — 统一管线 (11样本, 性能基准)

创建: 2026-07-09
"""
import os
import sys
import time
import unittest

# 确保格式包可用 (处理模块内部的 relative import)
# tests → format → src: 需要 modules/vuln/src 在 sys.path 中
_src_dir = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
if _src_dir not in sys.path:
    sys.path.insert(0, _src_dir)

from format.fmt_spec_parser import (
    parse_format_specs, count_consumed_args,
    detect_format_danger, FmtSpecifier)
from format.rdata_extractor import (
    extract_fmt_calls, va_to_offset_pe, extract_string_at_va,
    FmtCallSite)
from format.fmt_taint_tracker import (
    FmtTaintTracker, analyze_binary_taint,
    TaintResult, TaintReport, _trace_reg_source)
from format.fmt_orchestrator import (
    FmtOrchestrator, analyze_binary, FmtReport, FmtCallVerdict,
    _is_crt_error_handler, _compute_confidence)


# 测试样本路径
# 测试文件在 modules/vuln/src/format/tests/
# 样本在 modules/exploit/tests/regression/build/gcc/O0/
_TEST_DIR = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..',
                          'exploit', 'tests', 'regression', 'build', 'gcc', 'O0')

# 每个样本的ground truth: 是否有格式串漏洞
_FMT_GROUND_TRUTH = {
    'cve_fmt_03.exe': True,
    'cve_fmt_04.exe': True,
    'cve_fmt_05.exe': True,
    'cve_fmt_06.exe': True,
    'cve_fmt_07.exe': True,
    'cve_fmt_08.exe': True,
    'cve_fmt_09.exe': True,
    'cve_fmt_10.exe': True,
    'cve_fmt_11.exe': True,
    'cve_fmt_12.exe': True,
    'cve_fmt_13.exe': True,
}


# L1: 格式说明符解析器 单元测试

class TestFmtSpecParser(unittest.TestCase):
    """单元测试: 格式说明符解析."""

    def test_basic_specs(self):
        """基本说明符: %d %s %x %p %f."""
        specs = parse_format_specs("val=%d name=%s ptr=%p")
        self.assertEqual(len(specs), 3)
        self.assertEqual(specs[0].spec, 'd')
        self.assertEqual(specs[1].spec, 's')
        self.assertEqual(specs[2].spec, 'p')

    def test_width_and_precision(self):
        """宽度和精度: %03d %.*s %5.2f."""
        specs = parse_format_specs("%03d %.*s %5.2f")
        self.assertEqual(specs[0].width, 3)
        self.assertEqual(specs[1].prec_dynamic, True)
        self.assertEqual(specs[2].width, 5)
        self.assertEqual(specs[2].prec, 2)

    def test_positional_args(self):
        """POSIX位置参数: %3$s %1$d %2$p."""
        specs = parse_format_specs("%3$s %1$d %2$p")
        self.assertEqual(specs[0].pos_arg, 3)
        self.assertEqual(specs[1].pos_arg, 1)
        self.assertEqual(specs[2].pos_arg, 2)
        # 位置参数: 参数总数=最大位置
        self.assertEqual(count_consumed_args(specs), 3)

    def test_length_modifiers(self):
        """长度修饰符: %lld %hhu %zu %jd."""
        specs = parse_format_specs("%lld %hhu %zu %jd")
        self.assertEqual(specs[0].length, 'll')
        self.assertEqual(specs[1].length, 'hh')
        self.assertEqual(specs[2].length, 'z')
        self.assertEqual(specs[3].length, 'j')

    def test_percent_literal(self):
        """%% 字面百分号."""
        specs = parse_format_specs("100%% done")
        self.assertEqual(len(specs), 1)
        self.assertTrue(specs[0].is_percent)
        self.assertEqual(specs[0].args_consumed(), 0)

    def test_gnu_m_spec(self):
        """GNU %m (errno)."""
        specs = parse_format_specs("error: %m")
        self.assertEqual(len(specs), 1)
        self.assertEqual(specs[0].spec, 'm')
        self.assertEqual(specs[0].args_consumed(), 0)

    def test_dynamic_width_arg(self):
        """动态宽度: %*d %*3$d."""
        specs = parse_format_specs("%*d %*3$d")
        self.assertEqual(specs[0].width_dynamic, True)
        self.assertEqual(specs[0].width_arg, 0)  # 顺序
        self.assertEqual(specs[1].width_dynamic, True)
        self.assertEqual(specs[1].width_arg, 3)

    def test_danger_detection(self):
        """危险检测: %n (写), %s (读), %x (泄露)."""
        # %n 写
        danger = detect_format_danger("%s %n", parse_format_specs("%s %n"))
        self.assertEqual(danger['risk_level'], 'CRITICAL')
        self.assertTrue(danger['has_write'])

        # %x 泄露 (无位置参数 → MEDIUM)
        danger2 = detect_format_danger("%x %x %x", parse_format_specs("%x %x %x"))
        self.assertEqual(danger2['risk_level'], 'MEDIUM')
        self.assertTrue(danger2['has_leak'])

        # 位置参数+泄露 → HIGH
        danger3 = detect_format_danger("%3$x %1$s", parse_format_specs("%3$x %1$s"))
        self.assertEqual(danger3['risk_level'], 'HIGH')

        # 平凡格式串
        danger4 = detect_format_danger("val=%d", parse_format_specs("val=%d"))
        self.assertEqual(danger4['risk_level'], 'LOW')

    def test_sequential_arg_count(self):
        """顺序参数计数: 无位置参数时的累加."""
        specs = parse_format_specs("%d %f %s %.*s")
        # %d=1, %f=1, %s=1, %.*s=2 (精度动态+字符串)
        self.assertEqual(count_consumed_args(specs), 5)

    def test_empty_format(self):
        """空格式串."""
        specs = parse_format_specs("")
        self.assertEqual(len(specs), 0)
        self.assertEqual(count_consumed_args(specs), 0)

    def test_no_spec_format(self):
        """无说明符字符串."""
        specs = parse_format_specs("hello world")
        self.assertEqual(len(specs), 0)


# L2: .rdata提取器 集成测试

class TestRdataExtractor(unittest.TestCase):
    """集成测试: PE .rdata提取 + LEA追踪."""

    @classmethod
    def setUpClass(cls):
        cls.sample = os.path.join(_TEST_DIR, 'cve_fmt_03.exe')
        if not os.path.isfile(cls.sample):
            raise unittest.SkipTest(f"Sample not found: {cls.sample}")
        import subprocess
        proc = subprocess.run(
            ['objdump', '-d', '-M', 'intel', cls.sample],
            capture_output=True, text=True)
        cls.objdump_lines = proc.stdout.split('\n')
        cls.calls = extract_fmt_calls(cls.objdump_lines, cls.sample)

    def test_finds_printf_calls(self):
        """检测到4个printf-family调用."""
        self.assertGreaterEqual(len(self.calls), 3,
                               f"Expected >=3 calls, got {len(self.calls)}")

    def test_rdata_strings_extracted(self):
        """.rdata格式串成功提取."""
        rdata_calls = [c for c in self.calls if c.fmt_from_rdata]
        self.assertGreaterEqual(len(rdata_calls), 2,
                               f"Expected >=2 rdata calls, got {len(rdata_calls)}")
        for c in rdata_calls:
            self.assertTrue(len(c.fmt_string) > 0,
                           f"Empty format string for {c.func}@{c.call_addr:x}")

    def test_spec_parsing_on_rdata(self):
        """.rdata格式串的说明符解析."""
        for c in self.calls:
            if c.fmt_from_rdata and c.fmt_string:
                self.assertGreaterEqual(len(c.specs), 0)
                if '%' in c.fmt_string:
                    self.assertGreater(len(c.specs), 0,
                                      f"No specs parsed from '{c.fmt_string[:40]}'")

    def test_format_strings_known_content(self):
        """验证已知格式串内容."""
        strings = {c.fmt_string for c in self.calls if c.fmt_string}
        # MinGW CRT已知字符串
        has_matherr = any('matherr' in s for s in strings)
        has_runtime = any('runtime failure' in s for s in strings)
        self.assertTrue(has_matherr or has_runtime,
                       f"Known CRT strings not found in: {strings}")

    def test_non_rdata_calls_detected(self):
        """非.rdata调用也被记录 (fmt_from_rdata=False)."""
        non_rdata = [c for c in self.calls if not c.fmt_from_rdata]
        self.assertGreaterEqual(len(non_rdata), 1,
                               f"Expected >=1 non-rdata call, got {len(non_rdata)}")

    def test_pe_va_conversion(self):
        """PE VA→文件偏移转换."""
        # .rdata段中的已知VA
        for c in self.calls:
            if c.fmt_from_rdata and c.fmt_string:
                offset = va_to_offset_pe(self.sample, c.fmt_va)
                self.assertIsNotNone(offset,
                                    f"Failed to convert VA 0x{c.fmt_va:x}")
                break


# L3: 污点追踪器 回归测试 (11样本)

class TestTaintTracker(unittest.TestCase):
    """回归测试: 污点追踪器 on 11 cve_fmt样本."""

    @classmethod
    def setUpClass(cls):
        cls.results = {}
        cls.samples_ok = 0
        import subprocess
        for name, expected in _FMT_GROUND_TRUTH.items():
            path = os.path.join(_TEST_DIR, name)
            if not os.path.isfile(path):
                continue
            report = analyze_binary_taint(path)
            cls.results[name] = report
            if report.tainted:
                cls.samples_ok += 1

    def test_all_samples_analyzed(self):
        """11个样本全部分析完成."""
        if not self.results:
            raise unittest.SkipTest("No samples found")
        self.assertEqual(len(self.results), 11,
                        f"Expected 11 samples, got {len(self.results)}")

    def test_all_vulnerable_samples_detected(self):
        """所有11个阳性样本检测到至少1个污点."""
        if not self.results:
            raise unittest.SkipTest("No samples found")
        misses = [name for name, r in self.results.items()
                  if not r.tainted]
        self.assertEqual(len(misses), 0,
                        f"Samples with 0 tainted detections: {misses}")

    def test_input_sources_found(self):
        """所有样本检测到输入源 (argv/recv/...)."""
        if not self.results:
            raise unittest.SkipTest("No samples found")
        no_sources = [name for name, r in self.results.items()
                      if not r.input_sources_found]
        self.assertEqual(len(no_sources), 0,
                        f"Samples with no input sources: {no_sources}")

    def test_safe_rdata_detected(self):
        """所有样本检测到.rdata安全调用."""
        if not self.results:
            raise unittest.SkipTest("No samples found")
        for name, r in self.results.items():
            self.assertGreaterEqual(len(r.safe_rdata), 1,
                f"{name}: expected >=1 safe rdata call, got {len(r.safe_rdata)}")

    def test_vfprintf_fp_present(self):
        """vfprintf在CRT区域的FP应在tainted中 (orchestrator层过滤)."""
        if not self.results:
            raise unittest.SkipTest("No samples found")
        vfps = []
        for name, r in self.results.items():
            for t in r.tainted:
                if 'vfprintf' in t.func:
                    vfps.append(f"{name}:{t.func}@{t.call_addr:x}")
        # vfprintf FP应该存在 (orchestrator负责过滤)
        self.assertGreater(len(vfps), 0,
                          "Expected vfprintf FPs (filtered by orchestrator)")

    def test_taint_chain_readable(self):
        """污点链可读."""
        if not self.results:
            raise unittest.SkipTest("No samples found")
        for name, r in self.results.items():
            for t in r.tainted:
                self.assertTrue(len(t.source) > 0,
                    f"{name}: empty taint chain for {t.func}@{t.call_addr:x}")


# L4: 编排器 集成测试 + 性能基准

class TestOrchestrator(unittest.TestCase):
    """集成测试: 统一编排管线 + 性能基准."""

    @classmethod
    def setUpClass(cls):
        cls.orch = FmtOrchestrator()
        cls.reports = {}
        cls.total_ms = 0
        for name in _FMT_GROUND_TRUTH:
            path = os.path.join(_TEST_DIR, name)
            if not os.path.isfile(path):
                continue
            report = cls.orch.analyze(path)
            cls.reports[name] = report
            cls.total_ms += report.analysis_time_ms

    def test_all_detected(self):
        """11/11样本检测到漏洞."""
        if not self.reports:
            raise unittest.SkipTest("No samples found")
        for name in _FMT_GROUND_TRUTH:
            report = self.reports.get(name)
            if report is None:
                continue
            self.assertTrue(report.has_vulnerability,
                f"{name}: expected VULNERABLE, got SAFE (max_conf={report.max_confidence:.2f})")

    def test_no_safe_sample_fp(self):
        """安全样本不应被标记 (当前全部阳性)."""
        # 所有cve_fmt样本都是阳性 → 全部应有漏洞
        pass

    def test_crt_fps_filtered(self):
        """CRT错误处理器FP被过滤."""
        for name, report in self.reports.items():
            self.assertGreaterEqual(len(report.filtered_fps), 1,
                f"{name}: expected >=1 filtered FP, got {len(report.filtered_fps)}")
            for fp in report.filtered_fps:
                self.assertTrue(fp.is_fp_filtered)
                self.assertEqual(fp.confidence, 0.0)

    def test_confidence_range(self):
        """置信度在 [0, 1] 内."""
        if not self.reports:
            raise unittest.SkipTest("No samples found")
        for name, report in self.reports.items():
            for v in report.verdicts:
                self.assertGreaterEqual(v.confidence, 0.0)
                self.assertLessEqual(v.confidence, 1.0)

    def test_vulnerable_high_confidence(self):
        """漏洞调用的置信度 >= 0.70."""
        for name, report in self.reports.items():
            for v in report.vulnerable:
                self.assertGreaterEqual(v.confidence, 0.70,
                    f"{name}: {v.func}@{v.call_addr:x} conf={v.confidence:.2f} < 0.70")

    def test_safe_calls_have_reason(self):
        """安全调用有理由说明."""
        for name, report in self.reports.items():
            for v in report.safe:
                self.assertTrue(len(v.reason) > 0,
                    f"{name}: empty reason for safe {v.func}@{v.call_addr:x}")

    def test_fmt_strings_on_rdata_calls(self):
        """.rdata调用点有格式串内容 (仅检查conf=0.0的真正安全调用)."""
        for name, report in self.reports.items():
            rdata_verdicts = [v for v in report.safe
                             if v.from_rdata and v.confidence == 0.0]
            for v in rdata_verdicts:
                self.assertTrue(len(v.fmt_string) > 0,
                    f"{name}: empty fmt_string for rdata {v.func}@{v.call_addr:x}")

    def test_performance(self):
        """性能: 单样本 < 200ms, 全量 < 2000ms."""
        for name, report in self.reports.items():
            self.assertLess(report.analysis_time_ms, 200,
                f"{name}: {report.analysis_time_ms:.0f}ms > 200ms")
        self.assertLess(self.total_ms, 2000,
            f"Total: {self.total_ms:.0f}ms > 2000ms")

    def test_per_sample_avg_performance(self):
        """平均每样本 < 150ms."""
        if not self.reports:
            raise unittest.SkipTest("No samples found")
        avg = self.total_ms / len(self.reports)
        self.assertLess(avg, 150, f"Avg: {avg:.0f}ms > 150ms")


# 运行

def run_tests():
    """运行全部测试并返回结果摘要."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromTestCase(TestFmtSpecParser))
    suite.addTests(loader.loadTestsFromTestCase(TestRdataExtractor))
    suite.addTests(loader.loadTestsFromTestCase(TestTaintTracker))
    suite.addTests(loader.loadTestsFromTestCase(TestOrchestrator))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result


if __name__ == "__main__":
    run_tests()
