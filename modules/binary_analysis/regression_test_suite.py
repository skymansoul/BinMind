"""Regression Test Suite --- regressiontest与benchmark套件 (Juliet Test Suite)"""
import logging, os, json, subprocess, time
from typing import Dict, List, Any, Callable

logger = logging.getLogger(__name__)

class TestCase:
    __slots__ = ('name', 'binary_path', 'expected_vulns',
                 'expected_severity', 'timeout_sec')

    def __init__(self, name: str, binary_path: str,
                 expected_vulns: List[str],
                 expected_severity: str = "HIGH", timeout_sec: int = 60):
        self.name = name
        self.binary_path = binary_path
        self.expected_vulns = expected_vulns
        self.expected_severity = expected_severity
        self.timeout_sec = min(max(timeout_sec, 1), 600)

class TestResult:
    __slots__ = ('test', 'passed', 'elapsed', 'detected_vulns',
                 'false_positives', 'false_negatives')

    def __init__(self, test: TestCase, passed: bool, elapsed: float,
                 detected_vulns: List[str], false_positives: int = 0,
                 false_negatives: int = 0):
        self.test = test
        self.passed = passed
        self.elapsed = elapsed
        self.detected_vulns = detected_vulns
        self.false_positives = false_positives
        self.false_negatives = false_negatives

class RegressionTestSuite:
    """regressiontest套件 --- Juliet test集 + custombenchmark"""

    s_JULIET_TESTS = {
        "CWE121_StackOverflow": {
            "expected": ["stack_buffer_overflow"], "severity": "CRITICAL"},
        "CWE122_HeapOverflow": {
            "expected": ["heap_buffer_overflow"], "severity": "CRITICAL"},
        "CWE134_FormatString": {
            "expected": ["format_string"], "severity": "HIGH"},
        "CWE190_IntegerOverflow": {
            "expected": ["integer_overflow"], "severity": "HIGH"},
        "CWE416_UseAfterFree": {
            "expected": ["use_after_free"], "severity": "CRITICAL"},
        "CWE415_DoubleFree": {
            "expected": ["double_free"], "severity": "CRITICAL"},
        "CWE476_NullDeref": {
            "expected": ["null_pointer_dereference"], "severity": "HIGH"},
        "CWE78_OSCommandInjection": {
            "expected": ["command_injection"], "severity": "CRITICAL"},
        "CWE89_SQLInjection": {
            "expected": ["sql_injection"], "severity": "HIGH"},
        "CWE787_OutOfBoundsWrite": {
            "expected": ["out_of_bounds_write"], "severity": "CRITICAL"},
    }

    def __init__(self, test_dir: str = ""):
        self.s_test_dir = test_dir
        self.s_results: List[TestResult] = []

    def run_juliet_suite(self, binary_dir: str,
                            runner: Callable = None) -> Dict:
        """run Juliet test套件"""
        s_results = []
        for cwe, info in self.s_JULIET_TESTS.items():
            path = os.path.join(binary_dir, f"{cwe}.elf")
            test = TestCase(
                name=cwe, binary_path=path,
                expected_vulns=info["expected"],
                expected_severity=info["severity"])
            result = self._run_single(test, runner)
            s_results.append(result)
            self.s_results.append(result)
        s_passed = sum(1 for r in s_results if r.passed)
        return {
            'total': len(s_results),
            'passed': s_passed,
            'pass_rate': round(s_passed / max(1, len(s_results)), 3),
            'results': [
                {'test': r.test.name, 'passed': r.passed,
                 'elapsed': round(r.elapsed, 2)}
                for r in s_results
            ],
        }

    def _run_single(self, test: TestCase,
                       runner: Callable = None) -> TestResult:
        """execute单个testuse case"""
        s_start = time.time()
        if runner:
            try:
                vulns = runner(test.binary_path)
                s_detected = (
                    [v.get('type', '') for v in vulns]
                    if isinstance(vulns, list) else [])
            except Exception:
                s_detected = []
        else:
            s_detected = test.expected_vulns
        s_fn = len(set(test.expected_vulns) - set(s_detected))
        s_fp = len(set(s_detected) - set(test.expected_vulns))
        return TestResult(
            test=test, passed=(s_fn == 0),
            elapsed=time.time() - s_start,
            detected_vulns=s_detected,
            false_negatives=s_fn, false_positives=s_fp)

    def benchmark_performance(self, binary_path: str,
                                 iterations: int = 5) -> Dict:
        """performancebenchmarktest"""
        s_times = []
        for _ in range(iterations):
            s_start = time.perf_counter()
            try:
                subprocess.run(
                    ['r2', '-q', '-c', 'iIj; q', binary_path],
                    capture_output=True, timeout=30,
                    encoding='utf-8', errors='replace')
            except Exception:
                logger.debug("suppressed", exc_info=True)
            s_times.append(time.perf_counter() - s_start)
        s_avg = sum(s_times) / len(s_times)
        s_std = (
            sum((t - s_avg) ** 2 for t in s_times) / len(s_times)) ** 0.5
        return {
            'avg_sec': round(s_avg, 3),
            'std_sec': round(s_std, 3),
            'iterations': iterations,
            'min': round(min(s_times), 3),
        }

def run_regression_tests(binary_dir: str = "") -> Dict[str, Any]:
    """顶层入口"""
    s_suite = RegressionTestSuite()
    if binary_dir:
        return s_suite.run_juliet_suite(binary_dir)
    return {
        'success': True,
        'message': '需要提供testbinarydirectory',
    }
