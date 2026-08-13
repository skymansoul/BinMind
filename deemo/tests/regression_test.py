"""

堆溢出检测回归测试套件 — 自动编译/扫描/收集/比对.

流程:
  1. compile: 编译所有样本为 ELF
  2. scan: 对每个二进制运行堆溢出检测
  3. collect: 收集检测结果, 与预期比对
  4. report: 生成精度/召回/误报率报告

预期定义 (EXPECTED_MAP):
  - should_detect=True: 真阳性, 检测器应报告
  - should_detect=False: 误报测试, 检测器不应报告 (深度过滤目标)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# 预期结果映射
# sample_id → {vuln_type, should_detect, cwe, description}
EXPECTED_MAP: Dict[str, Dict[str, Any]] = {
    # True Positives — 检测器必须报告
    "sample_01": {"vuln_type": "heap_overflow", "should_detect": True,
                  "cwe": "CWE-122", "desc": "malloc(64) + memset(256)"},
    "sample_02": {"vuln_type": "heap_overflow", "should_detect": True,
                  "cwe": "CWE-122", "desc": "malloc in loop + memset overflow"},
    "sample_03": {"vuln_type": "heap_overflow", "should_detect": True,
                  "cwe": "CWE-122", "desc": "realloc shrink + overflow"},
    "sample_04": {"vuln_type": "heap_overflow", "should_detect": True,
                  "cwe": "CWE-122", "desc": "calloc + overflow"},
    "sample_05": {"vuln_type": "heap_overflow", "should_detect": True,
                  "cwe": "CWE-122", "desc": "realloc grow + overflow via memset"},
    "sample_06": {"vuln_type": "heap_overflow", "should_detect": True,
                  "cwe": "CWE-122", "desc": "multi buffer overflow"},
    # False Positives — 深度过滤应消除的误报
    "sample_07": {"vuln_type": "heap_overflow", "should_detect": False,
                  "cwe": "CWE-122", "desc": "FP: guard pattern if(n>MAX)n=MAX"},
    "sample_08": {"vuln_type": "heap_overflow", "should_detect": True,
                  "cwe": "CWE-122", "desc": "struct member overflow"},
    "sample_09": {"vuln_type": "heap_overflow", "should_detect": True,
                  "cwe": "CWE-122", "desc": "callback struct + buf overflow"},
    "sample_10": {"vuln_type": "heap_overflow", "should_detect": True,
                  "cwe": "CWE-122", "desc": "indirect pointer overflow"},
    "sample_11": {"vuln_type": "heap_overflow", "should_detect": True,
                  "cwe": "CWE-122", "desc": "dynamic size overflow"},
    "sample_12": {"vuln_type": "heap_overflow", "should_detect": True,
                  "cwe": "CWE-122", "desc": "adjacent buffer overflow"},
    "sample_13": {"vuln_type": "heap_overflow", "should_detect": True,
                  "cwe": "CWE-122", "desc": "loop write overflow"},
    # FP: malloc(0) allocation — 实现定义行为
    "sample_14": {"vuln_type": "heap_overflow", "should_detect": False,
                  "cwe": "CWE-122", "desc": "FP: malloc(0) + overflow"},
    "sample_15": {"vuln_type": "heap_overflow", "should_detect": True,
                  "cwe": "CWE-122", "desc": "strncpy bound bypass"},
    # FP: realloc((size_t)-1) — 分配失败路径
    "sample_16": {"vuln_type": "heap_overflow", "should_detect": False,
                  "cwe": "CWE-122", "desc": "FP: realloc(SIZE_MAX) allocation fail"},
    "sample_17": {"vuln_type": "heap_overflow", "should_detect": True,
                  "cwe": "CWE-122", "desc": "sprintf overflow"},
    "sample_18": {"vuln_type": "heap_overflow", "should_detect": True,
                  "cwe": "CWE-122", "desc": "memmove overflow"},
}


@dataclass
class ScanResult:
    """单个样本的扫描结果."""
    sample_id: str
    binary_path: str
    expected: bool          # should_detect
    detected: bool          # 是否报告了漏洞
    num_findings: int = 0
    findings: List[Dict] = field(default_factory=list)
    compile_ok: bool = False
    scan_ok: bool = False
    error: str = ""


@dataclass
class RegressionReport:
    """回归测试汇总报告."""
    total: int = 0
    compiled: int = 0
    scanned: int = 0
    true_positives: int = 0    # should_detect=True AND detected=True
    false_positives: int = 0   # should_detect=False AND detected=True
    true_negatives: int = 0    # should_detect=False AND detected=False
    false_negatives: int = 0   # should_detect=True AND detected=False
    results: List[ScanResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def fp_rate(self) -> float:
        """误报率: FP / (FP + TN)."""
        denom = self.false_positives + self.true_negatives
        return self.false_positives / denom if denom > 0 else 0.0

    def summary(self) -> str:
        return (
            f"Regression Report:\n"
            f"  Compiled: {self.compiled}/{self.total}\n"
            f"  Scanned:  {self.scanned}/{self.compiled}\n"
            f"  TP={self.true_positives} FP={self.false_positives} "
            f"TN={self.true_negatives} FN={self.false_negatives}\n"
            f"  Precision={self.precision:.2%} Recall={self.recall:.2%} "
            f"F1={self.f1:.2%} FP_Rate={self.fp_rate:.2%}\n"
            f"  Errors: {len(self.errors)}"
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            'total': self.total, 'compiled': self.compiled,
            'scanned': self.scanned,
            'true_positives': self.true_positives,
            'false_positives': self.false_positives,
            'true_negatives': self.true_negatives,
            'false_negatives': self.false_negatives,
            'precision': self.precision, 'recall': self.recall,
            'f1': self.f1, 'fp_rate': self.fp_rate,
            'errors': self.errors,
        }




"""
堆溢出检测回归测试套件 — 自动编译/扫描/收集/比对.

流程:
  1. compile: 编译所有样本为 ELF
  2. scan: 对每个二进制运行堆溢出检测
  3. collect: 收集检测结果, 与预期比对
  4. report: 生成精度/召回/误报率报告

预期定义 (EXPECTED_MAP):
  - should_detect=True: 真阳性, 检测器应报告
  - should_detect=False: 误报测试, 检测器不应报告 (深度过滤目标)
"""

# 预期结果映射
# sample_id → {vuln_type, should_detect, cwe, description}

class RegressionTestRunner:
    """堆溢出检测回归测试运行器."""

    def __init__(self, samples_root: str = None):
        if samples_root is None:
            samples_root = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                'samples', 'heap_overflow')
        self._samples_root = samples_root

    def run_all(self) -> RegressionReport:
        """运行完整回归测试."""
        t0 = time.time()
        report = RegressionReport()

        sample_dirs = sorted(
            [d for d in os.listdir(self._samples_root)
             if os.path.isdir(os.path.join(self._samples_root, d))
             and d.startswith('sample_')])

        report.total = len(sample_dirs)

        for sdir in sample_dirs:
            result = self._process_sample(sdir)
            report.results.append(result)

            if result.compile_ok:
                report.compiled += 1
            if result.scan_ok:
                report.scanned += 1

            # 分类
            if result.expected and result.detected:
                report.true_positives += 1
            elif result.expected and not result.detected:
                report.false_negatives += 1
            elif not result.expected and result.detected:
                report.false_positives += 1
            elif not result.expected and not result.detected:
                report.true_negatives += 1

            if result.error:
                report.errors.append(f"{sdir}: {result.error}")

        return report

    def _process_sample(self, sdir: str) -> ScanResult:
        """编译并扫描单个样本."""
        full_dir = os.path.join(self._samples_root, sdir)
        expected = EXPECTED_MAP.get(sdir, {}).get('should_detect', True)

        result = ScanResult(
            sample_id=sdir, binary_path="", expected=expected, detected=False)

        # 1. 编译
        src_file = os.path.join(full_dir, f"{sdir}.c")
        binary = os.path.join(full_dir, f"{sdir}.exe")
        if not os.path.exists(src_file):
            result.error = f"source not found: {src_file}"
            return result

        try:
            proc = subprocess.run(
                ['gcc', '-Wall', '-O0', '-g', '-o', binary, src_file],
                capture_output=True, text=True, timeout=30)
            if proc.returncode != 0:
                result.error = f"compile failed: {proc.stderr[:200]}"
                return result
            result.compile_ok = True
            result.binary_path = binary
        except Exception as e:
            result.error = f"compile error: {e}"
            return result

        # 2. 扫描
        try:
            findings = self._scan_binary(binary, sdir)
            result.scan_ok = True
            result.num_findings = len(findings)
            result.findings = findings
            result.detected = len(findings) > 0
        except Exception as e:
            result.error = f"scan error: {e}"

        return result

    def _scan_binary(self, binary_path: str, sample_id: str) -> List[Dict]:
        """对样本运行堆溢出检测.

        将C源码转换为类反编译IR后运行检测管线.
        """
        findings = []
        src_path = binary_path.replace('.exe', '.c') if binary_path.endswith('.exe') \
                   else os.path.join(os.path.dirname(binary_path), f'{sample_id}.c')

        if not os.path.exists(src_path):
            return findings

        try:
            with open(src_path, 'r', encoding='utf-8', errors='replace') as f:
                source_text = f.read()
        except Exception:
            return findings

        # C源码→伪代码IR转换
        ir_text = self._c_to_ir(source_text)

        # 用基线检测器分析
        try:
            from core.heap_overflow_detector import detect_heap_overflow
            raw_findings = detect_heap_overflow(ir_text.splitlines(), ir_text)
            for f in raw_findings:
                alloc_site = getattr(f, 'alloc_site', None)
                ov_store = getattr(f, 'overflow_store', None)
                findings.append({
                    'alloc_func': getattr(alloc_site, 'alloc_func', '') if alloc_site else '',
                    'alloc_size': getattr(alloc_site, 'size_arg', 0) if alloc_site else 0,
                    'write_func': getattr(ov_store, 'mnemonic', '') if ov_store else '',
                    'write_size': getattr(ov_store, 'store_size', 0) if ov_store else 0,
                    'confidence': getattr(f, 'confidence', 0),
                })
        except ImportError:
            pass

        return findings

    @staticmethod
    def _c_to_ir(c_source: str) -> str:
        """将C源码转换为类反编译伪代码IR.

        去类型声明/去强制转换/保留函数调用和赋值语义.
        """
        import re
        lines = []
        for line in c_source.splitlines():
            stripped = line.strip()
            # 跳过预处理/注释/空行/括号
            if stripped.startswith('#') or stripped.startswith('//') or stripped.startswith('/*'):
                continue
            if stripped.startswith('*') or stripped.startswith('}') or stripped.startswith(')'):
                continue
            if not stripped or stripped in ('{', '}'):
                continue
            # 先去强制转换: (type *) 和 (type) — 必须在类型剥离之前
            s = re.sub(r'\(\s*(?:char|int|void|size_t|unsigned|float|double|'
                       r'uint\d+_t|int\d+_t|long)\s*\**\s*\)', '', stripped)
            # 再去类型前缀 (含指针)
            s = re.sub(
                r'\b(?:char|int|short|long|void|float|double|size_t|ssize_t|'
                r'unsigned|signed|uint\d+_t|int\d+_t|const|static|volatile|'
                r'extern|register|struct\s+\w+)\s*\**\s*', '', s)
            # 去 if/while/for/else 关键字前缀 (保留条件表达式)
            s = re.sub(r'\b(?:if|while|for|else)\s*\(', '(', s)
            # 去 return/free/printf 等无关语句
            if re.match(r'\s*(?:return|free|printf|puts|fprintf|exit)\s*[\(;]', s):
                continue
            # 去分号/花括号
            s = s.rstrip(';').strip()
            if s:
                lines.append(s)
        return '\n'.join(lines)


def run_regression(samples_root: str = None) -> RegressionReport:
    """运行堆溢出回归测试."""
    runner = RegressionTestRunner(samples_root)
    return runner.run_all()


if __name__ == '__main__':
    base = sys.argv[1] if len(sys.argv) > 1 else None
    report = run_regression(base)
    print(report.summary())
    # 保存 JSON 报告
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            'regression_report.json')
    with open(out_path, 'w') as f:
        json.dump(report.to_dict(), f, indent=2)
    print(f"\nReport saved to: {out_path}")
