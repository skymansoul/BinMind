# UAF回归测试框架: 编译UAF样本 → 反汇编 → 扫描 → 收集结果
# 设计: 与regression_harness.py相同的架构, 适配UafDetector
import os
import sys
import json
import subprocess
import pathlib
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from analysis.uaf_detector import UafDetector, UafFinding, UafSeverity


@dataclass
class UafSampleDef:
    name: str
    cve: str
    expected_type: str          # 'uaf' | 'safe'
    expected_severity: str      # 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'NONE'
    pattern: str
    c_path: pathlib.Path
    binary_path: Optional[pathlib.Path] = None
    compile_ok: bool = False
    findings: List = field(default_factory=list)
    detected: bool = False
    error_msg: str = ""


@dataclass
class UafRegressionResult:
    samples: List[UafSampleDef]
    total: int = 0; compiled: int = 0; compile_failed: int = 0
    true_positives: int = 0; false_negatives: int = 0
    true_negatives: int = 0; false_positives: int = 0

    @property
    def precision(self) -> float:
        return self.true_positives / max(self.true_positives + self.false_positives, 1)
    @property
    def recall(self) -> float:
        return self.true_positives / max(self.true_positives + self.false_negatives, 1)
    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / max(p + r, 0.001)

    def summary(self) -> str:
        return "\n".join([
            "=" * 60, "  UAF回归测试结果摘要", "=" * 60,
            f"  总样本数:     {self.total}",
            f"  编译成功:     {self.compiled}",
            f"  编译失败:     {self.compile_failed}",
            "",
            f"  True  Positives (检出/应检出):  {self.true_positives}/{self.true_positives + self.false_negatives}",
            f"  False Negatives (漏报):        {self.false_negatives}",
            f"  True  Negatives (正确阴性):   {self.true_negatives}",
            f"  False Positives (误报):        {self.false_positives}",
            "",
            f"  精确率 (Precision): {self.precision:.1%}",
            f"  召回率 (Recall):    {self.recall:.1%}",
            f"  F1 分数:            {self.f1:.3f}",
            "=" * 60,
        ])


class UafRegressionHarness:
    def __init__(self, samples_dir: str = "cve_samples",
                 build_dir: str = "cve_samples/build"):
        self._samples_dir = pathlib.Path(samples_dir)
        self._build_dir = pathlib.Path(build_dir)
        self._build_dir.mkdir(parents=True, exist_ok=True)
        self._cc = "gcc"
        self._cflags = ["-Wall", "-O0", "-fno-stack-protector", "-g"]

    def discover_uaf_samples(self) -> List[UafSampleDef]:
        samples = []
        for d in sorted(self._samples_dir.iterdir()):
            if not d.is_dir() or d.name == 'build':
                continue
            # 只处理uaf样本
            if not d.name.startswith('uaf'):
                continue
            c_file = d / 'main.c'
            if not c_file.exists():
                continue

            readme = d / 'README.md'
            expected_type = 'uaf'
            severity = 'UNKNOWN'
            pattern = 'unknown'

            name_lower = d.name.lower()
            if 'safe' in name_lower:
                expected_type = 'safe'
                severity = 'NONE'

            if readme.exists():
                content = readme.read_text(encoding='utf-8')
                for line in content.split('\n'):
                    if 'CVE参考' in line or 'CVE编号' in line:
                        pass
                    elif '严重级别' in line:
                        severity = line.split('**')[1] if '**' in line else severity
                    elif '模式' in line:
                        pattern = line.split('`')[1] if '`' in line else pattern

            samples.append(UafSampleDef(
                name=d.name, cve='UAF-TEST',
                expected_type=expected_type, expected_severity=severity,
                pattern=pattern, c_path=c_file))
        return samples

    def compile_sample(self, sample: UafSampleDef) -> bool:
        out_path = self._build_dir / f"{sample.name}.exe"
        cmd = [self._cc] + self._cflags + ["-o", str(out_path), str(sample.c_path)]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                    timeout=30, encoding='utf-8', errors='replace')
            if result.returncode == 0:
                sample.binary_path = out_path
                sample.compile_ok = True
                return True
            else:
                sample.error_msg = result.stderr.strip()[:200]
                return False
        except Exception as e:
            sample.error_msg = str(e)[:200]
            return False

    def disassemble(self, binary_path: pathlib.Path):
        from tests.run_scanner import SampleScanner
        scanner = SampleScanner(use_advanced_engine=False)
        result = scanner.disassemble(str(binary_path))
        if result is None:
            return [], [], {}
        return result

    def scan_binary(self, sample: UafSampleDef) -> List:
        if not sample.binary_path or not sample.binary_path.exists():
            return []
        instrs, addrs, labels = self.disassemble(sample.binary_path)
        if not instrs:
            sample.error_msg = "反汇编无输出"
            return []

        from tests.run_scanner import SampleScanner
        scanner = SampleScanner(use_advanced_engine=False)
        funcs = scanner.extract_function_boundaries(instrs, labels)

        detector = UafDetector()
        findings = detector.analyze(instrs, funcs, instr_addrs=addrs)
        return findings

    def run(self) -> UafRegressionResult:
        print("=" * 60)
        print("  BinMind UAF检测回归测试")
        print("=" * 60)

        print("\n[1/3] 发现UAF样本...")
        samples = self.discover_uaf_samples()
        print(f"  发现 {len(samples)} 个UAF样本")

        print("\n[2/3] 编译+扫描...")
        for s in samples:
            if not self.compile_sample(s):
                print(f"  [BUILD_FAIL] {s.name}")
                continue
            findings = self.scan_binary(s)
            s.findings = findings
            s.detected = len(findings) > 0

            sevs = ','.join(f.severity.name for f in findings[:3])
            n = len(findings)
            if s.expected_type != 'safe':
                status = "[OK] 检出" if s.detected else "[FN!] 漏报"
            else:
                status = "[OK] 正确阴性" if not s.detected else "[FP!] 误报"
            print(f"  {s.name:30s} -> {n:2d} findings [{sevs:<20s}] -> {status}")

        print("\n[3/3] 计算统计...")
        result = UafRegressionResult(samples=samples)
        result.total = len(samples)
        result.compiled = sum(1 for s in samples if s.compile_ok)
        result.compile_failed = result.total - result.compiled

        for s in samples:
            if not s.compile_ok:
                continue
            expected_vuln = (s.expected_type != 'safe')
            if expected_vuln and s.detected:
                result.true_positives += 1
            elif expected_vuln and not s.detected:
                result.false_negatives += 1
            elif not expected_vuln and not s.detected:
                result.true_negatives += 1
            elif not expected_vuln and s.detected:
                result.false_positives += 1

        return result


def main():
    harness = UafRegressionHarness()
    result = harness.run()
    print()
    print(result.summary())

    # 详细列表
    print(f"\n{'样本':<30} {'预期':<10} {'检出':<6} {'判定':<12}")
    print("-" * 60)
    for s in result.samples:
        if s.compile_ok:
            verdict = ("✓ TP" if (s.expected_type != 'safe' and s.detected) else
                      "✓ TN" if (s.expected_type == 'safe' and not s.detected) else
                      "✗ FN" if (s.expected_type != 'safe' and not s.detected) else
                      "✗ FP")
            print(f"{s.name:<30} {s.expected_type:<10} {'YES' if s.detected else 'NO':<6} {verdict:<12}")

    # 漏报详情
    fns = [s for s in result.samples if s.compile_ok and s.expected_type != 'safe' and not s.detected]
    if fns:
        print(f"\n漏报详情 ({len(fns)}):")
        for s in fns:
            print(f"  {s.name}: {s.pattern}")

    # 误报详情
    fps = [s for s in result.samples if s.compile_ok and s.expected_type == 'safe' and s.detected]
    if fps:
        print(f"\n误报详情 ({len(fps)}):")
        for s in fps:
            for f in s.findings:
                print(f"  {s.name}: {f}")

    # 保存报告
    report_path = harness._build_dir / 'uaf_regression_report.json'
    report = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'summary': {
            'total': result.total, 'compiled': result.compiled,
            'true_positives': result.true_positives,
            'false_negatives': result.false_negatives,
            'true_negatives': result.true_negatives,
            'false_positives': result.false_positives,
            'precision': result.precision, 'recall': result.recall, 'f1': result.f1,
        },
        'samples': [{
            'name': s.name, 'expected_type': s.expected_type,
            'compile_ok': s.compile_ok, 'detected': s.detected,
            'num_findings': len(s.findings),
            'findings': [{'severity': str(f.severity), 'detail': f.detail}
                        for f in s.findings],
        } for s in result.samples],
    }
    with open(report_path, 'w', encoding='utf-8') as fp:
        json.dump(report, fp, indent=2, ensure_ascii=False)
    print(f"\n报告: {report_path}")

    return 0 if result.false_negatives == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
