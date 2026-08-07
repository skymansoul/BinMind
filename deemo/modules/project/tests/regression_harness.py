# 回归测试框架: 编译CVE样本 → 反汇编 → 扫描 → 收集结果
# 核心目的: 验证检测器在每个CVE启发样本上的检出/漏检情况
# 输出: 精确率/召回率/F1分数, 逐个样本的详细判定
# BinMind FP reduction benchmark 回归测试规范
import os
import sys
import json
import subprocess
import pathlib
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# Windows console encoding fix
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# 将项目根目录加入路径
PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from analysis.heap_overflow_detector import HeapOverflowDetector
from analysis.value_range import ValueRangeDomain
from analysis.pointer_provenance import PointerProvenanceTracker
from analysis.allocation_tracker import AllocationTracker
from analysis.heap_allocator_model import HeapAllocatorModel, AllocatorFamily
from analysis.false_positive_filter import FalsePositiveFilter


@dataclass
class SampleDef:
    """单个CVE样本的元数据."""
    name: str
    cve: str
    expected_type: str          # 'heap_overflow' | 'safe'
    expected_severity: str      # 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'NONE'
    pattern: str
    c_path: pathlib.Path
    binary_path: Optional[pathlib.Path] = None
    compile_ok: bool = False
    findings: List = field(default_factory=list)
    detected: bool = False
    error_msg: str = ""


@dataclass
class RegressionResult:
    """回归测试总体结果."""
    samples: List[SampleDef]
    total: int = 0
    compiled: int = 0
    compile_failed: int = 0

    # 分类统计
    true_positives: int = 0     # 应检出且检出了
    false_negatives: int = 0    # 应检出但未检出
    true_negatives: int = 0     # 不应检出且未检出
    false_positives: int = 0    # 不应检出但检出了

    @property
    def precision(self) -> float:
        detected = self.true_positives + self.false_positives
        return self.true_positives / max(detected, 1)

    @property
    def recall(self) -> float:
        should_detect = self.true_positives + self.false_negatives
        return self.true_positives / max(should_detect, 1)

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / max(p + r, 0.001)

    def summary(self) -> str:
        lines = [
            "=" * 60,
            "  回归测试结果摘要",
            "=" * 60,
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
        ]
        return "\n".join(lines)

    def detail_table(self) -> str:
        """逐个样本的详细表格."""
        lines = [
            f"{'样本':<25} {'CVE':<20} {'类型':<16} {'预期':<10} {'检出':<6} {'判定':<12}",
            "-" * 95,
        ]
        for s in self.samples:
            if s.compile_ok:
                verdict = "✓ TP" if (s.expected_type != 'safe' and s.detected) else \
                          "✓ TN" if (s.expected_type == 'safe' and not s.detected) else \
                          "✗ FN" if (s.expected_type != 'safe' and not s.detected) else \
                          "✗ FP"
                detected_str = "YES" if s.detected else "NO"
            else:
                verdict = "BUILD_FAIL"
                detected_str = "N/A"
            lines.append(
                f"{s.name:<25} {s.cve:<20} {s.expected_type:<16} "
                f"{s.expected_severity:<10} {detected_str:<6} {verdict:<12}"
            )
        return "\n".join(lines)


class RegressionHarness:
    """自动化回归测试框架.

    流程:
      1. 扫描 cve_samples/ 目录, 发现所有样本
      2. 编译每个样本为 PE/ELF
      3. objdump 反汇编
      4. 运行 HeapOverflowDetector
      5. 比较检出与预期
      6. 生成报告
    """

    def __init__(self, samples_dir: str = "cve_samples",
                 build_dir: str = "cve_samples/build"):
        self._samples_dir = pathlib.Path(samples_dir)
        self._build_dir = pathlib.Path(build_dir)
        self._build_dir.mkdir(parents=True, exist_ok=True)
        self._cc = "gcc"
        self._objdump = "objdump"
        self._cflags = ["-Wall", "-O0", "-fno-stack-protector", "-g"]

    def discover_samples(self) -> List[SampleDef]:
        """发现所有样本目录."""
        samples = []
        for d in sorted(self._samples_dir.iterdir()):
            if not d.is_dir() or d.name == 'build':
                continue
            c_file = d / 'main.c'
            if not c_file.exists():
                c_file = d / 'cve.c'
            if not c_file.exists():
                continue

            # 从目录名提取元数据
            readme = d / 'README.md'
            # [DEPRECATED] 基于cve00前缀的简单安全判定
            # expected_type = 'safe' if d.name.startswith('cve00') else 'heap_overflow'
            # 替换为: 基于README中的类型标记 + 目录名模式的综合判定
            expected_type = 'safe' if d.name.startswith('cve00') else 'heap_overflow'
            # 增强型安全样本识别: 路径条件保护/跨步安全/内存区域安全
            name_lower = d.name.lower()
            _SAFE_PATTERNS = [
                'path_cond_clamp', 'early_return',    # 路径条件保护
                'stride_loop_safe',                    # 跨步区间安全
                'mem_region',                          # 内存区域安全(栈写入)
                'safe_',                               # UAF安全对照样本
            ]
            # UAF样本: 命名以 uaf 开头 → 归入UAF检测器, 不参与堆溢出回归
            _UAF_PATTERNS = ['uaf']
            if any(p in name_lower for p in _UAF_PATTERNS):
                expected_type = 'uaf'
            if any(p in name_lower for p in _SAFE_PATTERNS):
                expected_type = 'safe'
            # 读取README获取详细信息
            cve = "UNKNOWN"
            severity = "UNKNOWN"
            pattern = "unknown"

            if readme.exists():
                content = readme.read_text(encoding='utf-8')
                for line in content.split('\n'):
                    if 'CVE编号' in line:
                        cve = line.split('**')[1] if '**' in line else 'UNKNOWN'
                    elif '漏洞类型' in line:
                        expected_type = 'heap_overflow' if 'heap_overflow' in line.lower() else expected_type
                    elif '严重级别' in line:
                        severity = line.split('**')[1] if '**' in line else 'UNKNOWN'
                    elif '溢出模式' in line:
                        pattern = line.split('`')[1] if '`' in line else 'unknown'

            samples.append(SampleDef(
                name=d.name,
                cve=cve,
                expected_type=expected_type,
                expected_severity=severity,
                pattern=pattern,
                c_path=c_file,
            ))
        return samples

    def compile_sample(self, sample: SampleDef) -> bool:
        """编译单个样本."""
        out_path = self._build_dir / f"{sample.name}.exe"
        cmd = [self._cc] + self._cflags + [
            "-o", str(out_path), str(sample.c_path)
        ]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30,
                encoding='utf-8', errors='replace')
            if result.returncode == 0:
                sample.binary_path = out_path
                sample.compile_ok = True
                return True
            else:
                sample.error_msg = result.stderr.strip()[:200]
                return False
        except subprocess.TimeoutExpired:
            sample.error_msg = "编译超时"
            return False
        except Exception as e:
            sample.error_msg = str(e)[:200]
            return False

    def compile_all(self, samples: List[SampleDef]) -> Tuple[int, int]:
        """编译所有样本. 返回 (成功数, 失败数)."""
        ok, fail = 0, 0
        for s in samples:
            if self.compile_sample(s):
                ok += 1
                print(f"  [OK] {s.name}")
            else:
                fail += 1
                print(f"  [FAIL] {s.name}: {s.error_msg[:80]}")
        return ok, fail

    def disassemble(self, binary_path: pathlib.Path) -> Tuple[List[str], List[int], Dict[int, str]]:
        """反汇编二进制文件. 使用与 run_scanner.py 相同的解析逻辑."""
        # 复用 SampleScanner 的已验证解析器
        from tests.run_scanner import SampleScanner
        scanner = SampleScanner(use_advanced_engine=False)
        result = scanner.disassemble(str(binary_path))
        if result is None:
            return [], [], {}
        return result

    def scan_binary(self, sample: SampleDef) -> List:
        """对已编译的样本运行检测器. 使用与 run_scanner.py 相同的接口."""
        if not sample.binary_path or not sample.binary_path.exists():
            return []

        instrs, addrs, labels = self.disassemble(sample.binary_path)

        if not instrs:
            sample.error_msg = "反汇编无输出"
            return []

        # 提取函数边界 (与 run_scanner.py 相同的逻辑)
        funcs = self._extract_func_bounds(instrs, labels)

        # 运行分析
        detector = HeapOverflowDetector()
        findings_raw = detector.analyze(instrs, funcs, instr_addrs=addrs)

        # 过滤CRT噪声: CRT内部函数和未命名自动函数(func_NNN)
        # func_NNN函数是CRT启动代码中无符号表的函数,
        # 其malloc/memcpy模式是MinGW运行时的副作用, 非用户代码
        _CRT_NOISE = {
            'duplicate_ppstrings', '__do_global_dtors', '__do_global_ctors',
            '__gcc_register_frame', '__gcc_deregister_frame',
            '__tmainCRTStartup', 'WinMainCRTStartup', 'mainCRTStartup',
            'atexit', 'check_managed_app', 'safe_flush',
            '__mingw_invalidParameterHandler',
        }
        _CRT_PREFIXES = ('__', '_.', '<')
        _AUTO_FUNC_RE = re.compile(r'^func_\d+$')

        findings = []
        for f in findings_raw:
            fname = f.function_name
            # CRT命名函数: 只保留非INFO/LOW的发现
            is_named_crt = (fname in _CRT_NOISE or
                           fname.startswith(_CRT_PREFIXES))
            if is_named_crt:
                if f.severity.name in ('INFO', 'LOW'):
                    continue
            # 自动函数(func_NNN): 全部过滤 (无符号表=非用户代码)
            if _AUTO_FUNC_RE.match(fname):
                continue
            findings.append(f)

        return findings

    def _extract_func_bounds(self, lines: List[str],
                              labels: Dict[int, str]) -> Dict[str, Tuple[int, int]]:
        """从反汇编提取函数边界. 复用 SampleScanner 已验证的逻辑."""
        from tests.run_scanner import SampleScanner
        scanner = SampleScanner(use_advanced_engine=False)
        return scanner.extract_function_boundaries(lines, labels)

    def evaluate_finding(self, sample: SampleDef,
                         findings: List) -> bool:
        """判断是否检出漏洞 (has_vuln_finding).

        统一语义: len(findings) > 0 → True (检出可疑写入)
        """
        return len(findings) > 0

    def run(self) -> RegressionResult:
        """运行完整回归测试 (仅堆溢出和safe样本, UAF样本由uaf_regression.py处理)."""
        print("=" * 60)
        print("  BinMind 堆溢出检测回归测试")
        print("=" * 60)

        # 1. 发现样本
        print("\n[1/4] 发现样本...")
        all_samples = self.discover_samples()
        # 分离UAF样本 (由 uaf_regression.py 独立测试)
        uaf_samples = [s for s in all_samples if s.expected_type == 'uaf']
        samples = [s for s in all_samples if s.expected_type != 'uaf']
        print(f"  发现 {len(all_samples)} 个样本 "
              f"(堆溢出/safe: {len(samples)}, UAF: {len(uaf_samples)} — 跳过)")

        # 2. 编译
        print("\n[2/4] 编译样本...")
        ok, fail = self.compile_all(samples)
        print(f"  编译: {ok} 成功, {fail} 失败")

        # 3. 扫描
        print("\n[3/4] 扫描二进制文件...")
        for s in samples:
            if not s.compile_ok:
                continue
            findings = self.scan_binary(s)
            s.findings = findings
            s.detected = self.evaluate_finding(s, findings)
            n_findings = len(findings)
            if s.expected_type == 'safe':
                status = "[OK] 正确阴性" if not s.detected else "[FP!] 误报"
            else:
                status = "[OK] 检出" if s.detected else "[FN!] 漏报"
            print(f"  {s.name:30s} -> {n_findings:3d} findings -> {status}")

        # 4. 统计
        print("\n[4/4] 计算统计...")
        result = RegressionResult(samples=samples)
        result.total = len(samples)
        result.compiled = ok
        result.compile_failed = fail

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
    harness = RegressionHarness()
    result = harness.run()

    print()
    print(result.summary())
    print()
    print(result.detail_table())

    # 漏报详情
    fns = [s for s in result.samples
           if s.compile_ok and s.expected_type != 'safe' and not s.detected]
    if fns:
        print(f"\n漏报样本详情 ({len(fns)}):")
        for s in fns:
            print(f"  {s.name} ({s.cve}): {s.error_msg or '无错误信息'}")

    # 误报详情
    fps = [s for s in result.samples
           if s.compile_ok and s.expected_type == 'safe' and s.detected]
    if fps:
        print(f"\n误报样本详情 ({len(fps)}):")
        for s in fps:
            for f in s.findings:
                print(f"  {s.name}: {f}")

    # 保存JSON报告
    report_path = harness._build_dir / 'regression_report.json'
    report = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'summary': {
            'total': result.total,
            'compiled': result.compiled,
            'compile_failed': result.compile_failed,
            'true_positives': result.true_positives,
            'false_negatives': result.false_negatives,
            'true_negatives': result.true_negatives,
            'false_positives': result.false_positives,
            'precision': result.precision,
            'recall': result.recall,
            'f1': result.f1,
        },
        'samples': [
            {
                'name': s.name,
                'cve': s.cve,
                'expected_type': s.expected_type,
                'pattern': s.pattern,
                'compile_ok': s.compile_ok,
                'detected': s.detected,
                'num_findings': len(s.findings),
                'error': s.error_msg,
                'findings': [
                    {
                        'severity': str(getattr(f, 'severity', '?')),
                        'message': str(getattr(f, 'message', str(f))),
                    }
                    for f in s.findings
                ],
            }
            for s in result.samples
        ],
    }
    with open(report_path, 'w', encoding='utf-8') as fp:
        json.dump(report, fp, indent=2, ensure_ascii=False)
    print(f"\n报告已保存: {report_path}")

    return 0 if result.false_negatives == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
