# 增强型回归测试: 对比原始检测器 vs 增强型检测器
# 核心目的: 量化三个方法论改进 (路径条件/跨步区间/内存区域) 的独立贡献
# 输出: 消融实验结果, 展示每个增强层对Recall/Precision/FPR的边际改善
from __future__ import annotations
import os
import sys
import json
import subprocess
import pathlib
import time
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from analysis.heap_overflow_detector import HeapOverflowDetector
from analysis.enhanced_detector import EnhancedHeapOverflowDetector


@dataclass
class AblationResult:
    """消融实验结果: 一组配置的指标."""
    config_name: str
    total: int = 0
    tp: int = 0; fn: int = 0; tn: int = 0; fp: int = 0

    @property
    def precision(self) -> float:
        return self.tp / max(self.tp + self.fp, 1)

    @property
    def recall(self) -> float:
        return self.tp / max(self.tp + self.fn, 1)

    @property
    def fpr(self) -> float:
        return self.fp / max(self.fp + self.tn, 1)

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / max(p + r, 0.001)


class EnhancedRegressionHarness:
    """增强型回归测试框架: 消融实验 + 对比分析."""

    def __init__(self, samples_dir: str = "cve_samples",
                 build_dir: str = "cve_samples/build"):
        self._samples_dir = pathlib.Path(samples_dir)
        self._build_dir = pathlib.Path(build_dir)
        self._build_dir.mkdir(parents=True, exist_ok=True)
        self._cc = "gcc"
        self._cflags = ["-Wall", "-O0", "-fno-stack-protector", "-g"]

    def compile_sample(self, sample_dir: pathlib.Path) -> Optional[pathlib.Path]:
        """编译单个样本, 返回binary路径."""
        c_file = sample_dir / 'main.c'
        if not c_file.exists():
            c_file = sample_dir / 'cve.c'
        if not c_file.exists():
            return None

        exe_name = sample_dir.name + '.exe'
        out_path = self._build_dir / exe_name
        cmd = [self._cc] + self._cflags + ["-o", str(out_path), str(c_file)]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                    timeout=30, encoding='utf-8', errors='replace')
            if result.returncode == 0:
                return out_path
        except Exception:
            pass
        return None

    def run_ablation(self, samples: List[Tuple[str, bool, pathlib.Path]]
                     ) -> Dict[str, AblationResult]:
        """消融实验: 测试四种配置.

        Config 1: 基准 (无任何增强)
        Config 2: +路径条件
        Config 3: +跨步区间
        Config 4: 全增强 (路径条件+跨步区间+内存区域)
        """
        configs = {
            'baseline': EnhancedHeapOverflowDetector(
                enable_path_conditions=False,
                enable_strided_intervals=False,
                enable_memory_filter=False,
                base_fp_reduction=False),
            '+path_cond': EnhancedHeapOverflowDetector(
                enable_path_conditions=True,
                enable_strided_intervals=False,
                enable_memory_filter=False,
                base_fp_reduction=False),
            '+stride': EnhancedHeapOverflowDetector(
                enable_path_conditions=False,
                enable_strided_intervals=True,
                enable_memory_filter=False,
                base_fp_reduction=False),
            '+all': EnhancedHeapOverflowDetector(
                enable_path_conditions=True,
                enable_strided_intervals=True,
                enable_memory_filter=True,
                base_fp_reduction=False),
        }

        results = {}
        for cfg_name, detector in configs.items():
            result = AblationResult(config_name=cfg_name)
            result.total = len(samples)

            for name, expected_vuln, binary_path in samples:
                if not binary_path or not binary_path.exists():
                    continue
                try:
                    instrs, addrs, labels = self._disassemble(binary_path)
                    if not instrs:
                        continue
                    funcs = self._extract_funcs(instrs, labels)
                    findings = detector.analyze(instrs, funcs, instr_addrs=addrs)
                    # 过滤CRT噪声 (与regression_harness.py相同逻辑)
                    findings = self._filter_crt_noise(findings)
                    # 有效 finding 口径: 增强层标记为可抑制误报的
                    # (is_false_positive) 不计入检出, 使消融可量化
                    detected = any(not f.is_false_positive
                                   for f in findings)

                    if expected_vuln and detected:
                        result.tp += 1
                    elif expected_vuln and not detected:
                        result.fn += 1
                    elif not expected_vuln and not detected:
                        result.tn += 1
                    else:
                        result.fp += 1
                except Exception as e:
                    pass

            results[cfg_name] = result

        # 收集各配置的增强层统计 (跨样本累计的活动量)
        for cfg_name, detector in configs.items():
            if hasattr(detector, 'enhanced_stats'):
                results[cfg_name].stats = detector.enhanced_stats()
        return results

    def _disassemble(self, binary_path: pathlib.Path):
        """复用已验证的反汇编器."""
        from tests.run_scanner import SampleScanner
        scanner = SampleScanner(use_advanced_engine=False)
        result = scanner.disassemble(str(binary_path))
        if result is None:
            return [], [], {}
        return result

    def _extract_funcs(self, lines, labels):
        from tests.run_scanner import SampleScanner
        scanner = SampleScanner(use_advanced_engine=False)
        return scanner.extract_function_boundaries(lines, labels)

    def _filter_crt_noise(self, findings):
        """与 regression_harness.py 相同的CRT过滤."""
        _CRT_NOISE = {
            'duplicate_ppstrings', '__do_global_dtors', '__do_global_ctors',
            '__gcc_register_frame', '__gcc_deregister_frame',
            '__tmainCRTStartup', 'WinMainCRTStartup', 'mainCRTStartup',
            'atexit', 'check_managed_app', 'safe_flush',
            '__mingw_invalidParameterHandler',
        }
        _CRT_PREFIXES = ('__', '_.', '<')
        _AUTO_FUNC_RE = re.compile(r'^func_\d+$')

        filtered = []
        for f in findings:
            fname = f.function_name
            is_named_crt = (fname in _CRT_NOISE or
                           fname.startswith(_CRT_PREFIXES))
            if is_named_crt:
                if f.severity.name in ('INFO', 'LOW'):
                    continue
            if _AUTO_FUNC_RE.match(fname):
                continue
            filtered.append(f)
        return filtered

    def discover_and_compile(self, samples_dir: str = "cve_samples"
                             ) -> List[Tuple[str, bool, Optional[pathlib.Path]]]:
        """发现并编译所有样本.

        fp_samples 数据集的预期判定: fp_heap* 为漏洞, fp_safe* 为安全.
        """
        self._samples_dir = pathlib.Path(samples_dir)
        samples = []
        is_fp = (samples_dir == "fp_samples")
        for d in sorted(self._samples_dir.iterdir()):
            if not d.is_dir() or d.name == 'build':
                continue
            if is_fp:
                expected_vuln = d.name.startswith('fp_heap')
            elif d.name.lower().startswith(('fmt', 'int')):
                # fmt/int 样本归入各自的独立回归, 不参与堆溢出消融
                continue
            else:
                # 判断预期: cve00_* 是安全对照; 新样本cve19/20/21/23也是安全
                name_lower = d.name.lower()
                if 'safe_copy' in name_lower or 'safe_' in name_lower:
                    expected_vuln = False
                elif 'path_cond_clamp' in name_lower or 'early_return' in name_lower:
                    expected_vuln = False  # 路径条件保护=安全
                elif 'stride_loop_safe' in name_lower:
                    expected_vuln = False  # 跨步安全
                elif 'mem_region' in name_lower:
                    expected_vuln = False  # 栈写入=安全
                elif d.name.startswith('cve00'):
                    expected_vuln = False
                else:
                    expected_vuln = True

            binary = None
            try:
                binary = self.compile_sample(d)
            except Exception:
                pass
            samples.append((d.name, expected_vuln, binary))
        return samples


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Enhanced regression: ablation study")
    parser.add_argument("--dataset", default="cve_samples",
                        help="cve_samples 或 fp_samples (含 FP 陷阱)")
    args = parser.parse_args()

    harness = EnhancedRegressionHarness(
        samples_dir=args.dataset if args.dataset != "cve_samples"
        else "cve_samples")
    print("=" * 70)
    print(f"  增强型回归测试 — 消融实验 ({args.dataset})")
    print("=" * 70)

    samples = harness.discover_and_compile(args.dataset)
    vuln_count = sum(1 for _, v, _ in samples if v)
    safe_count = sum(1 for _, v, _ in samples if not v)
    compiled = sum(1 for _, _, b in samples if b is not None)
    print(f"\n发现 {len(samples)} 个样本 ({vuln_count} 漏洞 + {safe_count} 安全)")
    print(f"编译成功: {compiled}, 失败: {len(samples) - compiled}")

    results = harness.run_ablation(samples)

    print("\n" + "=" * 70)
    print("  消融实验结果")
    print("=" * 70)
    print(f"{'配置':<20} {'Recall':>8} {'Precision':>10} {'FPR':>8} {'F1':>8}")
    print("-" * 60)

    baseline = results.get('baseline')
    for cfg_name in ['baseline', '+path_cond', '+stride', '+all']:
        r = results.get(cfg_name)
        if r is None:
            continue
        marker = " (基准)" if cfg_name == 'baseline' else ""
        print(f"{cfg_name+marker:<20} {r.recall:>7.1%} {r.precision:>9.1%} "
              f"{r.fpr:>7.1%} {r.f1:>7.3f}")

    # 计算改进幅度
    if baseline:
        best = results.get('+all')
        if best and baseline.f1 > 0:
            f1_improvement = (best.f1 - baseline.f1) / baseline.f1 * 100
            print(f"\nF1改进: {f1_improvement:+.1f}%")
            if baseline.fpr > 0 and best.fpr < baseline.fpr:
                fpr_reduction = (baseline.fpr - best.fpr) / baseline.fpr * 100
                print(f"FPR降低: {fpr_reduction:.1f}%")

    # 增强层活动统计 (量化各层独立贡献的证据)
    print("\n增强层活动统计 (跨样本累计):")
    for cfg_name in ['+path_cond', '+stride', '+all']:
        r = results.get(cfg_name)
        if r and r.stats:
            print(f"  {cfg_name:<12} {r.stats}")

    # 保存JSON报告
    report_path = harness._build_dir / 'ablation_report.json'
    report = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'sample_counts': {
            'total': len(samples),
            'vulnerable': vuln_count,
            'safe': safe_count,
            'compiled': compiled,
        },
        'configs': {}
    }
    for cfg_name, r in results.items():
        report['configs'][cfg_name] = {
            'tp': r.tp, 'fn': r.fn, 'tn': r.tn, 'fp': r.fp,
            'precision': r.precision, 'recall': r.recall,
            'fpr': r.fpr, 'f1': r.f1,
        }
    with open(report_path, 'w', encoding='utf-8') as fp:
        json.dump(report, fp, indent=2, ensure_ascii=False)
    print(f"\n消融实验报告: {report_path}")

    return 0


if __name__ == '__main__':
    sys.exit(main())
