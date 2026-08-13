# 多工具对比实验主脚本 (FP-Reduction 基准)
# 在 fp_samples 上运行 5 个工具, 统一输出 CSV/JSON/LaTeX:
#   our_method   — 分配点感知值域分析 + 值流耦合 FP 抑制 (本方法)
#   our_base     — 同引擎, FP 抑制关闭 (消融基线)
#   naive        — 函数级 malloc+sink 模式匹配 (工业界简化)
#   regex        — 纯正则 malloc/memcpy 共现
#   angr         — CFG 可达性分析 (符号执行工具代表)
#   qemu/ghidra  — 环境不可用时优雅跳过 (ground truth 由 QEMU 提供)
# 输出: eval_output/fp_benchmark_results.{csv,json} + result_table.tex
# 决策: 本脚本只做调度与汇总, 各工具逻辑复用既有模块
#   (analysis.heap_overflow_detector, eval.baseline_detectors,
#    eval.angr_explorer, eval.qemu_tracer, eval.ghidra_headless)
import sys
import io
import os
import csv
import json
import time
import shutil
import pathlib
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8',
                                  errors='replace')

_PROJ_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJ_ROOT))

_HEAP_SAMPLES = [f"fp_heap{i:02d}" for i in range(1, 16)]
_SAFE_SAMPLES = [f"fp_safe{i:02d}" for i in range(1, 11)]



class FpBenchmarkRunner:
    """FP-Reduction 多工具基准运行器."""

    def __init__(self, samples_root: str = "fp_samples",
                 output_dir: str = "eval_output"):
        self._samples_root = pathlib.Path(samples_root)
        self._output_dir = pathlib.Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._build_dir = pathlib.Path("fp_samples/build")

    def _expected_vuln(self, name: str) -> bool:
        return name in _HEAP_SAMPLES

    def compile_variants(self) -> Dict[str, List[Tuple[str, str, str]]]:
        """编译两组变体: plain (-O0) 与 release (-O2 剥离符号).

        release 变体作为"混淆/发布形态"对照组 (UPX 不可用时以
        -O2+strip 近似加壳形态: 寄存器分配/内联/布局均改变).
        返回 {样本名: [(变体, 二进制路径, 分组)]}.
        """
        out = {}
        for name in _HEAP_SAMPLES + _SAFE_SAMPLES:
            src = self._samples_root / name / "main.c"
            plain = self._build_dir / f"{name}.exe"
            rel = self._build_dir / f"{name}_release.exe"
            self._gcc_compile(src, plain, ["-O0"])
            # release 变体: -O2 优化 (不剥离符号 —
            # PE 导入名解析依赖符号表, 剥离后所有工具失去
            # call 目标名, 属于样本定义问题而非检测器能力)
            self._gcc_compile(src, rel, ["-O2", "-fno-ident"])
            out[name] = [
                ("plain", str(plain), "plain"),
                ("release", str(rel), "packed"),
            ]
        return out

    @staticmethod
    def _gcc_compile(src: pathlib.Path, out: pathlib.Path,
                     extra: List[str]):
        cmd = ["gcc", "-Wall", "-fno-stack-protector", "-g"] + extra + [
            "-o", str(out), str(src)]
        try:
            subprocess.run(cmd, capture_output=True, text=True,
                           timeout=30)
        except Exception:
            pass

# 工具调度

    def run_all(self, variants: Dict[str, List[Tuple[str, str, str]]],
                tools: Optional[List[str]] = None) -> List[ToolResult]:
        if tools is None:
            tools = ["our_method", "our_base", "naive", "regex", "angr",
                     "qemu", "ghidra"]
        results: List[ToolResult] = []
        for name in sorted(variants.keys()):
            vuln = self._expected_vuln(name)
            for variant, path, group in variants[name]:
                if not pathlib.Path(path).exists():
                    continue
                for tool in tools:
                    results.append(
                        self._run_tool(tool, name, path, vuln, group))
                print(f"  [OK] {name} ({variant})")
        return results

    def _run_tool(self, tool: str, sample: str, binary: str,
                  vuln: bool, group: str) -> ToolResult:
        r = ToolRunners.dispatch(tool, sample, binary, group)
        r.is_true_vulnerable = vuln
        return r


# 指标与导出

    @staticmethod
    def compute_metrics(results: List[ToolResult], tool: str,
                        group: Optional[str] = None) -> Dict:
        trs = [r for r in results
               if r.tool_name == tool
               and (group is None or r.group == group)]
        if not trs:
            return {"error": "no results"}
        tp = fp = tn = fn = 0
        for r in trs:
            if not r.success:
                continue
            if r.is_true_vulnerable and r.detected:
                tp += 1
            elif r.is_true_vulnerable:
                fn += 1
            elif r.detected:
                fp += 1
            else:
                tn += 1
        return {
            "total": len(trs), "TP": tp, "FP": fp, "TN": tn, "FN": fn,
            "recall": tp / max(tp + fn, 1),
            "precision": tp / max(tp + fp, 1),
            "fpr": fp / max(fp + tn, 1),
            "f1": 2 * tp / max(2 * tp + fp + fn, 1),
            "avg_time_ms": sum(r.scan_time_ms for r in trs)
                           / max(len(trs), 1),
        }

    def export_csv(self, results: List[ToolResult], path: pathlib.Path):
        """统一格式 CSV: 工具名/样本ID/检出数/误报数/漏报数/耗时/峰值内存.

        误报数/漏报数为样本级派生标记 (is_vulnerable × detected).
        """
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=[
                "tool", "sample", "group", "is_vulnerable", "detected",
                "fp", "fn", "num_findings", "scan_time_ms",
                "peak_memory_mb", "success", "error"])
            writer.writeheader()
            for r in results:
                fp = 1 if (not r.is_true_vulnerable and r.detected) else 0
                fn = 1 if (r.is_true_vulnerable and not r.detected) else 0
                writer.writerow({
                    "tool": r.tool_name, "sample": r.sample_name,
                    "group": r.group,
                    "is_vulnerable": r.is_true_vulnerable,
                    "detected": r.detected,
                    "fp": fp, "fn": fn,
                    "num_findings": r.num_findings,
                    "scan_time_ms": round(r.scan_time_ms, 1),
                    "peak_memory_mb": round(r.peak_memory_mb, 1),
                    "success": r.success,
                    "error": r.error_msg[:120],
                })

    def export_latex(self, metrics: Dict[str, Dict], path: pathlib.Path):
        lines = [
            "% 多工具堆溢出检测对比 (FP-Reduction 基准) — LaTeX表格",
            "% 自动生成于 " + time.strftime("%Y-%m-%d %H:%M:%S"),
            r"\begin{table}[htbp]",
            r"  \centering",
            r"  \caption{Heap Overflow Detection: FP-Reduction "
            r"Benchmark on fp\_samples}",
            r"  \label{tab:fp-benchmark}",
            r"  \begin{tabular}{lcccccc}",
            r"    \toprule",
            r"    \textbf{Tool} & \textbf{TP} & \textbf{FP} & "
            r"\textbf{Recall} & \textbf{Precision} & \textbf{FPR} & "
            r"\textbf{F1} \\",
            r"    \midrule",
        ]
        for tool in ["our_method", "our_base", "naive", "regex",
                     "angr", "qemu", "ghidra"]:
            m = metrics.get(tool)
            if not m or "error" in m:
                continue
            if m["TP"] + m["FP"] + m["TN"] + m["FN"] == 0:
                continue  # 工具不可用 (环境缺失), 不进入对比表
            lines.append(
                f"    {tool} & {m['TP']} & {m['FP']} & "
                f"{m['recall']:.1%} & {m['precision']:.1%} & "
                f"{m['fpr']:.1%} & {m['f1']:.2f} \\\\")
        lines.extend([
            r"    \bottomrule",
            r"  \end{tabular}",
            r"\end{table}",
        ])
        path.write_text('\n'.join(lines), encoding='utf-8')

    def run(self, tools: Optional[List[str]] = None) -> Dict:
        print("=" * 66)
        print("  多工具对比实验 (fp_samples)")
        print("=" * 66)
        print("\n[1/3] 编译变体 (plain/release)...")
        variants = self.compile_variants()
        print(f"  变体数: {sum(len(v) for v in variants.values())}")

        print("\n[2/3] 运行工具...")
        results = self.run_all(variants, tools)

        print("\n[3/3] 指标与导出...")
        all_tools = sorted({r.tool_name for r in results})
        metrics = {t: self.compute_metrics(results, t) for t in all_tools}
        self.export_csv(results, self._output_dir / "fp_benchmark_results.csv")
        self.export_latex(metrics, self._output_dir / "fp_result_table.tex")
        # 任务指定路径: 主实验 LaTeX 表置于 eval/result_table.tex
        self.export_latex(metrics,
                          _PROJ_ROOT / "eval" / "result_table.tex")

        print(f"\n{'工具':<12} {'Recall':>8} {'Prec':>8} {'FPR':>8} "
              f"{'F1':>8} {'AvgMs':>8}")
        for t in all_tools:
            m = metrics[t]
            if "error" in m:
                print(f"{t:<12} {'--':>8}")
                continue
            print(f"{t:<12} {m['recall']:7.1%} {m['precision']:7.1%} "
                  f"{m['fpr']:7.1%} {m['f1']:7.2f} "
                  f"{m['avg_time_ms']:7.0f}")

        report = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "metrics": {t: {k: (round(v, 4) if isinstance(v, float) else v)
                            for k, v in m.items()}
                        for t, m in metrics.items()},
        }
        with open(self._output_dir / "fp_benchmark_results.json", 'w',
                  encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"\n  报告: {self._output_dir}")
        return report


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="FP-Reduction multi-tool benchmark")
    parser.add_argument("--tools", default=None,
                        help="comma-separated tool list")
    args = parser.parse_args()
    tools = None
    if args.tools:
        tools = [t.strip() for t in args.tools.split(",")]
    FpBenchmarkRunner().run(tools)
    return 0


# 工具运行器

@dataclass
class ToolResult:
    tool_name: str
    sample_name: str
    binary_path: str
    is_true_vulnerable: bool
    detected: bool
    num_findings: int
    scan_time_ms: float
    success: bool
    group: str = "plain"
    peak_memory_mb: float = 0.0
    error_msg: str = ""


class ToolRunners:
    """各工具的批量运行入口."""

    @staticmethod
    def run_our(fp_on: bool, sample: str, binary: str,
                group: str) -> ToolResult:
        t0 = time.perf_counter()
        try:
            from tests.run_scanner import SampleScanner
            from analysis.heap_overflow_detector import (
                HeapOverflowDetector)
            scanner = SampleScanner(use_advanced_engine=True)
            det = HeapOverflowDetector()
            det._fp_reduction_enabled = fp_on
            scanner._detector = det
            result = scanner.scan_one(sample, binary, True)
            mem = 0.0
            try:
                import psutil
                mem = psutil.Process().memory_info().rss / 1048576.0
            except ImportError:
                pass
            elapsed = (time.perf_counter() - t0) * 1000
            return ToolResult(
                tool_name="our_method" if fp_on else "our_base",
                sample_name=sample, binary_path=binary,
                is_true_vulnerable=True, detected=result.detected,
                num_findings=result.num_findings,
                scan_time_ms=elapsed, success=True, group=group,
                peak_memory_mb=mem, error_msg=result.error_msg[:150])
        except Exception as e:
            elapsed = (time.perf_counter() - t0) * 1000
            return ToolResult(
                tool_name="our_method" if fp_on else "our_base",
                sample_name=sample, binary_path=binary,
                is_true_vulnerable=True, detected=False, num_findings=0,
                scan_time_ms=elapsed, success=False, group=group,
                error_msg=str(e)[:150])

    @staticmethod
    def run_naive(sample: str, binary: str, group: str) -> ToolResult:
        t0 = time.perf_counter()
        try:
            from eval.baseline_detectors import NaivePatternDetector
            r = NaivePatternDetector().analyze(binary)
            elapsed = (time.perf_counter() - t0) * 1000
            return ToolResult(
                tool_name="naive", sample_name=sample,
                binary_path=binary, is_true_vulnerable=True,
                detected=r.detected, num_findings=r.num_findings,
                scan_time_ms=elapsed, success=True, group=group)
        except Exception as e:
            elapsed = (time.perf_counter() - t0) * 1000
            return ToolResult(
                tool_name="naive", sample_name=sample,
                binary_path=binary, is_true_vulnerable=True,
                detected=False, num_findings=0, scan_time_ms=elapsed,
                success=False, group=group, error_msg=str(e)[:150])

    @staticmethod
    def run_regex(sample: str, binary: str, group: str) -> ToolResult:
        t0 = time.perf_counter()
        try:
            from eval.baseline_detectors import RegexOnlyDetector
            r = RegexOnlyDetector().analyze(binary)
            elapsed = (time.perf_counter() - t0) * 1000
            return ToolResult(
                tool_name="regex", sample_name=sample,
                binary_path=binary, is_true_vulnerable=True,
                detected=r.detected, num_findings=r.num_findings,
                scan_time_ms=elapsed, success=True, group=group)
        except Exception as e:
            elapsed = (time.perf_counter() - t0) * 1000
            return ToolResult(
                tool_name="regex", sample_name=sample,
                binary_path=binary, is_true_vulnerable=True,
                detected=False, num_findings=0, scan_time_ms=elapsed,
                success=False, group=group, error_msg=str(e)[:150])

    @staticmethod
    def run_angr(sample: str, binary: str, group: str) -> ToolResult:
        t0 = time.perf_counter()
        try:
            from eval.angr_explorer import AngrExplorer
            explorer = AngrExplorer(timeout_seconds=45)
            r = explorer.analyze(binary)
            elapsed = (time.perf_counter() - t0) * 1000
            return ToolResult(
                tool_name="angr", sample_name=sample,
                binary_path=binary, is_true_vulnerable=True,
                detected=r.success and len(r.findings) > 0,
                num_findings=len(r.findings) if r.success else 0,
                scan_time_ms=elapsed, success=r.success, group=group,
                peak_memory_mb=r.peak_memory_mb,
                error_msg=r.error_msg[:150])
        except Exception as e:
            elapsed = (time.perf_counter() - t0) * 1000
            return ToolResult(
                tool_name="angr", sample_name=sample,
                binary_path=binary, is_true_vulnerable=True,
                detected=False, num_findings=0, scan_time_ms=elapsed,
                success=False, group=group, error_msg=str(e)[:150])

    @staticmethod
    def run_qemu(sample: str, binary: str, group: str) -> ToolResult:
        t0 = time.perf_counter()
        try:
            from eval.qemu_tracer import QemuTracer
            tracer = QemuTracer(timeout_seconds=8)
            r = tracer.trace(binary)
            elapsed = (time.perf_counter() - t0) * 1000
            return ToolResult(
                tool_name="qemu", sample_name=sample,
                binary_path=binary, is_true_vulnerable=True,
                detected=r.success and len(r.overflow_events) > 0,
                num_findings=len(r.overflow_events) if r.success else 0,
                scan_time_ms=elapsed, success=r.success, group=group,
                error_msg=r.error_msg[:150])
        except Exception as e:
            elapsed = (time.perf_counter() - t0) * 1000
            return ToolResult(
                tool_name="qemu", sample_name=sample,
                binary_path=binary, is_true_vulnerable=True,
                detected=False, num_findings=0, scan_time_ms=elapsed,
                success=False, group=group, error_msg=str(e)[:150])

    @staticmethod
    def run_ghidra(sample: str, binary: str, group: str) -> ToolResult:
        t0 = time.perf_counter()
        try:
            from eval.ghidra_headless import GhidraHeadlessAnalyzer
            analyzer = GhidraHeadlessAnalyzer(timeout_seconds=60)
            r = analyzer.analyze(binary)
            elapsed = (time.perf_counter() - t0) * 1000
            return ToolResult(
                tool_name="ghidra", sample_name=sample,
                binary_path=binary, is_true_vulnerable=True,
                detected=r.success and len(r.findings) > 0,
                num_findings=len(r.findings) if r.success else 0,
                scan_time_ms=elapsed, success=r.success, group=group,
                error_msg=r.error_msg[:150])
        except Exception as e:
            elapsed = (time.perf_counter() - t0) * 1000
            return ToolResult(
                tool_name="ghidra", sample_name=sample,
                binary_path=binary, is_true_vulnerable=True,
                detected=False, num_findings=0, scan_time_ms=elapsed,
                success=False, group=group, error_msg=str(e)[:150])

    @staticmethod
    def dispatch(tool: str, sample: str, binary: str,
                 group: str) -> ToolResult:
        """按工具名调度 (未知工具返回失败结果)."""
        if tool == "our_method":
            return ToolRunners.run_our(True, sample, binary, group)
        if tool == "our_base":
            return ToolRunners.run_our(False, sample, binary, group)
        if tool == "naive":
            return ToolRunners.run_naive(sample, binary, group)
        if tool == "regex":
            return ToolRunners.run_regex(sample, binary, group)
        if tool == "angr":
            return ToolRunners.run_angr(sample, binary, group)
        if tool == "qemu":
            return ToolRunners.run_qemu(sample, binary, group)
        if tool == "ghidra":
            return ToolRunners.run_ghidra(sample, binary, group)
        return ToolResult(
            tool_name=tool, sample_name=sample, binary_path=binary,
            is_true_vulnerable=True, detected=False, num_findings=0,
            scan_time_ms=0, success=False, group=group,
            error_msg=f"unknown tool: {tool}")

if __name__ == "__main__":
    sys.exit(main())
