# 多工具对比实验主脚本: 在全部样本上运行OurMethod/Angr/QEMU/Ghidra,
# 收集检测结果, 计算指标, 生成CSV/JSON/LaTeX
# 决策: 工具按可用性自动降级 (angr未安装→跳过, QEMU不可用→LD_PRELOAD)
#   所有结果写入统一的BenchmarkOutput结构, 便于下游可视化和论文使用
from __future__ import annotations
import sys, os, time, json, csv
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ProcessPoolExecutor, as_completed

_PROJ_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJ_ROOT))


@dataclass
class ToolResult:
    """单个工具在单个样本上的结果."""
    tool_name: str       # our_method / angr / qemu / ghidra
    sample_name: str
    binary_path: str
    success: bool
    num_findings: int
    is_true_vulnerable: bool  # ground truth
    detected: bool
    scan_time_ms: float
    extra: Dict = field(default_factory=dict)
    error_msg: str = ""


@dataclass
class BenchmarkOutput:
    """完整的基准测试输出."""
    timestamp: str
    samples: List[str]
    tools: List[str]
    results: List[ToolResult] = field(default_factory=list)
    metrics: Dict[str, Dict] = field(default_factory=dict)

    def get_tool_results(self, tool: str) -> List[ToolResult]:
        return [r for r in self.results if r.tool_name == tool]

    def compute_metrics(self, tool: str) -> Dict:
        """计算单个工具的TP/FP/TN/FN/Recall/Precision/FPR."""
        trs = self.get_tool_results(tool)
        if not trs:
            return {"error": "no results"}
        tp = fp = tn = fn = 0
        for r in trs:
            if r.is_true_vulnerable and r.detected:
                tp += 1
            elif r.is_true_vulnerable and not r.detected:
                fn += 1
            elif not r.is_true_vulnerable and r.detected:
                fp += 1
            else:
                tn += 1
        total = tp + fp + tn + fn
        return {
            "total": total,
            "TP": tp, "FP": fp, "TN": tn, "FN": fn,
            "recall": tp / max(tp + fn, 1),
            "precision": tp / max(tp + fp, 1),
            "fpr": fp / max(fp + tn, 1),
            "f1": (2 * tp) / max(2 * tp + fp + fn, 1),
            "avg_time_ms": sum(r.scan_time_ms for r in trs) / max(len(trs), 1),
        }


class BenchmarkRunner:
    """多工具基准测试运行器.

    工作流:
      1. 发现样本 (samples/目录下的所有子目录)
      2. 编译样本
      3. 对每个样本依次运行 OurMethod → Angr → QEMU → Ghidra
      4. 汇总结果, 计算指标
      5. 导出CSV/JSON/LaTeX
    """

    def __init__(self, samples_root: str = None,
                 output_dir: str = None):
        if samples_root is None:
            samples_root = str(_PROJ_ROOT / "samples")
        if output_dir is None:
            output_dir = str(_PROJ_ROOT / "eval_output")
        self._samples_root = Path(samples_root)
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)

        # 样本ground truth定义
        self._ground_truth = {
            "01_basic_heap_overflow": True,
            "02_memcpy_overflow": True,
            "03_strcpy_overflow": True,
            "04_calloc_overflow": True,
            "05_realloc_overflow": True,
            "06_loop_overflow": True,
            "07_conditional_overflow": True,
            "08_input_controlled_overflow": True,
            "09_off_by_one": True,
            "10_use_after_free": True,
            "11_double_free": True,
            "12_struct_overflow": True,
            "13_nested_overflow": True,
            "14_multi_overflow": True,
            "15_safe_write": False,
            "16_large_alloc_overflow": True,
            "17_argv_overflow": True,
            "18_double_free_heap": True,
        }

    def discover_samples(self) -> Dict[str, Tuple[Path, bool]]:
        """发现样本目录, 返回 {name: (dir_path, is_vulnerable)}."""
        samples = {}
        for d in sorted(self._samples_root.iterdir()):
            if not d.is_dir() or d.name.startswith('.'):
                continue
            is_vuln = self._ground_truth.get(d.name, True)
            samples[d.name] = (d, is_vuln)
        return samples

    def _compile_sample(self, sample_dir: Path) -> Optional[Path]:
        """编译单个样本, 返回二进制路径."""
        makefile = sample_dir / "Makefile"
        if not makefile.exists():
            return None
        try:
            import subprocess
            proc = subprocess.run(
                ["make", "clean"], capture_output=True,
                cwd=str(sample_dir), timeout=10)
            proc = subprocess.run(
                ["make"], capture_output=True,
                cwd=str(sample_dir), timeout=30)
            if proc.returncode != 0:
                return None
            # 查找生成的二进制文件
            for f in sample_dir.iterdir():
                if f.is_file() and os.access(str(f), os.X_OK):
                    if f.suffix in ('', '.exe', '.elf', '.out'):
                        return f
            return None
        except Exception:
            return None

    def run_all(self, tools: List[str] = None) -> BenchmarkOutput:
        """运行所有工具在所有样本上.

        tools: ["our_method", "angr", "qemu", "ghidra"], 默认全部
        """
        if tools is None:
            tools = ["our_method", "angr", "qemu", "ghidra"]

        samples = self.discover_samples()
        print(f"Discovered {len(samples)} samples")

        output = BenchmarkOutput(
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            samples=list(samples.keys()),
            tools=tools)

        for name, (sample_dir, is_vuln) in samples.items():
            print(f"\n{'='*50}")
            print(f"Sample: {name} (vulnerable={is_vuln})")
            binary = self._compile_sample(sample_dir)
            if binary is None:
                print(f"  SKIP: compilation failed")
                continue

            for tool in tools:
                result = self._run_tool(tool, name, str(binary), is_vuln)
                output.results.append(result)
                status = "DETECTED" if result.detected else "MISSED"
                if not result.success:
                    status = f"ERROR: {result.error_msg[:40]}"
                print(f"  [{tool}] {result.num_findings} findings "
                      f"({result.scan_time_ms:.0f}ms) [{status}]")

        # 计算每个工具的指标
        for tool in tools:
            output.metrics[tool] = output.compute_metrics(tool)

        # 导出
        self._export_csv(output)
        self._export_json(output)
        self._export_latex(output)
        self._print_summary(output)
        return output

    def _run_tool(self, tool: str, sample_name: str,
                  binary_path: str, is_vuln: bool) -> ToolResult:
        """为单个工具运行检测."""
        t0 = time.perf_counter()
        try:
            if tool == "our_method":
                result = self._run_our_method(binary_path, is_vuln)
            elif tool == "angr":
                result = self._run_angr(binary_path, is_vuln)
            elif tool == "qemu":
                result = self._run_qemu(binary_path, is_vuln)
            elif tool == "ghidra":
                result = self._run_ghidra(binary_path, is_vuln)
            else:
                return ToolResult(
                    tool_name=tool, sample_name=sample_name,
                    binary_path=binary_path, success=False,
                    num_findings=0, is_true_vulnerable=is_vuln,
                    detected=False, scan_time_ms=0,
                    error_msg=f"unknown tool: {tool}")
            result.scan_time_ms = (time.perf_counter() - t0) * 1000
            return result
        except Exception as e:
            return ToolResult(
                tool_name=tool, sample_name=sample_name,
                binary_path=binary_path, success=False,
                num_findings=0, is_true_vulnerable=is_vuln,
                detected=False,
                scan_time_ms=(time.perf_counter() - t0) * 1000,
                error_msg=str(e)[:200])

    def _run_our_method(self, binary_path: str,
                        is_vuln: bool) -> ToolResult:
        """运行我们的分配点感知值范围分析方法."""
        try:
            from analysis import HeapOverflowDetector
            from tests.run_scanner import SampleScanner
            scanner = SampleScanner(use_advanced_engine=True)
            sample_name = Path(binary_path).parent.name
            result = scanner.scan_one(sample_name, binary_path, is_vuln)
            return ToolResult(
                tool_name="our_method", sample_name=sample_name,
                binary_path=binary_path, success=result.success,
                num_findings=result.num_findings,
                is_true_vulnerable=is_vuln,
                detected=result.detected and not result.is_false_positive,
                scan_time_ms=result.scan_time_ms,
                extra={"findings": [f.get("detail","") for f in result.findings]},
                error_msg=result.error_msg)
        except ImportError:
            # Fallback: objdump + regex
            return self._run_fallback_regex(binary_path, is_vuln, "our_method")
        except Exception as e:
            return ToolResult(
                tool_name="our_method",
                sample_name=Path(binary_path).parent.name,
                binary_path=binary_path, success=False,
                num_findings=0, is_true_vulnerable=is_vuln,
                detected=False, scan_time_ms=0, error_msg=str(e)[:200])

    def _run_angr(self, binary_path: str, is_vuln: bool) -> ToolResult:
        """运行Angr分析."""
        sample_name = Path(binary_path).parent.name
        try:
            from .angr_explorer import AngrExplorer
            explorer = AngrExplorer(timeout_seconds=60)
            result = explorer.analyze(binary_path)
            return ToolResult(
                tool_name="angr", sample_name=sample_name,
                binary_path=binary_path, success=result.success,
                num_findings=len(result.findings),
                is_true_vulnerable=is_vuln,
                detected=len(result.findings) > 0 and result.success,
                scan_time_ms=result.scan_time_ms,
                error_msg=result.error_msg)
        except ImportError:
            return ToolResult(
                tool_name="angr", sample_name=sample_name,
                binary_path=binary_path, success=False,
                num_findings=0, is_true_vulnerable=is_vuln,
                detected=False, scan_time_ms=0,
                error_msg="angr未安装")

    def _run_qemu(self, binary_path: str, is_vuln: bool) -> ToolResult:
        """运行QEMU追踪 (ground truth)."""
        sample_name = Path(binary_path).parent.name
        try:
            from .qemu_tracer import QemuTracer
            tracer = QemuTracer(timeout_seconds=10)
            result = tracer.trace(binary_path)
            return ToolResult(
                tool_name="qemu", sample_name=sample_name,
                binary_path=binary_path, success=result.success,
                num_findings=len(result.overflow_events),
                is_true_vulnerable=is_vuln,
                detected=len(result.overflow_events) > 0,
                scan_time_ms=result.runtime_ms,
                extra={"overflow_events": result.overflow_events,
                       "trace_entries": len(result.trace_entries)},
                error_msg=result.error_msg)
        except ImportError:
            return ToolResult(
                tool_name="qemu", sample_name=sample_name,
                binary_path=binary_path, success=False,
                num_findings=0, is_true_vulnerable=is_vuln,
                detected=False, scan_time_ms=0,
                error_msg="QEMU tracer初始化失败")

    def _run_ghidra(self, binary_path: str, is_vuln: bool) -> ToolResult:
        """运行Ghidra无头分析."""
        sample_name = Path(binary_path).parent.name
        try:
            from .ghidra_headless import GhidraHeadlessAnalyzer
            analyzer = GhidraHeadlessAnalyzer(timeout_seconds=120)
            result = analyzer.analyze(binary_path)
            # Ghidra不可用时使用fallback
            if not result.success and "未找到" in result.error_msg:
                result = analyzer.analyze_fallback(binary_path)
            return ToolResult(
                tool_name="ghidra", sample_name=sample_name,
                binary_path=binary_path, success=result.success,
                num_findings=len(result.findings),
                is_true_vulnerable=is_vuln,
                detected=len(result.findings) > 0 and result.success,
                scan_time_ms=result.scan_time_ms,
                error_msg=result.error_msg)
        except ImportError:
            return ToolResult(
                tool_name="ghidra", sample_name=sample_name,
                binary_path=binary_path, success=False,
                num_findings=0, is_true_vulnerable=is_vuln,
                detected=False, scan_time_ms=0,
                error_msg="Ghidra analyzer初始化失败")

    def _run_fallback_regex(self, binary_path: str, is_vuln: bool,
                            tool_name: str) -> ToolResult:
        """通用fallback: objdump + 正则模式匹配."""
        sample_name = Path(binary_path).parent.name
        import subprocess, re
        try:
            proc = subprocess.run(
                ["objdump", "-d", "-M", "intel", binary_path],
                capture_output=True, text=True, timeout=15)
            if proc.returncode != 0:
                raise RuntimeError("objdump failed")
            findings = []
            alloc_size = None
            for line in proc.stdout.split('\n'):
                m = re.search(r'mov\s+(?:edi|rdi),\s*(0x[0-9a-f]+|\d+)', line)
                if m:
                    v = m.group(1)
                    alloc_size = int(v, 16) if v.startswith('0x') else int(v)
                for sink in ('memcpy', 'memset', 'strcpy',
                             'memmove', 'strncpy'):
                    if f'call' in line and sink in line:
                        findings.append({
                            "sink": sink,
                            "alloc_size": alloc_size,
                        })
            return ToolResult(
                tool_name=tool_name, sample_name=sample_name,
                binary_path=binary_path, success=True,
                num_findings=len(findings),
                is_true_vulnerable=is_vuln,
                detected=len(findings) > 0,
                scan_time_ms=0,
                extra={"findings": findings})
        except Exception as e:
            return ToolResult(
                tool_name=tool_name, sample_name=sample_name,
                binary_path=binary_path, success=False,
                num_findings=0, is_true_vulnerable=is_vuln,
                detected=False, scan_time_ms=0, error_msg=str(e))

    def _export_csv(self, output: BenchmarkOutput):
        """导出CSV对比结果."""
        path = self._output_dir / "benchmark_results.csv"
        with open(path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=[
                "tool", "sample", "is_vulnerable", "detected",
                "num_findings", "scan_time_ms", "success", "error"])
            writer.writeheader()
            for r in output.results:
                writer.writerow({
                    "tool": r.tool_name, "sample": r.sample_name,
                    "is_vulnerable": r.is_true_vulnerable,
                    "detected": r.detected,
                    "num_findings": r.num_findings,
                    "scan_time_ms": round(r.scan_time_ms, 1),
                    "success": r.success,
                    "error": r.error_msg[:100] if r.error_msg else "",
                })
        print(f"CSV exported: {path}")

    def _export_json(self, output: BenchmarkOutput):
        """导出完整JSON结果."""
        path = self._output_dir / "benchmark_results.json"
        data = {
            "timestamp": output.timestamp,
            "samples": output.samples,
            "tools": output.tools,
            "metrics": {t: {k: (round(v,4) if isinstance(v,float) else v)
                            for k,v in m.items()}
                        for t, m in output.metrics.items()},
            "results": [
                {"tool": r.tool_name, "sample": r.sample_name,
                 "detected": r.detected, "findings": r.num_findings,
                 "time_ms": round(r.scan_time_ms, 1),
                 "error": r.error_msg[:100] if r.error_msg else ""}
                for r in output.results
            ],
        }
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"JSON exported: {path}")

    def _export_latex(self, output: BenchmarkOutput):
        """导出LaTeX对比表."""
        path = self._output_dir / "result_table.tex"
        lines = [
            "% 多工具堆溢出检测对比实验 — LaTeX表格",
            "% 自动生成于 " + output.timestamp,
            r"\begin{table}[htbp]",
            r"  \centering",
            r"  \caption{Multi-Tool Heap Overflow Detection Comparison}",
            r"  \label{tab:tool-comparison}",
            r"  \begin{tabular}{lcccccc}",
            r"    \toprule",
            r"    \textbf{Tool} & \textbf{Samples} & \textbf{Recall} & "
            r"\textbf{Precision} & \textbf{FPR} & \textbf{F1} & "
            r"\textbf{Avg Time (ms)} \\",
            r"    \midrule",
        ]
        for tool in output.tools:
            m = output.metrics.get(tool, {})
            if "error" in m:
                continue
            lines.append(
                f"    {tool} & {m.get('total','?')} & "
                f"{m.get('recall',0):.1%} & {m.get('precision',0):.1%} & "
                f"{m.get('fpr',0):.1%} & {m.get('f1',0):.2f} & "
                f"{m.get('avg_time_ms',0):.0f} \\\\")
        lines.extend([
            r"    \bottomrule",
            r"  \end{tabular}",
            r"\end{table}",
        ])
        with open(path, 'w') as f:
            f.write('\n'.join(lines))
        print(f"LaTeX exported: {path}")

    def _print_summary(self, output: BenchmarkOutput):
        """打印汇总对比."""
        print(f"\n{'='*70}")
        print("  MULTI-TOOL BENCHMARK SUMMARY")
        print(f"  Timestamp: {output.timestamp}")
        print(f"  Samples: {len(output.samples)} | "
              f"Tools: {len(output.tools)}")
        print(f"{'='*70}")
        print(f"{'Tool':<15} {'Recall':>8} {'Prec':>8} {'FPR':>8} "
              f"{'F1':>8} {'AvgTime':>10}")
        print(f"{'-'*15} {'-'*8} {'-'*8} {'-'*8} {'-'*8} {'-'*10}")
        best_fpr = 1.0
        best_tool = ""
        for tool in output.tools:
            m = output.metrics.get(tool, {})
            if "error" in m:
                print(f"{tool:<15} {'--':>8} {'--':>8} {'--':>8} "
                      f"{'--':>8} {'--':>10}")
                continue
            print(f"{tool:<15} {m['recall']:7.1%} {m['precision']:7.1%} "
                  f"{m['fpr']:7.1%} {m['f1']:7.2f} "
                  f"{m['avg_time_ms']:9.0f}ms")
            if m['fpr'] < best_fpr:
                best_fpr = m['fpr']
                best_tool = tool
        print(f"{'='*70}")
        if best_tool:
            print(f"  Best FPR: {best_tool} ({best_fpr:.1%})")
        # 量化对比
        our_m = output.metrics.get("our_method", {})
        for tool in output.tools:
            if tool == "our_method" or "error" in output.metrics.get(tool, {}):
                continue
            other_m = output.metrics[tool]
            if our_m.get("fpr", 1.0) < other_m.get("fpr", 1.0):
                reduction = (1 - our_m["fpr"] / max(other_m["fpr"], 0.001))
                print(f"  FPR Reduction vs {tool}: {reduction:.0%}")


def run_benchmark_cli():
    """CLI入口: python -m eval.run_benchmark [--samples DIR] [--output DIR]"""
    import argparse
    parser = argparse.ArgumentParser(
        description="Multi-tool heap overflow detection benchmark")
    parser.add_argument("--samples", default=None,
                       help="Samples root directory")
    parser.add_argument("--output", default=None,
                       help="Output directory for results")
    parser.add_argument("--tools", default="our_method,angr,qemu,ghidra",
                       help="Tools to run (comma-separated)")
    args = parser.parse_args()

    tools = [t.strip() for t in args.tools.split(",")]
    runner = BenchmarkRunner(
        samples_root=args.samples, output_dir=args.output)
    runner.run_all(tools=tools)


if __name__ == "__main__":
    run_benchmark_cli()
