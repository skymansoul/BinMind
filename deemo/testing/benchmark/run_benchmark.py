# 对比实验主启动脚本 - 喂样本→跑四工具→收集指标。
# 用法: python -m testing.benchmark.run_benchmark --samples <dir> [--timeout N]

import json, os, sys, time
from .collect_metrics import collect_all_metrics, generate_latex_table

# plot_results 位于 scripts/ 下, 此处按相对包名导入失败时降级为提示,
# 不影响本模块其余功能 (图表生成由 scripts/plot_results.py 单独完成)
try:
    from .plot_results import generate_plots
except ImportError:
    def generate_plots(report, output_dir):
        print(f"  [WARN] 未找到 testing.benchmark.plot_results, 图表生成跳过 "
              f"(可使用 scripts/plot_results.py 输出相同图表)")

MULTI_TOOL = False  # angr/QEMU/Ghidra 需单独安装, 默认只跑本工具


def main(samples_dir: str, timeout_sec: int = 120):
    print("=" * 60)
    print("BinMind 横向对比实验")
    print("=" * 60)

    if not os.path.isdir(samples_dir):
        print(f"样本目录不存在: {samples_dir}")
        return

    # 收集本工具指标
    print("\n[1/3] 本工具扫描...")
    from ..regression.compile_samples import compile_all
    from ..regression.scan_runner import run_scan

    binaries = compile_all(samples_dir)
    our_results = []
    for name, info in binaries.items():
        if isinstance(info, dict) and info.get("success") and info.get("binary_path"):
            sr = run_scan(info["binary_path"], name, timeout_sec)
            our_results.append(sr)

    # 外部工具 (条件性)
    angr_results = run_angr_if_available(binaries, timeout_sec)
    qemu_results = run_qemu_if_available(binaries, timeout_sec)
    ghidra_results = run_ghidra_if_available(binaries, timeout_sec)

    # 汇总指标
    print("\n[2/3] 汇总指标...")
    report = collect_all_metrics(
        our_results, angr_results, qemu_results, ghidra_results)
    print(f"  本工具: {report['our']['avg_time_sec']:.1f}s/sample, "
          f"检出 {report['our']['detections']}/{report['our']['total']}")
    if angr_results:
        print(f"  Angr:   {report['angr']['avg_time_sec']:.1f}s/sample, "
              f"检出 {report['angr']['detections']}/{report['angr']['total']}")

    # 生成产出
    print("\n[3/3] 生成表格和图表...")
    report_path = os.path.join(os.path.dirname(__file__), "benchmark_report.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    latex = generate_latex_table(report)
    latex_path = os.path.join(os.path.dirname(__file__), "table_template.tex")
    with open(latex_path, "w") as f:
        f.write(latex)

    generate_plots(report, os.path.dirname(__file__))

    print(f"\n产出文件:")
    print(f"  数据: {report_path}")
    print(f"  LaTeX表格: {latex_path}")
    print(f"  图表: {os.path.dirname(__file__)}/benchmark_*.png")


def run_angr_if_available(binaries, timeout):
    try:
        from testing.benchmark.angr_runner import run_angr_scan
        return run_angr_scan(binaries, timeout)
    except ImportError:
        return None

def run_qemu_if_available(binaries, timeout):
    try:
        from testing.benchmark.qemu_runner import run_qemu_scan
        return run_qemu_scan(binaries, timeout)
    except ImportError:
        return None

def run_ghidra_if_available(binaries, timeout):
    try:
        from testing.benchmark.ghidra_runner import run_ghidra_scan
        return run_ghidra_scan(binaries, timeout)
    except ImportError:
        return None


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples", default="../regression/samples")
    ap.add_argument("--timeout", type=int, default=120)
    args = ap.parse_args()
    main(args.samples, args.timeout)
