# 对比实验启动脚本 — 一键: 编译→多引擎扫描→汇总→表格+图
#
# 使用: python experiment_launcher.py [--skip-compile] [--engines internal,angr]
# 输出: results/summary.json + comparison_table.tex + comparison_bar.png

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).parent
RESULTS = HERE / "results"
RESULTS.mkdir(exist_ok=True)


def load_config() -> dict:
    cfg_path = HERE / "experiment_config.json"
    if cfg_path.exists():
        with open(cfg_path) as f:
            return json.load(f)
    return {
        "engines": ["internal", "angr", "ghidra", "qemu"],
        "timeout_per_sample_s": 120,
        "samples_dir": str(HERE / "samples"),
    }


def compile_samples() -> bool:
    print("[1/4] Compiling...")
    r = subprocess.run(
        [sys.executable, str(HERE / "compile_samples.py")],
        timeout=300,
    )
    return r.returncode == 0


def scan_with_all_engines(config: dict) -> dict:
    print("[2/4] Scanning...")
    all_results: dict[str, list] = {}
    samples_dir = Path(config.get("samples_dir", str(HERE / "samples")))
    timeout = config.get("timeout_per_sample_s", 120)

    binaries = []
    for d in sorted(samples_dir.iterdir()):
        if not d.is_dir():
            continue
        for pattern in ["vuln", "vuln_o0", "vuln_o2"]:
            p = d / pattern
            if p.exists() and os.access(str(p), os.X_OK):
                binaries.append((d.name, str(p)))
                break

    for engine in config.get("engines", ["internal"]):
        print(f"  Engine: {engine}")
        engine_results = []
        for name, path in binaries:
            t0 = time.perf_counter()
            if engine == "internal":
                findings = _scan_internal(path)
            elif engine == "angr":
                findings = _scan_angr(path, timeout)
            elif engine == "ghidra":
                findings = _scan_ghidra(path, timeout)
            elif engine == "qemu":
                findings = _scan_qemu(path, timeout)
            else:
                findings = []
            elapsed = time.perf_counter() - t0
            engine_results.append({
                "sample": name, "binary": path,
                "findings": findings, "time": round(elapsed, 2),
                "success": True,
            })
        all_results[engine] = engine_results

    return all_results


def _scan_internal(path: str) -> list:
    try:
        from core.vuln_analyzer import analyze_all
        return analyze_all(path)
    except Exception:
        return []


def _scan_angr(path: str, timeout: int) -> list:
    try:
        from tests.regression.scan_runner import scan_with_angr
        r = scan_with_angr(Path(path), timeout_s=timeout)
        return r.get("findings", [])
    except Exception:
        return []


def _scan_ghidra(path: str, timeout: int) -> list:
    try:
        from tests.regression.scan_runner import scan_with_ghidra
        r = scan_with_ghidra(Path(path), timeout_s=timeout)
        return r.get("findings", [])
    except Exception:
        return []


def _scan_qemu(path: str, timeout: int) -> list:
    try:
        from tests.regression.scan_runner import scan_with_qemu
        r = scan_with_qemu(Path(path), timeout_s=timeout)
        return r.get("findings", [])
    except Exception:
        return []


def compute_summary(all_results: dict) -> dict:
    print("[3/4] Computing summary...")
    gt_path = HERE / "ground_truth.json"
    gt = {}
    if gt_path.exists():
        with open(gt_path) as f:
            gt = json.load(f)

    summary = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_samples": len(gt),
        "engines": {},
    }
    for engine, results in all_results.items():
        tp = fp = fn = 0
        total_time = 0.0
        n = len(results)
        for r in results:
            name = r["sample"]
            expected = gt.get(name, [])
            total_time += r.get("time", 0)
            ftypes = set()
            for f in r.get("findings", []):
                ftypes.add(str(f.get("type", "")))
            hit = any(
                any(exp.lower() in ft.lower() for ft in ftypes)
                for exp in expected
            )
            if hit:
                tp += 1
            elif ftypes:
                fp += 1
            if not hit and expected:
                fn += 1

        denom = max(1, tp + fn)
        summary["engines"][engine] = {
            "tp": tp, "fp": fp, "fn": fn,
            "detection_rate": round(tp / denom, 3),
            "fp_rate": round(fp / max(1, tp + fp), 3),
            "avg_time_s": round(total_time / max(1, n), 1),
            "samples_scanned": n,
        }

    with open(RESULTS / "summary.json", "w") as f:
        json.dump(summary, f, indent=2)
    return summary


def generate_outputs(summary: dict) -> None:
    print("[4/4] Generating outputs...")

    # LaTeX table
    engines = summary.get("engines", {})
    tex = [
        r"\begin{table}[ht]", r"\centering",
        r"\caption{Cross-tool vulnerability detection comparison}",
        r"\label{tab:comparison}",
        r"\begin{tabular}{lcccc}",
        r"\toprule",
        r"Tool & Det. Rate & FP Rate & Avg Time(s) & Samples \\",
        r"\midrule",
    ]
    for name, m in engines.items():
        tex.append(
            f"{name} & {m['detection_rate']:.2f} & {m['fp_rate']:.2f} & "
            f"{m['avg_time_s']:.1f} & {m['samples_scanned']} \\\\"
        )
    tex.extend([r"\bottomrule", r"\end{tabular}", r"\end{table}"])
    (RESULTS / "comparison_table.tex").write_text("\n".join(tex))

    # Bar chart
    try:
        from tests.regression.plot_results import plot_comparison
        plot_comparison(summary, str(RESULTS / "comparison_bar.png"))
    except ImportError:
        print("  matplotlib not available, skipping plot")

    print(f"  Outputs: {RESULTS}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-compile", action="store_true")
    parser.add_argument("--engines", default="internal,angr")
    args = parser.parse_args()

    config = load_config()
    if args.engines:
        config["engines"] = [e.strip() for e in args.engines.split(",")]

    t0 = time.time()

    if not args.skip_compile:
        compile_samples()

    all_results = scan_with_all_engines(config)
    summary = compute_summary(all_results)
    generate_outputs(summary)

    print(f"\nDone. Total: {time.time() - t0:.1f}s")
    for eng, m in summary["engines"].items():
        print(f"  {eng}: det={m['detection_rate']:.2f} "
              f"fp={m['fp_rate']:.2f} "
              f"tp={m['tp']} fp={m['fp']} fn={m['fn']}")


if __name__ == "__main__":
    main()
