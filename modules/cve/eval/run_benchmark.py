# 多工具对比主实验 - 统一 CSV 基准测试.
#
# 决策逻辑:
#   对 regression/build 下全部编译产物运行四类工具:
#     BinMind-PcWBI   (本工作, 含来源约束写界推断)
#     BinMind-Baseline(同管线, 关闭 PcWBI)
#     angr            (CFG 探索器)
#     qemu-user       (动态 ground truth, PE 不支持时跳过)
#     ghidra-headless (通用反编译审计, 未配置时跳过)
#   输出 eval/results/benchmark.csv 与 benchmark.json,
#   含: 工具名、样本ID、优化档、加壳组、检出数、误报数、漏报数、
#       耗时、峰值内存.
#

import csv
import json
import os
import sys
import time
from pathlib import Path
from typing import List

ROOT = Path(__file__).resolve().parent
REGRESSION = ROOT.parent / "regression"
BUILD = REGRESSION / "build"
RESULTS_DIR = ROOT / "results"


def _ensure_paths():
    deemo = ROOT.parent.parent.parent
    for p in (str(deemo), str(deemo.parent), str(ROOT.parent)):
        if p not in sys.path:
            sys.path.insert(0, p)
    import shutil
    for d in (deemo / "modules" / "analysis" / "static",
              ROOT.parent / "heapdet", ROOT.parent / "regression"):
        cache = d / "__pycache__"
        if cache.exists():
            shutil.rmtree(cache, ignore_errors=True)


def _peak_mem_mb() -> float:
    """读取当前进程峰值内存 (Linux rusage / Windows psutil)."""
    # FIXME: ru_maxrss 为 Linux 语义 (KB), Windows 峰值内存取的是
    # 当前工作集快照而非真实峰值, 跨平台数值不可直接对比.
    try:
        import resource
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0
    except Exception:
        pass
    try:
        import psutil
        return psutil.Process().memory_info().peak_wset / (1024 * 1024)
    except Exception:
        return 0.0


class BenchmarkRow:
    def __init__(self, tool, sample, opt, group, gt, detected,
                 confirmed, time_ms, mem_mb, error="", available=True):
        self.tool = tool
        self.sample = sample
        self.opt = opt
        self.group = group
        self.gt = gt
        self.detected = detected
        self.confirmed = confirmed
        self.time_ms = time_ms
        self.mem_mb = mem_mb
        self.error = error
        self.available = available
        self.verdict = self._classify()

    def _classify(self) -> str:
        # 工具不可用 (未安装/格式不支持) 时不参与混淆统计.
        if not self.available:
            return "NA"
        if self.gt == "vulnerable":
            return "TP" if self.detected else "FN"
        return "FP" if self.detected else "TN"

    def to_csv(self):
        return [self.tool, self.sample, self.opt, self.group, self.gt,
                "Y" if self.detected else "N", self.confirmed,
                "1" if self.verdict == "FP" else "0",
                "1" if self.verdict == "FN" else "0",
                round(self.time_ms, 2), round(self.mem_mb, 2), self.error]


def run_binmind(binary, use_pcwbi: bool):
    from heapdet.scan import scan_binary
    t0 = time.perf_counter()
    m0 = _peak_mem_mb()
    report = scan_binary(binary, use_pcwbi=use_pcwbi)
    elapsed = (time.perf_counter() - t0) * 1000
    mem = _peak_mem_mb() - m0
    return report, elapsed, mem


def collect_binaries() -> List[dict]:
    """收集全部编译产物: [(binary, sample, opt, group, gt)]."""
    manifest_path = BUILD / "manifest_build.json"
    if not manifest_path.exists():
        print(f"build manifest not found: {manifest_path}. "
              "Run regression/compile_samples.py first.")
        return []
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    items = []
    for sample in manifest:
        gt = sample["ground_truth"]
        for opt in ("O0", "O2"):
            rec = sample.get(f"compiled_{opt}", {})
            binary = rec.get("binary", "")
            if rec.get("compiled") and os.path.exists(binary):
                items.append({"binary": binary, "sample": sample["sample_id"],
                              "opt": opt, "group": "unpacked", "gt": gt})
            pbin = rec.get("packed_binary", "")
            if pbin and os.path.exists(pbin):
                items.append({"binary": pbin, "sample": sample["sample_id"],
                              "opt": opt, "group": "packed", "gt": gt})
    return items


def main():
    _ensure_paths()
    items = collect_binaries()
    if not items:
        return

    from eval.qemu_tracer import qemu_available as qemu_ok
    from eval.ghidra_headless import ghidra_available as ghidra_ok
    from eval.angr_explorer import angr_available as angr_ok
    _qemu_ok = qemu_ok()
    _ghidra_ok = ghidra_ok()
    _angr_ok = angr_ok()

    rows: List[BenchmarkRow] = []
    total = len(items)
    for i, it in enumerate(items, 1):
        binary = it["binary"]
        print(f"[{i}/{total}] {it['sample']} {it['opt']} ({it['group']})")

        for tool in ("BinMind-PcWBI", "BinMind-Baseline", "angr",
                     "qemu-user", "ghidra-headless"):
            detected = False
            confirmed = 0
            elapsed = 0.0
            mem = 0.0
            error = ""
            available = True
            try:
                if tool.startswith("BinMind"):
                    report, elapsed, mem = run_binmind(
                        binary, use_pcwbi=(tool == "BinMind-PcWBI"))
                    detected = report.has_overflow()
                    confirmed = len(report.confirmed)
                    error = report.error
                elif tool == "angr":
                    if not _angr_ok:
                        available = False
                    else:
                        from eval.angr_explorer import explore
                        res = explore(binary, timeout_s=120)
                        detected = res["detected"]
                        confirmed = len(res["findings"])
                        elapsed = res["elapsed_ms"]
                        error = res["error"]
                elif tool == "qemu-user":
                    if not _qemu_ok:
                        available = False
                        error = "qemu not installed"
                    else:
                        from eval.qemu_tracer import trace
                        res = trace(binary)
                        detected = res["detected"]
                        confirmed = 1 if detected else 0
                        elapsed = res["elapsed_ms"]
                        error = res["error"]
                        if not res.get("detected") and res.get("error"):
                            available = res["error"] not in (
                                "qemu-user requires ELF (PE unsupported)",)
                            if "requires ELF" in res["error"]:
                                error = res["error"]
                elif tool == "ghidra-headless":
                    if not _ghidra_ok:
                        available = False
                        error = "GHIDRA_HOME not configured"
                    else:
                        from eval.ghidra_headless import trace
                        res = trace(binary)
                        detected = res["detected"]
                        confirmed = len(res["findings"])
                        elapsed = res["elapsed_ms"]
                        error = res["error"]
            except Exception as e:
                error = str(e)[:120]

            rows.append(BenchmarkRow(
                tool, it["sample"], it["opt"], it["group"], it["gt"],
                detected, confirmed, elapsed, mem, error, available))

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    csv_path = RESULTS_DIR / "benchmark.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["tool", "sample_id", "opt", "group", "ground_truth",
                    "detected", "confirmed_count", "fp", "fn",
                    "time_ms", "peak_mem_mb", "error"])
        for r in rows:
            w.writerow(r.to_csv())

    json_path = RESULTS_DIR / "benchmark.json"
    json_path.write_text(json.dumps(
        [{"tool": r.tool, "sample": r.sample, "opt": r.opt,
          "group": r.group, "ground_truth": r.gt, "detected": r.detected,
          "confirmed": r.confirmed, "verdict": r.verdict,
          "time_ms": r.time_ms, "mem_mb": r.mem_mb, "error": r.error}
         for r in rows], indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"\nbenchmark.csv -> {csv_path} ({len(rows)} rows)")
    print(f"benchmark.json -> {json_path}")


if __name__ == "__main__":
    main()
