# 扫描调度模块.
#
# 决策逻辑:
#   对 build/manifest_build.json 中每个编译产物调用 heapdet 扫描,
#   按样本 ground truth 判定 TP/FP/FN/TN:
#     - vulnerable 样本检出 confirmed -> TP; 未检出 -> FN.
# safe 样本检出 confirmed → FP; 未检出 → TN.
#   结果写 results/scan_results.json, 供收集模块汇总.
#

import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
BUILD_MANIFEST = ROOT / "build" / "manifest_build.json"
PACKED_VARIANTS = {}


def _ensure_paths():
    here = ROOT
    deemo = here.parent.parent.parent
    for p in (str(deemo), str(deemo.parent), str(here.parent)):
        if p not in sys.path:
            sys.path.insert(0, p)
    _purge_pycache(deemo / "modules" / "analysis" / "static")
    _purge_pycache(here.parent / "heapdet")


def _purge_pycache(directory: Path):
    """清除指定目录下的 __pycache__, 避免并发编辑产生陈旧字节码."""
    cache = directory / "__pycache__"
    if cache.exists():
        import shutil
        shutil.rmtree(cache, ignore_errors=True)


def classify(ground_truth: str, detected: bool) -> str:
    """按 ground truth 与检出结果分类."""
    if ground_truth == "vulnerable":
        return "TP" if detected else "FN"
    return "FP" if detected else "TN"


def scan_all() -> list:
    """扫描全部编译产物, 返回逐样本结果."""
    _ensure_paths()
    if not BUILD_MANIFEST.exists():
        print(f"build manifest not found: {BUILD_MANIFEST}. "
              "Run compile_samples.py first.")
        return []

    from heapdet.scan import scan_binary

    manifest = json.loads(BUILD_MANIFEST.read_text(encoding="utf-8"))
    results = []

    for sample in manifest:
        sid = sample["sample_id"]
        gt = sample["ground_truth"]
        expected = sample["expected"]
        for opt in ("O0", "O2"):
            rec = sample.get(f"compiled_{opt}", {})
            binary = rec.get("binary", "")
            if not rec.get("compiled") or not os.path.exists(binary):
                continue
            t0 = time.perf_counter()
            report = scan_binary(binary)
            elapsed = (time.perf_counter() - t0) * 1000

            detected = report.has_overflow()
            verdict = classify(gt, detected)
            results.append({
                "sample_id": sid,
                "cve": sample.get("cve", ""),
                "opt": opt,
                "ground_truth": gt,
                "expected": expected,
                "binary": binary,
                "detected": detected,
                "verdict": verdict,
                "confirmed_count": len(report.confirmed),
                "suspected_count": len(report.suspected),
                "benign_count": len(report.benign),
                "wb_stats": report.wb_stats,
                "elapsed_ms": round(elapsed, 2),
                "error": report.error,
                "reasons": [
                    f.get("wb_reason", "") for f in report.confirmed],
            })
            print(f"  [{verdict}] {sid} {opt}: confirmed="
                  f"{len(report.confirmed)} suspected="
                  f"{len(report.suspected)} {elapsed:.0f}ms"
                  + (f" err={report.error}" if report.error else ""))

        # 加壳变体 (若有): 归入 packed 组
        for opt in ("O0", "O2"):
            rec = sample.get(f"compiled_{opt}", {})
            pbin = rec.get("packed_binary", "")
            if pbin and os.path.exists(pbin):
                report = scan_binary(pbin)
                detected = report.has_overflow()
                verdict = classify(gt, detected)
                results.append({
                    "sample_id": sid, "cve": sample.get("cve", ""),
                    "opt": opt, "packed": True,
                    "ground_truth": gt, "expected": expected,
                    "binary": pbin, "detected": detected,
                    "verdict": verdict,
                    "confirmed_count": len(report.confirmed),
                    "suspected_count": len(report.suspected),
                    "benign_count": len(report.benign),
                    "wb_stats": report.wb_stats,
                    "elapsed_ms": report.elapsed_ms,
                    "error": report.error,
                    "reasons": [
                        f.get("wb_reason", "") for f in report.confirmed],
                })

    RESULTS.mkdir(parents=True, exist_ok=True)
    out = RESULTS / "scan_results.json"
    out.write_text(json.dumps(results, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    print(f"\nscan results -> {out} ({len(results)} rows)")
    return results


if __name__ == "__main__":
    scan_all()
