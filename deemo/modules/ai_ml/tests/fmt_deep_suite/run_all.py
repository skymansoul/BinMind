# 格式串深度套件——编译+扫描+收集一键入口
import json
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

BASE = Path(__file__).parent.parent.parent
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

SAMPLES = BASE / "tests" / "fmt_deep_samples"
BUILD = Path(__file__).parent / "build"
GCC = shutil.which("gcc") or "gcc"
FMT_POS = ('fmt_confirmed', 'fmt_likely')


def compile_all():
    BUILD.mkdir(parents=True, exist_ok=True)
    res = []
    for sd in sorted(d for d in SAMPLES.iterdir()
                     if d.is_dir() and (d / "vuln.c").exists()):
        for opt in ("O0", "O3"):
            out = BUILD / f"{sd.name}_{opt}.exe"
            if out.exists():
                out.unlink()
            r = subprocess.run([GCC, f"-{opt}", "-w", "-o", str(out),
                                str(sd / "vuln.c")],
                               capture_output=True, text=True, timeout=120)
            res.append((sd.name, opt, r.returncode == 0))
            print(f"  [{opt}] {sd.name}: {'OK' if r.returncode == 0 else 'FAIL'}")
    return res


def scan_one(exe: Path):
    from src.disasm.objdump_parser import ObjdumpParser
    from src.detect.pipeline_bridge import DetectionPipeline
    sample = exe.stem.rsplit("_", 1)[0]
    opt = exe.stem.rsplit("_", 1)[-1]
    t0 = time.perf_counter()
    r = subprocess.run(["objdump", "-d", "-M", "intel", str(exe)],
                       capture_output=True, text=True, timeout=60)
    funcs = ObjdumpParser()._parse_output(r.stdout) if r.returncode == 0 else []
    pipe = DetectionPipeline()
    det = False
    reasons = []
    for f in funcs:
        if len(f.instructions) < 3:
            continue
        try:
            reps = pipe.scan_function(f.instructions, f.bb_boundaries,
                                      f.cfg_edges, f.name)
        except Exception:
            continue
        for rep in reps:
            v = rep.combined_verdict.value
            if v in FMT_POS:
                det = True
                reasons.append(rep.reason[:80])
    return {"sample": sample, "opt": opt, "detected": det,
            "reasons": reasons, "time_ms": round((time.perf_counter() - t0) * 1000, 1)}


def main():
    rc = 0
    if "--only-scan" not in sys.argv:
        compile_all()
    results = []
    for exe in sorted(BUILD.glob("*.exe")):
        r = scan_one(exe)
        st = "DETECTED" if r["detected"] else "clean"
        print(f"  {exe.stem}: {st} ({r['time_ms']}ms)")
        results.append(r)
    (Path(__file__).parent / "scan_results.json").write_text(
        json.dumps(results, indent=2), encoding="utf-8")

    tp = fp = tn = fn = 0
    for r in results:
        exp = r["sample"].startswith("tp_")
        if exp and r["detected"]:
            tp += 1
        elif exp:
            fn += 1
        elif not r["detected"]:
            tn += 1
        else:
            fp += 1
    n = len(results)
    recall = tp / max(1, tp + fn)
    fpr = fp / max(1, fp + tn)
    precision = tp / max(1, tp + fp)
    f1 = 2 * precision * recall / max(0.001, precision + recall)
    summary = {"n": n, "tp": tp, "fp": fp, "tn": tn, "fn": fn,
               "recall": round(recall, 4), "fpr": round(fpr, 4),
               "precision": round(precision, 4), "f1": round(f1, 4)}
    (Path(__file__).parent / "benchmark_summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8")
    print(f"[fmt suite] n={n} TP={tp} FP={fp} TN={tn} FN={fn}")
    print(f"  Recall={recall:.1%} FPR={fpr:.1%} Precision={precision:.1%} F1={f1:.3f}")
    return 0 if (fn == 0 and fp == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
