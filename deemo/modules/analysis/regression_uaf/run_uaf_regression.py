# UAF回归 — 样本编译 + 扫描调度 + 结果收集.
# 样本: deemo/tests/uaf_benchmark (tp_01..06, tn_01..06, 含truth.json).
# 创建: 2026-08-06

import csv
import glob
import json
import subprocess
import sys
from pathlib import Path

_BENCH = Path(r"C:\Users\Administrator\Desktop\BinMind\deemo\tests\uaf_benchmark")
_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(_ROOT))


def compile_all(cc: str = "gcc"):
    ok = 0
    for d in sorted(_BENCH.iterdir()):
        if not (d / "sample.c").exists():
            continue
        exe = d / "vuln.exe"
        if exe.exists():
            ok += 1
            continue
        r = subprocess.run([cc, "-O0", "-g", "-fno-builtin", "sample.c",
                            "-o", "vuln.exe"], cwd=str(d),
                           capture_output=True, timeout=120)
        if r.returncode == 0 and exe.exists():
            ok += 1
    print(f"[uaf-compile] {ok} samples ready")
    return ok


def scan_all(out: Path = None):
    from scan_dispatch import scan_uaf
    out = out or (_ROOT / "results")
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    summary = {"TP": 0, "FP": 0, "FN": 0, "TN": 0, "time_ms": 0.0}
    for p in sorted(glob.glob(str(_BENCH / "*" / "vuln.exe"))):
        name = Path(p).parent.name
        truth = json.load(open(str(Path(p).parent / "truth.json"),
                               encoding="utf-8"))
        expect = bool(truth.get("expect_uaf", False))
        r = scan_uaf(p)
        v = "TP" if expect and r["count"] > 0 else \
            ("FN" if expect else ("FP" if r["count"] > 0 else "TN"))
        summary[v] += 1
        summary["time_ms"] += r["time_ms"]
        rows.append({
            "sample": name, "expect_uaf": expect, "verdict": v,
            "count": r["count"], "types": ";".join(r["types"]),
            "time_ms": r["time_ms"],
        })
    tp, fp, fn, tn = (summary["TP"], summary["FP"],
                      summary["FN"], summary["TN"])
    summary["recall"] = round(tp / max(tp + fn, 1) * 100, 2)
    summary["precision"] = round(tp / max(tp + fp, 1) * 100, 2)
    summary["fpr"] = round(fp / max(fp + tn, 1) * 100, 2)
    summary["f1"] = round(2 * tp / max(2 * tp + fp + fn, 1), 4)

    with open(out / "uaf_results.csv", "w", encoding="utf-8",
              newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    with open(out / "uaf_summary.json", "w", encoding="utf-8") as f:
        json.dump({"summary": summary, "rows": rows}, f, indent=2,
                  ensure_ascii=False)
    print(f"[uaf-scan] {json.dumps(summary)}")
    for r in rows:
        print(f"  {r['sample']:30s} {r['verdict']} count={r['count']} "
              f"types={r['types']}")
    return summary


if __name__ == "__main__":
    compile_all()
    scan_all()
