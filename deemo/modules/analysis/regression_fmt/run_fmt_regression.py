# fmt回归 — 扫描全部format_string样本并收集对比.
# 样本truth按vuln.c源码人工判定: 用户可控格式串/%n/泄漏 → vuln.
# 创建: 2023-09-01

import csv
import glob
import json
import sys
from pathlib import Path

_BASE = Path(r"C:\Users\Administrator\Desktop\BinMind\deemo\tests\samples\format_string")
_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(_ROOT))

_VULN = {
    "fmt_basic_direct", "fmt_conditional_fmtstr", "fmt_cross_func",
    "fmt_direct_user", "fmt_double_printf", "fmt_external_input",
    "fmt_got_overwrite", "fmt_heap_fmt", "fmt_heap_fmtstr",
    "fmt_indirect_fmt", "fmt_loop_printf", "fmt_loop_write",
    "fmt_n_bytes_written", "fmt_n_write", "fmt_nested_call",
    "fmt_offset_leak", "fmt_positional", "fmt_positional_arg",
    "fmt_snprintf_trunc", "fmt_stack_leak", "fmt_stack_write",
    "fmt_syslog_direct", "fmt_vprintf_proxy", "fmt_vprintf_wrap",
    "fmt_width_leak", "fmt_wrapper_func",
}
_SAFE = {
    "fmt_constant_safe", "fmt_double_percent", "fmt_indirect_arg",
    "fmt_inline_const", "fmt_snprintf_safe",
}


def scan_all(out: Path = None):
    from scan_dispatch import scan_fmt
    out = out or (_ROOT / "results")
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    summary = {"TP": 0, "FP": 0, "FN": 0, "TN": 0, "time_ms": 0.0}
    for p in sorted(glob.glob(str(_BASE / "*" / "vuln.exe"))):
        name = Path(p).parent.name
        if name in _VULN:
            expect = True
        elif name in _SAFE:
            expect = False
        else:
            continue
        r = scan_fmt(p)
        v = "TP" if expect and r["count"] > 0 else \
            ("FN" if expect else ("FP" if r["count"] > 0 else "TN"))
        summary[v] += 1
        summary["time_ms"] += r["time_ms"]
        rows.append({
            "sample": name, "expect_fmt": expect, "verdict": v,
            "count": r["count"], "types": ";".join(r["types"]),
            "time_ms": r["time_ms"],
        })
    tp, fp, fn, tn = summary["TP"], summary["FP"], summary["FN"], summary["TN"]
    summary["recall"] = round(tp / max(tp + fn, 1) * 100, 2)
    summary["precision"] = round(tp / max(tp + fp, 1) * 100, 2)
    summary["fpr"] = round(fp / max(fp + tn, 1) * 100, 2)
    summary["f1"] = round(2 * tp / max(2 * tp + fp + fn, 1), 4)
    with open(out / "fmt_results.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    with open(out / "fmt_summary.json", "w", encoding="utf-8") as f:
        json.dump({"summary": summary, "rows": rows}, f, indent=2,
                  ensure_ascii=False)
    print(f"[fmt-scan] {json.dumps(summary)}")
    for r in rows:
        print(f"  {r['sample']:32s} {r['verdict']} count={r['count']} "
              f"types={r['types']}")
    return summary


if __name__ == "__main__":
    scan_all()
