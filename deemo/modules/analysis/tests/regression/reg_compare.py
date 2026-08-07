# 回归测试 - 结果收集与对比模块
# 读取 reg_scanner.py 输出, 对比 ground truth (manifest 的 type 字段),
# 生成 TP/FP/TN/FN 汇总与 CSV 报告.
#
# 判定规则:
# 样本 type=uaf/fmt/heap/intof 且检测器命中 → TP
# 样本存在且检测器未命中且无错误 → FN (漏报)
# 检测器命中但样本 type 不匹配 → FP (误报, 本套件无此场景)
# 创建: 2026-08-06

import csv
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
RESULTS_DIR = HERE / "results"

_TYPE_LABEL = {
    "heap_overflow": "堆溢出",
    "uaf": "释放后使用",
    "format_string": "格式化字符串",
    "integer_overflow": "整数溢出",
}


def load_scan_results():
    p = RESULTS_DIR / "scan_results_v2.json"
    if not p.exists():
        return []
    return json.loads(p.read_text(encoding="utf-8"))


def compare_all() -> dict:
    results = load_scan_results()
    if not results:
        print("no scan results; run reg_scanner.py first")
        return {}

    by_type = {}
    for r in results:
        t = r.get("type", "unknown")
        hit = bool(r.get("hit"))
        err = bool(r.get("error"))
        entry = {
            "cve": r.get("cve", ""),
            "opt": r.get("opt", ""),
            "time_ms": r.get("time_ms", 0),
            "hit": hit,
            "error": r.get("error", ""),
        }
        by_type.setdefault(t, []).append(entry)

    summary = {}
    csv_rows = []
    for t, entries in by_type.items():
        total = len(entries)
        tp = sum(1 for e in entries if e["hit"])
        fn = sum(1 for e in entries if not e["hit"] and not e["error"])
        err = sum(1 for e in entries if e["error"])
        fp = 0  # 本套件所有样本均为真实漏洞样本, 无负样本
        summary[t] = {
            "total": total, "tp": tp, "fn": fn, "fp": fp,
            "errors": err,
            "recall": round(tp / max(tp + fn, 1), 4),
            "avg_time_ms": round(
                sum(e["time_ms"] for e in entries) / max(total, 1), 1),
        }
        for e in entries:
            csv_rows.append({
                "type": t, "type_label": _TYPE_LABEL.get(t, t),
                "cve": e["cve"], "opt": e["opt"],
                "result": "TP" if e["hit"] else ("ERR" if e["error"] else "FN"),
                "time_ms": e["time_ms"], "error": e["error"][:80],
            })

    # 全局指标
    all_tp = sum(s["tp"] for s in summary.values())
    all_fn = sum(s["fn"] for s in summary.values())
    all_err = sum(s["errors"] for s in summary.values())
    total = sum(s["total"] for s in summary.values())
    overall = {
        "total": total, "tp": all_tp, "fn": all_fn,
        "errors": all_err,
        "recall": round(all_tp / max(all_tp + all_fn, 1), 4),
    }

    # 输出 CSV
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    csv_path = RESULTS_DIR / "regression_summary.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=[
            "type", "type_label", "cve", "opt", "result", "time_ms", "error"])
        w.writeheader()
        w.writerows(csv_rows)

    # 输出 JSON
    out = {
        "timestamp": __import__("time").strftime("%Y-%m-%d %H:%M:%S"),
        "overall": overall,
        "by_type": summary,
    }
    (RESULTS_DIR / "regression_compare.json").write_text(
        json.dumps(out, indent=2, ensure_ascii=False))

    # 打印报告
    print("=" * 52)
    print("Regression Suite Summary")
    print("=" * 52)
    for t, s in sorted(summary.items()):
        print(f"  {_TYPE_LABEL.get(t,t):<10} TP={s['tp']:>2}/{s['total']:<2} "
              f"FN={s['fn']:<2} recall={s['recall']:.1%} "
              f"avg={s['avg_time_ms']}ms")
    print(f"  {'TOTAL':<10} TP={overall['tp']}/{overall['total']} "
          f"recall={overall['recall']:.1%}")
    return out


if __name__ == "__main__":
    compare_all()
