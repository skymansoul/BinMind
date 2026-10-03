# 统一结果仪表板: 读取所有基准数据, 输出人类可读摘要
# 决策: 独立于扫描器和测试框架, 只依赖JSON数据文件
import json, sys, os
from pathlib import Path
from collections import defaultdict

EVAL_DIR = Path(__file__).parent

def load_json(name):
    p = EVAL_DIR / name
    if p.exists():
        with open(p) as f: return json.load(f)
    return None

def main():
    print("=" * 60)
    print("  BinMind Detection Benchmark Dashboard")
    print("=" * 60)

    # 80-sample benchmark
    b80 = load_json("benchmark_80_samples.json")
    if b80:
        print(f"\nTest Samples: {b80['total_samples']} across {len(b80['categories'])} categories")
        for cat, count in b80['categories'].items():
            print(f"  {cat}: {count} samples")

    # Pipeline performance estimates
    perf = (b80 or {}).get("estimated_pipeline_performance", {})
    if perf:
        print(f"\nEstimated Detection Performance:")
        for tool, m in perf.items():
            print(f"  {tool}: det={m['detection_rate']} fp={m['false_positive_rate']}")

    # Regression results
    reg = load_json("regression_results.json")
    if reg:
        stats = reg.get("stats", {})
        print(f"\nRegression Test Summary:")
        for cat, s in stats.items():
            det = s.get('tp', 0) / max(s.get('tp', 0) + s.get('fn', 0), 1) * 100
            fp = s.get('fp', 0) / max(s.get('fp', 0) + s.get('tn', 0), 1) * 100 if (s.get('fp',0)+s.get('tn',0)) > 0 else 0
            print(f"  {cat}: {s.get('total',0)} samples, det={det:.0f}% fp={fp:.0f}%")

    # Full regression
    full = load_json("full_regression.json")
    if full:
        print(f"\nFull Regression: {full.get('total', 0)} samples processed")

    # Core module inventory
    core_dir = EVAL_DIR.parent / "core"
    py_count = len(list(core_dir.glob("*.py")))
    print(f"\nCore Modules: {py_count} Python files")

    print("\n" + "=" * 60)
    print("  Dashboard complete. Data files in eval/")
    print("=" * 60)
    return 0

if __name__ == "__main__":
    sys.exit(main())
