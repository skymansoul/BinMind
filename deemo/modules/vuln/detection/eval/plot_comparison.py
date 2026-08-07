# coding: utf-8
import json, sys, os
def plot(json_path, out_dir):
    try:
        import matplotlib; matplotlib.use("Agg")
        import matplotlib.pyplot as plt; import numpy as np
    except ImportError:
        print("matplotlib not installed, skipping plot"); return
    with open(json_path) as fp: data = json.load(fp)
    tools = list(data.keys())
    rates = []; times = []
    for t in tools:
        rs = data[t]; n = len(rs)
        d = sum(1 for r in rs if r.get("detected")); rates.append(d/max(n,1)*100)
        t_avg = sum(r.get("elapsed_sec",0) for r in rs)/max(n,1); times.append(t_avg)
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))
    colors = ["#2ecc71" if r>50 else "#e74c3c" for r in rates]
    b1 = ax1.bar(tools, rates, color=colors, edgecolor="black")
    ax1.set_ylabel("Detection Rate (%)"); ax1.set_title("Detection Rate"); ax1.set_ylim(0, 100)
    for bar, r in zip(b1, rates): ax1.text(bar.get_x()+bar.get_width()/2, bar.get_height()+1, f"{r:.0f}%", ha="center", fontsize=9)
    b2 = ax2.bar(tools, times, color="#3498db", edgecolor="black")
    ax2.set_ylabel("Avg Time (s)"); ax2.set_title("Average Analysis Time")
    for bar, t in zip(b2, times): ax2.text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.01, f"{t:.1f}s", ha="center", fontsize=8)
    plt.tight_layout(); out = os.path.join(out_dir, "comparison_chart.png")
    plt.savefig(out, dpi=150, bbox_inches="tight"); print(f"Chart saved: {out}")
if __name__ == "__main__":
    jp = sys.argv[1] if len(sys.argv)>1 else "benchmark_results.json"
    od = sys.argv[2] if len(sys.argv)>2 else "."
    plot(jp, od)
