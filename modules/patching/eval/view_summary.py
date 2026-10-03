import json, csv


def main():

    d = json.load(open(r'eval/benchmark_summary.json', encoding='utf-8'))
    print("=== Benchmark Summary ===")
    print(f"total_samples={d['total_samples']} tp_expected={d['tp_expected']} "
          f"fp_expected={d['fp_expected']} generated={d['generated_at']}")
    print(f"{'tool':14s} {'variant':6s} {'recall':>7s} {'fp_rate':>7s} "
          f"{'precision':>9s} {'tp':>3s} {'fn':>3s} {'fp_alarm':>8s} {'time':>6s}")
    for tool, variants in d['tools'].items():
        for variant, v in variants.items():
            print(f"  {tool:12s} {variant:6s} "
                  f"{v['recall_pct']:6.1f}% {v['fp_rate_pct']:6.1f}% "
                  f"{v['precision_pct']:8.1f}% "
                  f"{v['tp_detected']:3d} {v['fn']:3d} {v['fp_alarms']:8d} "
                  f"{v['avg_time']:5.2f}s")

    print("\n=== BinMind per-sample ===")
    rows = list(csv.reader(open(r'eval/benchmark_results.csv', encoding='utf-8')))
    for r in rows[1:]:
        if r[2] == 'BinMind' and r[1] == 'plain':
            mark = 'OK ' if r[3] == 'True' else 'MISS'
            print(f"  [{mark}] {r[0][:48]:50s} tp={r[4]} fp={r[5]} fn={r[6]} "
                  f"t={r[7]}s")


if __name__ == "__main__":
    main()
