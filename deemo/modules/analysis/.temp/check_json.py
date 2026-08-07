import json, sys
sys.stdout.reconfigure(encoding='utf-8')
d = json.load(open('modules/analysis/eval/results/regression_results.json'))
print(f"Keys: {list(d.keys())[:10]}")
if 'summary' in d:
    print(f"Summary: {json.dumps(d['summary'], indent=2)}")
elif 'metrics' in d:
    print(f"Metrics: {json.dumps(d['metrics'], indent=2)}")
else:
    for k, v in d.items():
        if isinstance(v, (str, int, float)):
            print(f"  {k}: {v}")
