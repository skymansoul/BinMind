"""查看FCPV FN样本."""
import json, sys
sys.path.insert(0, '.')
r = json.load(open('eval/results/fmt_suite_results.json'))
for s in r['source_level']['per_sample']:
    if s['fcpv'] == 'FN':
        print(f"{s['sample']}: fcpv={s['fcpv']} conf={s['fcpv_conf']} reason={s['fcpv_reason']}")
