import json
data = json.load(open('eval/results/uaf_full_benchmark.json', 'r', encoding='utf-8'))
for d in data['details']:
    if 'cve_real' in d.get('sample', ''):
        print(f"{d['sample']:30s} cat={d['category']:20s} exp={d['expected']:10s} hoig={d['hoig_only']:10s} pcol={d['pcol']:10s}")
