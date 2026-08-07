import json

with open(r'C:\Users\Administrator\Desktop\BinMind\deemo\eval\results\unified_benchmark_results.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

stack_samples = [r for r in data['results'] if r['type'] == 'stack_overflow']
print(f"Total stack_overflow samples: {len(stack_samples)}")
print()

for s in stack_samples:
    dets = s['detections']
    heap = dets.get('heap', {})
    fmt = dets.get('format_string', {})
    intovf = dets.get('integer_overflow', {})
    uaf = dets.get('uaf', {})
    has_stack = 'stack_overflow' in dets
    name = s['sample']
    print(f"  {name:55s} heap={heap.get('detected', False)}  fmt={fmt.get('detected', False)}  int={intovf.get('detected', False)}  uaf={uaf.get('detected', False)}  has_stack_det={has_stack}")

print()

# 统计: 27个stack样本中, 有多少被任何检测器检出
any_detected = 0
for s in stack_samples:
    dets = s['detections']
    if (dets.get('heap', {}).get('detected', False) or
        dets.get('format_string', {}).get('detected', False) or
        dets.get('integer_overflow', {}).get('detected', False) or
        dets.get('uaf', {}).get('detected', False)):
        any_detected += 1

print(f"Stack samples detected by ANY available detector: {any_detected}/{len(stack_samples)} = {any_detected/len(stack_samples)*100:.1f}%")
print(f"Stack samples with actual stack_overflow detector field: {sum(1 for s in stack_samples if 'stack_overflow' in s['detections'])}/{len(stack_samples)}")
