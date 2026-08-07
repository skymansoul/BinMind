import json

with open(r'C:\Users\Administrator\Desktop\BinMind\deemo\eval\results\unified_benchmark_results.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

# 详细分析哪些被检出
stack_samples = [r for r in data['results'] if r['type'] == 'stack_overflow']

print("=== DETAILED ANALYSIS OF 27 STACK_OVERFLOW SAMPLES ===\n")

# Categorize
detected_by_heap = []
detected_by_fmt = []
detected_by_int = []
detected_by_any = []
not_detected = []

for s in stack_samples:
    dets = s['detections']
    name = s['sample']
    h = dets.get('heap', {}).get('detected', False)
    f_ = dets.get('format_string', {}).get('detected', False)
    i = dets.get('integer_overflow', {}).get('detected', False)
    u = dets.get('uaf', {}).get('detected', False)
    
    if h: detected_by_heap.append(name)
    if f_: detected_by_fmt.append(name)
    if i: detected_by_int.append(name)
    if h or f_ or i or u:
        detected_by_any.append(name)
    else:
        not_detected.append(name)

print(f"Detected by heap detector (false positive for stack): {len(detected_by_heap)}")
for n in detected_by_heap:
    print(f"  - {n}")

print(f"\nDetected by format_string detector (false positive for stack): {len(detected_by_fmt)}")
for n in detected_by_fmt:
    print(f"  - {n}")

print(f"\nDetected by integer_overflow detector (false positive for stack): {len(detected_by_int)}")
for n in detected_by_int:
    print(f"  - {n}")

print(f"\nDetected by ANY detector: {len(detected_by_any)}/27 = {len(detected_by_any)/27*100:.1f}%")

print(f"\nNOT detected by ANY detector: {len(not_detected)}/27 = {len(not_detected)/27*100:.1f}%")
for n in not_detected:
    print(f"  - {n}")

# 关键结论
print("\n=== KEY FINDING ===")
print(f"stack_overflow detector was NEVER RUN on any of the 27 samples!")
print(f"The unified_triple_benchmark.py only runs: heap, format_string, integer_overflow, uaf")
print(f"It does NOT include a stack_overflow detection step.")
print(f"")
print(f"The '18.5%' likely comes from cross-type false positives:")
print(f"  5/27 = 18.5% detected by heap detector (these are FALSE POSITIVES)")
print(f"  2/27 detected by int_overflow detector (also false positives)")
