import json, os

DEMO = r'C:\Users\Administrator\Desktop\BinMind\deemo'

# 1. 堆扫描结果汇总
f = open(os.path.join(DEMO, '.temp/results_heap/heap_scan_with_llm.json'), 'r', encoding='utf-8')
heap_data = json.load(f)
f.close()

print('=== 堆扫描 summary ===')
print(json.dumps(heap_data['summary'], ensure_ascii=False, indent=2))

print('\n=== 堆溢出样本逐条 ===')
for r in heap_data['results']:
    if r['label'] == 'heap_overflow':
        llm = r.get('llm', {})
        llm_status = llm.get('status', 'N/A')
        llm_time = llm.get('elapsed_sec', 0)
        print('  {} | find={} conf={} poss={} filt={} uaf={} | llm={}({}s)'.format(
            r['sample'], r['total_findings'], r['confirmed'], r['possible'],
            r['filtered'], r['uaf_findings'], llm_status, llm_time))

print('\n=== 堆安全样本逐条 ===')
for r in heap_data['results']:
    if r['label'] == 'heap_safe':
        llm = r.get('llm', {})
        llm_status = llm.get('status', 'N/A')
        llm_time = llm.get('elapsed_sec', 0)
        print('  {} | find={} conf={} poss={} filt={} | llm={}({}s)'.format(
            r['sample'], r['total_findings'], r['confirmed'], r['possible'],
            r['filtered'], llm_status, llm_time))

print('\n=== 堆边界样本逐条 ===')
for r in heap_data['results']:
    if r['label'] == 'heap_edge':
        llm = r.get('llm', {})
        llm_status = llm.get('status', 'N/A')
        llm_time = llm.get('elapsed_sec', 0)
        print('  {} | find={} conf={} poss={} | llm={}({}s)'.format(
            r['sample'], r['total_findings'], r['confirmed'], r['possible'],
            llm_status, llm_time))

# 2. 回归测试报告
reg_path = os.path.join(DEMO, 'tests/regression_report.json')
if os.path.exists(reg_path):
    f = open(reg_path, 'r', encoding='utf-8')
    reg = json.load(f)
    f.close()
    print('\n=== 回归测试报告 ===')
    print(json.dumps(reg, ensure_ascii=False, indent=2)[:3000])

# 3. 端到端管线测试
e2e_path = os.path.join(DEMO, '.temp/e2e_results.json')
if os.path.exists(e2e_path):
    f = open(e2e_path, 'r', encoding='utf-8')
    e2e = json.load(f)
    f.close()
    print('\n=== E2E 结果 ===')
    print(json.dumps(e2e, ensure_ascii=False, indent=2)[:3000])

# 4. 统一基准结果
bench_path = os.path.join(DEMO, 'eval/results/unified_benchmark_results.json')
if os.path.exists(bench_path):
    f = open(bench_path, 'r', encoding='utf-8')
    bench = json.load(f)
    f.close()
    print('\n=== 基准结果 summary ===')
    s = bench.get('summary', bench.get('type_stats', {}))
    print(json.dumps(s, ensure_ascii=False, indent=2)[:2000])
    total = bench.get('total_samples', len(bench.get('results', [])))
    print('总样本数:', total)
