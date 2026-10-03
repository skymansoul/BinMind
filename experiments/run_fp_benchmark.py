"""堆溢出FP过滤基准测试 — 在所有CVE样本上运行区间约束过滤器,
统计: 总发现数、过滤数(真FP)、保留数(真TP+不确定)、
      误过滤数(假阴性)、FP减少率、TP保留率。
输出 experiments/results/fp_benchmark.json
"""
import sys, io, os, json, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.value_range_analyzer import HeapFalsePositiveFilter

# 测试用例: (名称, 伪代码, 是堆漏洞, 是真阳性还是FP)
# 伪代码模拟Ghidra/IDA对编译后二进制的反编译输出
CASES = [
# 真阳性 (真漏洞, 不应过滤)
    ("CVE-001", "char *buf = malloc(64);\nmemcpy(buf, data, 256);", True, True),
    ("CVE-006", "size_t len = strlen(s);\nchar *buf = malloc(len);\nmemcpy(buf, s, len);\nbuf[len] = 0;", True, True),
    ("CVE-012", "char *p = realloc(old, 32);\nmemcpy(p, old, 64);", True, True),
    ("CVE-013", "char *buf = malloc(100);\nmemcpy(buf, src, 200);", True, True),
    ("CVE-014", "char *buf = malloc(64);\nmemmove(buf + 32, buf, 64);", True, True),

# 假阳性 (安全代码, 应被过滤)
    ("SAFE-001", "char *buf = malloc(256);\nmemcpy(buf, \"fixed_data\", 11);", True, False),
    ("SAFE-002", "char *buf = malloc(128);\nmemcpy(buf, src, 64);", True, False),
    ("SAFE-003", "char *a = malloc(64);\nmemcpy(a, \"x\", 2);\nchar *b = malloc(256);\nmemcpy(b, \"y\", 2);", True, False),

# 非堆漏洞 (不受FP过滤器影响)
    ("CVE-002", "char *ptr = malloc(128);\nfree(ptr);\nprintf(\"%s\", ptr);", False, True),
    ("CVE-003", "char *msg = recv(0, buf, 256, 0);\nprintf(msg);", False, True),
    ("CVE-004", "char name[32];\nstrcpy(name, input);", False, True),
    ("CVE-005", "char *p = malloc(64);\nfree(p);\nfree(p);", False, True),
]

def _extract_first_alloc_var(code: str) -> str:
    import re
    m = re.search(r'\b(\w+)\s*=\s*malloc\(', code)
    if m: return m.group(1)
    m = re.search(r'\b(\w+)\s*=\s*realloc\(', code)
    if m: return m.group(1)
    return 'buf'

filt = HeapFalsePositiveFilter()
results = []
tp_before = fp_before = tp_after = fp_after = 0
filtered_correct = filtered_wrong = 0

for name, code, is_heap, is_tp in CASES:
    findings = [{'alloc_var': _extract_first_alloc_var(code),
                 'confidence': 0.6, 'type': 'heap_overflow' if is_heap else 'other'}]
    filtered = filt.filter(code, findings)
    stats = filt.stats(code)

    kept = len(filtered)
    removed = len(findings) - kept
    verdict = filtered[0].get('fp_filter_verdict', '?') if filtered else 'filtered'

    entry = {
        'name': name, 'is_heap': is_heap, 'ground_truth_tp': is_tp if is_heap else None,
        'findings_before': len(findings), 'findings_after': kept,
        'filtered_out': removed, 'verdict': verdict,
        'fp_filter_stats': stats,
    }

    if is_heap:
        tp_before += 1 if is_tp else 0
        fp_before += 0 if is_tp else 1
        if is_tp and kept > 0: tp_after += 1
        if is_tp and kept == 0: filtered_wrong += 1
        if not is_tp and kept == 0: filtered_correct += 1
        if not is_tp and kept > 0: fp_after += 1

    results.append(entry)

summary = {
    'total_heap_samples': tp_before + fp_before,
    'true_positives_before': tp_before,
    'false_positives_before': fp_before,
    'true_positives_after': tp_after,
    'false_positives_after': fp_after,
    'fp_correctly_filtered': filtered_correct,
    'tp_wrongly_filtered': filtered_wrong,
    'fp_reduction_pct': round(filtered_correct * 100 / max(1, fp_before), 1),
    'tp_retention_pct': round(tp_after * 100 / max(1, tp_before), 1),
    'precision_before': round(tp_before / max(1, tp_before + fp_before), 3),
    'precision_after': round(tp_after / max(1, tp_after + fp_after), 3),
}

os.makedirs('experiments/results', exist_ok=True)
with open('experiments/results/fp_benchmark.json', 'w') as f:
    json.dump({'results': results, 'summary': summary}, f, indent=2)

print(json.dumps(summary, indent=2))
print(f"Saved to experiments/results/fp_benchmark.json")
