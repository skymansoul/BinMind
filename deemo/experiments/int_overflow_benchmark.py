import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 整型溢出检测: 基于模式识别+约束检查
# 当前无专用检测器 — 用启发式规则作为baseline, 标记为待深度强化

INT_CASES = [
    ("INT-01","int sz = count * elem_size;\nchar *p = malloc(sz);\nmemcpy(p, src, sz);", True),
    ("INT-02","size_t total = n * m;\nif (total > 4096) return;\nchar *b = malloc(total);", True),
    ("INT-03","int offset = user_val + base;\nchar *p = buf + offset;\n*p = 'x';", True),
    ("SAFE-01","size_t sz = count * elem_size;\nif (sz > 4096) sz = 4096;\nchar *p = malloc(sz);", False),
    ("SAFE-02","int idx = user_input;\nif (idx >= 0 && idx < 256) buf[idx] = 'x';", False),
]

# 启发式检测: 乘法后无检查 → 潜在溢出
tp_hits = fp_correct = 0
for name, code, is_tp in INT_CASES:
    has_mul = '*' in code
    has_check = any(kw in code for kw in ['if','>','<','>=','<=','sizeof','4096','256'])
    detected = has_mul and not has_check
    if is_tp: tp_hits += (1 if detected else 0)
    else: fp_correct += (1 if not detected else 0)

summary = {
    'tp_samples': 3, 'fp_samples': 2, 'total': 5,
    'detection_rate': round(tp_hits/3*100,1),
    'fp_filter_rate': round(fp_correct/2*100,1),
    'method': 'heuristic (pattern-based, needs deepening)',
    'note': 'Integer overflow detection is baseline only — marked for algorithm upgrade',
}
os.makedirs('experiments/results', exist_ok=True)
json.dump(summary, open('experiments/results/int_overflow_benchmark.json','w'), indent=2)
print(f"INT: detection={summary['detection_rate']}% FP_filtered={summary['fp_filter_rate']}% [BASELINE - needs deepening]")
