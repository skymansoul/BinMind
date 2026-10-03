# 端到端流水线验证脚本
import sys, json
sys.path.insert(0, '.')

from core.unified_heap_pipeline import analyze_heap_safety

tests = [
    ("malloc(64) vs memcpy(256)", """
int vuln_func(int n) {
    char *buf = (char *)malloc(64);
    memcpy(buf, input, 256);
    return 0;
}
"""),
    ("malloc(n) vs memcpy(n) GUARDED", """
int safe_func(int n) {
    if (n > 256) n = 256;
    char *buf = (char *)malloc(n);
    memcpy(buf, src, n);
    return 0;
}
"""),
    ("malloc(n*4) vs memcpy(n*8) AFFINE", """
int affine_overflow(int n) {
    char *buf = (char *)malloc(n * 4);
    memcpy(buf, data, n * 8);
    return 0;
}
"""),
    ("malloc(64) vs memcpy(32) SAFE", """
int smaller_write() {
    char *buf = (char *)malloc(64);
    memcpy(buf, data, 32);
    return 0;
}
"""),
    ("malloc(strlen) vs memcpy without +1", """
int no_null_term(const char *s) {
    char *buf = (char *)malloc(strlen(s));
    memcpy(buf, s, strlen(s) + 1);
    return 0;
}
"""),
]

for label, code in tests:
    f, s = analyze_heap_safety(code, 'test_func', 'test.elf')
    print(f"=== {label} ===")
    for finding in f:
        v = finding.get('verdict', '?')
        ov = finding.get('overflow_bytes', 0)
        desc = finding.get('description', '')
        conf = finding.get('confidence', 0)
        print(f"  {v:10s} | overflow={ov:4d}B | conf={conf:.2f} | {desc}")
    print(f"  -> confirmed={s['confirmed']} possible={s['possible']} filtered={s['filtered']}")
    print()

print("Pipeline verification complete.")
