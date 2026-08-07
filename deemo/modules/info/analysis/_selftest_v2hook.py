# 临时自测: heap_overflow_v2 集成流相关配对前后的行为对比
import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\info\analysis")
from heap_overflow_v2 import detect_heap_overflow_v2

CASES = {
    "TP_tainted_size": (
        "int n = atoi(argv[1]);\nchar *buf = malloc(64);\nmemcpy(buf, src, n);\n", True),
    "TP_plain_overflow": (
        "int n = 128;\nchar *buf = malloc(64);\nmemcpy(buf, src, n);\n", True),
    "TN_equal_size": (
        "int n = 128;\nchar *buf = malloc(128);\nmemcpy(buf, src, n);\n", False),
    "TN_unrelated_alloc": (
        "int n = 128;\nchar *other = malloc(32);\nchar *buf = malloc(128);\nmemcpy(buf, src, n);\n", False),
    "TN_guarded": (
        "int n = atoi(argv[1]);\nchar *buf = malloc(64);\nif (n > 64) return;\nmemcpy(buf, src, n);\n", False),
}

print(f"{'name':<22} {'expect':<6} {'detected':<8} {'conf':<6} {'pairs':<6} {'method'}")
for name, (code, expect) in CASES.items():
    r = detect_heap_overflow_v2(code=code)
    found = r["stats"]["total"] > 0
    conf = max((f["confidence"] for f in r["findings"]), default=0)
    verdict = "OK" if (found == expect) else "MISMATCH"
    print(f"{name:<22} {str(expect):<6} {str(found):<8} {conf:<6.2f} {r['alloc_write_pairs_total']:<6} {r['method']}  {verdict}")
