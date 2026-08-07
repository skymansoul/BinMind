# 临时自测: FC-VRA 检测器在 TP/TN 迷你样本上的行为验证
import sys, json
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\info\analysis")
from fc_vra_detector import detect_heap_overflow_fcv3

CASES = {
    # (name, code, expect_overflow)
    "TP_plain_malloc_memcpy_overflow": (
        "int n = 128;\nchar *buf = malloc(64);\nmemcpy(buf, src, n);\n", True),
    "TP_unbounded_strcpy": (
        "char *buf = malloc(64);\nstrcpy(buf, src);\n", True),
    "TP_tainted_size": (
        "int n = atoi(argv[1]);\nchar *buf = malloc(64);\nmemcpy(buf, src, n);\n", True),
    "TP_loop_manual": (
        "char *buf = malloc(16);\nint i;\nfor (i=0;i<64;i++) { buf[i++] = 0; }\n", True),
    "TN_equal_size": (
        "int n = 128;\nchar *buf = malloc(128);\nmemcpy(buf, src, n);\n", False),
    "TN_smaller_write": (
        "int n = 64;\nchar *buf = malloc(128);\nmemcpy(buf, src, n);\n", False),
    "TN_guarded": (
        "int n = atoi(argv[1]);\nchar *buf = malloc(64);\nif (n > 64) return;\nmemcpy(buf, src, n);\n", False),
    "TN_algebraic_equal": (
        "int n = atoi(argv[1]);\nchar *buf = malloc(n*4);\nmemcpy(buf, src, n*4);\n", False),
    "TN_unrelated_alloc": (
        "int n = 128;\nchar *other = malloc(32);\nchar *buf = malloc(128);\nmemcpy(buf, src, n);\n", False),
}

print(f"{'name':<30} {'expect':<6} {'detected':<8} {'conf':<6} {'fp_red':<7} {'pairs'}")
for name, (code, expect) in CASES.items():
    r = detect_heap_overflow_fcv3(code=code)
    found = r["stats"]["total"] > 0
    conf = max((f["confidence"] for f in r["findings"]), default=0)
    verdict = "OK" if (found == expect) else "MISMATCH"
    print(f"{name:<30} {str(expect):<6} {str(found):<8} {conf:<6.2f} {r['fp_reduction_pct']:<7.1f} {r['alloc_write_pairs_total']:<4} {verdict}")
