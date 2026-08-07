"""SGAV smoke test."""
import sys
sys.path.insert(0, '.')
from analysis.sgav_pipeline import SGAVVerifier

v = SGAVVerifier()

# Test 1: gets overflow
code1 = "#include <stdio.h>\nvoid vuln() {\n    char buf[64];\n    gets(buf);\n}"
r1 = v.verify(code1)
print("Test1 (gets):", len(r1), "results:", r1[0].reason if r1 else "NONE")

# Test 2: strcpy with guard -> SAFE
code2 = "#include <string.h>\nvoid safe_copy(const char *s) {\n    char buf[32];\n    if (strlen(s) < 32) {\n        strcpy(buf, s);\n    }\n}"
r2 = v.verify(code2)
print("Test2 (guarded strcpy):", len(r2), "results:", [x.verdict.value for x in r2])

# Test 3: memcpy with size > buf -> VULN
code3 = "#include <string.h>\nvoid vuln() {\n    char buf[32];\n    memcpy(buf, src, 64);\n}"
r3 = v.verify(code3)
print("Test3 (memcpy oversized):", len(r3), "results:", r3[0].reason if r3 else "NONE")

# Test 4: snprintf with sizeof -> SAFE
code4 = "#include <stdio.h>\nvoid safe(const char *s) {\n    char buf[32];\n    snprintf(buf, sizeof(buf), \"%s\", s);\n}"
r4 = v.verify(code4)
print("Test4 (snprintf sizeof):", len(r4), "results:", [x.verdict.value for x in r4])

# Test 5: alias detection
code5 = "#include <string.h>\nvoid vuln(const char *s) {\n    char buf[32];\n    char *p = buf;\n    strcpy(p, s);\n}"
r5 = v.verify(code5)
print("Test5 (alias strcpy):", len(r5), "results:", r5[0].reason if r5 else "NONE")

# Test 6: strncpy with sizeof -> SAFE
code6 = "#include <string.h>\nvoid safe(const char *s) {\n    char buf[32];\n    strncpy(buf, s, sizeof(buf) - 1);\n    buf[31] = 0;\n}"
r6 = v.verify(code6)
print("Test6 (strncpy sizeof):", len(r6), "results:", [x.verdict.value for x in r6])

# Test 7: strcat chain -> VULN
code7 = "#include <string.h>\nint main() {\n    char buf[32] = {0};\n    strcat(buf, \"AAAA\");\n    strcat(buf, \"BBBB\");\n    strcat(buf, \"CCCC\");\n    strcat(buf, \"DDDD\");\n    strcat(buf, \"EEEE\");\n}"
r7 = v.verify(code7)
print("Test7 (strcat chain):", len(r7), "results:", r7[0].reason if r7 else "NONE")

# Test 8: recursive with large frame -> VULN
code8 = "#include <stdio.h>\nvoid recurse(int d) {\n    char local[4096];\n    if (d > 0) recurse(d - 1);\n}"
r8 = v.verify(code8)
print("Test8 (recursive):", len(r8), "results:", r8[0].reason if r8 else "NONE")
