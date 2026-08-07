#!/usr/bin/env python3
"""调试ASIP失败样本的候选提取逻辑."""
import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from core.asip_source_detector import (
    extract_candidates_v2, _extract_allocs, _extract_writes,
    _extract_clamps, _extract_guards, _extract_loop_bounds,
)

# cve_27: malloc(1) + memcpy
src27 = "int main() {\n    char *buf = malloc(1);\n    memcpy(buf, src, 16);\n    return 0;\n}"
allocs = _extract_allocs(src27.split('\n'))
print("cve_27 allocs:", allocs)
for a in allocs:
    ws = _extract_writes(src27.split('\n'), a)
    print("  writes:", ws)
cands = extract_candidates_v2(src27)
print("  cands:", len(cands), cands)

# cve_03: strcpy
src03 = 'int main() {\n    char *buf = malloc(16);\n    strcpy(buf, "long string");\n    return 0;\n}'
allocs = _extract_allocs(src03.split('\n'))
print("\ncve_03 allocs:", allocs)
for a in allocs:
    ws = _extract_writes(src03.split('\n'), a)
    print("  writes:", ws)
cands = extract_candidates_v2(src03)
print("  cands:", len(cands))

# cve_04: p[64] = 0
src04 = "int main() {\n    char *p = malloc(64);\n    p[64] = 0;\n    return 0;\n}"
allocs = _extract_allocs(src04.split('\n'))
print("\ncve_04 allocs:", allocs)
for a in allocs:
    ws = _extract_writes(src04.split('\n'), a)
    print("  writes:", ws)
cands = extract_candidates_v2(src04)
print("  cands:", len(cands))

# cve_06: clamp then memcpy
src06 = "int main(int n) {\n    if (n > 128) n = 128;\n    char *buf = malloc(64);\n    memcpy(buf, src, n);\n    return 0;\n}"
allocs = _extract_allocs(src06.split('\n'))
clamps = _extract_clamps(src06.split('\n'))
guards = _extract_guards(src06.split('\n'))
print("\ncve_06 allocs:", allocs, "clamps:", clamps, "guards:", guards)
cands = extract_candidates_v2(src06)
print("  cands:", len(cands))

# cve_10: pointer write
src10 = "int main() {\n    char *buf = malloc(8);\n    *(int *)(buf + 4) = 0x41414141;\n    *(int *)(buf + 8) = 0x42424242;\n    return 0;\n}"
allocs = _extract_allocs(src10.split('\n'))
print("\ncve_10 allocs:", allocs)
for a in allocs:
    ws = _extract_writes(src10.split('\n'), a)
    print("  writes:", ws)

# cve_09: dynamic alloc
src09 = "int main(int n) {\n    char *buf = malloc(n);\n    memcpy(buf, src, n * 2);\n    return 0;\n}"
allocs = _extract_allocs(src09.split('\n'))
print("\ncve_09 allocs:", allocs)
for a in allocs:
    ws = _extract_writes(src09.split('\n'), a)
    print("  writes:", ws)

# cve_28: calloc(1, 64) - should be SAFE
src28 = "int main() {\n    char *buf = calloc(1, 64);\n    memcpy(buf, src, 32);\n    return 0;\n}"
allocs = _extract_allocs(src28.split('\n'))
print("\ncve_28 allocs:", allocs)

# cve_02: loop write
src02 = "int main(int argc, char **argv) {\n    char *buf = malloc(64);\n    for (int i = 0; i < 128; i++) {\n        buf[i] = argv[1][i];\n    }\n    return 0;\n}"
allocs = _extract_allocs(src02.split('\n'))
loops = _extract_loop_bounds(src02.split('\n'))
print("\ncve_02 allocs:", allocs, "loops:", loops)
for a in allocs:
    ws = _extract_writes(src02.split('\n'), a)
    print("  writes:", ws)
