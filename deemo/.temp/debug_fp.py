#!/usr/bin/env python3
"""调试v3的FP: 分析SAFE样本为何被检出."""
import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from core.asip_source_detector import (
    extract_candidates_v3, _extract_allocs, _extract_writes,
    _extract_clamps, _extract_guards, _extract_loop_bounds,
)

# cve_11: if(n>64) return; malloc(64); memcpy(buf,src,n)
src11 = """int main(int n) {
    if (n > 64) return;
    char *buf = malloc(64);
    memcpy(buf, src, n);
    return 0;
}"""
lines = src11.strip().split('\n')
allocs = _extract_allocs(lines)
guards = _extract_guards(lines)
print("cve_11 allocs:", allocs)
print("cve_11 guards:", guards)
for a in allocs:
    ws = _extract_writes(lines, a)
    print("  writes:", ws)
cands = extract_candidates_v3(src11)
print("  candidates:", [(c.description, c.confidence) for c in cands])

# cve_17: if(n>64) n=64; malloc(64); memcpy(buf,src,n)
src17 = """int main(int n) {
    if (n > 64) n = 64;
    char *buf = malloc(64);
    memcpy(buf, src, n);
    return 0;
}"""
lines17 = src17.strip().split('\n')
clamps = _extract_clamps(lines17)
guards = _extract_guards(lines17)
print("\ncve_17 clamps:", clamps, "guards:", guards)
cands17 = extract_candidates_v3(src17)
print("  candidates:", [(c.description, c.confidence) for c in cands17])

# cve_13: n = get_size(); if(n>256) n=256; malloc(256); memcpy(buf,src,n)
src13 = """int main() {
    int n = get_size();
    if (n > 256) n = 256;
    char *buf = malloc(256);
    memcpy(buf, src, n);
    return 0;
}"""
cands13 = extract_candidates_v3(src13)
print("\ncve_13 candidates:", [(c.description, c.confidence) for c in cands13])

# cve_32: malloc(64); if(n>64) n=64; memcpy(buf,src,n)
src32 = """int main(int n) {
    char *buf = malloc(64);
    if (n > 64) n = 64;
    memcpy(buf, src, n);
    return 0;
}"""
cands32 = extract_candidates_v3(src32)
print("\ncve_32 candidates:", [(c.description, c.confidence) for c in cands32])

# cve_21: malloc(17); *(int*)(buf+16)=0; — allocator对齐
src21 = """int main() {
    char *buf = malloc(17);
    *(int *)(buf + 16) = 0;
    return 0;
}"""
cands21 = extract_candidates_v3(src21)
print("\ncve_21 candidates:", [(c.description, c.confidence) for c in cands21])

# cve_33: malloc(256); if(len>256) return -1; memcpy(p,data,len)
src33 = """int main(int len) {
    char *p = malloc(256);
    if (len > 256) return -1;
    memcpy(p, data, len);
    return 0;
}"""
cands33 = extract_candidates_v3(src33)
print("\ncve_33 candidates:", [(c.description, c.confidence) for c in cands33])

# cve_55: malloc(64); if(n>1000) n=1000; for(i=0;i<n;i++) buf[i%64]=src[i]
src55 = """int main(int n) {
    if (n > 1000) n = 1000;
    char *buf = malloc(64);
    for (int i = 0; i < n; i++) {
        buf[i % 64] = src[i];
    }
    return 0;
}"""
cands55 = extract_candidates_v3(src55)
print("\ncve_55 candidates:", [(c.description, c.confidence) for c in cands55])
