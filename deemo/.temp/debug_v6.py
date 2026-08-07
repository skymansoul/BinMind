#!/usr/bin/env python3
"""调试最后5个失败样本."""
import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from core.asip_source_detector import (
    extract_candidates_v3, _extract_allocs, _extract_writes,
    _extract_guard_limits, _extract_clamp_limits,
    _extract_path_conditions, _extract_alloc_size_var,
)

# cve_25: malloc(sizeof(struct S)) → size=64
# s->count=0; memcpy(s->data, src, 32)
src25 = """int main() {
    struct S { char data[32]; int count; };
    struct S *s = malloc(sizeof(struct S));
    s->count = 0;
    memcpy(s->data, src, 32);
    return 0;
}"""
allocs25 = _extract_allocs(src25.strip().split('\n'))
print("cve_25 allocs:", [(a.result_var, a.size_arg) for a in allocs25])
for a in allocs25:
    ws = _extract_writes(src25.strip().split('\n'), a)
    print("  writes:", [(s.mnemonic, s.offset, s.store_size, sz) for s, sz in ws])
cands25 = extract_candidates_v3(src25)
print("  candidates:", [(c.description, c.overflow_bytes) for c in cands25])

# cve_36: malloc(pkt_len) memcpy(hdr, pkt, pkt_len) — dynamic=dynamic
src36 = """int main(int pkt_len) {
    if (pkt_len < 10) return -1;
    char *hdr = malloc(pkt_len);
    memcpy(hdr, pkt, pkt_len);
    return 0;
}"""
allocs36 = _extract_allocs(src36.strip().split('\n'))
print("\ncve_36 allocs:", [(a.result_var, a.size_arg, a.size_is_dynamic) for a in allocs36])
sv36 = _extract_alloc_size_var(src36.strip().split('\n'))
print("  size_vars:", sv36)
cands36 = extract_candidates_v3(src36)
print("  candidates:", [(c.description, c.overflow_bytes) for c in cands36])

# cve_38: malloc(sizeof(Header)+64) → 96
# h->len=32; memcpy(h->data, src, 32)
src38 = """int main() {
    struct Header { int type; int len; char data[]; };
    struct Header *h = malloc(sizeof(struct Header) + 64);
    h->len = 32;
    memcpy(h->data, src, 32);
    return 0;
}"""
allocs38 = _extract_allocs(src38.strip().split('\n'))
print("\ncve_38 allocs:", [(a.result_var, a.size_arg) for a in allocs38])
for a in allocs38:
    ws = _extract_writes(src38.strip().split('\n'), a)
    print("  writes:", [(s.mnemonic, s.offset, s.store_size, sz) for s, sz in ws])

# cve_43: if(n>0&&n<=256) sz=n; else sz=64; malloc(256); memcpy(buf,src,sz)
src43 = """int main(int n) {
    int sz;
    if (n > 0 && n <= 256) {
        sz = n;
    } else {
        sz = 64;
    }
    char *buf = malloc(256);
    memcpy(buf, src, sz);
    return 0;
}"""
g43 = _extract_guard_limits(src43.strip().split('\n'))
c43 = _extract_clamp_limits(src43.strip().split('\n'))
p43 = _extract_path_conditions(src43.strip().split('\n'))
print("\ncve_43 guards:", g43, "clamps:", c43, "paths:", p43)
cands43 = extract_candidates_v3(src43)
print("  candidates:", [(c.description, c.overflow_bytes) for c in cands43])

# cve_34: malloc(argc*8) + memcpy(buf+i*16, argv[i], 16)
src34 = """int main(int argc, char **argv) {
    char *buf = malloc(argc * 8);
    for (int i = 0; i < argc; i++) {
        memcpy(buf + i * 16, argv[i], 16);
    }
    return 0;
}"""
allocs34 = _extract_allocs(src34.strip().split('\n'))
print("\ncve_34 allocs:", [(a.result_var, a.size_arg, a.size_is_dynamic) for a in allocs34])
