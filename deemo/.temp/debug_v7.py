#!/usr/bin/env python3
import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from core.asip_source_detector import _extract_allocs, extract_candidates_v3, _extract_alloc_size_var

# cve_51: malloc(sizeof(struct Small)) → should be small
src51 = """int main() {
    struct Small { int x; int y; };
    struct Small *s = malloc(sizeof(struct Small));
    memcpy(s, data, 32);
    return 0;
}"""
allocs51 = _extract_allocs(src51.strip().split('\n'))
print("cve_51 allocs:", [(a.result_var, a.size_arg) for a in allocs51])

# cve_36: malloc(pkt_len) memcpy(hdr, pkt, pkt_len)
src36 = """int main(int pkt_len) {
    if (pkt_len < 10) return -1;
    char *hdr = malloc(pkt_len);
    memcpy(hdr, pkt, pkt_len);
    return 0;
}"""
allocs36 = _extract_allocs(src36.strip().split('\n'))
sv36 = _extract_alloc_size_var(src36.strip().split('\n'))
print("\ncve_36 allocs:", [(a.result_var, a.size_arg, a.size_is_dynamic) for a in allocs36])
print("  size_vars:", sv36)

# cve_43
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
from core.asip_source_detector import _extract_guard_limits, _extract_clamp_limits, _extract_path_conditions
g43 = _extract_guard_limits(src43.strip().split('\n'))
c43 = _extract_clamp_limits(src43.strip().split('\n'))
p43 = _extract_path_conditions(src43.strip().split('\n'))
print("\ncve_43 guards:", g43, "clamps:", c43, "paths:", p43)
