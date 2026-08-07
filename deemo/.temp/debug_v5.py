#!/usr/bin/env python3
"""调试剩余9个失败样本."""
import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from core.asip_source_detector import (
    extract_candidates_v3, _extract_allocs, _extract_writes,
    _extract_guard_limits, _extract_clamp_limits, _extract_loop_bounds,
    _extract_modulo_protections, _extract_path_conditions,
    _is_within_slack_space,
)
from analysis.allocator_chunk_model import estimate_chunk_layout

# cve_04: malloc(64) p[64]=0 — off-by-one
print("cve_04: malloc(64) p[64]=0")
layout = estimate_chunk_layout(64, 'malloc')
print(f"  usable={layout.usable_size}, slack={layout.slack_space}")
print(f"  write_end=65, slack_space={layout.slack_space}, alloc//4={64//4}")
print(f"  within_slack={_is_within_slack_space(64, 65)}")

# cve_25: malloc(sizeof(struct S)) s->count=0; memcpy(s->data,src,32)
src25 = """int main() {
    struct S { char data[32]; int count; };
    struct S *s = malloc(sizeof(struct S));
    s->count = 0;
    memcpy(s->data, src, 32);
    return 0;
}"""
cands25 = extract_candidates_v3(src25)
print(f"\ncve_25: candidates={len(cands25)}")
for c in cands25:
    print(f"  {c.description}")

# cve_31: memcpy 64 + buf[64]=0
src31 = """int main() {
    char *buf = malloc(64);
    char *args = get_user_input();
    memcpy(buf, args, 64);
    buf[64] = '\\0';
    return 0;
}"""
cands31 = extract_candidates_v3(src31)
print(f"\ncve_31: candidates={len(cands31)}")
allocs31 = _extract_allocs(src31.strip().split('\n'))
for a in allocs31:
    ws = _extract_writes(src31.strip().split('\n'), a)
    print(f"  writes: {[(s.mnemonic, s.offset, s.store_size, sz) for s, sz in ws]}")
layout31 = estimate_chunk_layout(64, 'malloc')
print(f"  usable={layout31.usable_size}, slack={layout31.slack_space}")
print(f"  write_end=65, within_slack={_is_within_slack_space(64, 65)}")

# cve_34: malloc(argc*8) + loop memcpy(buf+i*16,argv[i],16)
src34 = """int main(int argc, char **argv) {
    char *buf = malloc(argc * 8);
    for (int i = 0; i < argc; i++) {
        memcpy(buf + i * 16, argv[i], 16);
    }
    return 0;
}"""
cands34 = extract_candidates_v3(src34)
print(f"\ncve_34: candidates={len(cands34)}")

# cve_36: malloc(pkt_len) memcpy(hdr,pkt,pkt_len) — SAFE
src36 = """int main(int pkt_len) {
    if (pkt_len < 10) return -1;
    char *hdr = malloc(pkt_len);
    memcpy(hdr, pkt, pkt_len);
    return 0;
}"""
cands36 = extract_candidates_v3(src36)
print(f"\ncve_36: candidates={len(cands36)}")

# cve_37: malloc(32) memcpy@0+24B + memcpy@24+16B
src37 = """int main() {
    char *buf = malloc(32);
    memcpy(buf, src1, 24);
    memcpy(buf + 24, src2, 16);
    return 0;
}"""
cands37 = extract_candidates_v3(src37)
print(f"\ncve_37: candidates={len(cands37)}")
layout37 = estimate_chunk_layout(32, 'malloc')
print(f"  usable={layout37.usable_size}, slack={layout37.slack_space}")
print(f"  write_end=40, within_slack={_is_within_slack_space(32, 40)}")

# cve_38: malloc(sizeof(Header)+64) memcpy(h->data,src,32)
src38 = """int main() {
    struct Header { int type; int len; char data[]; };
    struct Header *h = malloc(sizeof(struct Header) + 64);
    h->len = 32;
    memcpy(h->data, src, 32);
    return 0;
}"""
cands38 = extract_candidates_v3(src38)
print(f"\ncve_38: candidates={len(cands38)}")

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
cands43 = extract_candidates_v3(src43)
print(f"\ncve_43: candidates={len(cands43)}")
g43 = _extract_guard_limits(src43.strip().split('\n'))
c43 = _extract_clamp_limits(src43.strip().split('\n'))
p43 = _extract_path_conditions(src43.strip().split('\n'))
print(f"  guards={g43}, clamps={c43}, paths={p43}")

# cve_55: buf[i%64] = src[i] with clamp n=1000
src55 = """int main(int n) {
    if (n > 1000) n = 1000;
    char *buf = malloc(64);
    for (int i = 0; i < n; i++) {
        buf[i % 64] = src[i];
    }
    return 0;
}"""
cands55 = extract_candidates_v3(src55)
print(f"\ncve_55: candidates={len(cands55)}")
mod55 = _extract_modulo_protections(src55.strip().split('\n'))
print(f"  modulos={mod55}")
