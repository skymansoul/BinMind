#!/usr/bin/env python3
"""深度诊断: 检查malloc变量名提取和候选配对."""
import re, sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

# Heartbleed 源码
code = """
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef struct {
    uint16_t payload_length;
    unsigned char payload[0];
} heartbeat_t;

int process_heartbeat(unsigned char *pkt, unsigned int pkt_len) {
    if (pkt_len < 3) return -1;
    heartbeat_t *hb = (heartbeat_t *)pkt;
    unsigned int payload_sz = hb->payload_length;
    unsigned int actual_sz = pkt_len - 3;
    unsigned char *response = (unsigned char *)malloc(payload_sz + 16);
    if (!response) return -1;
    memcpy(response + 16, hb->payload, payload_sz);
    free(response);
    return 0;
}
"""

# 预处理
code_clean = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
code_clean = re.sub(r'//[^\n]*', '', code_clean)
lines = code_clean.strip().split('\n')
ir = [l.strip() for l in lines if l.strip()]

for i, line in enumerate(ir):
    print('Line %d: %s' % (i, line))

# 用新提取器提取
from core.source_level_candidate_extractor import extract_candidates_from_code, _extract_alloc_sites

# 测试结构体定义
struct_defs = {}
code_joined = ' '.join(ir)
for sm in re.finditer(r'typedef\s+struct\s*\{([^}]*)\}\s*(\w+)', code_joined):
    struct_defs[sm.group(2)] = sm.group(1)
    print('\nStruct: %s -> %s' % (sm.group(2), sm.group(1)[:60]))

alloc_sites = _extract_alloc_sites(ir, struct_defs)
print('\nAlloc sites:')
for a in alloc_sites:
    print('  pc=%d func=%s size=%d is_dyn=%s var=%s size_str=%s' % (
        a['pc'], a['func'], a['size_arg'], a['is_dyn'], a['var'], a['size_str']))

# 完整提取
candidates, ir_lines = extract_candidates_from_code(code)
print('\nCandidates: %d' % len(candidates))
for c in candidates:
    print('  alloc=%s(%s) var=%s write=%s offset=%d offset_dyn=%s desc=%s' % (
        c.alloc_site.alloc_func, c.alloc_site.size_arg, c.alloc_site.result_var,
        c.overflow_store.mnemonic, c.overflow_store.offset,
        c.overflow_store.offset_is_dynamic, c.description))
