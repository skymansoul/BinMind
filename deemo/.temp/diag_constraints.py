#!/usr/bin/env python3
"""诊断: 约束收集器对动态大小的追踪情况."""
import sys, re
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from core.source_level_candidate_extractor import extract_candidates_from_code
from core.cj_constraint_collector import collect_constraints

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

candidates, ir_lines = extract_candidates_from_code(code)
for c in candidates:
    print('Candidate:')
    print('  alloc: func=%s size_arg=%d is_dyn=%s size_expr=[%s] result_var=[%s]' % (
        c.alloc_site.alloc_func, c.alloc_site.size_arg,
        c.alloc_site.size_is_dynamic, c.alloc_site.size_expr,
        c.alloc_site.result_var))
    print('  store: mnemonic=%s offset=%d offset_dyn=%s store_size=%d' % (
        c.overflow_store.mnemonic, c.overflow_store.offset,
        c.overflow_store.offset_is_dynamic, c.overflow_store.store_size))
    
    sys_obj = collect_constraints(c, ir_lines, code)
    print('  ConstraintSystem:')
    print('    alloc_var=[%s] alloc_size=%d' % (sys_obj.alloc_var, sys_obj.alloc_size))
    print('    copy_var=[%s] copy_size=%d' % (sys_obj.copy_var, sys_obj.copy_size))
    print('    offset_var=[%s] offset_val=%d' % (sys_obj.offset_var, sys_obj.offset_val))
    print('    loop_var=[%s] loop_bound=%d' % (sys_obj.loop_var, sys_obj.loop_bound))
    print('    mnemonic=[%s] store_size=%d' % (sys_obj.mnemonic, sys_obj.store_size))
    print('    num_constraints=%d' % len(sys_obj.constraints))
    for j, con in enumerate(sys_obj.constraints):
        print('    [%d] %s' % (j, con.description))
