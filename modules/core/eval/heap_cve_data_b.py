# -*- coding: utf-8 -*-
"""堆溢出 CVE 基准样本 IR 数据 (B 组: 扩展样本 17-20).

边缘场景真阳性/假阳性的结构化 IR 定义.
"""

from typing import Any, Dict

SAMPLE_IR_B = {
# 扩展样本: TP — 边缘场景真阳性
    'cve_sample_17': {
        'is_vuln': True, 'cve': 'CVE-2019-14934',
        'alloc_site': 0x401008, 'write_site': 0x401014,
        'alloc_size': 0, 'write_size': 0,
        'alloc_var': 'total', 'write_var': 'user_len',
        'taint': 'external_input', 'cross_func': False, 'bounds_check': False,
        'desc': 'calloc(nmemb,size) + memcpy(user_len > total) — calloc内部乘但外部memcpy用独立len',
        'ir_chain': [
            (0x401000, 'mov', 'nmemb', 'user_count', None),       # 用户控制nmemb
            (0x401002, 'mov', 'elem_sz', '0x30', None),            # size=48
            (0x401004, 'mov', 'arg1', 'nmemb', None),
            (0x401006, 'mov', 'arg2', 'elem_sz', None),
            (0x401008, 'call', 'calloc', 'nmemb,elem_sz', 'buf'),  # calloc(nmemb,48)
            (0x40100c, 'mov', 'arg1', 'buf', None),
            (0x401010, 'mov', 'arg3', 'user_len', None),           # user_len != nmemb*48
            (0x401014, 'call', 'memcpy', 'buf,src,user_len', None),
        ],
        'def_use': {0x401000: [0x401004], 0x401002: [0x401006]},
    },
    'cve_sample_18': {
        'is_vuln': True, 'cve': 'CVE-2020-10757',
        'alloc_site': 0x401008, 'write_site': 0x401018,
        'alloc_size': 0, 'write_size': 0,
        'alloc_var': 'loop_alloc', 'write_var': 'loop_write',
        'taint': 'external_input', 'cross_func': False, 'bounds_check': False,
        'desc': '循环累加: alloc=64, 循环strcat导致total>64 — 累积溢出',
        'ir_chain': [
            (0x401000, 'mov', 'loop_alloc', '0x40', None),        # alloc=64
            (0x401004, 'call', 'malloc', 'loop_alloc', 'buf'),
            (0x401008, 'mov', 'loop_write', '0', None),           # 累加器初始0
            (0x40100c, 'loop', 'loop_write', 'loop_write', 'slen'), # loop_write += slen
            (0x401010, 'cmp', 'loop_write', 'loop_alloc', None),  # 检查 but too late
            (0x401014, 'mov', 'arg3', 'loop_write', None),        # 写入loop_write>alloc
            (0x401018, 'call', 'strcat', 'buf,src', None),
        ],
        'def_use': {0x401000: [0x401004, 0x401010], 0x401008: [0x40100c],
                    0x40100c: [0x401010, 0x401014]},
    },

# 扩展样本: FP — 边缘场景假阳性 (安全代码)
    'cve_sample_19': {
        'is_vuln': False, 'cve': 'SAFE-REALLOC-GROW',
        'alloc_site': 0x401008, 'write_site': 0x401010,
        'alloc_size': 0, 'write_size': 0,
        'alloc_var': 'new_sz', 'write_var': 'new_sz',
        'taint': 'external_input', 'cross_func': False, 'bounds_check': False,
        'desc': 'realloc(p,new_sz=128) → alloc_size==write_size, VCT应证安全',
        'ir_chain': [
            (0x401000, 'mov', 'orig_sz', '0x40', None),            # 64
            (0x401002, 'call', 'malloc', 'orig_sz', 'p'),
            (0x401004, 'mov', 'new_sz', '0x80', None),             # 128
            (0x401008, 'call', 'realloc', 'p,new_sz', 'p2'),
            (0x40100c, 'mov', 'arg3', 'new_sz', None),             # 用realloc后的size
            (0x401010, 'call', 'memcpy', 'p2,src,new_sz', None),
        ],
        'def_use': {0x401004: [0x401008], 0x401004: [0x40100c]},
        'expected_filter': 'L1.5_VCT',  # realloc大小==写入大小, 同源
    },
    'cve_sample_20': {
        'is_vuln': False, 'cve': 'SAFE-PTR-DIFF-GUARD',
        'alloc_site': 0x401004, 'write_site': 0x401014,
        'alloc_size': 64, 'write_size': 32,
        'alloc_var': 'alloc_sz', 'write_var': 'diff',
        'taint': 'external_input', 'cross_func': False, 'bounds_check': True,
        'desc': 'ptr差值边界检查: end-start≤alloc, write=diff≤alloc → safe',
        'ir_chain': [
            (0x401000, 'mov', 'alloc_sz', '0x40', None),
            (0x401004, 'call', 'malloc', 'alloc_sz', 'buf'),
            (0x401006, 'mov', 'end', 'buf_end', None),
            (0x401008, 'mov', 'start', 'buf_start', None),
            (0x40100a, 'sub', 'diff', 'end', 'start'),             # diff = end-start
            (0x401010, 'cmp', 'diff', 'alloc_sz', None),           # if diff ≤ alloc_sz
            (0x401012, 'mov', 'arg3', 'diff', None),               # write = diff ≤ alloc
            (0x401014, 'call', 'memcpy', 'buf,src,diff', None),
        ],
        'def_use': {0x401000: [0x401004, 0x401010], 0x401006: [0x40100a],
                    0x401008: [0x40100a], 0x40100a: [0x401010, 0x401012]},
        'expected_filter': 'L1_value_range',  # diff=end-start≤alloc, alloc≥write
    },
}
