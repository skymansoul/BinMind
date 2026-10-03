# -*- coding: utf-8 -*-
"""堆溢出 CVE 基准样本 IR 数据 (A 组: 样本 01-13).

真阳性 + 假阳性组样本的结构化 IR 定义, 供 heap_cve_benchmark 穿越
多层过滤管线评估.
"""

from typing import Any, Dict

SAMPLE_IR_A = {
# TP: 真阳性 (真实堆溢出)
    'cve_sample_01': {
        'is_vuln': True, 'cve': 'CVE-2020-29370',
        'alloc_site': 0x401000, 'write_site': 0x401010,
        'alloc_size': 256, 'write_size': 512,
        'alloc_var': 'max_alloc', 'write_var': 'user_size',
        'taint': 'external_input', 'cross_func': False, 'bounds_check': False,
        'desc': 'kmalloc(256) + memcpy(user_size=512) — 用户可控size',
        'ir_chain': [
            (0x401000, 'mov', 'max_alloc', '0x100', None),  # max_alloc=256
            (0x401004, 'mov', 'arg1', 'max_alloc', None),    # 传参1
            (0x401008, 'call', 'malloc', 'arg1', 'buf'),     # buf=malloc(256)
            (0x40100c, 'mov', 'arg3', 'user_size', None),    # 传参3=user_size (单独来源)
            (0x401010, 'call', 'memcpy', 'buf,src,user_size', None),
        ],
        'def_use': {0x401000: [0x401004], 0x401004: [0x401008]},
    },
    'cve_sample_02': {
        'is_vuln': True, 'cve': 'CVE-2019-9213',
        'alloc_site': 0x401000, 'write_site': 0x401010,
        'alloc_size': 4096, 'write_size': 8192,
        'alloc_var': 'page_sz', 'write_var': 'user_sz',
        'taint': 'external_input', 'cross_func': False, 'bounds_check': False,
        'desc': 'mmap零页绕过 → 用户写入落入内核堆',
        'ir_chain': [
            (0x401000, 'mov', 'page_sz', '0x1000', None),
            (0x401004, 'call', 'mmap', 'page_sz', 'buf'),
            (0x401008, 'mov', 'arg3', 'user_sz', None),
            (0x401010, 'call', 'memcpy', 'buf,src,user_sz', None),
        ],
        'def_use': {},
    },
    'cve_sample_03': {
        'is_vuln': True, 'cve': 'CVE-2021-3156',
        'alloc_site': 0x401000, 'write_site': 0x401018,
        'alloc_size': 0, 'write_size': 0,  # 运行时确定
        'alloc_var': 'alloc_sz', 'write_var': 'actual_sz',
        'taint': 'external_input', 'cross_func': False, 'bounds_check': False,
        'desc': 'sudoedit: alloc=strlen+16, 但转义循环导致实际写入>alloc',
        'ir_chain': [
            (0x401000, 'call', 'strlen', 'input', 'len'),
            (0x401004, 'add', 'alloc_sz', 'len', '0x10'),     # alloc_sz=len+16
            (0x401008, 'call', 'malloc', 'alloc_sz', 'buf'),
            (0x40100c, 'loop', 'actual_sz', 'len', 'escaped'), # actual_sz > len (转义)
            (0x401010, 'mov', 'arg1', 'buf', None),
            (0x401014, 'mov', 'arg3', 'actual_sz', None),
            (0x401018, 'call', 'memcpy', 'buf,src,actual_sz', None),
        ],
        'def_use': {0x401000: [0x401004], 0x401004: [0x401008], 0x40100c: [0x401014]},
    },
    'cve_sample_05': {
        'is_vuln': True, 'cve': 'CVE-2016-10190',
        'alloc_site': 0x401004, 'write_site': 0x401008,
        'alloc_size': 1024, 'write_size': 1536,
        'alloc_var': 'chunk_hdr', 'write_var': 'write_sz',  # write_sz=chunk_hdr+512, VCT不可证≤
        'taint': 'external_input', 'cross_func': False, 'bounds_check': False,
        'desc': 'FFmpeg: malloc(chunk_hdr=1024) + memset(chunk_hdr+512)',
        'ir_chain': [
            (0x401000, 'mov', 'chunk_hdr', '0x400', None),     # 1024
            (0x401002, 'add', 'write_sz', 'chunk_hdr', '0x200'), # +512 → write_sz>chunk_hdr
            (0x401004, 'call', 'malloc', 'chunk_hdr', 'buf'),
            (0x401008, 'call', 'memset', 'buf,0,write_sz', None),
        ],
        'def_use': {0x401000: [0x401002, 0x401004], 0x401002: [0x401008]},
    },
    'cve_sample_06': {
        'is_vuln': True, 'cve': 'CVE-INT-HEAP',
        'alloc_site': 0x401006, 'write_site': 0x401010,
        'alloc_size': 0, 'write_size': 0,
        'alloc_var': 'total', 'write_var': 'total',
        'taint': 'external_input', 'cross_func': False, 'bounds_check': False,
        'desc': '整数溢出→堆: malloc(n*m) 溢出回绕, 分配不足',
        'int_overflow_risk': True,  # mul溢出, VCT不可证安全
        'ir_chain': [
            (0x401000, 'mov', 'n', '0x10000', None),
            (0x401002, 'mov', 'm', '0x10000', None),
            (0x401004, 'mul', 'total', 'n', 'm'),              # 溢出
            (0x401006, 'call', 'malloc', 'total', 'buf'),
            (0x401008, 'mov', 'arg1', 'buf', None),
            (0x40100a, 'mov', 'arg3', 'total', None),
            (0x401010, 'call', 'memcpy', 'buf,src,total', None),
        ],
        'def_use': {0x401000: [0x401004], 0x401002: [0x401004],
                    0x401004: [0x401006, 0x40100a]},
    },
    'cve_sample_07': {
        'is_vuln': True, 'cve': 'CVE-2015-0235',
        'alloc_site': 0x401006, 'write_site': 0x401010,
        'alloc_size': 0, 'write_size': 0,
        'alloc_var': 'new_sz', 'write_var': 'sz',  # realloc缩小→new_sz=sz-4, write仍用sz
        'taint': 'external_input', 'cross_func': False, 'bounds_check': False,
        'desc': 'GHOST: realloc缩小4B, memcpy仍用旧sz',
        'ir_chain': [
            (0x401000, 'add', 'sz', 'len', '8'),               # sz=len+8
            (0x401002, 'call', 'malloc', 'sz', 'buf'),
            (0x401004, 'sub', 'new_sz', 'sz', '4'),             # new_sz=sz-4
            (0x401006, 'call', 'realloc', 'buf,new_sz', 'buf2'),
            (0x401008, 'mov', 'arg1', 'buf2', None),
            (0x40100a, 'mov', 'arg3', 'sz', None),             # 仍用旧sz!
            (0x401010, 'call', 'memcpy', 'buf2,src,sz', None),
        ],
        'def_use': {0x401000: [0x401002, 0x401004, 0x40100a],
                    0x401004: [0x401006]},
    },
    'cve_sample_09': {
        'is_vuln': True, 'cve': 'CVE-2014-0160',
        'alloc_site': 0x401000, 'write_site': 0x401008,
        'alloc_size': 0, 'write_size': 0,
        'alloc_var': 'payload_len', 'write_var': 'payload_len',
        'taint': 'external_input', 'cross_func': False, 'bounds_check': False,
        'desc': 'Heartbleed: malloc(payload_len) 但实际payload更小, memcpy可越界',
        'ir_chain': [
            (0x401000, 'call', 'malloc', 'payload_len', 'buf'),
            (0x401004, 'mov', 'arg1', 'buf', None),
            (0x401006, 'mov', 'arg3', 'payload_len', None),
            (0x401008, 'call', 'memcpy', 'buf,src,payload_len', None),
        ],
        'def_use': {},
    },
    'cve_sample_10': {
        'is_vuln': True, 'cve': 'CVE-MULTIPATH',
        'alloc_site': 0x401000, 'write_site': 0x401014,
        'alloc_size': 128, 'write_size': 256,  # 危险路径
        'alloc_var': 'const_128', 'write_var': 'branch_sz',
        'taint': 'external_input', 'cross_func': False, 'bounds_check': False,
        'desc': '多路径: 安全路径写64B, 危险路径写256B>128B',
        'ir_chain': [
            (0x401000, 'mov', 'const_128', '0x80', None),
            (0x401002, 'call', 'malloc', 'const_128', 'buf'),
            (0x401004, 'cmp', 'mode', '0', None),              # if mode==0
            (0x401008, 'je', 'safe_path', None, None),
            (0x40100c, 'mov', 'branch_sz', '0x100', None),      # 危险:256
            (0x401014, 'call', 'memcpy', 'buf,src,branch_sz', None),
        ],
        'def_use': {0x401000: [0x401002], 0x40100c: [0x401014]},
    },
    'cve_sample_12': {
        'is_vuln': True, 'cve': 'CVE-RECURSIVE',
        'alloc_site': 0x401004, 'write_site': 0x401010,
        'alloc_size': 32, 'write_size': 200,
        'alloc_var': 'const_32', 'write_var': 'plen',
        'taint': 'external_input', 'cross_func': True, 'bounds_check': False,
        'desc': '递归: malloc(32) + memcpy(plen≤256), plen=200>32',
        'ir_chain': [
            (0x401000, 'call', 'malloc', 'sizeof_node', 'node'),
            (0x401004, 'call', 'malloc', 'const_32', 'data_buf'),
            (0x401008, 'mov', 'arg1', 'data_buf', None),
            (0x40100a, 'mov', 'arg3', 'plen', None),
            (0x401010, 'call', 'memcpy', 'data_buf,payload,plen', None),
        ],
        'def_use': {},
    },
    'cve_sample_14': {
        'is_vuln': True, 'cve': 'CVE-2022-0185',
        'alloc_site': 0x401004, 'write_site': 0x401010,
        'alloc_size': 64, 'write_size': 256,
        'alloc_var': 'total', 'write_var': 'snprintf_lim',
        'taint': 'external_input', 'cross_func': False, 'bounds_check': False,
        'desc': 'fsconfig: malloc(64) + snprintf(buf,256,...) — size参数不一致',
        'ir_chain': [
            (0x401000, 'mov', 'total', '0x40', None),
            (0x401004, 'call', 'malloc', 'total', 'buf'),
            (0x401008, 'mov', 'snprintf_lim', '0x100', None),  # 256
            (0x401010, 'call', 'snprintf', 'buf,snprintf_lim,...', None),
        ],
        'def_use': {0x401000: [0x401004]},
    },
    'cve_sample_15': {
        'is_vuln': True, 'cve': 'CVE-2023-0461',
        'alloc_site': 0x401000, 'write_site': 0x401010,
        'alloc_size': 0, 'write_size': 0,
        'alloc_var': 'fixed_sz', 'write_var': 'user_sz',
        'taint': 'external_input', 'cross_func': True, 'bounds_check': False,
        'desc': 'io_uring: fixed buffer refcount → UAF后可溢出',
        'ir_chain': [
            (0x401000, 'call', 'malloc', 'fixed_sz', 'buf'),
            (0x401004, 'call', 'io_register', 'buf', 'ref'),
            (0x401008, 'mov', 'arg1', 'buf', None),
            (0x40100a, 'mov', 'arg3', 'user_sz', None),
            (0x401010, 'call', 'memcpy', 'buf,src,user_sz', None),
        ],
        'def_use': {},
    },
    'cve_sample_16': {
        'is_vuln': True, 'cve': 'CVE-STRCAT',
        'alloc_site': 0x401004, 'write_site': 0x401018,
        'alloc_size': 0, 'write_size': 0,
        'alloc_var': 'alloc', 'write_var': 'actual_total',
        'taint': 'external_input', 'cross_func': False, 'bounds_check': False,
        'desc': 'strcat链: alloc=dir+32, 拼接后总长>alloc',
        'ir_chain': [
            (0x401000, 'call', 'strlen', 'dir', 'dirlen'),
            (0x401002, 'add', 'alloc', 'dirlen', '0x20'),      # +32
            (0x401004, 'call', 'malloc', 'alloc', 'path'),
            (0x401006, 'call', 'strcat', 'path,dir', None),
            (0x401008, 'call', 'strcat', 'path,/', None),
            (0x40100a, 'call', 'strcat', 'path,file', None),
            (0x40100c, 'call', 'strcat', 'path,.', None),
            (0x40100e, 'call', 'strcat', 'path,ext', None),
            (0x401010, 'add', 'actual_total', 'dirlen', 'file_total'),
            (0x401018, 'mov', 'final_len', 'actual_total', None),
        ],
        'def_use': {0x401000: [0x401002], 0x401002: [0x401004], 0x401010: [0x401018]},
    },

# FP: 假阳性 (安全代码, 应被过滤)
    'cve_sample_04': {
        'is_vuln': False, 'cve': 'SAFE-BOUNDS',
        'alloc_site': 0x401000, 'write_site': 0x401010,
        'alloc_size': 256, 'write_size': 128,
        'alloc_var': 'buf_sz', 'write_var': 'capped_sz',
        'taint': 'external_input', 'cross_func': False, 'bounds_check': True,
        'desc': '安全: 边界检查后alloc=256≥write=128',
        'ir_chain': [
            (0x401000, 'mov', 'buf_sz', '0x100', None),
            (0x401002, 'cmp', 'user_sz', '0x100', None),
            (0x401004, 'cmovg', 'capped_sz', '0x100', 'user_sz'), # cap
            (0x401006, 'call', 'malloc', 'buf_sz', 'buf'),
            (0x401010, 'call', 'memcpy', 'buf,src,capped_sz', None),
        ],
        'def_use': {0x401000: [0x401006], 0x401004: [0x401010]},
        'expected_filter': 'L1_value_range',  # alloc≥write → 可证安全
    },
    'cve_sample_08': {
        'is_vuln': False, 'cve': 'SAFE-SAME-VAR',
        'alloc_site': 0x401000, 'write_site': 0x401008,
        'alloc_size': 0, 'write_size': 0,
        'alloc_var': 'size', 'write_var': 'size',
        'taint': 'external_input', 'cross_func': False, 'bounds_check': False,
        'desc': '安全: alloc和write用同一变量size, VCT可证同源',
        'ir_chain': [
            (0x401000, 'mov', 'size', '0x80', None),           # size=128
            (0x401002, 'call', 'malloc', 'size', 'buf'),
            (0x401004, 'mov', 'arg1', 'buf', None),
            (0x401006, 'mov', 'arg3', 'size', None),           # 同一变量
            (0x401008, 'call', 'memcpy', 'buf,src,size', None),
        ],
        'def_use': {0x401000: [0x401002, 0x401006]},          # size→malloc, size→memcpy
        'expected_filter': 'VCT',  # VCT证明malloc(N)和memcpy(N)用同一变量
    },
    'cve_sample_11': {
        'is_vuln': False, 'cve': 'SAFE-INTERNAL',
        'alloc_site': 0x401000, 'write_site': 0x401008,
        'alloc_size': 64, 'write_size': 128,
        'alloc_var': 'buf_sz', 'write_var': 'internal_sz',
        'taint': 'internal_data', 'cross_func': False, 'bounds_check': False,
        'desc': '安全: 内部分配间数据拷贝, 无外部输入',
        'ir_chain': [
            (0x401000, 'mov', 'buf_sz', '0x40', None),
            (0x401002, 'call', 'malloc', 'buf_sz', 'buf1'),
            (0x401004, 'call', 'malloc', '0x80', 'buf2'),
            (0x401006, 'mov', 'internal_sz', '0x80', None),
            (0x401008, 'call', 'memcpy', 'buf1,buf2,internal_sz', None),
        ],
        'def_use': {0x401000: [0x401002]},
        'expected_filter': 'L2_taint',  # 内部数据→降权
    },
    'cve_sample_13': {
        'is_vuln': False, 'cve': 'SAFE-ALLOC-CONSTRAINT',
        'alloc_site': 0x401000, 'write_site': 0x401006,
        'alloc_size': 5, 'write_size': 8,
        'alloc_var': 'small_req', 'write_var': 'write_8',
        'taint': 'external_input', 'cross_func': False, 'bounds_check': False,
        'desc': '安全: malloc(5)→usable=16≥write=8, 分配器约束证明安全',
        'ir_chain': [
            (0x401000, 'mov', 'small_req', '5', None),
            (0x401002, 'call', 'malloc', 'small_req', 'buf'),
            (0x401004, 'mov', 'write_8', '8', None),
            (0x401006, 'call', 'memcpy', 'buf,src,write_8', None),
        ],
        'def_use': {0x401000: [0x401002]},
        'expected_filter': 'L5_constraint',  # 分配器约束 usable=16≥8
    },
}
