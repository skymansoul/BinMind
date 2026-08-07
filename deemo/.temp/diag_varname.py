#!/usr/bin/env python3
"""诊断变量名提取正则匹配问题."""
import re

# 当前正则
var_re = re.compile(r'\w+[\s*]+(\w+)\s*=\s*\(?.*?\)?\s*malloc')

# 测试各种声明形式
test_lines = [
    "char *buf = (char*)malloc(64);",
    "char *response = (unsigned char *)malloc(payload_sz + 16);",
    "unsigned char *buf = (unsigned char *)malloc(alloc_sz);",
    "char *new_buf = (char *)realloc(buffer, needed);",
    "scatterlist_t *sg_list = (scatterlist_t *)data_buf;",
    "uint8_t *map_val = (uint8_t *)malloc(MAP_VALUE_SIZE);",
    "poly1305_ctx *ctx = (poly1305_ctx *)calloc(1, sizeof(poly1305_ctx));",
    "char *channel_buf = (char *)malloc(window_sz);",
]

for line in test_lines:
    m = var_re.search(line)
    if m:
        print(f"OK: var={m.group(1)} <- {line}")
    else:
        print(f"FAIL: {line}")
        # 尝试简单匹配
        m2 = re.search(r'(\w+)\s*=\s*\(.*?\)\s*malloc', line)
        if m2:
            print(f"  -> simple match: var={m2.group(1)}")
        else:
            print(f"  -> no match at all")
