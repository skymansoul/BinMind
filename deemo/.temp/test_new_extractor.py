#!/usr/bin/env python3
"""测试强化版候选提取器 — 验证3种新写入模式的候选提取."""
import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from core.source_level_candidate_extractor import extract_candidates_from_code

# 测试1: 数组索引写入
code1 = """
#include <stdlib.h>
int main() {
    char *buf = (char*)malloc(64);
    int i;
    for (i = 0; i < 128; i++) {
        buf[i] = 'A';
    }
    free(buf);
}
"""
c1, _ = extract_candidates_from_code(code1)
print('Test1 (array index write): %d candidates' % len(c1))
for c in c1:
    print('  alloc=%s size=%d write=%s offset_dyn=%s desc=%s' % (
        c.alloc_site.alloc_func, c.alloc_site.size_arg,
        c.overflow_store.mnemonic, c.overflow_store.offset_is_dynamic,
        c.description))

# 测试2: sprintf写入
code2 = """
#include <stdlib.h>
#include <stdio.h>
int main() {
    char *buf = (char*)malloc(64);
    sprintf(buf, "%s", long_str);
    free(buf);
}
"""
c2, _ = extract_candidates_from_code(code2)
print('Test2 (sprintf write): %d candidates' % len(c2))
for c in c2:
    print('  alloc=%s size=%d write=%s offset_dyn=%s desc=%s' % (
        c.alloc_site.alloc_func, c.alloc_site.size_arg,
        c.overflow_store.mnemonic, c.overflow_store.offset_is_dynamic,
        c.description))

# 测试3: 指针算术写入
code3 = """
#include <stdlib.h>
int main() {
    char *buf = (char*)malloc(64);
    *(buf + 128) = 'B';
    free(buf);
}
"""
c3, _ = extract_candidates_from_code(code3)
print('Test3 (ptr deref write): %d candidates' % len(c3))
for c in c3:
    print('  alloc=%s size=%d write=%s offset=%d offset_dyn=%s desc=%s' % (
        c.alloc_site.alloc_func, c.alloc_site.size_arg,
        c.overflow_store.mnemonic, c.overflow_store.offset,
        c.overflow_store.offset_is_dynamic, c.description))

# 测试4: 原有memcpy写入（兼容性）
code4 = """
#include <stdlib.h>
#include <string.h>
int main() {
    char *buf = (char*)malloc(64);
    memcpy(buf, src, 128);
    free(buf);
}
"""
c4, _ = extract_candidates_from_code(code4)
print('Test4 (memcpy write - compat): %d candidates' % len(c4))
for c in c4:
    print('  alloc=%s size=%d write=%s offset_dyn=%s desc=%s' % (
        c.alloc_site.alloc_func, c.alloc_site.size_arg,
        c.overflow_store.mnemonic, c.overflow_store.offset_is_dynamic,
        c.description))

# 测试5: CVE-2021-3156 sudo模式 — buf[out++]=cmdline[i]
code5 = """
#include <stdlib.h>
#include <string.h>
int main() {
    size_t alloc_sz = 128;
    char *buf = (char *)malloc(alloc_sz);
    size_t out = 0;
    for (size_t i = 0; i < 255; i++) {
        buf[out++] = 'A';
    }
    buf[out] = '\\0';
    free(buf);
}
"""
c5, _ = extract_candidates_from_code(code5)
print('Test5 (sudo-style buf[out++]=...): %d candidates' % len(c5))
for c in c5:
    print('  alloc=%s size=%d write=%s offset_dyn=%s desc=%s var=%s' % (
        c.alloc_site.alloc_func, c.alloc_site.size_arg,
        c.overflow_store.mnemonic, c.overflow_store.offset_is_dynamic,
        c.description, c.alloc_site.result_var))
