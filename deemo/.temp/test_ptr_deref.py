#!/usr/bin/env python3
"""测试指针算术写入 — 修复后的完整验证."""
import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from core.source_level_candidate_extractor import extract_candidates_from_code

# 测试3: 指针算术写入 *(buf + 128) = 'B'
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

# 测试5: sudo模式（修复size_arg）
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
print('Test5 (sudo-style): %d candidates' % len(c5))
for c in c5:
    print('  alloc=%s size_arg=%d is_dyn=%s write=%s desc=%s var=%s' % (
        c.alloc_site.alloc_func, c.alloc_site.size_arg,
        c.alloc_site.size_is_dynamic, c.overflow_store.mnemonic,
        c.description, c.alloc_site.result_var))

# 测试6: 复合CVE样本 — memcpy + 指针偏移 + 数组索引
code6 = """
#include <stdlib.h>
#include <string.h>
int process(char *data, size_t len) {
    char *buf = (char*)malloc(256);
    memcpy(buf, data, len);
    buf[len] = '\\0';
    *(buf + 512) = 'X';
    free(buf);
}
"""
c6, _ = extract_candidates_from_code(code6)
print('Test6 (mixed patterns): %d candidates' % len(c6))
for c in c6:
    print('  alloc=%s size=%d write=%s offset=%d offset_dyn=%s desc=%s' % (
        c.alloc_site.alloc_func, c.alloc_site.size_arg,
        c.overflow_store.mnemonic, c.overflow_store.offset,
        c.overflow_store.offset_is_dynamic, c.description))
