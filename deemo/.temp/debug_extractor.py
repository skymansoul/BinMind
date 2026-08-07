#!/usr/bin/env python3
"""调试强化版候选提取器 — 诊断数组索引和指针算术写入匹配问题."""
import re
import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

# 测试数组索引正则
_array_write_re = re.compile(
    r'(\w+)\s*\[\s*(\w+)(?:\s*\+\s*(\d+))?\s*\]\s*=')

line1 = "buf[i] = 'A';"
m1 = _array_write_re.search(line1)
print('line1 match:', m1.groups() if m1 else 'None')

line2 = "buf[out++] = 'A';"
m2 = _array_write_re.search(line2)
print('line2 match:', m2.groups() if m2 else 'None - post-increment not supported')

# 修正: 支持post-increment
_array_write_re2 = re.compile(
    r'(\w+)\s*\[\s*(\w+)(?:\+\+|--)?\s*\]\s*=')
m3 = _array_write_re2.search(line2)
print('line2 match (with++):', m3.groups() if m3 else 'None')

# 测试指针算术正则
_ptr_deref_re = re.compile(
    r'\*\s*\(\s*(\w+)\s*\+\s*(\w+|\d+)\s*\)\s*=')

line3 = "*(buf + 128) = 'B';"
m4 = _ptr_deref_re.search(line3)
print('line3 match:', m4.groups() if m4 else 'None')

# 关键: 检查_is_heap_var逻辑
from core.source_level_candidate_extractor import (
    extract_candidates_from_code, _is_heap_var, _extract_alloc_sites
)

code = """
#include <stdlib.h>
int main() {
    char *buf = (char*)malloc(64);
    int i;
    buf[i] = 'A';
}
"""
import re as re_mod
code_clean = re_mod.sub(r'/\*.*?\*/', '', code, flags=re_mod.DOTALL)
code_clean = re_mod.sub(r'//[^\n]*', '', code_clean)
lines = code_clean.strip().split('\n')
ir = [l.strip() for l in lines if l.strip()]

alloc_sites = _extract_alloc_sites(ir, {})
print('alloc_sites:', alloc_sites)
print('is_heap_var("buf"):', _is_heap_var('buf', alloc_sites))
