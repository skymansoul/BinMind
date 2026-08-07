#!/usr/bin/env python3
"""调试指针算术写入正则."""
import re

# 当前正则
_ptr_deref_re = re.compile(
    r'\*\s*\(\s*(\w+)\s*\+\s*(\w+|\d+)\s*\)\s*=')

line = "*(buf + 128) = 'B';"
m = _ptr_deref_re.search(line)
print('Current regex match:', m.groups() if m else 'None')

# 问题: 代码预处理后行尾有分号
line2 = "*( buf + 128 ) = 'B';"
m2 = _ptr_deref_re.search(line2)
print('With spaces:', m2.groups() if m2 else 'None')

# 看看实际代码中是什么样
code = """
#include <stdlib.h>
int main() {
    char *buf = (char*)malloc(64);
    *(buf + 128) = 'B';
    free(buf);
}
"""
import re as re_mod
code_clean = re_mod.sub(r'/\*.*?\*/', '', code, flags=re_mod.DOTALL)
code_clean = re_mod.sub(r'//[^\n]*', '', code_clean)
lines = code_clean.strip().split('\n')
ir = [l.strip() for l in lines if l.strip()]
for i, line in enumerate(ir):
    m3 = _ptr_deref_re.search(line)
    print('Line %d: "%s" -> match=%s' % (i, line, m3.groups() if m3 else 'None'))

# 另一个模式: memcpy(buf + offset, ...) 中 buf+offset 是指针算术
# 但这不是 *(ptr+off)=val 赋值形式，而是作为函数参数
# 这种情况下在memcpy中已处理（_parse_dst会解析 buf+N）

# 直接赋值形式: *(buf + 128) = 'B' 
# 另一种形式: buf[128] = 'B' (已被数组索引正则覆盖)

# 关键: 原正则匹配正确，问题可能在_heap_var判断
# 让我验证
sys_path = [r"C:\Users\Administrator\Desktop\BinMind", r"C:\Users\Administrator\Desktop\BinMind\deemo"]
import sys
for p in sys_path:
    if p not in sys.path:
        sys.path.insert(0, p)

from core.source_level_candidate_extractor import _extract_alloc_sites, _is_heap_var

alloc_sites = _extract_alloc_sites(ir, {})
print('alloc_sites:', alloc_sites)
print('is_heap_var("buf"):', _is_heap_var('buf', alloc_sites))
