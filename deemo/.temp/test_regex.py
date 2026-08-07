"""Test bounded API regexes."""
import re

text1 = '    snprintf(buf, sizeof(buf), fmt, s);'
pat = re.compile(r'\bsnprintf\s*\(\s*(\w[\w]*)\s*,\s*(.+?)\s*,', re.DOTALL)
m = pat.search(text1)
print("snprintf sizeof:", m)
if m: print("  target:", m.group(1), "size:", repr(m.group(2)))

text2 = '    strncpy(buf, s, sizeof(buf) - 1);'
pat3 = re.compile(r'\bstrncpy\s*\(\s*(\w[\w]*)\s*,\s*[^,]+,\s*(.+?)\)\s*;', re.DOTALL)
m3 = pat3.search(text2)
print("strncpy sizeof-1:", m3)
if m3: print("  target:", m3.group(1), "size:", repr(m3.group(2)))

text3 = '    memcpy(buf, src, 64);'
pat4 = re.compile(r'\bmemcpy\s*\(\s*(\w[\w]*)\s*,[^,]+,\s*(.+?)\)\s*;', re.DOTALL)
m4 = pat4.search(text3)
print("memcpy const:", m4)
if m4: print("  target:", m4.group(1), "size:", repr(m4.group(2)))

text4 = '    memcpy(buf, src, sz);'
m4b = pat4.search(text4)
print("memcpy var:", m4b)
if m4b: print("  target:", m4b.group(1), "size:", repr(m4b.group(2)))
