#!/usr/bin/env python3
import sys, re
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from core.asip_source_detector import _ALLOC_RE, _SIZEOF_RE, _parse_alloc_size

src = "struct S *s = malloc(sizeof(struct S));"
m = _ALLOC_RE.search(src)
if m:
    print("alloc match:")
    print(f"  result_var={m.group(1)}")
    print(f"  func={m.group(2)}")
    print(f"  raw_args='{m.group(3)}'")
    size, is_dyn = _parse_alloc_size(m.group(2).lower(), m.group(3).strip())
    print(f"  size={size}, is_dynamic={is_dyn}")
