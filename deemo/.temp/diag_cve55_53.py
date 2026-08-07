"""深入诊断cve_55和cve_53"""
import sys, re
from pathlib import Path

sys.path.insert(0, str(Path(r"C:\Users\Administrator\Desktop\BinMind\deemo")))

from analysis.heap_overflow_src_phases import find_allocs, find_writes
from analysis.heap_overflow_src_patterns import _skip_block_comments, parse_alloc_size, _base_var
from analysis.heap_overflow_src_interproc import resolve_factory_allocs, resolve_cross_func_writes, _split_functions

SAMPLE_DIR = Path(r"C:\Users\Administrator\Desktop\BinMind\deemo\tests\cve_samples\heap_overflow")

# cve_55
print("=== cve_55 ===")
d = SAMPLE_DIR / "cve_55_returned_ptr_overflow"
source = (d / "returned_ptr_overflow.c").read_text(encoding="utf-8")
lines = source.splitlines()
valid = {ln for ln, _ in _skip_block_comments(lines)}

allocs = find_allocs(lines, valid)
print("Direct allocs:")
for a in allocs:
    print(f"  L{a.line}: {a.func}({a.size_expr}) -> {a.var} const={a.size_const}")

factory_allocs = resolve_factory_allocs(lines, allocs)
print("Factory allocs:")
for a in factory_allocs:
    print(f"  L{a.line}: {a.func}({a.size_expr}) -> {a.var} const={a.size_const}")

# Check what _find_return_malloc returns
funcs = _split_functions(lines)
for name, (params, body) in funcs.items():
    print(f"  Function '{name}': params={params}, body_lines={len(body)}")
    for i, line in enumerate(body):
        text = line.strip()
        if 'malloc' in text:
            print(f"    body[{i}]: {text}")

# Check parse_alloc_size for "16"
print(f"\nparse_alloc_size('16', lines, 10) = {parse_alloc_size('16', lines, 10)}")

# The issue: resolve_factory_allocs calls parse_alloc_size with sz_expr from
# the call site args, but get_field_buf() has no args - so args is empty
# Let's trace
print("\nTracing resolve_factory_allocs for 'p = get_field_buf();':")
for i, line in enumerate(lines, start=1):
    text = line.strip()
    m = re.search(r'(\w[\w]*)\s*=\s*(\w[\w]*)\s*\(([^)]*)\)\s*;', text)
    if m:
        var = m.group(1)
        callee = m.group(2)
        args_str = m.group(3).strip()
        print(f"  L{i}: var={var} callee={callee} args='{args_str}'")
        if callee in funcs:
            params, body = funcs[callee]
            print(f"    params={params}")
            # _find_return_malloc
            for bl in body:
                bt = bl.strip()
                rm = re.search(
                    r'return\s+(?:\(\s*\w[\w]*\s*\*\s*\)\s*)?'
                    r'(malloc|calloc|realloc)\s*\(([^)]+)\)', bt)
                if rm:
                    func = rm.group(1)
                    args_str2 = rm.group(2).strip()
                    first_arg = args_str2.split(',')[0].strip()
                    print(f"    return {func}({args_str2}), first_arg='{first_arg}'")
                    print(f"    first_arg in params: {first_arg in params}")
                    try:
                        int(first_arg, 0)
                        print(f"    int('{first_arg}',0) = {int(first_arg, 0)}")
                    except ValueError:
                        print(f"    int('{first_arg}',0) fails")
