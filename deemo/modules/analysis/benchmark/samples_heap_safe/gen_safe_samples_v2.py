# FP倾向安全样本 v2 - 分离 vuln/safe 为独立二进制
# v1问题: vuln+safe在同一binary中导致检测结果分类困难.
# v2: 每个pattern编译出 _vuln.exe (应检出) 和 _safe.exe (不应检出).

import json, subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BIN_DIR = ROOT / "bin_v2"
BIN_DIR.mkdir(parents=True, exist_ok=True)

_HEADER = """#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile void *volatile_sink;
#define MK_BARRIER(x) __asm__ __volatile__("" : : "r"(x) : "memory")

"""

# 10 FP patterns, 每个生成 _vuln.c + _safe.c 两个独立源文件


def gen_align_safe(is_vuln: bool) -> str:
    # glibc: malloc(62) 的 chunk=80, usable=72. 写 63 实际安全.
    # vuln 须超过 usable 才能真溢出 → 写 80.
    alloc, write_size = (62, 80) if is_vuln else (62, 62)
    desc = "OVERFLOW: memcpy 80 > malloc 62 usable 72" if is_vuln else "SAFE: memcpy 62 <= malloc 62 (glibc align)"
    return f"""/** align_safe_{'vuln' if is_vuln else 'safe'}: {desc} */
{_HEADER}
int main() {{
    void *p = malloc(62);
    if (!p) return 1;
    volatile_sink = p;
    MK_BARRIER(0);
    char *src = (char*)malloc(256);
    memset(src, 'A', {write_size});
    memcpy(p, src, {write_size});
    free(src);
    printf("align_safe: {'vuln' if is_vuln else 'safe'}\\n");
    return 0;
}}
"""


def gen_bounds_check(is_vuln: bool) -> str:
    if is_vuln:
        body = 'int len = 256; if (len > 256) return 1; char *src = malloc(len+128); memset(src,88,len+128); memcpy(p, src, len+128); free(src);'
    else:
        body = 'int len = 128; if (len > 128) return 1; char *src = malloc(len); memset(src,88,len); memcpy(p, src, len); free(src);'
    desc = "OVERFLOW: len+128 bypasses check" if is_vuln else "SAFE: bounds check caps len"
    return f"""/** bounds_check_{'vuln' if is_vuln else 'safe'}: {desc} */
{_HEADER}
int main() {{
    void *p = malloc(256);
    if (!p) return 1;
    volatile_sink = p;
    MK_BARRIER(0);
    {body}
    printf("bounds_check: {'vuln' if is_vuln else 'safe'}\\n");
    return 0;
}}
"""


def gen_alloc_correlation(is_vuln: bool) -> str:
    if is_vuln:
        body = 'int sz = 128; char *src = malloc(256); memset(src,65,256); sz = 16; memcpy(p, src, 256); free(src);'
    else:
        body = 'int sz = 128; char *src = malloc(sz); memset(src,88,sz); memcpy(p, src, sz); free(src);'
    desc = "OVERFLOW: sz modified after alloc" if is_vuln else "SAFE: same variable for alloc+write"
    return f"""/** alloc_correlation_{'vuln' if is_vuln else 'safe'}: {desc} */
{_HEADER}
int main() {{
    void *p = malloc(128);
    if (!p) return 1;
    volatile_sink = p;
    MK_BARRIER(0);
    {body}
    printf("alloc_correlation: {'vuln' if is_vuln else 'safe'}\\n");
    return 0;
}}
"""


def gen_struct_field(is_vuln: bool) -> str:
    if is_vuln:
        body = 'typedef struct { char hdr[32]; char data[64]; } Obj; Obj *obj = (Obj*)p; char *src = malloc(128); memset(src,65,128); memcpy(obj->data, src, 128); free(src);'
    else:
        body = 'typedef struct { char hdr[32]; char data[64]; } Obj; Obj *obj = (Obj*)p; char *src = malloc(64); memset(src,88,64); memcpy(obj->data, src, 64); free(src);'
    desc = "OVERFLOW: 128 > data[64]" if is_vuln else "SAFE: field access within bounds"
    return f"""/** struct_field_{'vuln' if is_vuln else 'safe'}: {desc} */
{_HEADER}
int main() {{
    void *p = malloc(96);
    if (!p) return 1;
    volatile_sink = p;
    MK_BARRIER(0);
    {body}
    printf("struct_field: {'vuln' if is_vuln else 'safe'}\\n");
    return 0;
}}
"""


def gen_realloc(is_vuln: bool) -> str:
    if is_vuln:
        body = 'void *q = realloc(p, 128); if (q) p = q; char *src = malloc(256); memset(src,65,256); memcpy(p, src, 256); free(src);'
    else:
        body = 'void *q = realloc(p, 128); if (q) p = q; char *src = malloc(120); memset(src,88,120); memcpy(p, src, 120); free(src);'
    desc = "OVERFLOW: 256 > realloc 128" if is_vuln else "SAFE: realloc size tracked"
    return f"""/** realloc_{'vuln' if is_vuln else 'safe'}: {desc} */
{_HEADER}
int main() {{
    void *p = malloc(64);
    if (!p) return 1;
    volatile_sink = p;
    MK_BARRIER(0);
    {body}
    printf("realloc: {'vuln' if is_vuln else 'safe'}\\n");
    return 0;
}}
"""


def gen_double_bounds(is_vuln: bool) -> str:
    if is_vuln:
        body = 'int len = 1024; if (len < 0) return 1; if (len > 512) len = 512; char *src = malloc(1024); memset(src,88,1024); memcpy(p, src, 1024); free(src);'
    else:
        body = 'int len = 512; if (len < 0) return 1; if (len > 512) len = 512; char *src = malloc(len); memset(src,88,len); memcpy(p, src, len); free(src);'
    desc = "OVERFLOW: write uses uncapped value" if is_vuln else "SAFE: capped len used for write"
    return f"""/** double_bounds_{'vuln' if is_vuln else 'safe'}: {desc} */
{_HEADER}
int main() {{
    void *p = malloc(512);
    if (!p) return 1;
    volatile_sink = p;
    MK_BARRIER(0);
    {body}
    printf("double_bounds: {'vuln' if is_vuln else 'safe'}\\n");
    return 0;
}}
"""


def gen_strncpy(is_vuln: bool) -> str:
    if is_vuln:
        body = 'char *src = malloc(128); memset(src,65,127); src[127]=0; strncpy((char*)p, src, 128); free(src);'
    else:
        body = 'char *src = malloc(63); memset(src,88,62); src[62]=0; strncpy((char*)p, src, 63); free(src);'
    desc = "OVERFLOW: strncpy 128 > alloc 64" if is_vuln else "SAFE: strncpy 63 <= alloc 64"
    return f"""/** strncpy_{'vuln' if is_vuln else 'safe'}: {desc} */
{_HEADER}
int main() {{
    void *p = malloc(64);
    if (!p) return 1;
    volatile_sink = p;
    MK_BARRIER(0);
    {body}
    printf("strncpy: {'vuln' if is_vuln else 'safe'}\\n");
    return 0;
}}
"""


def gen_constant_prop(is_vuln: bool) -> str:
    if is_vuln:
        body = 'enum { BUFSZ = 256 }; char *src = malloc(512); memset(src,65,512); int ws = 512; memcpy(p, src, ws); free(src);'
    else:
        body = 'enum { BUFSZ = 256 }; char *src = malloc(128); memset(src,88,128); memcpy(p, src, 128); free(src);'
    desc = "OVERFLOW: variable write size 512 > 256" if is_vuln else "SAFE: constant 128 <= BUFSZ 256"
    return f"""/** constant_prop_{'vuln' if is_vuln else 'safe'}: {desc} */
{_HEADER}
int main() {{
    void *p = malloc(256);
    if (!p) return 1;
    volatile_sink = p;
    MK_BARRIER(0);
    {body}
    printf("constant_prop: {'vuln' if is_vuln else 'safe'}\\n");
    return 0;
}}
"""


def gen_calloc(is_vuln: bool) -> str:
    if is_vuln:
        body = 'char *src = malloc(128); memset(src,65,128); memcpy(p, src, 128); free(src);'
    else:
        body = 'char *src = malloc(64); memset(src,88,64); memcpy(p, src, 64); free(src);'
    desc = "OVERFLOW: memcpy 128 > calloc 64" if is_vuln else "SAFE: memcpy 64 = calloc 64"
    alloc_func = "calloc(64, 1)"
    return f"""/** calloc_{'vuln' if is_vuln else 'safe'}: {desc} */
{_HEADER}
int main() {{
    void *p = calloc(64, 1);
    if (!p) return 1;
    volatile_sink = p;
    MK_BARRIER(0);
    {body}
    printf("calloc: {'vuln' if is_vuln else 'safe'}\\n");
    return 0;
}}
"""


def gen_loop_accumulate(is_vuln: bool) -> str:
    if is_vuln:
        body = 'char *src = malloc(256); memset(src,65,256); for (int i=0; i<5; i++) memcpy((char*)p+i*64, src, 64); free(src);'
    else:
        body = 'char *src = malloc(256); memset(src,88,64); for (int i=0; i<4; i++) memcpy((char*)p+i*64, src, 64); free(src);'
    desc = "OVERFLOW: 5*64=320 > alloc 256" if is_vuln else "SAFE: 4*64=256 = alloc 256"
    return f"""/** loop_accumulate_{'vuln' if is_vuln else 'safe'}: {desc} */
{_HEADER}
int main() {{
    void *p = malloc(256);
    if (!p) return 1;
    volatile_sink = p;
    MK_BARRIER(0);
    {body}
    printf("loop_accumulate: {'vuln' if is_vuln else 'safe'}\\n");
    return 0;
}}
"""


_GENERATORS = {
    "align_safe": gen_align_safe,
    "bounds_check_safe": gen_bounds_check,
    "alloc_correlation_safe": gen_alloc_correlation,
    "struct_field_safe": gen_struct_field,
    "realloc_safe": gen_realloc,
    "double_bounds_safe": gen_double_bounds,
    "strncpy_safe": gen_strncpy,
    "constant_prop_safe": gen_constant_prop,
    "calloc_safe": gen_calloc,
    "loop_accumulate_safe": gen_loop_accumulate,
}


def generate_all(compile: bool = True):
    manifest = []

    for name, gen_fn in _GENERATORS.items():
        for is_vuln in (True, False):
            variant = "vuln" if is_vuln else "safe"
            src = gen_fn(is_vuln)
            src_path = ROOT / f"{name}_{variant}.c"
            src_path.write_text(src, encoding="utf-8")

            for opt in ("O0", "O2", "Os"):
                exe_name = f"{name}_{variant}_heap_{opt}.exe"
                exe_path = BIN_DIR / exe_name
                compiled = False
                if compile:
                    result = subprocess.run(
                        ["gcc", f"-{opt}", "-no-pie", "-fno-pie",
                         "-fno-builtin", "-o", str(exe_path), str(src_path)],
                        capture_output=True, text=True, timeout=30)
                    compiled = (result.returncode == 0)
                    if not compiled:
                        err = (result.stderr or result.stdout or "")[:200]
                        print(f"  COMPILE ERROR {name}_{variant} {opt}: {err}")

                manifest.append({
                    "name": f"{name}_{variant}",
                    "type": "heap_overflow",
                    "pattern": name,
                    "is_vuln": is_vuln,
                    "is_fp_prone": not is_vuln,
                    "binary": str(exe_path.resolve()),
                    "compiler": "gcc", "opt": opt,
                    "compiled": compiled,
                    "source": str(src_path.resolve()),
                })

        print(f"  {name} vuln+safe generated")

    manifest_path = ROOT / "benchmark_fp_safe_v2_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False))
    cc = sum(1 for m in manifest if m["compiled"])
    print(f"\nFP-safe v2 manifest: {manifest_path} "
          f"({len(manifest)} entries, {cc} compiled)")
    return manifest


if __name__ == "__main__":
    print(f"Generating FP-prone safe samples v2 (separate vuln/safe binaries)...")
    generate_all(compile=True)
    print("Done.")
