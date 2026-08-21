# 堆溢出FP倾向性基准样本生成器 (False-Positive-Prone Safe Samples)
# 生成会让Angr/Ghidra等naive工具误报但在我们检测器中
# 被5阶段FP过滤正确消除的安全代码模式.
# 核心: 验证FP过滤管线在真实场景下的有效性.

import json, subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BIN_DIR = ROOT / "bin"
BIN_DIR.mkdir(parents=True, exist_ok=True)

_HEADER = """#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile void *volatile_sink;
#define MK_BARRIER(x) __asm__ __volatile__("" : "+r"(x) : : "memory")

"""

# FP模式定义
# 每种模式包含: name, description, c_code (含vuln/safe两个函数)

FP_PATTERNS = []

# Pattern 1: glibc对齐安全 — malloc(62)实际可用80字节, 写入63字节安全
FP_PATTERNS.append({
    "name": "align_safe",
    "desc": "malloc(62) → glibc chunk=80 usable=64, memcpy 63 bytes → safe",
    "alloc_size": 62, "write_size": 63, "fp_type": "align_boundary",
})

# Pattern 2: bounds check保护 — 写入前通过cmp/jcc检查
FP_PATTERNS.append({
    "name": "bounds_check_safe",
    "desc": "if(len > alloc_sz) return; memcpy(buf, src, len) → safe via bounds check",
    "alloc_size": 256, "write_size": 128, "fp_type": "bounds_check",
})

# Pattern 3: allocation-site correlation — malloc(X) + memcpy(X)
FP_PATTERNS.append({
    "name": "alloc_correlation_safe",
    "desc": "sz=128; p=malloc(sz); memcpy(p, src, sz) → same variable",
    "alloc_size": 128, "write_size": 128, "fp_type": "alloc_correlation",
})

# Pattern 4: struct字段合法访问 — [rbp+0x24]是字段不是溢出
FP_PATTERNS.append({
    "name": "struct_field_safe",
    "desc": "struct {hdr[32]; data[64];} → memcpy(p+32, src, 64) is field access",
    "alloc_size": 96, "write_size": 64, "fp_type": "struct_field",
})

# Pattern 5: realloc扩展 — realloc扩大后再写入, 新大小足够
FP_PATTERNS.append({
    "name": "realloc_safe",
    "desc": "p=malloc(64); p=realloc(p,128); memcpy(p, src, 120) → safe after realloc",
    "alloc_size": 128, "write_size": 120, "fp_type": "realloc_growth",
})

# Pattern 6: 多级bounds check — 双重条件保护
FP_PATTERNS.append({
    "name": "double_bounds_safe",
    "desc": "if(len<0)return; if(len>alloc_sz)len=alloc_sz; memcpy(p,src,len)",
    "alloc_size": 512, "write_size": 256, "fp_type": "double_bounds",
})

# Pattern 7: strncpy边界安全 — strncpy(dst,src,sizeof(dst)-1)
FP_PATTERNS.append({
    "name": "strncpy_safe",
    "desc": "strncpy(p, src, alloc_sz-1) → no overflow (null term has space)",
    "alloc_size": 64, "write_size": 63, "fp_type": "strncpy_nullterm",
})

# Pattern 8: 常量传播安全 — memcpy大小来自已知常量≤分配大小
FP_PATTERNS.append({
    "name": "constant_prop_safe",
    "desc": "#define BUFSZ 256; p=malloc(BUFSZ); memcpy(p,src,128) → const <= alloc",
    "alloc_size": 256, "write_size": 128, "fp_type": "constant_propagation",
})

# Pattern 9: calloc零初始化 — 与malloc同样的边界检查
FP_PATTERNS.append({
    "name": "calloc_safe",
    "desc": "calloc(64,1) → 64 bytes; memcpy(p, src, 64) → safe",
    "alloc_size": 64, "write_size": 64, "fp_type": "calloc_boundary",
})

# Pattern 10: loop累计写入在范围内
FP_PATTERNS.append({
    "name": "loop_accumulate_safe",
    "desc": "p=malloc(256); for(i=0;i<4;i++) memcpy(p+i*64, src, 64) → total=256 OK",
    "alloc_size": 256, "write_size": 64, "fp_type": "loop_accumulate",
})


def _gen_source(name: str, desc: str, alloc_sz: int, write_sz: int,
                vuln_body: str, safe_body: str) -> str:
    return f'''/**
 * FP-Prone Safe Sample: {name}
 * {desc}
 *
 * 对静态分析的挑战:
 *   1. Naive工具只比较 malloc(N) 和 memcpy(M), N<M → FP
 *   2. 需考虑分配器对齐, bounds check, 字段访问, 常量传播等来消除FP
 *   3. O2/Os优化可能改变指令顺序, 打乱数据流分析
 */
{_HEADER}
__attribute__((noinline))
void {name}_vuln(int count) {{
    void *p = malloc({alloc_sz});
    if (!p) return;
    volatile_sink = p;
    MK_BARRIER(count);
{chr(10).join(f'    {l}' for l in vuln_body.split(chr(10)))}
    printf("{name}: vuln done\\n");
}}

__attribute__((noinline))
void {name}_safe(int count) {{
    void *p = malloc({alloc_sz});
    if (!p) return;
    volatile_sink = p;
    MK_BARRIER(count);
{chr(10).join(f'    {l}' for l in safe_body.split(chr(10)))}
    printf("{name}: safe done\\n");
}}

int main(int argc, char **argv) {{
    int count = 65536;
    if (argc > 1) count = atoi(argv[1]);
    printf("FP-prone test: {name}\\n");
    {name}_vuln(count);
    {name}_safe(count);
    return 0;
}}
'''


def gen_align_safe():
    return _gen_source("align_safe",
        "malloc(62)→glibc chunk 80 bytes usable 64, memcpy 63 → safe",
        62,
        63,
        vuln_body="char *src = (char*)malloc(256); memset(src, 'A', 63); memcpy(p, src, 63); free(src);",
        safe_body="char *src = (char*)malloc(256); memset(src, 'A', 62); memcpy(p, src, 62); free(src);")


def gen_bounds_check_safe():
    return _gen_source("bounds_check_safe",
        "if(len>alloc_sz)return; memcpy → safe via bounds check",
        256,
        128,
        vuln_body="int len = count % 256;\n"
                  "    if (len > 256) return;  // naive: len in [0,255] seems safe\n"
                  "    char *src = (char*)malloc(len+128);\n"
                  "    memset(src, 'X', len+128);\n"
                  "    memcpy(p, src, len+128);  // len+128 up to 383, overflow!\n"
                  "    free(src);",
        safe_body="int len = count % 256;\n"
                  "    if (len > 128) return;  // bounds check: len <= 128\n"
                  "    char *src = (char*)malloc(len);\n"
                  "    memset(src, 'X', len);\n"
                  "    memcpy(p, src, len);  // len <= 128 < 256, safe\n"
                  "    free(src);")


def gen_alloc_correlation_safe():
    return _gen_source("alloc_correlation_safe",
        "sz=128; p=malloc(sz); memcpy(p,src,sz) → same variable",
        128,
        128,
        vuln_body="int sz = 128;\n"
                  "    char *src = (char*)malloc(256);\n"
                  "    memset(src, 'A', 256);\n"
                  "    // 注意: sz被修改了但分配大小不变 → 溢出\n"
                  "    sz = count % 64;  // sz现在可能很小\n"
                  "    memcpy(p, src, 256);  // 实际写入256 > alloc 128\n"
                  "    free(src);",
        safe_body="int sz = 128;\n"
                  "    char *src = (char*)malloc(sz);\n"
                  "    memset(src, 'X', sz);\n"
                  "    memcpy(p, src, sz);  // 分配=写入=同一变量sz → 安全\n"
                  "    free(src);")


def gen_struct_field_safe():
    return _gen_source("struct_field_safe",
        "struct{hdr[32];data[64];} memcpy(p+32,src,64) → field access",
        96,
        64,
        vuln_body="typedef struct { char hdr[32]; char data[64]; } Obj;\n"
                  "    Obj *obj = (Obj*)p;\n"
                  "    char *src = (char*)malloc(128);\n"
                  "    memset(src, 'A', 128);\n"
                  "    memcpy(obj->data, src, 128);  // 溢出: data只有64字节\n"
                  "    free(src);",
        safe_body="typedef struct { char hdr[32]; char data[64]; } Obj;\n"
                  "    Obj *obj = (Obj*)p;\n"
                  "    char *src = (char*)malloc(64);\n"
                  "    memset(src, 'X', 64);\n"
                  "    memcpy(obj->data, src, 64);  // 合法字段访问\n"
                  "    free(src);")


def gen_realloc_safe():
    return _gen_source("realloc_safe",
        "p=malloc(64); p=realloc(p,128); memcpy(p,src,120) → safe after realloc",
        128,
        120,
        vuln_body="void *q = realloc(p, 128);\n"
                  "    if (q) p = q;\n"
                  "    char *src = (char*)malloc(256);\n"
                  "    memset(src, 'A', 256);\n"
                  "    memcpy(p, src, 256);  // 溢出: realloc给了128, 写入256\n"
                  "    free(src);",
        safe_body="void *q = realloc(p, 128);\n"
                  "    if (q) p = q;\n"
                  "    char *src = (char*)malloc(120);\n"
                  "    memset(src, 'X', 120);\n"
                  "    memcpy(p, src, 120);  // 在realloc后的128范围内\n"
                  "    free(src);")


def gen_double_bounds_safe():
    return _gen_source("double_bounds_safe",
        "if(len<0)return; if(len>alloc_sz)len=alloc_sz → capped safe",
        512,
        256,
        vuln_body="int len = count % 1024;\n"
                  "    if (len < 0) return;\n"
                  "    if (len > 512) len = 512;  // cap to alloc size\n"
                  "    char *src = (char*)malloc(len);\n"
                  "    memset(src, 'X', len);\n"
                  "    // 分配512, len被cap到512, 但写入用未cap的原始值\n"
                  "    memcpy(p, src, count % 1024);  // 可能溢出!\n"
                  "    free(src);",
        safe_body="int len = count % 512;\n"
                  "    if (len < 0) return;\n"
                  "    if (len > 512) len = 512;\n"
                  "    char *src = (char*)malloc(len);\n"
                  "    memset(src, 'X', len);\n"
                  "    memcpy(p, src, len);  // len被正确cap, 安全\n"
                  "    free(src);")


def gen_strncpy_safe():
    return _gen_source("strncpy_safe",
        "strncpy(p, src, alloc_sz-1) → null terminator有空间",
        64,
        63,
        vuln_body="char *src = (char*)malloc(128);\n"
                  "    memset(src, 'A', 127); src[127] = 0;\n"
                  "    strncpy((char*)p, src, 128);  // write 128 > alloc 64\n"
                  "    free(src);",
        safe_body="char *src = (char*)malloc(63);\n"
                  "    memset(src, 'X', 62); src[62] = 0;\n"
                  "    strncpy((char*)p, src, 63);  // write 63 <= alloc 64, safe\n"
                  "    free(src);")


def gen_constant_prop_safe():
    return _gen_source("constant_prop_safe",
        "#define BUFSZ 256; memcpy(p,src,128) → const 128 <= 256",
        256,
        128,
        vuln_body="enum { BUFSZ = 256 };\n"
                  "    char *src = (char*)malloc(512);\n"
                  "    memset(src, 'A', 512);\n"
                  "    int write_sz = count % 512;  // 不可追踪的变量\n"
                  "    memcpy(p, src, write_sz);  // 可能溢出!\n"
                  "    free(src);",
        safe_body="enum { BUFSZ = 256 };\n"
                  "    char *src = (char*)malloc(BUFSZ);\n"
                  "    memset(src, 'X', 128);\n"
                  "    memcpy(p, src, 128);  // 128是常量, ≤分配大小 → 安全\n"
                  "    free(src);")


def gen_calloc_safe():
    return _gen_source("calloc_safe",
        "calloc(64,1) → 64 bytes; memcpy(p,src,64) → boundary OK",
        64,
        64,
        vuln_body="char *src = (char*)malloc(128);\n"
                  "    memset(src, 'A', 128);\n"
                  "    memcpy(p, src, 128);  // 溢出: 写入128 > alloc 64\n"
                  "    free(src);",
        safe_body="char *src = (char*)malloc(64);\n"
                  "    memset(src, 'X', 64);\n"
                  "    memcpy(p, src, 64);  // 精确边界, 安全\n"
                  "    free(src);")


def gen_loop_accumulate_safe():
    return _gen_source("loop_accumulate_safe",
        "malloc(256); for(i=0;i<4;i++) memcpy(p+i*64,src,64) → total 256 safe",
        256,
        64,
        vuln_body="char *src = (char*)malloc(256);\n"
                  "    memset(src, 'A', 256);\n"
                  "    // 5次迭代 * 64 = 320 > alloc 256 → 溢出\n"
                  "    for (int i = 0; i < 5; i++)\n"
                  "        memcpy((char*)p + i * 64, src, 64);\n"
                  "    free(src);",
        safe_body="char *src = (char*)malloc(256);\n"
                  "    memset(src, 'X', 64);\n"
                  "    // 4次迭代 * 64 = 256 = alloc → 安全\n"
                  "    for (int i = 0; i < 4; i++)\n"
                  "        memcpy((char*)p + i * 64, src, 64);\n"
                  "    free(src);")


_GENERATORS = {
    "align_safe": gen_align_safe,
    "bounds_check_safe": gen_bounds_check_safe,
    "alloc_correlation_safe": gen_alloc_correlation_safe,
    "struct_field_safe": gen_struct_field_safe,
    "realloc_safe": gen_realloc_safe,
    "double_bounds_safe": gen_double_bounds_safe,
    "strncpy_safe": gen_strncpy_safe,
    "constant_prop_safe": gen_constant_prop_safe,
    "calloc_safe": gen_calloc_safe,
    "loop_accumulate_safe": gen_loop_accumulate_safe,
}


def generate_all(compile: bool = True):
    manifest = []

    for pattern in FP_PATTERNS:
        name = pattern["name"]
        gen_fn = _GENERATORS.get(name)
        if not gen_fn:
            continue

        src = gen_fn()
        src_path = ROOT / f"{name}.c"
        src_path.write_text(src, encoding="utf-8")

        for opt in ("O0", "O2", "Os"):
            exe_name = f"{name}_heap_{opt}.exe"
            exe_path = BIN_DIR / exe_name
            compiled = False
            if compile:
                result = subprocess.run(
                    ["gcc", f"-{opt}", "-no-pie", "-fno-pie", "-fno-builtin",
                     "-o", str(exe_path), str(src_path)],
                    capture_output=True, text=True, timeout=30)
                compiled = (result.returncode == 0)
                if not compiled:
                    err = (result.stderr or result.stdout or "")[:200]
                    print(f"  COMPILE ERROR {name} {opt}: {err}")

            manifest.append({
                "name": name,
                "type": "heap_overflow",
                "pattern": pattern["fp_type"],
                "is_fp_prone": True,
                "binary": str(exe_path.resolve()),
                "compiler": "gcc", "opt": opt,
                "compiled": compiled,
                "alloc_size": pattern["alloc_size"],
                "write_size": pattern["write_size"],
                "source": str(src_path.resolve()),
            })

        print(f"  {name} ({pattern['fp_type']}) generated")

    manifest_path = ROOT / "benchmark_fp_safe_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False))
    cc = sum(1 for m in manifest if m["compiled"])
    print(f"\nFP-prone safe manifest: {manifest_path} "
          f"({len(manifest)} entries, {cc} compiled)")
    return manifest


if __name__ == "__main__":
    print(f"Generating {len(FP_PATTERNS)} FP-prone safe heap samples...")
    generate_all(compile=True)
    print("Done.")
