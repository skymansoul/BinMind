# 分配-写关联 验证样本生成器 - 同源分配-写入关联测试集
#
# 目标: 量化 分配-写关联 (Allocation-Write Co-Sourcing) 引擎对
# "分配大小 = 写入大小且同根来源" 类误报的过滤能力.
# 此类样本 Angr/Ghidra 等符号执行/函数名匹配工具误报率极高
# (无法判定 N 和 M 来自同一变量), 是堆溢出检测误报的主要来源.
#
# 每组样本编译 vuln (真溢出, 应检出) 与 safe (同源安全, 应过滤) 两个二进制:
#   awsc_same_var:      malloc(sz); memcpy(p, src, sz)          → safe
#                       malloc(sz); memcpy(p, src, sz+128)      → vuln
#   awsc_param_flow:    size 经函数参数/栈槽传播后同时用于分配与写入
#   awsc_calc_same:     len = n*4; malloc(len); memcpy(p, src, len)
#   awsc_off_by_k:      malloc(sz); memcpy(p, src, sz+k), k<padding → safe
#                       k>padding → vuln
#   awsc_loop_fill:     循环逐段写入累计=分配 → safe; 累计>分配 → vuln
#
# 判定依据: 分配-写关联引擎后向根来源追踪, 若 alloc_root == write_root
# 且 write_const <= alloc_const → SAFE; 若偏移超过 padding → 溢出.

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BIN_DIR = ROOT / "bin"
BIN_DIR.mkdir(parents=True, exist_ok=True)

_HEADER = """#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char payload[8192];
"""


def gen_same_var(is_vuln: bool) -> str:
    ws = "sz + 128" if is_vuln else "sz"
    desc = "OVERFLOW: write sz+128 > alloc sz" if is_vuln \
        else "SAFE: write sz == alloc sz (same variable)"
    return f"""/** awsc_same_var_{'vuln' if is_vuln else 'safe'}: {desc} */
{_HEADER}
void f(void) {{
    volatile unsigned int sz = 256;
    char *buf = (char *)malloc(sz);
    if (!buf) return;
    memcpy(buf, payload, {ws});
    free(buf);
    printf("done\\n");
}}
int main(void) {{ memset(payload,'A',sizeof(payload)); f(); return 0; }}
"""


def gen_param_flow(is_vuln: bool) -> str:
    ws = "s2 + 64" if is_vuln else "s2"
    desc = "OVERFLOW: write s2+64 > alloc s2 (param flow)" if is_vuln \
        else "SAFE: write s2 == alloc s2 (param flow)"
    return f"""/** awsc_param_flow_{'vuln' if is_vuln else 'safe'}: {desc} */
{_HEADER}
void f(int n) {{
    /* n 经局部变量传播后同时用于分配与写入 */
    int s1 = n * 4;
    int s2 = s1;
    char *buf = (char *)malloc(s2);
    if (!buf) return;
    memcpy(buf, payload, {ws});
    free(buf);
    printf("done\\n");
}}
int main(void) {{ memset(payload,'A',sizeof(payload)); f(64); return 0; }}
"""


def gen_calc_same(is_vuln: bool) -> str:
    ws = "len + 1" if is_vuln else "len"
    desc = "OVERFLOW: write len+1 > alloc len" if is_vuln \
        else "SAFE: write len == alloc len (calc)"
    return f"""/** awsc_calc_same_{'vuln' if is_vuln else 'safe'}: {desc} */
{_HEADER}
void f(int n) {{
    size_t len = (size_t)n * 4;
    char *buf = (char *)malloc(len);
    if (!buf) return;
    memcpy(buf, payload, {ws});
    free(buf);
    printf("done\\n");
}}
int main(void) {{ memset(payload,'A',sizeof(payload)); f(64); return 0; }}
"""


def gen_off_by_k(is_vuln: bool) -> str:
    # 请求 62 → glibc usable 72. off=8 安全(对齐padding), off=32 溢出.
    off = 32 if is_vuln else 8
    desc = f"OVERFLOW: write sz+{off} > usable" if is_vuln \
        else f"SAFE: write sz+{off} within glibc padding"
    return f"""/** awsc_off_by_k_{'vuln' if is_vuln else 'safe'}: {desc} */
{_HEADER}
void f(void) {{
    volatile unsigned int sz = 62;
    char *buf = (char *)malloc(sz);
    if (!buf) return;
    memcpy(buf, payload, sz + {off});
    free(buf);
    printf("done\\n");
}}
int main(void) {{ memset(payload,'A',sizeof(payload)); f(); return 0; }}
"""


def gen_loop_fill(is_vuln: bool) -> str:
    # 循环逐段写入, 累计 = 分配大小.
    iters = 5 if is_vuln else 4  # 5*64=320 > 256; 4*64=256 == 256
    desc = "OVERFLOW: loop cumulative 5*64 > alloc 256" if is_vuln \
        else "SAFE: loop cumulative 4*64 == alloc 256"
    return f"""/** awsc_loop_fill_{'vuln' if is_vuln else 'safe'}: {desc} */
{_HEADER}
void f(void) {{
    char *buf = (char *)malloc(256);
    if (!buf) return;
    for (int i = 0; i < {iters}; i++) {{
        memcpy(buf + i * 64, payload, 64);
    }}
    free(buf);
    printf("done\\n");
}}
int main(void) {{ memset(payload,'A',sizeof(payload)); f(); return 0; }}
"""


_GENERATORS = {
    "awsc_same_var": gen_same_var,
    "awsc_param_flow": gen_param_flow,
    "awsc_calc_same": gen_calc_same,
    "awsc_off_by_k": gen_off_by_k,
    "awsc_loop_fill": gen_loop_fill,
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
                exe_name = f"{name}_{variant}_{opt}.exe"
                exe_path = BIN_DIR / exe_name
                compiled = False
                if compile:
                    r = subprocess.run(
                        ["gcc", f"-{opt}", "-no-pie", "-fno-pie",
                         "-fno-builtin", "-o", str(exe_path), str(src_path)],
                        capture_output=True, text=True, timeout=30)
                    compiled = (r.returncode == 0)
                    if not compiled:
                        print(f"  COMPILE ERR {name}_{variant} {opt}: "
                              f"{(r.stderr or '')[:120]}")
                manifest.append({
                    "name": f"{name}_{variant}",
                    "type": "heap_overflow",
                    "pattern": name,
                    "is_vuln": is_vuln,
                    "binary": str(exe_path.resolve()),
                    "opt": opt,
                    "compiled": compiled,
                    "source": str(src_path.resolve()),
                })
        print(f"  {name} vuln+safe generated")

    out = ROOT / "alloc_write_manifest.json"
    out.write_text(json.dumps(manifest, indent=2, ensure_ascii=False))
    cc = sum(1 for m in manifest if m["compiled"])
    print(f"alloc_write_manifest.json: {len(manifest)} entries, {cc} compiled")


if __name__ == "__main__":
    generate_all(compile=True)
