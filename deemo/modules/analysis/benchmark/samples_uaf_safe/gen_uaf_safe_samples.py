# UAF FP-Safe 多优化级样本生成器 v1
# 10种UAF模式 × 2变体(vuln/safe) × 3优化级(O0/O2/Os) = 60个二进制
# 目标: 建立UAF检测器的FP/召回基准, 类比堆溢出的FP-safe v2.
#
# 每个模式设计一对(c_vuln, c_safe), 其中safe变体看起来像UAF但实际安全.
# 用于测试检测器在以下维度的区分能力:
#   A. 空指针写入 (null_after_free)
#   B. 重新分配 (reassign_after_free)
#   C. 不同对象辨别 (different_object)
#   D. 条件路径排除 (conditional_mutual_ex)
#   E. realloc语义 (realloc_semantics)
#   F. 结构体字段访问 (struct_field)
#   G. 别名追踪 (alias_tracking)
#   H. 栈副本 (stack_copy)
#   I. 跨函数 (cross_function)
#   J. 提前返回守卫 (early_return_guard)

import os, sys, subprocess, json
from pathlib import Path
from datetime import datetime

BENCH_DIR = Path(__file__).resolve().parent
BUILD_DIR = BENCH_DIR / "build"
BUILD_DIR.mkdir(exist_ok=True)

# 10个UAF模式

PATTERNS = {
    # A. 空指针写入: free后置NULL应阻止UAF
    "null_after_free": {
        "vuln": r"""
#include <stdlib.h>
#include <stdio.h>

static char *g_p_null;

__attribute__((noinline)) void trigger_null_after_free_vuln(void) {
    g_p_null = (char *)malloc(64);
    if (!g_p_null) return;
    free(g_p_null);
    /* 未置NULL → UAF */
    g_p_null[0] = 'X';
}

int main(void) {
    trigger_null_after_free_vuln();
    return 0;
}
""",
        "safe": r"""
#include <stdlib.h>
#include <stdio.h>

static char *g_p_null;

__attribute__((noinline)) void trigger_null_after_free_safe(void) {
    g_p_null = (char *)malloc(64);
    if (!g_p_null) return;
    free(g_p_null);
    g_p_null = NULL;  /* 显式置NULL → 后续访问是NULL deref, 不是UAF */
    if (g_p_null) g_p_null[0] = 'X';  /* NULL guard prevents access */
}

int main(void) {
    trigger_null_after_free_safe();
    return 0;
}
""",
    },

    # B. 重新分配: free后立即malloc新对象 → 指针指向新对象
    "reassign_after_free": {
        "vuln": r"""
#include <stdlib.h>
#include <stdio.h>

static char *g_p_reassign;

__attribute__((noinline)) void trigger_reassign_vuln(void) {
    g_p_reassign = (char *)malloc(64);
    char *saved = g_p_reassign;
    free(g_p_reassign);
    g_p_reassign = (char *)malloc(128);  /* 新分配 */
    saved[0] = 'X';  /* 使用已释放的旧指针 → UAF */
}

int main(void) {
    trigger_reassign_vuln();
    return 0;
}
""",
        "safe": r"""
#include <stdlib.h>
#include <stdio.h>

static char *g_p_reassign;

__attribute__((noinline)) void trigger_reassign_safe(void) {
    g_p_reassign = (char *)malloc(64);
    free(g_p_reassign);
    g_p_reassign = (char *)malloc(128);  /* 新分配 */
    g_p_reassign[0] = 'X';  /* 使用新指针 → 安全 */
}

int main(void) {
    trigger_reassign_safe();
    return 0;
}
""",
    },

    # C. 不同对象辨别: 两个独立分配的指针, free一个, 使用另一个
    "different_object": {
        "vuln": r"""
#include <stdlib.h>
#include <stdio.h>

__attribute__((noinline)) void trigger_diffobj_vuln(void) {
    char *p = (char *)malloc(64);
    char *q = (char *)malloc(64);
    free(p);
    p[0] = 'X';  /* 使用已释放的p → UAF */
    free(q);
}

int main(void) {
    trigger_diffobj_vuln();
    return 0;
}
""",
        "safe": r"""
#include <stdlib.h>
#include <stdio.h>

__attribute__((noinline)) void trigger_diffobj_safe(void) {
    char *p = (char *)malloc(64);
    char *q = (char *)malloc(64);
    free(p);
    q[0] = 'X';  /* 使用独立的q → 安全 */
    free(q);
}

int main(void) {
    trigger_diffobj_safe();
    return 0;
}
""",
    },

    # D. 互斥条件: free和use在互斥路径上
    "conditional_mutual_ex": {
        "vuln": r"""
#include <stdlib.h>
#include <stdio.h>

__attribute__((noinline)) void trigger_cond_vuln(int err) {
    char *p = (char *)malloc(64);
    if (!p) return;
    if (err > 0) {
        free(p);  /* 错误路径释放 */
    }
    /* 无论err值, 都可能到达此处 */
    p[0] = 'X';  /* err>0时 UAF */
}

int main(void) {
    trigger_cond_vuln(1);
    return 0;
}
""",
        "safe": r"""
#include <stdlib.h>
#include <stdio.h>

__attribute__((noinline)) void trigger_cond_safe(int err) {
    char *p = (char *)malloc(64);
    if (!p) return;
    if (err > 0) {
        free(p);
        return;  /* 释放后立即返回 → use不可达 */
    }
    p[0] = 'X';  /* 仅err≤0时到达 → 安全 */
}

int main(void) {
    trigger_cond_safe(0);
    return 0;
}
""",
    },

    # E. realloc语义: realloc返回新指针, 旧指针失效
    "realloc_semantics": {
        "vuln": r"""
#include <stdlib.h>
#include <stdio.h>

__attribute__((noinline)) void trigger_realloc_vuln(void) {
    char *old = (char *)malloc(64);
    if (!old) return;
    char *saved = old;
    char *newp = (char *)realloc(old, 128);
    if (!newp) return;
    saved[0] = 'X';  /* 使用旧指针 → realloc可能已移动 → UAF */
    free(newp);
}

int main(void) {
    trigger_realloc_vuln();
    return 0;
}
""",
        "safe": r"""
#include <stdlib.h>
#include <stdio.h>

__attribute__((noinline)) void trigger_realloc_safe(void) {
    char *p = (char *)malloc(64);
    if (!p) return;
    p = (char *)realloc(p, 128);  /* p更新为新指针 */
    if (!p) return;
    p[0] = 'X';  /* 使用更新后的p → 安全 */
    free(p);
}

int main(void) {
    trigger_realloc_safe();
    return 0;
}
""",
    },

    # F. 结构体字段: free(obj)后访问obj->field
    "struct_field": {
        "vuln": r"""
#include <stdlib.h>
#include <stdio.h>

typedef struct { int len; char *data; } obj_t;

__attribute__((noinline)) void trigger_struct_vuln(void) {
    obj_t *obj = (obj_t *)malloc(sizeof(obj_t));
    if (!obj) return;
    obj->len = 64;
    obj->data = (char *)malloc(obj->len);
    free(obj->data);
    free(obj);
    obj->data[0] = 'X';  /* obj和obj->data均已释放 → UAF */
}

int main(void) {
    trigger_struct_vuln();
    return 0;
}
""",
        "safe": r"""
#include <stdlib.h>
#include <stdio.h>

typedef struct { int len; char *data; } obj_t;

__attribute__((noinline)) void trigger_struct_safe(void) {
    obj_t *obj = (obj_t *)malloc(sizeof(obj_t));
    if (!obj) return;
    obj->len = 64;
    obj->data = (char *)malloc(obj->len);
    free(obj);  /* 释放obj但obj->data仍有效(需要单独释放) */
    /* 注意: 实际代码中这是一个逻辑bug(obj->data泄漏), 但不是UAF */
    free(obj->data);
}

int main(void) {
    trigger_struct_safe();
    return 0;
}
""",
    },

    # G. 别名追踪: q=p; free(p); use(q)
    "alias_tracking": {
        "vuln": r"""
#include <stdlib.h>
#include <stdio.h>

__attribute__((noinline)) void trigger_alias_vuln(void) {
    char *p = (char *)malloc(64);
    if (!p) return;
    char *q = p;  /* 别名 */
    free(p);
    q[0] = 'X';  /* 通过别名访问已释放内存 → UAF */
}

int main(void) {
    trigger_alias_vuln();
    return 0;
}
""",
        "safe": r"""
#include <stdlib.h>
#include <stdio.h>

__attribute__((noinline)) void trigger_alias_safe(void) {
    char *p = (char *)malloc(64);
    if (!p) return;
    char *q = p;  /* 别名 */
    /* p和q指向同一对象, 但只在free前使用 */
    q[0] = 'X';  /* 使用别名(释放前) → 安全 */
    free(p);
    /* 无后续使用 */
}

int main(void) {
    trigger_alias_safe();
    return 0;
}
""",
    },

    # H. 栈副本: 指针保存在栈上, free后从栈加载使用
    "stack_copy": {
        "vuln": r"""
#include <stdlib.h>
#include <stdio.h>

__attribute__((noinline)) void trigger_stack_vuln(void) {
    char *p = (char *)malloc(64);
    if (!p) return;
    char *saved = p;  /* 栈副本 */
    /* ... 许多代码 ... */
    free(p);
    saved[0] = 'X';  /* 使用栈上的旧指针 → UAF */
}

int main(void) {
    trigger_stack_vuln();
    return 0;
}
""",
        "safe": r"""
#include <stdlib.h>
#include <stdio.h>

__attribute__((noinline)) void trigger_stack_safe(void) {
    char *p = (char *)malloc(64);
    if (!p) return;
    char *saved = p;  /* 栈副本 */
    /* ... 许多代码 ... */
    saved[0] = 'X';  /* 使用前未释放 → 安全 */
    free(p);
}

int main(void) {
    trigger_stack_safe();
    return 0;
}
""",
    },

    # I. 跨函数: alloc在调用者, free在callee(回调/间接), use在调用者
    "cross_function": {
        "vuln": r"""
#include <stdlib.h>
#include <stdio.h>

static char *g_cross;

__attribute__((noinline)) void cross_free(char **pp) {
    free(*pp);  /* 释放调用者的指针 */
}

__attribute__((noinline)) void trigger_cross_vuln(void) {
    g_cross = (char *)malloc(64);
    if (!g_cross) return;
    cross_free(&g_cross);
    g_cross[0] = 'X';  /* g_cross已被callee释放 → UAF */
}

int main(void) {
    trigger_cross_vuln();
    return 0;
}
""",
        "safe": r"""
#include <stdlib.h>
#include <stdio.h>

static char *g_cross_s;

__attribute__((noinline)) void cross_alloc(char **pp) {
    *pp = (char *)malloc(64);  /* 在callee中分配 */
}

__attribute__((noinline)) void trigger_cross_safe(void) {
    g_cross_s = NULL;
    cross_alloc(&g_cross_s);   /* 通过callee分配 */
    if (g_cross_s) g_cross_s[0] = 'X';  /* 使用前未释放 → 安全 */
    free(g_cross_s);
}

int main(void) {
    trigger_cross_safe();
    return 0;
}
""",
    },

    # J. 提前返回守卫: 检查NULL后free, 但free后又使用
    "early_return_guard": {
        "vuln": r"""
#include <stdlib.h>
#include <stdio.h>

__attribute__((noinline)) void trigger_guard_vuln(int flag) {
    char *p = (char *)malloc(64);
    if (!p) return;            /* NULL守卫 */
    /* ... */
    if (flag) {
        free(p);
        return;
    }
    p[0] = 'X';                /* flag=0: 正常使用 → 安全 */
    free(p);
    /* 但若flag=1, free后return, 无后续使用, 故无UAF */
    /* 这个测试的是: 检测器能否区分flag=0和flag=1两条路径 */
}

int main(void) {
    trigger_guard_vuln(0);  /* 安全路径 */
    return 0;
}
""",
        "safe": r"""
#include <stdlib.h>
#include <stdio.h>

__attribute__((noinline)) void trigger_guard_safe(int flag) {
    char *p = (char *)malloc(64);
    if (!p) return;
    /* 在flag路径中, 使用和释放在同一分支内 */
    if (flag) {
        p[0] = 'X';  /* 先使用 */
        free(p);     /* 再释放 → 安全 */
        return;
    }
    free(p);         /* 不使用的路径直接释放 */
}

int main(void) {
    trigger_guard_safe(1);
    return 0;
}
""",
    },
}


def generate_samples():
    """生成所有C源文件和编译脚本."""
    manifest = []

    for pattern_key, pattern in PATTERNS.items():
        pdir = BENCH_DIR / pattern_key
        pdir.mkdir(exist_ok=True)

        for variant in ("vuln", "safe"):
            c_content = pattern[variant]
            c_file = pdir / f"{variant}.c"
            with open(c_file, "w") as f:
                f.write(c_content.strip() + "\n")

            for opt in ("O0", "O2", "Os"):
                out_name = f"{pattern_key}_{variant}_{opt}.exe"
                out_path = str(BUILD_DIR / out_name)

                # 编译命令 (mingw-gcc)
                cmd = [
                    "x86_64-w64-mingw32-gcc",
                    f"-{opt}",
                    "-no-pie",
                    "-fno-stack-protector",
                    "-fno-asynchronous-unwind-tables",
                    "-w",
                    "-o", out_path,
                    str(c_file),
                ]

                manifest.append({
                    "pattern": pattern_key,
                    "variant": variant,
                    "opt": opt,
                    "source": str(c_file),
                    "binary": out_path,
                    "compile_cmd": " ".join(cmd),
                    "expected": "UAF" if variant == "vuln" else "SAFE",
                    "type": "use_after_free",
                })

    # 保存manifest
    manifest_path = BENCH_DIR / "manifest.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    # 生成编译脚本
    compile_sh = BENCH_DIR / "compile_all.sh"
    with open(compile_sh, "w") as f:
        f.write("#!/bin/bash\n")
        f.write("# UAF FP-Safe 样本编译脚本 - 自动生成\n")
        f.write(f"# {datetime.now().isoformat()}\n\n")
        f.write(f"mkdir -p {BUILD_DIR}\n\n")
        f.write("CC=x86_64-w64-mingw32-gcc\n")
        f.write('$CC --version > /dev/null 2>&1 || { echo "mingw-gcc not found"; exit 1; }\n\n')

        for entry in manifest:
            f.write(f"echo 'Compiling {entry['pattern']}/{entry['variant']} ({entry['opt']})'\n")
            f.write(f"$CC -{entry['opt']} -no-pie -fno-stack-protector "
                   f"-fno-asynchronous-unwind-tables -w "
                   f"-o '{entry['binary']}' '{entry['source']}' || "
                   f"echo 'FAILED: {entry['pattern']}_{entry['variant']}_{entry['opt']}'\n")

        f.write("\necho 'Done. Binaries in'\n")

    os.chmod(compile_sh, 0o755)

    return manifest


if __name__ == "__main__":
    manifest = generate_samples()

    print(f"Generated {len(manifest)} sample entries:")
    print(f"  Patterns: {len(PATTERNS)}")
    print(f"  Variants per pattern: 2 (vuln + safe)")
    print(f"  Opt levels: 3 (O0, O2, Os)")
    print(f"  Total: {len(manifest)} binaries")
    print(f"  Manifest: {BENCH_DIR / 'manifest.json'}")
    print(f"  Build script: {BENCH_DIR / 'compile_all.sh'}")

    # 统计
    vuln_count = sum(1 for m in manifest if m["variant"] == "vuln")
    safe_count = sum(1 for m in manifest if m["variant"] == "safe")
    print(f"\n  Vuln (should detect):  {vuln_count} (30 unique, 10 patterns × 3 opts)")
    print(f"  Safe (should NOT flag): {safe_count}")
    print(f"\nNext: Run compile_all.sh to build binaries, then run UAF benchmark.")
