"""批量生成UAF误报诱发样本 (安全代码) + 真实UAF对照样本.

设计依据: 针对 binary_uaf_scanner 的已知误报根源 —
  R1: 路径不敏感 — 分支内 free 与分支外 use 互斥仍被报 (fp_06, 09, 10)
  R2: 无条件 pass_as_arg — free 后指针仅被无害传递 (打印/记录) 被报
  R3: realloc 语义 — realloc 失败分支旧指针仍有效被误标 freed
  R4: 条件置空 — free 后分支内 p=NULL, 分支外 free(p) ≡ free(NULL)

每个 fp_NN 对应一个真实 UAF 对照样本 uaf_NN (同形态但真漏洞),
用于验证改进在消除误报时不损失召回.
"""

import os

BASE = os.path.dirname(os.path.abspath(__file__))

SAMPLES = {
    # 误报诱发 (安全)
    "fp_01_pass_freed_to_printf": {
        "kind": "safe",
        "desc": "free 后指针仅传给 printf(%p) 打印 — 无解引用",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
int main(void) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    sprintf(p, "data");
    printf("[*] %s\n", p);
    free(p);
    printf("[*] freed %p\n", (void *)p);   /* 无害传递: 仅打印地址 */
    return 0;
}
""",
    },
    "fp_02_realloc_fail_keep_old": {
        "kind": "safe",
        "desc": "realloc 失败分支保留旧指针并继续使用 — C 语义合法",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    strcpy(p, "hello");
    char *q = (char *)realloc(p, 4096);
    if (q) {
        p = q;                     /* 成功: 旧指针作废 */
    }
    printf("[*] %s\n", p);         /* 失败路径: p 仍有效 */
    free(p);
    return 0;
}
""",
    },
    "fp_03_cond_null_after_free": {
        "kind": "safe",
        "desc": "free 后条件置空, 之后 free(p) ≡ free(NULL)",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    if (argc > 1) {
        free(p);
        p = NULL;                  /* 分支内置空 */
    }
    free(p);                       /* p==NULL 或未分配 — 均安全 */
    printf("[*] done\n");
    return 0;
}
""",
    },
    "fp_04_branch_mutex_free_use": {
        "kind": "safe",
        "desc": "free 与 use 位于互斥分支 (err 分支释放, 正常分支使用)",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int process(char *p) {
    if (!p) return -1;
    size_t len = strlen(p);
    if (len > 100) {
        free(p);                   /* 超长 → 释放并返回 */
        return -1;
    }
    printf("[*] %s (%zu)\n", p, len);  /* 正常路径使用 — 与 free 互斥 */
    return 0;
}
int main(int argc, char **argv) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    if (argc > 1) strcpy(p, argv[1]);
    else strcpy(p, "short");
    int rc = process(p);
    if (rc == 0) free(p);
    return 0;
}
""",
    },
    "fp_05_cond_free_before_use": {
        "kind": "safe",
        "desc": "条件释放: if (cond) free(p); 之后仅判空使用",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    if (argc > 1) {
        free(p);                   /* 条件释放 */
        p = NULL;
    }
    if (p) printf("[*] %c\n", p[0]);   /* 未释放路径才使用 */
    return 0;
}
""",
    },
    "fp_06_stack_slot_reused": {
        "kind": "safe",
        "desc": "栈槽被新指针覆盖后加载 — 陈旧 freed 标记应清除",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    strcpy(p, "first");
    free(p);
    char *q = (char *)malloc(128);   /* 新对象写入同一栈槽 */
    if (!q) return 1;
    strcpy(q, "second");
    printf("[*] %s\n", q);           /* 使用新对象 — 非 UAF */
    free(q);
    return 0;
}
""",
    },
    "fp_07_free_then_reassign": {
        "kind": "safe",
        "desc": "free 后立即重赋值再使用 — 生命周期完整",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    free(p);
    p = (char *)malloc(64);          /* 重赋值 */
    if (!p) return 1;
    strcpy(p, "new");
    printf("[*] %s\n", p);
    free(p);
    return 0;
}
""",
    },
    "fp_08_wrapper_free_returns": {
        "kind": "safe",
        "desc": "包装函数释放后立即返回 — 调用者不使用返回值",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void cleanup(char *p) {
    if (!p) return;
    free(p);
}
int main(void) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    strcpy(p, "temp");
    cleanup(p);                      /* p 被释放 */
    printf("[*] done\n");            /* 之后不使用 p */
    return 0;
}
""",
    },
    # 真实 UAF 对照 (同形态真漏洞)
    "uaf_01_pass_freed_to_strlen": {
        "kind": "vuln",
        "desc": "free 后指针传给 strlen — 解引用型 UAF",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    strcpy(p, "data");
    free(p);
    printf("[*] len=%zu\n", strlen(p));   /* UAF: strlen 解引用 */
    return 0;
}
""",
    },
    "uaf_02_realloc_then_use_old": {
        "kind": "vuln",
        "desc": "realloc 成功后仍使用旧指针 — 悬空",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    strcpy(p, "hello");
    char *q = (char *)realloc(p, 4096);
    if (!q) return 1;
    printf("[*] %s\n", p);         /* UAF: realloc 成功后旧指针已释放 */
    free(q);
    return 0;
}
""",
    },
    "uaf_03_double_free_same_path": {
        "kind": "vuln",
        "desc": "同路径两次 free — double-free",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
int main(void) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    free(p);
    free(p);                       /* UAF: double free */
    printf("[*] done\n");
    return 0;
}
""",
    },
    "uaf_04_use_after_free_direct": {
        "kind": "vuln",
        "desc": "free 后直接读写 — 经典 UAF",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    strcpy(p, "data");
    free(p);
    p[0] = 'X';                    /* UAF: 写已释放内存 */
    printf("[*] %c\n", p[0]);
    return 0;
}
""",
    },
    "uaf_05_cond_free_then_use": {
        "kind": "vuln",
        "desc": "条件释放后无条件使用 — 释放路径上的 UAF",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    if (argc > 1) {
        free(p);                   /* 条件释放 */
    }
    printf("[*] %s\n", p);         /* UAF: 释放路径仍使用 */
    return 0;
}
""",
    },
    "uaf_06_stack_slot_dangling": {
        "kind": "vuln",
        "desc": "栈槽保存 freed 指针, 之后经栈槽解引用",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    strcpy(p, "data");
    char *saved = p;
    free(p);
    printf("[*] %s\n", saved);     /* UAF: 别名经栈槽使用 */
    return 0;
}
""",
    },
    "uaf_07_struct_field_uaf": {
        "kind": "vuln",
        "desc": "结构体字段指针 freed 后经字段访问",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct node { int id; char *name; };
int main(void) {
    struct node *n = (struct node *)malloc(sizeof(*n));
    if (!n) return 1;
    n->id = 1;
    n->name = (char *)malloc(32);
    if (!n->name) return 1;
    strcpy(n->name, "alice");
    free(n->name);
    printf("[*] %s\n", n->name);   /* UAF: 字段解引用 */
    free(n);
    return 0;
}
""",
    },
    "uaf_08_wrapper_returns_freed": {
        "kind": "vuln",
        "desc": "包装函数释放后返回指针, 调用者解引用",
        "code": r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static char *make_temp(void) {
    char *p = (char *)malloc(64);
    if (!p) return NULL;
    strcpy(p, "temp");
    free(p);                       /* 释放后返回 */
    return p;
}
int main(void) {
    char *p = make_temp();
    if (!p) return 1;
    printf("[*] %s\n", p);         /* UAF: 悬空返回 */
    return 0;
}
""",
    },
}


def write_sample(name, info):
    d = os.path.join(BASE, name)
    os.makedirs(os.path.join(d, "src"), exist_ok=True)
    with open(os.path.join(d, "src", "vuln.c"), "w") as f:
        f.write(info["code"])
    makefile = """CC = gcc
CFLAGS = -Wall -O0 -g -no-pie -fno-stack-protector -z execstack
TARGET = vuln

all: $(TARGET)

$(TARGET): src/vuln.c
\t$(CC) $(CFLAGS) -o $@ $<

clean:
\trm -f $(TARGET)

.PHONY: all clean
"""
    with open(os.path.join(d, "Makefile"), "w") as f:
        f.write(makefile)
    readme = f"""# {name}

- **类型**: {'真实 UAF 漏洞' if info['kind'] == 'vuln' else '良性样本 (UAF 误报诱发)'}
- **描述**: {info['desc']}
- **设计意图**: {'与 fp_ 对应样本同形态的真漏洞, 用于验证召回保持' if info['kind'] == 'vuln' else '诱发既有检测器的路径不敏感/无害传递/realloc 语义误报根源'}
"""
    with open(os.path.join(d, "README.md"), "w") as f:
        f.write(readme)


if __name__ == "__main__":
    for name, info in SAMPLES.items():
        write_sample(name, info)
        print(f"  [OK] {name}")
    print(f"Generated {len(SAMPLES)} UAF samples in {BASE}")
