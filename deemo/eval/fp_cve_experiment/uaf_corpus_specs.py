"""UAF 语料库规格 — 15个UAF样本 + 15个安全样本.

创建: 2026-08-08
设计决策:
  - TP 样本覆盖真实 UAF 形态: 直接释放后用、跨函数、别名、条件释放、
    循环释放、realloc、信号处理、线程模拟、结构体字段、函数指针等.
  - FP 样本覆盖误报模式: 分支互斥(if/else 各自 free/use)、释放后置NULL、
    释放后重新赋值、use先于free(地址序陷阱)、NULL检查(不构成防护, 仍应
    检出, 置于TP侧验证不过滤)、释放后只读全局、独立对象等.
  - truth: expected_vuln + mode 描述误报/检出模式.
"""

UAF_TP_SAMPLES = [
    {
        'id': 'uaf_tp_01_direct',
        'mode': '直接释放后立即解引用',
        'src': r'''
/* UAF-TP-01: free(p) 后直接 p[0] 写入. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *p = (char *)malloc(16);
    if (!p) return 1;
    memcpy(p, "hello", 6);
    free(p);
    p[0] = 'X';
    printf("%c\n", p[0]);
    return 0;
}
''',
    },
    {
        'id': 'uaf_tp_02_alias',
        'mode': '别名指针 q 与 p 指向同一对象, free(p) 后经 q 使用',
        'src': r'''
/* UAF-TP-02: p/q 别名, free(p) 后 q[0] 写入. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *p = (char *)malloc(32);
    char *q = p;
    if (!p) return 1;
    strcpy(q, "alias");
    free(p);
    q[0] = 'Y';
    printf("%s\n", q);
    return 0;
}
''',
    },
    {
        'id': 'uaf_tp_03_cross_fn',
        'mode': '跨函数: alloc_fn 返回指针, free_fn 释放, use_fn 使用',
        'src': r'''
/* UAF-TP-03: free_fn(p) 后 use_fn(p) 解引用. */
#include <stdlib.h>
#include <stdio.h>

char *alloc_fn(void) { return (char *)malloc(64); }
void free_fn(char *p) { free(p); }
void use_fn(char *p) { p[0] = 'Z'; }

int main(void) {
    char *p = alloc_fn();
    if (!p) return 1;
    free_fn(p);
    use_fn(p);
    printf("%c\n", p[0]);
    return 0;
}
''',
    },
    {
        'id': 'uaf_tp_04_cond_free',
        'mode': '条件释放后无条件使用',
        'src': r'''
/* UAF-TP-04: if(cond) free(p); 之后无条件 p[0] 读. */
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv) {
    (void)argv;
    char *p = (char *)malloc(16);
    if (!p) return 1;
    if (argc > 1) {
        free(p);
    }
    printf("%d\n", p[0]);
    free(p);
    return 0;
}
''',
    },
    {
        'id': 'uaf_tp_05_struct_field',
        'mode': '结构体字段指针 free 后字段访问',
        'src': r'''
/* UAF-TP-05: obj->buf free 后 obj->buf[0] 访问. */
#include <stdlib.h>
#include <stdio.h>

typedef struct {
    int id;
    char *buf;
} obj_t;

int main(void) {
    obj_t *o = (obj_t *)malloc(sizeof(obj_t));
    if (!o) return 1;
    o->id = 1;
    o->buf = (char *)malloc(8);
    if (!o->buf) return 1;
    o->buf[0] = 'A';
    free(o->buf);
    o->buf[0] = 'B';
    printf("%d %c\n", o->id, o->buf[0]);
    free(o);
    return 0;
}
''',
    },
    {
        'id': 'uaf_tp_06_realloc',
        'mode': 'realloc 失败后旧指针使用 (悬垂)',
        'src': r'''
/* UAF-TP-06: realloc 缩小后按旧偏移继续写入 (悬垂语义简化). */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    strcpy(p, "before");
    free(p);
    char *q = (char *)malloc(64);
    if (!q) return 1;
    memcpy(q, "after", 6);
    free(q);
    p[0] = 'R';
    printf("%c\n", p[0]);
    return 0;
}
''',
    },
    {
        'id': 'uaf_tp_07_func_ptr',
        'mode': '释放后经函数指针调用',
        'src': r'''
/* UAF-TP-07: 函数指针表释放后调用. */
#include <stdlib.h>
#include <stdio.h>

typedef void (*handler_t)(void);
void h1(void) { printf("h1\n"); }

int main(void) {
    handler_t *tab = (handler_t *)malloc(2 * sizeof(handler_t));
    if (!tab) return 1;
    tab[0] = h1;
    free(tab);
    tab[0]();
    return 0;
}
''',
    },
    {
        'id': 'uaf_tp_08_loop_free',
        'mode': '循环内释放, 循环后使用',
        'src': r'''
/* UAF-TP-08: for 循环内 free(p), 循环后 p[0] 使用. */
#include <stdlib.h>
#include <stdio.h>

int main(void) {
    char *p = (char *)malloc(16);
    if (!p) return 1;
    for (int i = 0; i < 3; i++) {
        if (i == 2) free(p);
    }
    p[0] = 'L';
    printf("%c\n", p[0]);
    return 0;
}
''',
    },
    {
        'id': 'uaf_tp_09_double_free',
        'mode': 'double free (同类时序缺陷)',
        'src': r'''
/* UAF-TP-09: 同一指针两次 free. */
#include <stdlib.h>
#include <stdio.h>

int main(void) {
    char *p = (char *)malloc(8);
    if (!p) return 1;
    free(p);
    free(p);
    return 0;
}
''',
    },
    {
        'id': 'uaf_tp_10_stack_reload',
        'mode': '释放后从栈槽重载指针再使用',
        'src': r'''
/* UAF-TP-10: free 后 mov rax,[rbp-8] 重载并写入. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *p = (char *)malloc(24);
    if (!p) return 1;
    memset(p, 'a', 8);
    free(p);
    char *r = p;
    r[0] = 'c';
    printf("%c\n", r[0]);
    return 0;
}
''',
    },
    {
        'id': 'uaf_tp_11_global_dangle',
        'mode': '全局指针释放后其他函数使用',
        'src': r'''
/* UAF-TP-11: 全局指针 g 释放后 use_global 解引用. */
#include <stdlib.h>
#include <stdio.h>

static char *g;
void init_global(void) { g = (char *)malloc(16); }
void free_global(void) { free(g); }
void use_global(void) { g[0] = 'G'; }

int main(void) {
    init_global();
    if (!g) return 1;
    free_global();
    use_global();
    printf("%c\n", g[0]);
    return 0;
}
''',
    },
    {
        'id': 'uaf_tp_12_null_check',
        'mode': 'NULL检查后使用 (语义修正: NULL检查不构成防护)',
        'src': r'''
/* UAF-TP-12: free(p) 后 if(p) p[0] 使用 — NULL检查不防护, 必须检出. */
#include <stdlib.h>
#include <stdio.h>

int main(void) {
    char *p = (char *)malloc(16);
    if (!p) return 1;
    free(p);
    if (p) {
        p[0] = 'N';
    }
    printf("%d\n", p[0]);
    return 0;
}
''',
    },
    {
        'id': 'uaf_tp_13_guard_free_use',
        'mode': '守卫分支中 free, 守卫外使用',
        'src': r'''
/* UAF-TP-13: if(len>10) free(p); 随后无条件 p[0] 写入. */
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv) {
    int len = argc > 1 ? 20 : 5;
    char *p = (char *)malloc(32);
    if (!p) return 1;
    if (len > 10) {
        free(p);
    }
    p[0] = 'Q';
    printf("%c\n", p[0]);
    return 0;
}
''',
    },
    {
        'id': 'uaf_tp_14_io_uring_style',
        'mode': '异步风格: 释放后经结构体回调使用',
        'src': r'''
/* UAF-TP-14: req 释放后, 其内嵌回调数据被读取. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct {
    int kind;
    char payload[8];
} req_t;

int main(void) {
    req_t *req = (req_t *)malloc(sizeof(req_t));
    if (!req) return 1;
    req->kind = 7;
    memset(req->payload, 'p', 8);
    free(req);
    req->kind = 9;
    printf("%d\n", req->kind);
    return 0;
}
''',
    },
    {
        'id': 'uaf_tp_15_thread_sim',
        'mode': '线程竞争模拟: free 后另一"线程函数"使用',
        'src': r'''
/* UAF-TP-15: worker(p) 在 release(p) 之后解引用 p. */
#include <stdlib.h>
#include <stdio.h>

void release(char *p) { free(p); }
void worker(char *p) { p[0] = 'W'; }

int main(void) {
    char *p = (char *)malloc(16);
    if (!p) return 1;
    release(p);
    worker(p);
    printf("%c\n", p[0]);
    return 0;
}
''',
    },
]

UAF_FP_SAMPLES = [
    {
        'id': 'uaf_fp_01_exclusive_branch',
        'mode': 'if/else 分支互斥: free 与 use 不同时执行',
        'src': r'''
/* 安全: if/else 互斥 — free 与 use 各自独占一个分支. */
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv) {
    (void)argv;
    char *p = (char *)malloc(16);
    if (!p) return 1;
    if (argc > 1) {
        free(p);
    } else {
        p[0] = 'S';
        printf("%c\n", p[0]);
        free(p);
    }
    return 0;
}
''',
    },
    {
        'id': 'uaf_fp_02_null_after_free',
        'mode': '释放后置 NULL, 后续 if(p) 防护',
        'src': r'''
/* 安全: free 后 p=NULL, 后续使用被 NULL 检查拦截. */
#include <stdlib.h>
#include <stdio.h>

int main(void) {
    char *p = (char *)malloc(16);
    if (!p) return 1;
    free(p);
    p = 0;
    if (p) {
        p[0] = 'X';
    }
    return 0;
}
''',
    },
    {
        'id': 'uaf_fp_03_reassign',
        'mode': '释放后重新分配, 新对象使用',
        'src': r'''
/* 安全: free(p) 后 p 重新 malloc, 后续使用新对象. */
#include <stdlib.h>
#include <stdio.h>

int main(void) {
    char *p = (char *)malloc(16);
    if (!p) return 1;
    free(p);
    p = (char *)malloc(16);
    if (!p) return 1;
    p[0] = 'R';
    printf("%c\n", p[0]);
    free(p);
    return 0;
}
''',
    },
    {
        'id': 'uaf_fp_04_use_before_free',
        'mode': 'use 先于 free (地址序: free 在前才构成候选)',
        'src': r'''
/* 安全: 写入发生在 free 之前, 线性序正确. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *p = (char *)malloc(16);
    if (!p) return 1;
    strcpy(p, "first");
    printf("%s\n", p);
    free(p);
    return 0;
}
''',
    },
    {
        'id': 'uaf_fp_05_independent_objs',
        'mode': '两个独立对象, free(a) 后写 b',
        'src': r'''
/* 安全: a/b 独立对象, 释放 a 后写入 b. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *a = (char *)malloc(16);
    char *b = (char *)malloc(16);
    if (!a || !b) return 1;
    strcpy(a, "aaaa");
    strcpy(b, "bbbb");
    free(a);
    b[0] = 'B';
    printf("%s\n", b);
    free(b);
    return 0;
}
''',
    },
    {
        'id': 'uaf_fp_06_early_return_use',
        'mode': '提前返回路径上的使用 (不经过 free)',
        'src': r'''
/* 安全: use 在不经过 free 的提前返回路径上. */
#include <stdlib.h>
#include <stdio.h>

int process(char *p, int flag) {
    if (flag) {
        return p[0];
    }
    free(p);
    return 0;
}

int main(void) {
    char *p = (char *)malloc(16);
    if (!p) return 1;
    int r = process(p, 1);
    free(p);
    printf("%d\n", r);
    return 0;
}
''',
    },
    {
        'id': 'uaf_fp_07_guard_free_use_excl',
        'mode': '同一守卫控制 free 与 use (二者同真同假)',
        'src': r'''
/* 安全: if(flag){free}else{use} 经同一守卫互斥. */
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv) {
    int flag = argc > 1;
    char *p = (char *)malloc(16);
    if (!p) return 1;
    if (flag) {
        free(p);
    } else {
        p[0] = 'S';
        printf("%c\n", p[0]);
        free(p);
    }
    return 0;
}
''',
    },
    {
        'id': 'uaf_fp_08_use_in_loop_before_free',
        'mode': '循环内使用均在 free 之前',
        'src': r'''
/* 安全: 循环写入全部在 free 之前. */
#include <stdlib.h>
#include <stdio.h>

int main(void) {
    char *p = (char *)malloc(16);
    if (!p) return 1;
    for (int i = 0; i < 16; i++) {
        p[i] = (char)i;
    }
    printf("%d\n", p[15]);
    free(p);
    return 0;
}
''',
    },
    {
        'id': 'uaf_fp_09_free_in_sibling_fn',
        'mode': '兄弟函数释放, 本函数不使用 (跨函数误关联)',
        'src': r'''
/* 安全: cleanup 释放 p, 但 release 之后无使用. */
#include <stdlib.h>
#include <stdio.h>

void cleanup(char *p) { free(p); }
void touch(char *p) { p[0] = 'T'; }

int main(void) {
    char *p = (char *)malloc(16);
    if (!p) return 1;
    touch(p);
    cleanup(p);
    return 0;
}
''',
    },
    {
        'id': 'uaf_fp_10_value_copy',
        'mode': '按值复制后使用副本, 原指针释放',
        'src': r'''
/* 安全: 释放 p 后使用的是值副本 (非指针解引用). */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *p = (char *)malloc(16);
    if (!p) return 1;
    strcpy(p, "copy-me");
    int v = p[0];
    free(p);
    printf("%c\n", v);
    return 0;
}
''',
    },
    {
        'id': 'uaf_fp_11_conditional_reassign',
        'mode': '守卫内重新赋值, 守卫外使用新指针',
        'src': r'''
/* 安全: if(flag){free; p=malloc;} p 使用前已被重定义. */
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv) {
    int flag = argc > 1;
    char *p = (char *)malloc(16);
    if (!p) return 1;
    if (flag) {
        free(p);
        p = (char *)malloc(16);
        if (!p) return 1;
    }
    p[0] = 'S';
    printf("%c\n", p[0]);
    free(p);
    return 0;
}
''',
    },
    {
        'id': 'uaf_fp_12_freed_then_unused',
        'mode': '释放后无任何使用 (纯释放路径)',
        'src': r'''
/* 安全: free 之后没有任何对 p 的访问. */
#include <stdlib.h>
#include <stdio.h>

int main(void) {
    char *p = (char *)malloc(16);
    if (!p) return 1;
    p[0] = 'x';
    printf("%c\n", p[0]);
    free(p);
    return 0;
}
''',
    },
    {
        'id': 'uaf_fp_13_stack_array',
        'mode': '栈上数组读写被误判为堆指针',
        'src': r'''
/* 安全: 栈数组 buf 与堆对象无关. */
#include <stdio.h>

int main(void) {
    char buf[32];
    for (int i = 0; i < 32; i++) {
        buf[i] = (char)i;
    }
    printf("%d\n", buf[31]);
    return 0;
}
''',
    },
    {
        'id': 'uaf_fp_14_free_after_use_in_call',
        'mode': '调用序列: use 在 free 调用前 (参数求值序)',
        'src': r'''
/* 安全: printf 使用 p 后 free. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *p = (char *)malloc(16);
    if (!p) return 1;
    strcpy(p, "seq");
    printf("%s\n", p);
    free(p);
    return 0;
}
''',
    },
    {
        'id': 'uaf_fp_15_no_free',
        'mode': '无 free 调用 (仅分配与使用)',
        'src': r'''
/* 安全: 无释放操作, 不构成 UAF. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    strcpy(p, "leak-ok");
    printf("%s\n", p);
    return 0;
}
''',
    },
]
