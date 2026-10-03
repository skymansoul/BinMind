TN = [
    dict(id="tn_01_null_after_free", label="tn", cwe="CWE-0",
         cve="安全模式: free 后置 NULL",
         title="free(p); p=NULL; 空态保护", trigger="直接执行 main",
         why="p 置 NULL 后经 if(p) 守卫, 不会解引用已释放对象",
         expect_overflow=False,
         code='''
#include <stdlib.h>
typedef struct { int v; } obj_t;
int main(void) {
    obj_t *p = (obj_t *)malloc(sizeof(obj_t));
    if (!p) return -1;
    free(p);
    p = NULL;
    if (p) { p->v = 1; }
    return 0;
}
'''),
    dict(id="tn_02_reassign_after_free", label="tn", cwe="CWE-0",
         cve="安全模式: free 后重分配",
         title="free 后 malloc 新对象再使用", trigger="直接执行 main",
         why="p 重新指向新堆对象, 解引用的是新内存",
         expect_overflow=False,
         code='''
#include <stdlib.h>
typedef struct { int v; } obj_t;
int main(void) {
    obj_t *p = (obj_t *)malloc(sizeof(obj_t));
    if (!p) return -1;
    free(p);
    p = (obj_t *)malloc(sizeof(obj_t));
    if (!p) return -1;
    p->v = 2;
    free(p);
    return 0;
}
'''),
    dict(id="tn_03_guard_before_use", label="tn", cwe="CWE-0",
         cve="安全模式: 守卫块内使用",
         title="if(p) 守卫内解引用 (p 未释放时)", trigger="直接执行 main",
         why="使用位于 if(p) 块内, 守卫路径成立",
         expect_overflow=False,
         code='''
#include <stdlib.h>
typedef struct { int v; } obj_t;
int main(void) {
    obj_t *p = (obj_t *)malloc(sizeof(obj_t));
    if (!p) return -1;
    if (p) { p->v = 3; }
    free(p);
    return 0;
}
'''),
    dict(id="tn_04_branch_exclusive", label="tn", cwe="CWE-0",
         cve="安全模式: 分支互斥",
         title="释放与使用在不同互斥分支", trigger="./sample 0",
         why="free 与解引用由互斥条件分隔, 实际只走一支",
         expect_overflow=False,
         code='''
#include <stdlib.h>
#include <stdio.h>
typedef struct { int v; } obj_t;
int main(int argc, char **argv) {
    int flag = argc > 1 ? atoi(argv[1]) : 0;
    obj_t *p = (obj_t *)malloc(sizeof(obj_t));
    if (!p) return -1;
    if (flag) { free(p); } else { p->v = 4; free(p); }
    return 0;
}
'''),
    dict(id="tn_05_refcount_protected", label="tn", cwe="CWE-0",
         cve="安全模式: 引用计数保护",
         title="refcount 计数保护下释放", trigger="直接执行 main",
         why="引用计数未归零时不真正释放, 解引用安全",
         expect_overflow=False,
         code='''
#include <stdlib.h>
typedef struct { int refs; int v; } obj_t;
int main(void) {
    obj_t *p = (obj_t *)malloc(sizeof(obj_t));
    if (!p) return -1;
    p->refs = 2;
    if (--p->refs == 0) { free(p); }
    if (p->refs > 0) { p->v = 5; }
    if (--p->refs == 0) { free(p); }
    return 0;
}
'''),
    dict(id="tn_06_use_before_free", label="tn", cwe="CWE-0",
         cve="安全模式: 使用在释放之前",
         title="先使用后释放", trigger="直接执行 main",
         why="解引用发生在 free 之前",
         expect_overflow=False,
         code='''
#include <stdlib.h>
typedef struct { int v; } obj_t;
int main(void) {
    obj_t *p = (obj_t *)malloc(sizeof(obj_t));
    if (!p) return -1;
    p->v = 6;
    free(p);
    return 0;
}
'''),
    dict(id="tn_07_alias_reassigned", label="tn", cwe="CWE-0",
         cve="安全模式: 别名重指向新对象",
         title="别名 q 重分配后使用", trigger="直接执行 main",
         why="q 在 p 释放后重新 malloc, 解引用新对象",
         expect_overflow=False,
         code='''
#include <stdlib.h>
typedef struct { int v; } obj_t;
int main(void) {
    obj_t *p = (obj_t *)malloc(sizeof(obj_t));
    if (!p) return -1;
    obj_t *q = p;
    free(p);
    q = (obj_t *)malloc(sizeof(obj_t));
    if (!q) return -1;
    q->v = 7;
    free(q);
    return 0;
}
'''),
    dict(id="tn_08_value_only", label="tn", cwe="CWE-0",
         cve="安全模式: 仅取地址不解引用",
         title="free 后仅取指针值", trigger="直接执行 main",
         why="只把指针当整数值记录, 无解引用",
         expect_overflow=False,
         code='''
#include <stdlib.h>
#include <stdio.h>
int main(void) {
    void *p = malloc(16);
    if (!p) return -1;
    free(p);
    unsigned long addr = (unsigned long)p;
    printf("%lu", addr);
    return 0;
}
'''),
    dict(id="tn_09_free_other_var", label="tn", cwe="CWE-0",
         cve="安全模式: 释放另一对象",
         title="释放 q 但使用 p", trigger="直接执行 main",
         why="free 的是 q, 解引用的是未释放的 p",
         expect_overflow=False,
         code='''
#include <stdlib.h>
typedef struct { int v; } obj_t;
int main(void) {
    obj_t *p = (obj_t *)malloc(sizeof(obj_t));
    obj_t *q = (obj_t *)malloc(sizeof(obj_t));
    if (!p || !q) return -1;
    free(q);
    p->v = 9;
    free(p);
    return 0;
}
'''),
    dict(id="tn_10_no_use_after", label="tn", cwe="CWE-0",
         cve="安全模式: 释放后无使用",
         title="free 后直接返回", trigger="直接执行 main",
         why="free 后无任何解引用",
         expect_overflow=False,
         code='''
#include <stdlib.h>
int main(void) {
    void *p = malloc(16);
    if (!p) return -1;
    free(p);
    return 0;
}
'''),
    dict(id="tn_11_free_then_exit", label="tn", cwe="CWE-0",
         cve="安全模式: 释放后立即退出",
         title="free 后 exit", trigger="直接执行 main",
         why="exit 前释放, 无后续访问",
         expect_overflow=False,
         code='''
#include <stdlib.h>
int main(void) {
    void *p = malloc(16);
    if (!p) return -1;
    free(p);
    exit(0);
}
'''),
    dict(id="tn_12_stack_only", label="tn", cwe="CWE-0",
         cve="安全模式: 栈对象 (非堆)",
         title="栈对象解引用, 无 free", trigger="直接执行 main",
         why="无堆分配, 无 free 调用, 不存在 UAF",
         expect_overflow=False,
         code='''
typedef struct { int v; } obj_t;
int main(void) {
    obj_t s = {0};
    s.v = 12;
    return 0;
}
'''),
    dict(id="tn_13_scope_limited", label="tn", cwe="CWE-0",
         cve="安全模式: 作用域隔离",
         title="局部指针生命周期内使用", trigger="直接执行 main",
         why="helper 内部分配先取值再释放, main 用独立指针",
         expect_overflow=False,
         code='''
#include <stdlib.h>
typedef struct { int v; } obj_t;
static int helper(void) {
    obj_t *t = (obj_t *)malloc(sizeof(obj_t));
    if (!t) return -1;
    int v = t->v;
    free(t);
    return v;
}
int main(void) {
    obj_t *p = (obj_t *)malloc(sizeof(obj_t));
    if (!p) return -1;
    p->v = helper();
    free(p);
    return 0;
}
'''),
    dict(id="tn_14_array_no_deref", label="tn", cwe="CWE-0",
         cve="安全模式: 数组仅作缓冲不解引用",
         title="free 数组后仅传 NULL 检查", trigger="直接执行 main",
         why="free 后仅比较指针非空, 无解引用",
         expect_overflow=False,
         code='''
#include <stdlib.h>
int main(void) {
    int *p = (int *)malloc(8 * sizeof(int));
    if (!p) return -1;
    free(p);
    if (p == NULL) { return 1; }
    return 0;
}
'''),
    dict(id="tn_15_guard_loop_safe", label="tn", cwe="CWE-0",
         cve="安全模式: 循环内守卫后解引用",
         title="循环内释放+置空+守卫使用", trigger="直接执行 main",
         why="每轮循环释放后立即置空并守卫, 解引用仅在非空时发生",
         expect_overflow=False,
         code='''
#include <stdlib.h>
typedef struct { int v; } obj_t;
int main(void) {
    obj_t *p = (obj_t *)malloc(sizeof(obj_t));
    if (!p) return -1;
    int i;
    for (i = 0; i < 3; i++) {
        if (i == 1) { free(p); p = NULL; }
        if (p) { p->v = i; }
    }
    return 0;
}
'''),
]
