TP = [
    dict(id="tp_01_direct_uaf", label="tp", cwe="CWE-416",
         cve="CVE-2015-0235 (GHOST) 类直接释放后解引用",
         title="free 后字段解引用", trigger="直接执行 main",
         why="free(p) 后 p->flag 访问已释放对象, 无空态/重赋值",
         expect_overflow=True,
         code='''
#include <stdlib.h>
typedef struct { int flag; } obj_t;
int main(void) {
    obj_t *p = (obj_t *)malloc(sizeof(obj_t));
    if (!p) return -1;
    free(p);
    p->flag = 1;
    return 0;
}
'''),
    dict(id="tp_02_alias_uaf", label="tp", cwe="CWE-416",
         cve="CVE-2022-1011 类别名 UAF",
         title="别名指针解引用已释放对象", trigger="直接执行 main",
         why="q 是 p 的别名, free(p) 后 q->f 访问同一已释放对象",
         expect_overflow=True,
         code='''
#include <stdlib.h>
typedef struct { int f; } obj_t;
int main(void) {
    obj_t *p = (obj_t *)malloc(sizeof(obj_t));
    if (!p) return -1;
    obj_t *q = p;
    free(p);
    q->f = 2;
    return 0;
}
'''),
    dict(id="tp_03_cross_func_uaf", label="tp", cwe="CWE-416",
         cve="CVE-2019-15291 类跨函数 UAF",
         title="free 后回调函数解引用", trigger="直接执行 main",
         why="freed 指针传入回调后解引用, 逃逸分析确认",
         expect_overflow=True,
         code='''
#include <stdlib.h>
typedef struct { int v; } obj_t;
static void touch(obj_t *o) { o->v = 3; }
int main(void) {
    obj_t *p = (obj_t *)malloc(sizeof(obj_t));
    if (!p) return -1;
    free(p);
    touch(p);
    return 0;
}
'''),
    dict(id="tp_04_loop_uaf", label="tp", cwe="CWE-416",
         cve="CVE-2018-9568 类循环内 UAF",
         title="循环内释放后解引用", trigger="直接执行 main",
         why="循环首轮 free, 次轮仍解引用 p",
         expect_overflow=True,
         code='''
#include <stdlib.h>
typedef struct { int v; } obj_t;
int main(void) {
    obj_t *p = (obj_t *)malloc(sizeof(obj_t));
    if (!p) return -1;
    int i;
    for (i = 0; i < 3; i++) {
        if (i == 1) { free(p); }
        p->v = i;
    }
    return 0;
}
'''),
    dict(id="tp_05_conditional_uaf", label="tp", cwe="CWE-416",
         cve="CVE-2017-16995 类条件触发 UAF",
         title="条件分支释放后无保护解引用", trigger="./sample 1",
         why="flag=1 时 free, 随后无条件 p->v 解引用",
         expect_overflow=True,
         code='''
#include <stdlib.h>
#include <stdio.h>
typedef struct { int v; } obj_t;
int main(int argc, char **argv) {
    int flag = argc > 1 ? atoi(argv[1]) : 0;
    obj_t *p = (obj_t *)malloc(sizeof(obj_t));
    if (!p) return -1;
    if (flag) { free(p); }
    p->v = 5;
    return 0;
}
'''),
    dict(id="tp_06_passed_to_func", label="tp", cwe="CWE-416",
         cve="CVE-2020-7460 类传参 UAF",
         title="free 后传参解引用", trigger="直接执行 main",
         why="print_obj 解引用已释放指针",
         expect_overflow=True,
         code='''
#include <stdlib.h>
#include <stdio.h>
typedef struct { int v; } obj_t;
static void print_obj(obj_t *o) { printf("%d", o->v); }
int main(void) {
    obj_t *p = (obj_t *)malloc(sizeof(obj_t));
    if (!p) return -1;
    free(p);
    print_obj(p);
    return 0;
}
'''),
    dict(id="tp_07_struct_field_uaf", label="tp", cwe="CWE-416",
         cve="CVE-2021-34556 类结构体内指针 UAF",
         title="释放外层对象后解引用内嵌指针", trigger="直接执行 main",
         why="free(c) 后 c->data 访问已释放内存",
         expect_overflow=True,
         code='''
#include <stdlib.h>
typedef struct { char *data; } container_t;
int main(void) {
    container_t *c = (container_t *)malloc(sizeof(container_t));
    if (!c) return -1;
    c->data = (char *)malloc(16);
    free(c);
    c->data[0] = 'A';
    return 0;
}
'''),
    dict(id="tp_08_global_escape", label="tp", cwe="CWE-416",
         cve="CVE-2014-3153 类全局逃逸 UAF",
         title="全局指针持有释放对象", trigger="直接执行 main",
         why="g_ptr 保存 p, free(p) 后经 g_ptr 解引用",
         expect_overflow=True,
         code='''
#include <stdlib.h>
typedef struct { int v; } obj_t;
static obj_t *g_ptr;
int main(void) {
    obj_t *p = (obj_t *)malloc(sizeof(obj_t));
    if (!p) return -1;
    g_ptr = p;
    free(p);
    g_ptr->v = 7;
    return 0;
}
'''),
    dict(id="tp_09_pointer_arith_uaf", label="tp", cwe="CWE-416",
         cve="CVE-2016-6187 类指针运算 UAF",
         title="free 后经偏移指针解引用", trigger="直接执行 main",
         why="free(p) 后 p+1 仍指向已释放区域",
         expect_overflow=True,
         code='''
#include <stdlib.h>
int main(void) {
    int *p = (int *)malloc(16 * sizeof(int));
    if (!p) return -1;
    free(p);
    p[2] = 9;
    return 0;
}
'''),
    dict(id="tp_10_double_deref", label="tp", cwe="CWE-416",
         cve="CVE-2016-2177 类二次解引用 UAF",
         title="free 后 *p 写已释放内存", trigger="直接执行 main",
         why="*p = 值 对已释放堆块写入",
         expect_overflow=True,
         code='''
#include <stdlib.h>
int main(void) {
    int *p = (int *)malloc(sizeof(int));
    if (!p) return -1;
    free(p);
    *p = 10;
    return 0;
}
'''),
    dict(id="tp_11_array_index_uaf", label="tp", cwe="CWE-416",
         cve="CVE-2020-27786 类数组下标 UAF",
         title="free 后数组元素写", trigger="直接执行 main",
         why="p[0] 在 free 后写入",
         expect_overflow=True,
         code='''
#include <stdlib.h>
int main(void) {
    int *p = (int *)malloc(8 * sizeof(int));
    if (!p) return -1;
    free(p);
    p[0] = 11;
    return 0;
}
'''),
    dict(id="tp_12_string_field_uaf", label="tp", cwe="CWE-416",
         cve="CVE-2019-0708 类字符串字段 UAF",
         title="free 后字符串字段读取", trigger="直接执行 main",
         why="strlen(s->name) 在 free(s) 后访问",
         expect_overflow=True,
         code='''
#include <stdlib.h>
#include <string.h>
typedef struct { char *name; } rec_t;
int main(void) {
    rec_t *s = (rec_t *)malloc(sizeof(rec_t));
    if (!s) return -1;
    s->name = (char *)malloc(32);
    free(s);
    if (s->name[0]) { return 1; }
    return 0;
}
'''),
    dict(id="tp_13_realloc_then_use_free", label="tp", cwe="CWE-416",
         cve="CVE-2018-14634 类 realloc+free 双释放 UAF",
         title="realloc 旧指针 free 后误用", trigger="直接执行 main",
         why="realloc 后仍用旧指针 old 操作",
         expect_overflow=True,
         code='''
#include <stdlib.h>
int main(void) {
    int *old = (int *)malloc(8);
    if (!old) return -1;
    int *newp = (int *)realloc(old, 64);
    if (!newp) return -1;
    old[0] = 13;
    return 0;
}
'''),
    dict(id="tp_14_free_then_scan", label="tp", cwe="CWE-416",
         cve="CVE-2020-7460 类遍历后释放",
         title="释放后链表遍历解引用", trigger="直接执行 main",
         why="head 释放后仍遍历 next 字段",
         expect_overflow=True,
         code='''
#include <stdlib.h>
typedef struct node { struct node *next; int v; } node_t;
int main(void) {
    node_t *head = (node_t *)malloc(sizeof(node_t));
    if (!head) return -1;
    node_t *cur = head;
    free(head);
    while (cur) { cur = cur->next; }
    return 0;
}
'''),
    dict(id="tp_15_conditional_double_use", label="tp", cwe="CWE-416",
         cve="CVE-2017-1000112 类条件解引用 UAF",
         title="free 后条件解引用", trigger="直接执行 main",
         why="free(p) 后 p->v 访问, 无守卫",
         expect_overflow=True,
         code='''
#include <stdlib.h>
typedef struct { int v; } obj_t;
int main(void) {
    obj_t *p = (obj_t *)malloc(sizeof(obj_t));
    if (!p) return -1;
    free(p);
    if (p->v > 0) { return 1; }
    return 0;
}
'''),
]
