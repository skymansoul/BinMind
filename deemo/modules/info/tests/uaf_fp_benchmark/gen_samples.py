#!/usr/bin/env python
# coding: utf-8
# tests/uaf_fp_benchmark/gen_samples.py — UAF 误报基准样本生成器
# 15 个漏洞样本 (tp_*) + 15 个安全对照 (tn_*)。每个样本: vuln.c + Makefile
# + README.md + truth.json。运行: python gen_samples.py [--out 输出目录]

import json
from pathlib import Path


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

MAKEFILE = ("CC = gcc\nCFLAGS = -Wall -Wextra -O0 -g\nTARGET = sample\n"
            "all: $(TARGET)\n$(TARGET): vuln.c\n\t$(CC) $(CFLAGS) -o "
            "$(TARGET) vuln.c\nclean:\n\t$(RM) $(TARGET)\n")

README_TEMPLATE = ("# {sid}: {title}\n\n## CWE\n{cwe}\n\n## 漏洞描述\n{cve}"
                   "\n\n## 触发条件\n{trigger}\n\n## 为何有效\n{why}\n\n"
                   "## Build\n```bash\nmake\n./sample\n```\n")


def _write(out: Path, spec: dict):
    d = out / spec["id"]
    d.mkdir(parents=True, exist_ok=True)
    header = ("/* UAF TP sample */\n" if spec["label"] == "tp"
              else "/* UAF TN (safe) sample */\n")
    (d / "vuln.c").write_text(header + spec["code"].strip() + "\n",
                              encoding="utf-8")
    (d / "Makefile").write_text(MAKEFILE, encoding="utf-8")
    (d / "README.md").write_text(README_TEMPLATE.format(sid=spec["id"], **spec),
                                 encoding="utf-8")
    truth = {"sample_id": spec["id"], "label": spec["label"],
             "cwe": spec["cwe"], "cve": spec["cve"],
             "expect_overflow": spec["expect_overflow"],
             "trigger": spec["trigger"], "why": spec["why"]}
    (d / "truth.json").write_text(json.dumps(truth, indent=2,
                                             ensure_ascii=False),
                                  encoding="utf-8")





def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=str(Path(__file__).parent))
    args = parser.parse_args()
    out = Path(args.out)
    for spec in TP + TN:
        _write(out, spec)
    print(f"Generated {len(TP) + len(TN)} UAF samples in {out}")


if __name__ == "__main__":
    main()
