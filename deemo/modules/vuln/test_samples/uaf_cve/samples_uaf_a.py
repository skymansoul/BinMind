# coding: utf-8
# 创建: 2026-04-30  |  UAF 语料数据 A——TP 样本 1-6
#
"""UAF TP 样本数据. 仅数据, 无逻辑."""

SAMPLES_UAF_A = [
    {
        "id": "uaf_01_simple_read",
        "cve": "None (synthetic)",
        "title": "Simple use-after-free read",
        "pattern": "malloc → free → deref 读取",
        "trigger": "free 后立即解引用读取悬垂指针",
        "why": "free 与 use 解析到同一对象身份 (obj@alloc), 无重分配",
        "code": r'''/* uaf_01_simple_read — free 后解引用读取 (TP)。
 * Expected: UAF */
#include <stdlib.h>

int main(void) {
    int *p = (int *)malloc(64);
    if (!p) return 1;
    free(p);
    int v = p[0];                 /* use-after-free read */
    return v;
}
''',
    },
    {
        "id": "uaf_02_simple_write",
        "cve": "None (synthetic)",
        "title": "Simple use-after-free write",
        "pattern": "malloc → free → 经指针写",
        "trigger": "free 后经悬垂指针写入",
        "why": "写解引用基寄存器归因到已释放对象",
        "code": r'''/* uaf_02_simple_write — free 后写 (TP)。
 * Expected: UAF */
#include <stdlib.h>

int main(void) {
    char *p = (char *)malloc(32);
    if (!p) return 1;
    free(p);
    p[0] = 'A';                   /* use-after-free write */
    return 0;
}
''',
    },
    {
        "id": "uaf_03_indirect_call",
        "cve": "None (synthetic)",
        "title": "Use-after-free via dangling function pointer",
        "pattern": "malloc 存函数指针 → free → call *ptr",
        "trigger": "free 后经悬垂指针间接调用",
        "why": "call_via 解引用归因到已释放对象 (控制流接管)",
        "code": r'''/* uaf_03_indirect_call — free 后经悬垂指针调用 (TP)。
 * Expected: UAF */
#include <stdlib.h>

static void h(void) {}

int main(void) {
    void (**fp)() = (void (**)())malloc(16);
    if (!fp) return 1;
    *fp = h;
    free(fp);
    (**fp)();                     /* use-after-free indirect call */
    return 0;
}
''',
    },
    {
        "id": "uaf_04_alias_reg",
        "cve": "None (synthetic)",
        "title": "UAF via register alias",
        "pattern": "p=buf; free(p); 经 buf 解引用",
        "trigger": "别名寄存器持有同一对象, free 后经原寄存器使用",
        "why": "寄存器链解析到同一 alloc 点",
        "code": r'''/* uaf_04_alias_reg — 寄存器别名 UAF (TP)。
 * Expected: UAF */
#include <stdlib.h>

int main(void) {
    int *buf = (int *)malloc(64);
    if (!buf) return 1;
    int *p = buf;
    free(p);
    return buf[0];                /* use via alias */
}
''',
    },
    {
        "id": "uaf_05_via_second_slot",
        "cve": "None (synthetic)",
        "title": "UAF through aliased stack slot",
        "pattern": "p 与 buf 同一对象, free(p), 经 buf 槽使用",
        "trigger": "两栈槽持有同一对象, 经另一槽使用",
        "why": "栈槽关联到同一 alloc 点",
        "code": r'''/* uaf_05_via_second_slot — 别名栈槽 UAF (TP)。
 * Expected: UAF */
#include <stdlib.h>

int main(void) {
    char *buf = (char *)malloc(32);
    if (!buf) return 1;
    char *p = buf;
    free(p);
    char c = buf[1];              /* use via other slot */
    return c;
}
''',
    },
    {
        "id": "uaf_06_conditional",
        "cve": "None (synthetic)",
        "title": "UAF with conditional free",
        "pattern": "if(cond) free(p); 之后无条件使用 p",
        "trigger": "某分支 free, 后续统一使用",
        "why": "free 点归因到对象, 后续解引用同对象",
        "code": r'''/* uaf_06_conditional — 条件分支 free 后使用 (TP)。
 * Expected: UAF */
#include <stdlib.h>

int main(int argc, char **argv) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    if (argc > 1) free(p);
    return p[0];                  /* use after conditional free */
}
''',
    },
]
