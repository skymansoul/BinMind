# coding: utf-8
#
"""UAF TP 样本数据. 仅数据, 无逻辑."""

SAMPLES_UAF_B = [
    {
        "id": "uaf_07_loop",
        "cve": "None (synthetic)",
        "title": "UAF in loop (free then use next iteration)",
        "pattern": "循环内 free, 下一轮迭代解引用",
        "trigger": "首次迭代 free, 后续迭代经旧指针使用",
        "why": "free 与 use 同函数同对象, 窗口内无重分配",
        "code": r'''/* uaf_07_loop — 循环内 free 后使用 (TP)。
 * Expected: UAF */
#include <stdlib.h>

int main(void) {
    char *p = (char *)malloc(16);
    if (!p) return 1;
    for (int i = 0; i < 4; i++) {
        if (i == 2) free(p);
        if (i == 3) p[0] = 'B';   /* use after free */
    }
    return 0;
}
''',
    },
    {
        "id": "uaf_08_struct_field",
        "cve": "None (synthetic)",
        "title": "UAF via struct field write",
        "pattern": "free(struct) → 写 struct 字段",
        "trigger": "释放对象后写其成员",
        "why": "字段写经结构体指针解引用, 归因到已释放对象",
        "code": r'''/* uaf_08_struct_field — free 后写结构体字段 (TP)。
 * Expected: UAF */
#include <stdlib.h>

typedef struct { int a; int b; } S;

int main(void) {
    S *s = (S *)malloc(sizeof(S));
    if (!s) return 1;
    free(s);
    s->a = 42;                    /* UAF write to field */
    return 0;
}
''',
    },
    {
        "id": "uaf_09_after_call",
        "cve": "None (synthetic)",
        "title": "UAF after intervening unrelated call",
        "pattern": "free(p) → 无关调用 → 重新加载 p 使用",
        "trigger": "中间无关调用后仍用旧指针",
        "why": "槽值跨调用稳定, 解引用仍归因到已释放对象",
        "code": r'''/* uaf_09_after_call — 无关调用后 UAF (TP)。
 * Expected: UAF */
#include <stdlib.h>

static void busy(void) {}

int main(void) {
    char *p = (char *)malloc(32);
    if (!p) return 1;
    free(p);
    busy();                       /* unrelated call */
    return p[0];                  /* use after free */
}
''',
    },
    {
        "id": "uaf_10_realloc_old",
        "cve": "None (synthetic)",
        "title": "Use of pointer invalidated by realloc",
        "pattern": "p=realloc(p,big) 后仍用旧 p",
        "trigger": "realloc 可能移动对象, 旧指针失效后使用",
        "why": "旧指针对象失效后解引用",
        "code": r'''/* uaf_10_realloc_old — realloc 后使用旧指针 (TP)。
 * Expected: UAF */
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *p = (char *)malloc(16);
    if (!p) return 1;
    char *q = p;
    p = (char *)realloc(p, 512);
    if (!p) return 1;
    q[0] = 'C';                   /* use of invalidated old pointer */
    free(p);
    return 0;
}
''',
    },
    {
        "id": "uaf_11_member_read",
        "cve": "None (synthetic)",
        "title": "UAF member read after free",
        "pattern": "free(obj) → 读 obj->field",
        "trigger": "释放后读成员",
        "why": "读解引用归因到已释放对象",
        "code": r'''/* uaf_11_member_read — free 后读成员 (TP)。
 * Expected: UAF */
#include <stdlib.h>

typedef struct { int len; char data[16]; } H;

int main(void) {
    H *h = (H *)malloc(sizeof(H));
    if (!h) return 1;
    free(h);
    return h->len;                /* UAF read */
}
''',
    },
    {
        "id": "uaf_12_store_through",
        "cve": "None (synthetic)",
        "title": "UAF store through dangling pointer",
        "pattern": "free(p) → *(int*)p = v",
        "trigger": "经悬垂指针做间接存储",
        "why": "存储指令的 [reg] 基寄存器归因到已释放对象",
        "code": r'''/* uaf_12_store_through — free 后经指针存储 (TP)。
 * Expected: UAF */
#include <stdlib.h>

int main(void) {
    int *p = (int *)malloc(16);
    if (!p) return 1;
    free(p);
    *p = 0xdeadbeef;              /* store through dangling pointer */
    return 0;
}
''',
    },
]
