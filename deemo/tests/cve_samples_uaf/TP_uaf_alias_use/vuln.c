/*
 * TP_uaf_alias_use — 通过别名指针的Use-After-Free。
 *
 * 场景: q=p; free(p); *q 通过别名访问已释放内存.
 * 预期: UAF检测器应检出 (TRUE POSITIVE).
 * 别名分析应识别 q是p的别名, 确认时序违反.
 *
 * CWE-416: Use After Free
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int value;
    char name[16];
} Record;

int main() {
    Record *p = (Record *)malloc(sizeof(Record));
    if (!p) return 1;
    p->value = 100;
    strcpy(p->name, "original");

    Record *q = p;  /* q是p的别名 */

    printf("value=%d\n", q->value);

    free(p);        /* 释放p → q也悬空 */

    /* UAF: 通过别名q访问已释放内存 */
    printf("after free: %d\n", q->value);  /* ← UAF HERE */

    return 0;
}
