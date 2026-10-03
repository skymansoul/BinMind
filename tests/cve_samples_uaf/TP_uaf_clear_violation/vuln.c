/*
 * TP_uaf_clear_violation — 明确的 Use-After-Free.
 *
 * 场景: free(p) 后继续使用 *p, 无任何保护.
 * 预期: UAF检测器应检出 (TRUE POSITIVE).
 * TARPS验证: 应判定为 CONFIRMED.
 *
 * CWE-416: Use After Free
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int id;
    char data[32];
} Object;

void process_object(Object *obj) {
    printf("id=%d data=%s\n", obj->id, obj->data);
}

int main() {
    Object *p = (Object *)malloc(sizeof(Object));
    if (!p) return 1;
    p->id = 42;
    strcpy(p->data, "sensitive");

    process_object(p);  /* 正常使用 */

    free(p);            /* 释放 */

    /* UAF: free后继续使用p */
    printf("after free: id=%d\n", p->id);  /* ← UAF HERE */
    return 0;
}
