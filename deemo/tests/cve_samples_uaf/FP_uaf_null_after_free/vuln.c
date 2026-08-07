/*
 * FP_uaf_null_after_free — free后置NULL (False Positive for TARPS Stage A).
 *
 * 场景: free(p); p=NULL; 之后无法通过p进行UAF.
 * 基线检测器可能因 free→use模式 而误报.
 * TARPS Stage A 应正确 FILTER.
 *
 * 预期: 基线检测器可能误报, TARPS应过滤.
 */
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    int value;
    char *name;
} Entry;

int main() {
    Entry *p = (Entry *)malloc(sizeof(Entry));
    if (!p) return 1;
    p->value = 42;
    p->name = "test";

    printf("value=%d\n", p->value);

    free(p);     /* 释放 */
    p = NULL;    /* 立即置NULL → 安全 */

    /* p为NULL, 无法解引用 → 无UAF */
    if (p != NULL) {
        printf("value=%d\n", p->value);  /* 此路径不可达 */
    }

    return 0;
}
