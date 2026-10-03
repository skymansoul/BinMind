/*
 * FP_uaf_reuse_after_free — free后立即复用 (False Positive for TARPS Stage B).
 *
 * 场景: free(p); p=malloc(...); 旧指针被立即复用.
 * 实际上旧内存块可能被重新分配, 但p现在指向新块.
 * TARPS Stage B 应正确 FILTER.
 *
 * 预期: 基线检测器可能误报, TARPS应过滤.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    strcpy(p, "original data");

    printf("before: %s\n", p);

    free(p);              /* 释放旧块 */
    p = (char *)malloc(128);  /* 立即分配新块 → p不再悬空 */
    strcpy(p, "new data");

    printf("after: %s\n", p);  /* p指向新块, 安全 */

    free(p);
    return 0;
}
