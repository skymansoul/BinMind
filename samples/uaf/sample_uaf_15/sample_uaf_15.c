/*
 * sample_uaf_15 — Alias nullified but original not (FP edge case).
 *
 * q=p; free(p); p=NULL; 但q未置NULL.
 * 然后if(q) guard通过, use(q) → UAF.
 * 这是别名追踪遗漏的场景: 只NULL置零了主指针, 别名未处理.
 *
 * TARPS预期: DEF_TP — 别名q未NULL置零, 真正的UAF
 * 编译: gcc -o sample_uaf_15 sample_uaf_15.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *p = (char *)malloc(128);
    if (!p) return 1;
    strcpy(p, "alias_edge_case");

    char *q = p;   /* 别名 */

    free(p);
    p = NULL;      /* 只置零了p, q仍是悬垂指针 */

    /* q未被置NULL — 指向已释放内存 */
    if (q != NULL) {
        /* NULL检查通过! q != NULL 但内存已释放 */
        strcpy(q, "uaf_via_unprotected_alias");
    }

    printf("edge case done\n");
    return 0;
}
