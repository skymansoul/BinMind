/*
 * sample_uaf_05 — Double free.
 *
 * 两次free同一指针 — UAF的特殊形式.
 * CWE-415: Double Free.
 *
 * TARPS预期: DEF_TP — 无任何保护措施
 */

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    char *p = (char *)malloc(64);
    if (!p) return 1;

    free(p);
    free(p);  /* double free */

    printf("double freed\n");
    return 0;
}
