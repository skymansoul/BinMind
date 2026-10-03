/*
 * sample_uaf_12 — UAF after realloc (realloc返回新地址).
 *
 * realloc可能返回新地址, 旧指针失效.
 * 若继续使用旧指针, 是UAF (旧内存已free).
 *
 * TARPS预期: DEF_TP — realloc后旧指针UAF
 * 编译: gcc -o sample_uaf_12 sample_uaf_12.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *old_ptr = (char *)malloc(64);
    if (!old_ptr) return 1;
    strcpy(old_ptr, "original");

    /* realloc返回新地址, 旧内存隐式free */
    char *new_ptr = (char *)realloc(old_ptr, 256);
    if (!new_ptr) {
        free(old_ptr);
        return 1;
    }

    /* BUG: 仍使用old_ptr — 它可能已指向已释放内存 */
    strcpy(old_ptr, "uaf after realloc");

    /* 正确做法是使用new_ptr */
    strcpy(new_ptr, "safe_usage");

    printf("new=%s\n", new_ptr);
    free(new_ptr);
    return 0;
}
