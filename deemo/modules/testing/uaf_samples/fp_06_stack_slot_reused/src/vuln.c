#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    strcpy(p, "first");
    free(p);
    char *q = (char *)malloc(128);   /* 新对象写入同一栈槽 */
    if (!q) return 1;
    strcpy(q, "second");
    printf("[*] %s\n", q);           /* 使用新对象 — 非 UAF */
    free(q);
    return 0;
}
