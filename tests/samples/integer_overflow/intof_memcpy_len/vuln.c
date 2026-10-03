#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* INTOF-10: memcpy长度溢出 — 溢出的长度参数导致memcpy越界
 * CWE-190→CWE-122: Integer overflow cascading to heap overflow */
int main(int argc, char **argv) {
    int n;
    if (argc < 2) n = 50;
    else n = atoi(argv[1]);

    int copy_size = n * 4;    /* 可能溢出 */
    int alloc_size = n * 4;   /* 可能溢出 */

    char *src = (char *)malloc(alloc_size);
    char *dst = (char *)malloc(alloc_size);
    if (!src || !dst) { free(src); free(dst); return 1; }
    memset(src, 'A', n * 4);

    /* VULNERABLE: copy_size溢出后变得很小, 但memset写了n*4 */
    memcpy(dst, src, copy_size);

    free(src); free(dst);
    return 0;
}
