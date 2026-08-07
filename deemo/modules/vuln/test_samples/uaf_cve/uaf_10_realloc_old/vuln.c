/* uaf_10_realloc_old — realloc 后使用旧指针 (TP)。
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
