#include <stdio.h>
#include <stdlib.h>

int main(void) {
    char *p = (char *)malloc(1024);
    if (!p) return 1;
    /* n*size wraps: 0x40000001 * 4 = 4 */
    size_t n = 0x40000001;
    char *q = (char *)realloc(p, n * 4);
    if (q) {
        p = q;
        /* OVERFLOW: thinks it has 0x40000001*4 bytes, has only 4 */
        p[1000] = 'X';  /* heap overflow */
        printf("realloc overflow: p[1000] = %c\n", p[1000]);
    }
    free(p);
    return 0;
}
