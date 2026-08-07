#include <stdio.h>
#include <stdlib.h>
/* IO-15: 混合类型算术 — int*unsigned long 的隐式提升歧义 */
int main(int argc, char **argv) {
    int count = argc > 1 ? atoi(argv[1]) : 1000000;
    unsigned long elem_size = 4096;
    /* count*siz → int*ulong → ulong, 但count先被提升 */
    unsigned long total = (unsigned long)count * elem_size;
    if (total > 100 * 1024 * 1024) { printf("too large\n"); return 1; }
    int *buf = (int *)malloc((size_t)total);
    if (!buf) { printf("alloc failed\n"); return 1; }
    for (int i = 0; i < count; i++) buf[i] = i;  /* VULNERABLE if total too small */
    free(buf); return 0;
}
