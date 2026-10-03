#include <stdio.h>
#include <stdlib.h>
/* IO-10: malloc(0) — 当size计算溢出为0时, malloc(0)返回有效指针 */
int main(int argc, char **argv) {
    unsigned short n = (unsigned short)(argc > 1 ? atoi(argv[1]) : 65536);
    /* 65536 % 65536 = 0 → n=0 → malloc(0) */
    size_t alloc = (size_t)n * 1024;  /* 0 * 1024 = 0 */
    char *buf = (char *)malloc(alloc);
    printf("malloc(%zu) = %p\n", alloc, (void *)buf);
    if (buf) {
        for (int i = 0; i < 100; i++) buf[i] = 'X';  /* VULNERABLE */
        free(buf);
    }
    return 0;
}
