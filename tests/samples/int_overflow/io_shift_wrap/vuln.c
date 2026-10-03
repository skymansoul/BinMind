#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* IO-05: 左移溢出 — 1 << bits 可能超过类型范围 */
int main(int argc, char **argv) {
    int bits = argc > 1 ? atoi(argv[1]) : 30;
    size_t alloc = (size_t)1 << bits;  /* bits=31时, 1<<31溢出int, 提升后可能异常 */
    char *buf = (char *)malloc(alloc);
    if (!buf) { printf("malloc failed for 1<<%d\n", bits); return 1; }
    memset(buf, 0, alloc);
    printf("allocated 1<<%d = %zu bytes\n", bits, alloc);
    free(buf); return 0;
}
