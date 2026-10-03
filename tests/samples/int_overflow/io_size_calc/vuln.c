#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* IO-07: 复杂尺寸计算中的隐式溢出 — (a+b)*c 可能溢出 */
int main(int argc, char **argv) {
    int hdr = 64;
    int body = argc > 1 ? atoi(argv[1]) : 2000000000;
    int footer = 64;
    /* size = hdr + body * 2 + footer  中间乘法可能溢出 */
    size_t size = (size_t)(hdr + body * 2 + footer);
    char *buf = (char *)malloc(size);
    if (!buf) { printf("alloc failed\n"); return 1; }
    memset(buf, 0, size);
    free(buf); return 0;
}
