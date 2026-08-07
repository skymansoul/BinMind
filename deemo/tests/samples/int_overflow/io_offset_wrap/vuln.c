#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* IO-08: 偏移计算回绕 — ptr+offset可能回绕到低地址 */
int main(int argc, char **argv) {
    unsigned int base = 0xFFFFFF00u;
    unsigned int off  = argc > 1 ? (unsigned)atoi(argv[1]) : 512u;
    char *buf = (char *)malloc(4096);
    if (!buf) return 1;
    memset(buf, 0, 4096);
    /* base+off可能超过UINT_MAX回绕 */
    unsigned int idx = base + off;
    if (idx < 4096) buf[idx] = 'X';  /* VULNERABLE: idx可能回绕 */
    printf("idx=%u\n", idx);
    free(buf); return 0;
}
