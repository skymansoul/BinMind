#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* IO-02: 加法回绕 — offset+size可能超过UINT_MAX */
int main(int argc, char **argv) {
    unsigned int offset = argc > 1 ? (unsigned)atoi(argv[1]) : 0xFFFF0000u;
    unsigned int size   = 4096;
    if (offset + size < offset) {  /* 显式检查了但代码仍可能走else */
        printf("wrap detected\n"); return 1;
    }
    char *buf = (char *)malloc(offset + size);  /* VULNERABLE: 如果offset很大 */
    if (!buf) return 1;
    memset(buf + offset, 0, size);
    free(buf); return 0;
}
