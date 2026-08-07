/* tainted写入固定alloc: malloc(64)+memcpy(atoi(argv)) — 用户控制写入大小 */
#include <stdlib.h>
#include <string.h>
void taint_fixed_overflow(int argc, char **argv) {
    char *buf = malloc(64);
    if (!buf) return;
    int len = atoi(argv[1]);
    memcpy(buf, src, len);
    free(buf);
}
