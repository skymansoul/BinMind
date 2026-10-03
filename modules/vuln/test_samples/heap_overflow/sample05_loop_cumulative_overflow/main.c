/* 循环累积写入堆溢出.
 *
 * 每次写入 chunk_size, 循环 N 次, 累积 > alloc.
 * Expected: TP (loop-aware detection needed)
 */
#include <stdlib.h>
#include <string.h>

int main() {
    char *buf = (char *)malloc(512);
    if (!buf) return 1;
    int offset = 0;
    for (int i = 0; i < 16; i++) {
        /* 每次写 64 字节, 16×64=1024 > 512 → OVERFLOW */
        memset(buf + offset, 'A' + i, 64);
        offset += 64;
    }
    free(buf);
    return 0;
}
