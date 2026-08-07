/* heap_overflow_02 — off-by-one 堆溢出 (NULL byte poisoning)
 *
 * 经典 off-by-one: malloc(N) 后写入 N+1 字节,
 * 覆盖下一 chunk 的 size 字段低字节.
 * 测试检测器对 1-字节越界的敏感性.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    size_t len = 64;
    char *buf = (char *)malloc(len);
    if (!buf) return 1;
    memset(buf, 'B', len);
    /* BUG: off-by-one — 在 buf[64] 写入 NULL */
    buf[len] = '\0';
    printf("wrote %zu+1 bytes to %zu-byte allocation\n", len, len);
    free(buf);
    return 0;
}
