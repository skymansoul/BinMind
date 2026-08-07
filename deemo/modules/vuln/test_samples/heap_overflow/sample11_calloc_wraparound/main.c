/* calloc 溢出 — nmemb * size 乘法回绕.
 *
 * calloc(nmemb=0x10000001, size=256) → 乘积回绕 32-bit → alloc 小.
 * Expected: TP (calloc wraparound detection)
 */
#include <stdlib.h>
#include <string.h>

int main() {
    /* nmemb*size = 0x10000001*256 mod 2^32 = 256 → alloc 仅256字节 */
    char *buf = (char *)calloc(0x10000001, 256);
    if (!buf) return 1;
    /* 期望 nmemb*size 字节, 写入远超 alloc → OVERFLOW */
    memset(buf, 0, 512);
    free(buf);
    return 0;
}
