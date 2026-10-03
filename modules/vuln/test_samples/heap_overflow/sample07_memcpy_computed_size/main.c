/* memcpy 计算 size 溢出 — alloc 和 copy 使用不同的 size 变量.
 *
 * alloc = user_size - 1 (off-by-one), copy = user_size.
 * Expected: TP (memcpy size > alloc size)
 */
#include <stdlib.h>
#include <string.h>

int main() {
    int user_size = 128;
    int alloc_size = user_size - 1;  /* 127 */
    char *buf = (char *)malloc(alloc_size);
    if (!buf) return 1;
    /* copy_size(128) > alloc_size(127) → OVERFLOW by 1 byte */
    memset(buf, 0xFF, user_size);
    free(buf);
    return 0;
}
