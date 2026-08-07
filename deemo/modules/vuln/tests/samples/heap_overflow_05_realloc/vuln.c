/* heap_overflow_05 — realloc 后使用旧大小导致的溢出
 *
 * realloc 改变分配大小后, 代码仍使用原大小.
 * 测试检测器对 realloc 语义和大小更新追踪.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    size_t old_size = 32;
    char *buf = (char *)malloc(old_size);
    if (!buf) return 1;

    /* realloc 缩小至 16 bytes */
    buf = (char *)realloc(buf, 16);
    if (!buf) return 1;

    /* BUG: 仍使用 old_size (32) 写入 → 越界 16 bytes */
    memset(buf, 'X', old_size);

    printf("wrote %zu bytes to 16-byte realloc'd buffer\n", old_size);
    free(buf);
    return 0;
}
