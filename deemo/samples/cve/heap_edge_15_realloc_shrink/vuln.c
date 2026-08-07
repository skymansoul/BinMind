/* heap_edge_15: realloc收缩后写入 — alloc→expand→shrink→write
 * malloc(32) → realloc(128) → realloc(16) → memcpy(48)
 * 最终alloc=16, write=48 → 溢出32字节
 * EXPECT: OVERFLOW — 收缩后再写入超过当前分配大小
 */
#include <stdlib.h>
#include <string.h>

int resize_and_write(const char *src) {
    char *buf = malloc(32);
    if (!buf) return -1;

    /* 扩展: 128 > 32 ✓ */
    buf = realloc(buf, 128);
    if (!buf) return -1;

    /* 收缩: 16 < 128 — buf丢失了前面的容量 */
    buf = realloc(buf, 16);
    if (!buf) return -1;

    /* BUG: 写入48字节到只有16字节的缓冲区 */
    memcpy(buf, src, 48);
    free(buf);
    return 0;
}

int main(void) {
    char data[64];
    memset(data, 'E', 64);
    return resize_and_write(data);
}
