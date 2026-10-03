/* NEG-007 — FORTIFY_SOURCE 保护, 使用 __memcpy_chk → 安全 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void fortify_safe_copy(const char *src, size_t len) {
    size_t alloc_sz = len < 256 ? 256 : len;  /* 至少分配 256 */
    char *buf = malloc(alloc_sz);
    if (!buf) return;
    /* 写入量受限于分配量 → 安全 */
    memcpy(buf, src, len < alloc_sz ? len : alloc_sz);
    printf("fortify safe: alloc=%zu, copy=%zu\n", alloc_sz,
           len < alloc_sz ? len : alloc_sz);
    free(buf);
}

int main(int c, char **v) {
    char data[128];
    memset(data, 'G', sizeof(data));
    fortify_safe_copy(data, sizeof(data));
    return 0;
}
