/* NEG-003 — 有边界检查守卫, memcpy 前检查了长度 → 安全, 不应报警 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define MAX_SIZE 1024

void guarded_copy(const char *src, size_t src_len) {
    /* 边界检查: 若 src_len > MAX_SIZE 则截断 */
    size_t copy_len = src_len > MAX_SIZE ? MAX_SIZE : src_len;
    char *buf = malloc(MAX_SIZE);
    if (!buf) return;
    memcpy(buf, src, copy_len);  /* 守卫保证了 copy_len ≤ MAX_SIZE */
    printf("guarded copy: %zu bytes\n", copy_len);
    free(buf);
}

int main(int c, char **v) {
    char data[2048];
    memset(data, 'C', sizeof(data));
    guarded_copy(data, sizeof(data));
    return 0;
}
