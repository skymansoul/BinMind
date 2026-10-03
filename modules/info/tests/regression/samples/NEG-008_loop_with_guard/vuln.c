/* NEG-008 — 循环中有边界守卫, 不会溢出 → 安全 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void guarded_loop_write(const char **chunks, int n_chunks, int chunk_sz) {
    int total = n_chunks * chunk_sz;
    char *buf = malloc(total);
    if (!buf) return;
    int offset = 0;
    for (int i = 0; i < n_chunks; i++) {
        /* 边界守卫: 确保不超出分配范围 */
        if (offset + chunk_sz > total) break;
        memcpy(buf + offset, chunks[i], chunk_sz);
        offset += chunk_sz;
    }
    printf("guarded loop: written=%d, alloc=%d\n", offset, total);
    free(buf);
}

int main(int c, char **v) {
    const char *chunks[4];
    char data[4][64];
    for (int i = 0; i < 4; i++) {
        memset(data[i], 'H' + i, 64);
        chunks[i] = data[i];
    }
    guarded_loop_write(chunks, 4, 64);
    return 0;
}
