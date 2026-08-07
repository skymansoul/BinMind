/* heap_edge_13: 三元条件分配大小 — flag ? small : large
 * alloc = min_len (guarded), write = MAX_SAFE = 128
 * EXPECT: SAFE — guard条件钳制分配>=写入
 */
#include <stdlib.h>
#include <string.h>

#define MAX_SAFE 128
#define LARGE_BUF 1024

static int g_mode = 0;  /* 0=compact, 1=verbose */

int process_input(const char *input, size_t len) {
    /* guard: 截断超长输入 */
    if (len > MAX_SAFE) len = MAX_SAFE;

    /* 三元分配: compact模式用恰好大小, verbose用大缓冲区 */
    size_t alloc_sz = (g_mode == 0) ? len : LARGE_BUF;

    char *buf = malloc(alloc_sz);
    if (!buf) return -1;

    /* alloc_sz >= len (guard保证) → SAFE */
    memcpy(buf, input, len);
    free(buf);
    return 0;
}

int main(void) {
    char data[256];
    memset(data, 'C', 256);
    g_mode = 0;
    return process_input(data, 256);
}
