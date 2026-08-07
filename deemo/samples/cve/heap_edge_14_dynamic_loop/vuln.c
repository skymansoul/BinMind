/* heap_edge_14: 动态循环边界 — for(i < runtime_limit) buf[i]=x
 * alloc = 64, loop_limit = 100 (显式常量超过分配)
 * EXPECT: OVERFLOW — 循环100次 > 分配64字节
 */
#include <stdlib.h>
#include <string.h>

static int g_config_iters = 100;

int fill_buffer(void) {
    char *buf = malloc(64);
    if (!buf) return -1;
    /* BUG: 循环次数100 > 分配大小64 */
    for (int i = 0; i < g_config_iters; i++) {
        buf[i] = 'D';
    }
    free(buf);
    return 0;
}

int main(void) {
    return fill_buffer();
}
