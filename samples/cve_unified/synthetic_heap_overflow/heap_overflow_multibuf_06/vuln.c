/* heap_overflow_multibuf_06 — 多缓冲区: A overflow 会覆盖相邻的 B
 * 核心场景: 连续两个 malloc → 大概率相邻, overflow from A into B.
 * 误报诱因: 不知道 A 和 B 的相对位置, 可能误判溢出目标.
 * 我们的优势: heap_shape_model 推断 A/B 相邻, 若 B 含函数指针 → exploitability 升高.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef void (*callback_t)(void);

static void safe_handler(void) { printf("safe\n"); }

int main(void) {
    char *bufA = (char *)malloc(32);
    /* bufB contains a function pointer near its start */
    struct { char data[24]; callback_t cb; } *bufB =
        (void *)malloc(sizeof(*bufB));
    if (!bufA || !bufB) return 1;
    bufB->cb = safe_handler;

    /* overflow bufA → reaches into bufB's function pointer */
    memset(bufA, 'A', 48); /* 48 > 32, overflows 16B into bufB */

    bufB->cb(); /* may crash or call corrupted pointer */
    free(bufA);
    free(bufB);
    return 0;
}
