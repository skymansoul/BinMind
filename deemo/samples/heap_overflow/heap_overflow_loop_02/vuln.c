/* heap_overflow_loop_02 — 循环边界溢出: for(i=0;i<=N;i++) buf[i]=x, N==alloc_size
 * 误报诱因: 循环上界推断困难, 纯模式匹配不知循环跑多少次.
 * 我们的优势: strided interval 追踪循环变量 i ∈ [0, N], 推断 N==alloc_size 时溢出.
 *   guard_inference 配合: 若 cmp i,N; jle loop 在写入前 → 路径安全.
 */
#include <stdlib.h>
#include <string.h>

void process(size_t n) {
    char *buf = (char *)malloc(n);
    if (!buf) return;
    /* <= n means n+1 iterations, last one writes buf[n] = overflow */
    for (size_t i = 0; i <= n; i++) {
        buf[i] = (char)(i & 0xff);
    }
    free(buf);
}

int main(void) {
    process(64); /* triggers overflow: buf[64] is 1 byte past allocation */
    return 0;
}
