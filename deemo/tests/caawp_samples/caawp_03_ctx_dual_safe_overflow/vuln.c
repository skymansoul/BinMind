/* 双调用点: safe(256,128)+overflow(64,256) — 上下文区分关键场景
 * helper在同一函数被调用两次, 一次安全一次溢出.
 * 上下文不敏感分析会将两处合并, 无法精确定位溢出.
 * Has vulnerability: True
 */
#include <stdlib.h>
#include <string.h>
void helper(char *dst, int sz) {
    memcpy(dst, src, sz);
}
void dual_call() {
    char *safe_buf = malloc(256);
    if (!safe_buf) return;
    helper(safe_buf, 128);
    free(safe_buf);

    char *overflow_buf = malloc(64);
    if (!overflow_buf) return;
    helper(overflow_buf, 256);
    free(overflow_buf);
}
