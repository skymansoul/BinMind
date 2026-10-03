/* 跨函数堆溢出 — caller 分配, callee 写入越界.
 *
 * caller allocates 64 bytes, passes to callee which writes 256.
 * 这是 heap-cve-14 类模式: 跨函数 size 参数 > alloc.
 * Expected: TP (cross-function detection needed)
 */
#include <stdlib.h>
#include <string.h>

static void process_buffer(char *buf, int len) {
    /* callee: 使用 len 而非原始 alloc size */
    memset(buf, 0x42, len);  /* len=256 > alloc=64 → OVERFLOW */
}

int main() {
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    process_buffer(buf, 256);
    free(buf);
    return 0;
}
