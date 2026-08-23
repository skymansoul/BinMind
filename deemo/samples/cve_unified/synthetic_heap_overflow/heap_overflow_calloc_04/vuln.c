/* heap_overflow_calloc_04 — calloc 乘法溢出 + 后续写入
 * 误报诱因: calloc(n, size) 中若 n*size 乘积超过 SIZE_MAX → 分配比预期小.
 *   多数工具不看 calloc 的乘积, 只当 malloc(n*size).
 * 我们的优势: allocator_constraints 追踪 calloc 两参数的乘积语义.
 */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int main(void) {
    /* calloc(1024, 1024) = 1MB, safe */
    /* calloc(65536, 65536) overflows uint32 but not size_t on 64-bit */
    size_t n = 4096;
    size_t sz = 1024;
    char *buf = (char *)calloc(n, sz); /* 4MB */
    if (!buf) return 1;
    /* write 4MB+1KB → overflow even on correct allocation */
    memset(buf, 0, n * sz + 1024);
    free(buf);
    return 0;
}
