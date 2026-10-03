/* HEAPOVERFLOW-015: calloc乘法 vs 简单区间——L3值范围cmp约束
 * calloc(4, 16) = 64字节分配，但汇编中是两个独立参数
 * 需要正确识别calloc的参数语义——不是简单的(rdi=4, rsi=16)
 * memcpy的size参数经过cmp rdx, 80约束→实际≤80
 * L3应追踪到cmp约束缩小范围，而非保守使用[0, 2^32-1]
 */

#include <stdlib.h>
#include <string.h>

void calloc_with_cmp_constraint(int count, int elem_size,
                                 unsigned char *input, int input_len) {
    /* calloc(count, elem_size) → 实际分配 = count * elem_size */
    float *buf = (float *)calloc(count, elem_size);
    if (!buf) return;

    int copy_len = input_len;
    /* cmp约束: 调用者保证input_len≤count*elem_size */
    if (copy_len > count * elem_size) {
        copy_len = count * elem_size;
    }

    /* 若count=4, elem_size=16: alloc=64, copy_len≤64→安全
     * L3应追踪copy_len经过cmp的约束而非unknown
     * 简单过滤器看到rdx=unknown→误报 */
    if (buf && input && copy_len > 0) {
        memcpy(buf, input, copy_len);
    }

    free(buf);
}

int main() {
    unsigned char data[64];
    memset(data, 0x41, sizeof(data));
    calloc_with_cmp_constraint(4, 16, data, 60);
    return 0;
}
