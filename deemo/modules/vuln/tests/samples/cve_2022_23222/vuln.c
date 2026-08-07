/* CVE-2022-23222 — Linux kernel BPF JIT 本地权限提升
 *
 * 触发条件: BPF 验证器对 32-bit 寄存器的范围检查不正确,
 * 导致 JIT 编译后的代码可能越界访问内核堆内存。
 *
 * 测试目标: 值域分析的符号位处理 — 32-bit 截断后的值
 * 可能被错误地当作正数处理, 溢出堆缓冲区。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct bpf_ctx {
    uint8_t *stack;
    int32_t stack_size;
};

static int bpf_jit_compile(struct bpf_ctx *ctx, int32_t offset) {
    /* 模拟: 32-bit 截断导致 offset 从负数变为大正数 */
    int32_t truncated_offset = (int32_t)((uint32_t)offset & 0xFFFFFFFF);

    if (truncated_offset < 0 || truncated_offset >= ctx->stack_size)
        return -1;

    /* 看似通过了边界检查, 但如果有 off-by-one... */
    /* BUG: 应该是 truncated_offset + 8 <= ctx->stack_size */
    memset(ctx->stack + truncated_offset, 0, 8);
    return 0;
}

int main(int argc, char **argv) {
    struct bpf_ctx ctx;
    int32_t offset;
    ctx.stack_size = 256;
    ctx.stack = (uint8_t *)malloc(ctx.stack_size);

    offset = (argc >= 2) ? (int32_t)atoi(argv[1]) : 250;
    bpf_jit_compile(&ctx, offset);

    free(ctx.stack);
    return 0;
}
