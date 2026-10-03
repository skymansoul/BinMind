/* CVE-2022-23222 — Linux kernel BPF verifier heap overflow
 * Pattern: realloc 缩小后仍用旧 size 写入
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct bpf_ctx { char *buf; int old_size; };

void resize_and_write(struct bpf_ctx *ctx, int new_size, char *data, int data_len) {
    ctx->buf = (char *)realloc(ctx->buf, new_size);
    /* BUG: 用 old_size (可能 > new_size) 做写入判断 */
    if (ctx->old_size >= data_len) {
        memcpy(ctx->buf, data, data_len); /* new_size(=64) < old_size(=256) → OVERFLOW */
    }
}

int main(int argc, char **argv) {
    struct bpf_ctx ctx;
    ctx.buf = (char *)malloc(256);
    ctx.old_size = 256;
    char data[512]; memset(data, 'B', sizeof(data));
    resize_and_write(&ctx, 64, data, 256);
    return 0;
}
