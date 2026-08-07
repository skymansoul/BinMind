/*
 * CVE-2023-0461 — Linux kernel: io_uring 堆 UAF→溢出 (CWE-416)
 *
 * Linux kernel 6.1.7 之前: io_uring 子系统中 IORING_OP_READ/WRITE
 * 的 fixed-buffer 引用计数管理错误. 攻击者在 IO 操作进行中
 * 注销固定缓冲区, 导致 io_uring worker 访问已释放的堆页面.
 *
 * 影响: UAF 后堆内存可能已被不同对象复用, 导致数据损坏或代码执行.
 *
 * CVSS: 7.8 (High), CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>

#define IORING_MAX_BUFS 16

typedef struct {
    void **bufs;
    int *ref_counts;
    int nbufs;
} io_ring_ctx;

static io_ring_ctx *g_ctx;

/* 模拟: 用户空间注销固定缓冲区 */
void unregister_buffers(io_ring_ctx *ctx) {
    for (int i = 0; i < ctx->nbufs; i++) {
        if (ctx->ref_counts[i] == 0) {
            free(ctx->bufs[i]); /* ← [VULN] worker 可能还在用 */
            ctx->bufs[i] = NULL;
        }
    }
    free(ctx->bufs);
    free(ctx->ref_counts);
}

/* 模拟: io_uring worker 继续使用已释放的缓冲区 */
void *io_worker(void *arg) {
    int buf_idx = *(int *)arg;

    if (g_ctx && g_ctx->bufs && g_ctx->bufs[buf_idx]) {
        /* [VULN] buf 可能已被 unregister_buffers 释放 */
        char *buf = (char *)g_ctx->bufs[buf_idx];

        /* 写入数据 — 如果 buf 被 reuse 为其他对象, 造成堆损坏 */
        memset(buf, 0x41, 4096); /* ← UAF write */
    }
    return NULL;
}

int main(void) {
    g_ctx = (io_ring_ctx *)malloc(sizeof(io_ring_ctx));
    g_ctx->nbufs = 4;
    g_ctx->bufs = (void **)calloc(g_ctx->nbufs, sizeof(void *));
    g_ctx->ref_counts = (int *)calloc(g_ctx->nbufs, sizeof(int));

    for (int i = 0; i < g_ctx->nbufs; i++) {
        g_ctx->bufs[i] = malloc(4096);
        g_ctx->ref_counts[i] = 0; /* 标记为未使用 */
    }

    int buf_id = 2;
    pthread_t worker;
    pthread_create(&worker, NULL, io_worker, &buf_id);

    /* 竞态: 同时注销缓冲区 */
    unregister_buffers(g_ctx);

    pthread_join(worker, NULL);
    free(g_ctx);
    return 0;
}
