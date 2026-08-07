/*
 * CVE-2017-11176 — Linux kernel mq_notify 竞态→UAF/堆溢出 (CWE-416/CWE-122)
 *
 * Linux kernel 4.11.9 之前: net/socket.c 中 mq_notify 的 sock 指针在调用
 * fget() 和实际使用之间存在竞争窗口, 可能使指针指向已释放的堆内存.
 *
 * 虽然这是 UAF, 但 UAF 后堆内存可能被其他对象复用, 导致堆溢出或信息泄露.
 *
 * 文献: "Exploiting the Linux Kernel via mq_notify" — Lexfo, 2017.
 * CVSS: 7.8 (High), CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
 */

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#define MAX_MSG_SIZE 8192

typedef struct {
    int sock_fd;
    char *msg_buf;
    size_t msg_len;
} notif_ctx;

/* [VULN] 竞态条件模拟: thread1 释放 ctx, thread2 仍在使用 */
notif_ctx *g_ctx = NULL;

void *thread_sender(void *arg) {
    notif_ctx *ctx = (notif_ctx *)arg;

    /* 正常流程: 分配堆缓冲区发送消息 */
    ctx->msg_buf = (char *)malloc(ctx->msg_len);
    if (!ctx->msg_buf) return NULL;
    memset(ctx->msg_buf, 'M', ctx->msg_len);

    return NULL;
}

void *thread_releaser(void *arg) {
    /* 释放 ctx 的 msg_buf — thread_sender 可能仍在使用 */
    if (g_ctx && g_ctx->msg_buf) {
        free(g_ctx->msg_buf);        /* ← UAF: sender 可能还未完成写入 */
        g_ctx->msg_buf = NULL;
    }
    return NULL;
}

int main(void) {
    g_ctx = (notif_ctx *)malloc(sizeof(notif_ctx));
    g_ctx->msg_len = MAX_MSG_SIZE;
    g_ctx->msg_buf = NULL;

    pthread_t t1, t2;
    pthread_create(&t1, NULL, thread_sender, g_ctx);
    pthread_create(&t2, NULL, thread_releaser, NULL);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    free(g_ctx);
    return 0;
}
