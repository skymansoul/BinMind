/*
 * CVE-2021-26708 模式复刻 — vsock UAF (双锁竞争)
 * 真实漏洞: 内核 vsock 释放 sock 后 pkt 队列仍引用, 可提权
 * 触发条件: 并发 recv/close 竞争
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct vsock_pkt {
    struct vsock_sock *vsk;
    char data[64];
    int len;
};

struct vsock_sock {
    int refcnt;
    int destroyed;
    char name[8];
};

struct vsock_sock *vsock_sock_new(void) {
    struct vsock_sock *v = (struct vsock_sock *)malloc(sizeof(*v));
    v->refcnt = 1;
    v->destroyed = 0;
    strcpy(v->name, "vsock0");
    return v;
}

void vsock_release(struct vsock_sock *v) {
    v->destroyed = 1;
    if (--v->refcnt == 0)
        free(v);              /* sock 释放 */
}

void vsock_process_pkt(struct vsock_pkt *pkt) {
    /* 缺陷: 未检查 pkt->vsk 是否已释放 */
    if (pkt->vsk->destroyed)  /* UAF 读 */
        printf("destroyed\n");
    else
        printf("process %s\n", pkt->vsk->name);
}

int main(int argc, char **argv) {
    struct vsock_sock *v = vsock_sock_new();
    struct vsock_pkt *pkt = (struct vsock_pkt *)malloc(sizeof(*pkt));
    pkt->vsk = v;
    pkt->len = 16;
    memset(pkt->data, 'P', 16);

    /* 模拟竞争: release 后 pkt 队列仍含该 vsk 引用 */
    vsock_release(v);
    vsock_process_pkt(pkt);   /* UAF */
    free(pkt);
    return 0;
}
