/*
 * CVE-2020-0041 模式复刻 — HIDP UAF (Android)
 * 真实漏洞: hidp_session 释放后 socket 回调仍引用, 可 RCE
 * 触发条件: 断开连接后 socket 发送数据触发 UAF
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct hidp_session {
    int socket_fd;
    char rbuf[32];
    int terminated;
};

struct hidp_conn {
    struct hidp_session *session;
    int alive;
};

void hidp_session_terminate(struct hidp_session *s) {
    s->terminated = 1;
    free(s);                  /* session 释放 */
}

int hidp_send_frame(struct hidp_conn *c, const char *data, int len) {
    /* 缺陷: 未检查 session 是否已终止 */
    if (len > (int)sizeof(c->session->rbuf))
        len = (int)sizeof(c->session->rbuf);
    memcpy(c->session->rbuf, data, len);   /* UAF 写 */
    return len;
}

int main(int argc, char **argv) {
    struct hidp_conn *c = (struct hidp_conn *)malloc(sizeof(*c));
    c->session = (struct hidp_session *)malloc(sizeof(*c->session));
    c->session->socket_fd = 3;
    c->session->terminated = 0;
    c->alive = 1;

    char msg[16];
    memset(msg, 'A', 16);

    /* 先终止 session, 再经 conn 发送 — UAF */
    hidp_session_terminate(c->session);
    hidp_send_frame(c, msg, 16);
    free(c);
    return 0;
}
