/*
 * UAF 安全对照 C — 释放后立即退出作用域, 无后续使用 (TN)
 * 目标: 验证"释放后无使用"不误报
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct session {
    int fd;
    char buf[16];
};

int process(struct session *s, const char *data) {
    if (!s) return -1;
    memcpy(s->buf, data, 8);
    return s->fd;
}

int main(int argc, char **argv) {
    struct session *s = (struct session *)malloc(sizeof(*s));
    s->fd = 3;
    memset(s->buf, 0, sizeof(s->buf));
    int r = process(s, "hello");
    printf("r=%d\n", r);
    free(s);                  /* 释放 */
    /* 之后 s 不再被使用 — 无 UAF */
    return 0;
}
