/*
 * UAF 安全对照 A — free 后置 NULL (TN)
 * 目标: 验证"置空即安全"模式不被误报
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct buffer {
    char *data;
    int len;
};

void buffer_free(struct buffer *b) {
    free(b->data);
    b->data = NULL;           /* 置空: 后续使用被 guard 拦截 */
    b->len = 0;
}

int buffer_read(struct buffer *b, char *out, int n) {
    if (!b->data) return -1;  /* 安全: NULL 检查 */
    if (n > b->len) n = b->len;
    memcpy(out, b->data, n);
    return n;
}

int main(int argc, char **argv) {
    struct buffer *b = (struct buffer *)malloc(sizeof(*b));
    b->data = (char *)malloc(32);
    memset(b->data, 'S', 32);
    b->len = 32;
    char out[16];
    buffer_free(b);
    int n = buffer_read(b, out, 8);   /* 返回 -1, 无 UAF */
    printf("read: %d\n", n);
    free(b);
    return 0;
}
