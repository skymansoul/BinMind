/* CVE-2025-uaf-toctou CWE-416: TOCTOU UAF — 指针有效性检查后、使用前被另一路径释放 (check/use race) */
#include <stdlib.h>
#include <string.h>

typedef struct Conn {
    int fd;
    int refcount;
    char *buffer;
} Conn;

static Conn *g_conn = NULL;

Conn *conn_create(int fd) {
    Conn *c = malloc(sizeof(Conn));
    c->fd = fd;
    c->refcount = 1;
    c->buffer = malloc(1024);
    return c;
}

void conn_release(Conn *c) {
    if (!c) return;
    c->refcount--;
    if (c->refcount <= 0) {
        free(c->buffer);
        free(c);
    }
}

/* BUG: check和use之间conn可能被另一线程/路径释放 (refcount减为0) */
int conn_send_data(Conn *c, const char *data, int len) {
    /* 检查指针有效性 */
    if (!c || !c->buffer) return -1;

    /* TOCTOU窗口: 另一路径可能在此时调用conn_release两次 */
    /* c->buffer 可能已释放 */

    /* UAF: 向可能已释放的buffer写入数据 */
    if (len <= 1024) {
        memcpy(c->buffer, data, len);
        return len;
    }
    return -1;
}

int trigger_uaf(void) {
    Conn *c = conn_create(1);

    /* 模拟TOCTOU: check之后、use之前refcount归零 */
    /* 路径A: 检查通过 */
    if (c && c->buffer) {
        /* 路径B (并发/回调): 释放conn */
        conn_release(c);  /* refcount: 1→0, buffer freed */

        /* 路径A继续: UAF写入已释放的buffer */
        memcpy(c->buffer, "PWND", 4);  /* UAF! */
    }
    return 0;
}

int main() {
    trigger_uaf();
    return 0;
}
