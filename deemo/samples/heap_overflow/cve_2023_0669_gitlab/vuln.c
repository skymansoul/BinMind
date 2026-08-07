/* CVE-2023-0669 — GitLab CE/EE Go-based Metasploit RPC heap overflow (C模拟)
 * 原始: Go `encoding/gob` 反序列化时 unchecked buffer growth.
 * 简化: 动态扩展缓冲区, 但在特定路径未校验扩展后大小.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct buffer { char *data; size_t cap; size_t len; };

int buf_grow(struct buffer *b, size_t need) {
    if (b->cap >= need) return 0;
    size_t new_cap = need * 2;
    char *nd = (char *)realloc(b->data, new_cap);
    if (!nd) return -1;
    b->data = nd; b->cap = new_cap;
    return 0;
}

int buf_append(struct buffer *b, const char *src, size_t n) {
    /* bug: buf_grow checks need but doesn't account for len */
    if (b->len + n > b->cap) buf_grow(b, b->len + n);
    memcpy(b->data + b->len, src, n);
    b->len += n;
    return 0;
}

int main(void) {
    struct buffer b = {NULL, 0, 0};
    b.data = (char *)malloc(16); b.cap = 16;
    /* trigger growth path; off-by-one in capacity check */
    buf_append(&b, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 32);
    free(b.data);
    return 0;
}
