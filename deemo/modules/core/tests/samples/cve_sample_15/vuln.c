/* CVE-2023-0461 (模拟) — Linux kernel io_uring 堆溢出
 * 真实: 5.18+, io_uring fixed buffer 引用计数问题导致 UAF/溢出 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct io_buf {
    char *ptr;
    unsigned int len;
    unsigned int refcount;
};

void register_buffer(struct io_buf *b, const char *data, unsigned int dlen) {
    b->ptr = (char *)malloc(512);
    b->len = 512;
    b->refcount = 1;
    /* 漏洞: dlen 未被验证, 可能 > 512 */
    unsigned int copy = dlen; /* 缺少 min(dlen, b->len) */
    memcpy(b->ptr, data, copy);
}

int main(void) {
    struct io_buf b = {0};
    char payload[2048];
    memset(payload, 0x41, sizeof(payload));
    register_buffer(&b, payload, 1024); /* 1024 > 512 */
    free(b.ptr);
    return 0;
}
