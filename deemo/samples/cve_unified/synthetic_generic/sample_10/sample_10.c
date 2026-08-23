/*
 * sample_10 — 有/无符号混淆导致堆溢出.
 *
 * 漏洞: 用户传入的 size_t 被赋值给 int (有符号截断),
 * 后续 malloc 使用截断后的大小 → 分配不足.
 *
 * CWE-195: Signed to Unsigned Conversion Error.
 * CVE-2015-7547 (glibc getaddrinfo) 的简化版.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_buf_size;  /* 有符号! */

void process_data(const char *data, size_t len) {
    g_buf_size = (int)len;  /* 截断: 若 len > INT_MAX */
    char *buf = (char *)malloc(g_buf_size);
    if (!buf) return;

    /* 用原始 len (size_t, 可能很大) 写入 → 溢出 */
    memcpy(buf, data, len);
    printf("processed: %s\n", buf);
    free(buf);
}

int main(void) {
    char data[256];
    memset(data, 'D', sizeof(data));
    data[255] = '\0';

    process_data(data, 256);  /* 256 > 127 (int截断后的某个值?) */
    return 0;
}
