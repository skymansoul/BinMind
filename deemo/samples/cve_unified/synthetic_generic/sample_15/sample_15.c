/*
 * sample_15 — strncpy 误用导致的堆溢出.
 *
 * 漏洞: strncpy 不会自动添加 null terminator,
 * 且如果 src 长度 >= n, dest 不会被 null-terminated.
 * 但这里的问题是: n 大于 dest 的实际大小.
 *
 * CWE-122 + CWE-170 (Improper Null Termination).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    const char *src = "This is a long source string that exceeds buffer size";
    size_t buf_size = 16;

    char *buf = (char *)malloc(buf_size);
    if (!buf) return 1;

    /* strncpy 的第三个参数用了错误的大小 (128 > 16) */
    strncpy(buf, src, 128);

    printf("buf = %.16s\n", buf);
    free(buf);
    return 0;
}
