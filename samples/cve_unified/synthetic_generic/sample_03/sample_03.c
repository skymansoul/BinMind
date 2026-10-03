/*
 * sample_03 — strlen 无+1 导致堆溢出.
 *
 * 漏洞: malloc(strlen(src)) 没有为 null terminator 预留空间,
 * strcpy 写入 strlen(src)+1 字节 → 1字节溢出.
 *
 * 这是CVE-2016-0718 (expat) 和 CVE-2015-1283 (Chromium) 的经典模式.
 *
 * CWE-122 + CWE-193.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    const char *src = "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD"; /* 32 chars */
    char *buf = (char *)malloc(strlen(src));  /* 只分配32, 没+1 */
    if (!buf) return 1;

    strcpy(buf, src);  /* 写入33字节 (含\0) → 1字节溢出 */

    printf("buf = %s\n", buf);
    free(buf);
    return 0;
}
