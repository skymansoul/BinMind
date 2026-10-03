/* CVE-2017-1000112 (Linux UDP fragmentation) 堆溢出复现 — skb 重组时
   偏移计算越界. 简化: malloc(1024) + memcpy(buf + 896, src, 512)
   (偏移+长度越界). */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf;
    char *src;

    buf = (char *)malloc(1024);
    src = (char *)malloc(512);
    if (!buf || !src) {
        return 1;
    }
    memset(src, 'u', 512);
    memcpy(buf + 896, src, 512);
    free(buf);
    free(src);
    return 0;
}
