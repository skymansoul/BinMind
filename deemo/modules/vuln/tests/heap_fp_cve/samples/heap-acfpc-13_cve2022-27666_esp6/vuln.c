/* CVE-2022-27666 (Linux esp6 GCMP) 堆溢出复现 — 加密余量计算错误导致
   esp6 数据路径越界写. 简化: malloc(512) + memcpy(buf, src, 1024). */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf;
    char *src;

    buf = (char *)malloc(512);
    src = (char *)malloc(1024);
    if (!buf || !src) {
        return 1;
    }
    memset(src, 'e', 1024);
    memcpy(buf, src, 1024);
    free(buf);
    free(src);
    return 0;
}
