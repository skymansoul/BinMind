/* CVE-2023-24329 (curl URL 解析) 未定义行为 → 堆溢出复现 — 解析器在
   未定义行为路径上长度计算错误, 导致越界写. 简化: malloc(64) +
   memcpy(buf, url, 128). */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *buf;
    char *url;

    if (argc < 2) {
        return 0;
    }
    url = (char *)malloc(128);
    buf = (char *)malloc(64);
    if (!url || !buf) {
        return 1;
    }
    memcpy(url, argv[1], 127);
    url[127] = 0;
    memcpy(buf, url, 128);
    free(buf);
    free(url);
    return 0;
}
