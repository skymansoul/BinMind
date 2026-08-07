/* CVE-2022-0185 (Linux fs_context) 堆溢出复现 — legacy_parse_param 将
   用户输入按 PAGE_SIZE 复制到 256 字节 slab 对象, 无边界检查.
   简化: malloc(256) + memcpy(buf, src, 4096) 常量大越界. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PAGE_SIZE 4096

int main(void) {
    char *buf;
    char *src;

    buf = (char *)malloc(256);
    src = (char *)malloc(PAGE_SIZE);
    if (!buf || !src) {
        return 1;
    }
    memset(src, 'x', PAGE_SIZE);
    memcpy(buf, src, PAGE_SIZE);
    free(buf);
    free(src);
    return 0;
}
