/* CVE-2020-14386 (Linux af_packet tpacket) 堆溢出复现 — 整数溢出导致
   越界写: n = 用户长度; 分配 len = n * 2 (溢出后小), 随后 memcpy 写 n 字节.
   简化: malloc(1024) + memcpy(buf, src, 4096) 大常量. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf;
    char *src;

    buf = (char *)malloc(1024);
    src = (char *)malloc(4096);
    if (!buf || !src) {
        return 1;
    }
    memset(src, 'p', 4096);
    memcpy(buf, src, 4096);
    free(buf);
    free(src);
    return 0;
}
