/* CVE-2024-2961 (glibc iconv UTF-8) 堆溢出复现 — 转换函数对输入长度
   的错误假设导致输出缓冲越界. 简化: malloc(256) 后按输入长度 512
   字节 memcpy. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *out;
    char *in;

    out = (char *)malloc(256);
    in = (char *)malloc(512);
    if (!out || !in) {
        return 1;
    }
    memset(in, 'i', 512);
    memcpy(out, in, 512);
    free(out);
    free(in);
    return 0;
}
