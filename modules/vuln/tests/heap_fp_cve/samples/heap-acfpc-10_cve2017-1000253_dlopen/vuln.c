/* CVE-2017-1000253 (glibc __libc_dlopen_mode) 堆溢出复现 — 动态装载器
   将长路径 strcpy 进固定 128 字节缓冲. 简化: malloc(128) +
   strcpy(buf, long_path). */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *buf;

    if (argc < 2) {
        return 0;
    }
    buf = (char *)malloc(128);
    if (!buf) {
        return 1;
    }
    strcpy(buf, argv[1]);
    printf("%s\n", buf);
    free(buf);
    return 0;
}
