// cve08_medium_overflow — 不受信任大小: malloc(128)→memset(384), ProFTPD模式
// CVE参考: CVE-2015-3306, 模式: untrusted_size
// 编译: gcc -Wall -O0 -fno-stack-protector -g -o cve08_medium_overflow main.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALLOC_SIZE 128
#define WRITE_SIZE 384

int main(int argc, char **argv) {
    char *buf = (char *)malloc(ALLOC_SIZE);
    if (!buf) return 1;

    // 漏洞: 分配128B但写入384B
    // 溢出256B
    memset(buf, 'A', WRITE_SIZE);

    printf("buf=%p, wrote %d into %d-byte alloc\n",
           (void *)buf, WRITE_SIZE, ALLOC_SIZE);
    free(buf);
    return 0;
}
