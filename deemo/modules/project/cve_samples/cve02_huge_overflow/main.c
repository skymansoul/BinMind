// cve02_huge_overflow — Heartbleed模式: malloc(32)→memcpy(65535), 极大超出分配
// CVE参考: CVE-2014-0160, 模式: heartbleed_size
// 编译: gcc -Wall -O0 -fno-stack-protector -g -o cve02_huge_overflow main.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALLOC_SIZE 32
#define WRITE_SIZE 65535

int main(int argc, char **argv) {
    char *buf = (char *)malloc(ALLOC_SIZE);
    if (!buf) return 1;

    // 漏洞: 分配32B但写入65535B
    // 溢出65503B
    memset(buf, 'A', WRITE_SIZE);

    printf("buf=%p, wrote %d into %d-byte alloc\n",
           (void *)buf, WRITE_SIZE, ALLOC_SIZE);
    free(buf);
    return 0;
}
