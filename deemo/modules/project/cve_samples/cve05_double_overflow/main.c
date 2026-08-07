// cve05_double_overflow — 双倍溢出: malloc(256)→memcpy(512), diff补丁模式
// CVE参考: CVE-2022-39253, 模式: double_size
// 编译: gcc -Wall -O0 -fno-stack-protector -g -o cve05_double_overflow main.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALLOC_SIZE 256
#define WRITE_SIZE 512

int main(int argc, char **argv) {
    char *buf = (char *)malloc(ALLOC_SIZE);
    if (!buf) return 1;

    // 漏洞: 分配256B但写入512B
    // 溢出256B
    static const char src[512] = {0};
    memcpy(buf, src, WRITE_SIZE);

    printf("buf=%p, wrote %d into %d-byte alloc\n",
           (void *)buf, WRITE_SIZE, ALLOC_SIZE);
    free(buf);
    return 0;
}
