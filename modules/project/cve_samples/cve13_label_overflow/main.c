// cve13_label_overflow — DNS标签: malloc(256)→memset(512), 标签解压溢出
// CVE参考: CVE-2017-9445, 模式: dns_label
// 编译: gcc -Wall -O0 -fno-stack-protector -g -o cve13_label_overflow main.c
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
    memset(buf, 'A', WRITE_SIZE);

    printf("buf=%p, wrote %d into %d-byte alloc\n",
           (void *)buf, WRITE_SIZE, ALLOC_SIZE);
    free(buf);
    return 0;
}
