// cve07_large_alloc_small_write — 大分配溢出: malloc(4096)→memset(8192), SSH数据包模式
// CVE参考: CVE-2019-3855, 模式: packet_overflow
// 编译: gcc -Wall -O0 -fno-stack-protector -g -o cve07_large_alloc_small_write main.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALLOC_SIZE 4096
#define WRITE_SIZE 8192

int main(int argc, char **argv) {
    char *buf = (char *)malloc(ALLOC_SIZE);
    if (!buf) return 1;

    // 漏洞: 分配4096B但写入8192B
    // 溢出4096B
    memset(buf, 'A', WRITE_SIZE);

    printf("buf=%p, wrote %d into %d-byte alloc\n",
           (void *)buf, WRITE_SIZE, ALLOC_SIZE);
    free(buf);
    return 0;
}
