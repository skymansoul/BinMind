// cve15_bind_tkey — TKEY响应: malloc(512)→memset(1024), BIND TKEY溢出
// CVE参考: CVE-2015-5477, 模式: tkey_response
// 编译: gcc -Wall -O0 -fno-stack-protector -g -o cve15_bind_tkey main.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALLOC_SIZE 512
#define WRITE_SIZE 1024

int main(int argc, char **argv) {
    char *buf = (char *)malloc(ALLOC_SIZE);
    if (!buf) return 1;

    // 漏洞: 分配512B但写入1024B
    // 溢出512B
    memset(buf, 'A', WRITE_SIZE);

    printf("buf=%p, wrote %d into %d-byte alloc\n",
           (void *)buf, WRITE_SIZE, ALLOC_SIZE);
    free(buf);
    return 0;
}
