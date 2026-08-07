// cve09_realloc_mismatch — Realloc不匹配: malloc(256)→realloc→memset(1024)但realloc未扩展
// CVE参考: CVE-2016-0777, 模式: realloc_resume
// 编译: gcc -Wall -O0 -fno-stack-protector -g -o cve09_realloc_mismatch main.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALLOC_SIZE 256
#define WRITE_SIZE 1024

int main(int argc, char **argv) {
    char *buf = (char *)malloc(ALLOC_SIZE);
    if (!buf) return 1;

    // 漏洞: 分配256B但写入1024B
    // 溢出768B
    memset(buf, 'A', WRITE_SIZE);

    printf("buf=%p, wrote %d into %d-byte alloc\n",
           (void *)buf, WRITE_SIZE, ALLOC_SIZE);
    free(buf);
    return 0;
}
