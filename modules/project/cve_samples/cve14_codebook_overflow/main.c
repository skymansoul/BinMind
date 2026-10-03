// cve14_codebook_overflow — Codebook: malloc(1024)→memset(2048), Vorbis codebook
// CVE参考: CVE-2018-5146, 模式: vorbis_codebook
// 编译: gcc -Wall -O0 -fno-stack-protector -g -o cve14_codebook_overflow main.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALLOC_SIZE 1024
#define WRITE_SIZE 2048

int main(int argc, char **argv) {
    char *buf = (char *)malloc(ALLOC_SIZE);
    if (!buf) return 1;

    // 漏洞: 分配1024B但写入2048B
    // 溢出1024B
    memset(buf, 'A', WRITE_SIZE);

    printf("buf=%p, wrote %d into %d-byte alloc\n",
           (void *)buf, WRITE_SIZE, ALLOC_SIZE);
    free(buf);
    return 0;
}
