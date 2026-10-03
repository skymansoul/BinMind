// cve12_struct_overflow — 表溢出: malloc(630)→memset(1024), Huffman表溢出
// CVE参考: CVE-2023-4863, 模式: huffman_table
// 编译: gcc -Wall -O0 -fno-stack-protector -g -o cve12_struct_overflow main.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALLOC_SIZE 630
#define WRITE_SIZE 1024

int main(int argc, char **argv) {
    char *buf = (char *)malloc(ALLOC_SIZE);
    if (!buf) return 1;

    // 漏洞: 分配630B但写入1024B
    // 溢出394B
    memset(buf, 'A', WRITE_SIZE);

    printf("buf=%p, wrote %d into %d-byte alloc\n",
           (void *)buf, WRITE_SIZE, ALLOC_SIZE);
    free(buf);
    return 0;
}
