// cve10_stack_vs_heap — BPF绕过: malloc(256)→memset(512), 验证器绕过模式
// CVE参考: CVE-2020-8835, 模式: bpf_bypass
// 编译: gcc -Wall -O0 -fno-stack-protector -g -o cve10_stack_vs_heap main.c
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
