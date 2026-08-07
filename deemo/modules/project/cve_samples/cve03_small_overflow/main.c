// cve03_small_overflow — Off-by-one: malloc(16)→memset(17), 仅超出1字节
// CVE参考: CVE-2021-3156, 模式: off_by_one
// 编译: gcc -Wall -O0 -fno-stack-protector -g -o cve03_small_overflow main.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALLOC_SIZE 16
#define WRITE_SIZE 17

int main(int argc, char **argv) {
    char *buf = (char *)malloc(ALLOC_SIZE);
    if (!buf) return 1;

    // 漏洞: 分配16B但写入17B
    // 溢出1B
    memset(buf, 'A', WRITE_SIZE);

    printf("buf=%p, wrote %d into %d-byte alloc\n",
           (void *)buf, WRITE_SIZE, ALLOC_SIZE);
    free(buf);
    return 0;
}
