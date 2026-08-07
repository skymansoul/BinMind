// cve06_tiny_overflow — 极小分配: malloc(1)→memset(256), 整数截断模式
// CVE参考: CVE-2013-2028, 模式: chunk_truncation
// 编译: gcc -Wall -O0 -fno-stack-protector -g -o cve06_tiny_overflow main.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALLOC_SIZE 1
#define WRITE_SIZE 256

int main(int argc, char **argv) {
    char *buf = (char *)malloc(ALLOC_SIZE);
    if (!buf) return 1;

    // 漏洞: 分配1B但写入256B
    // 溢出255B
    memset(buf, 'A', WRITE_SIZE);

    printf("buf=%p, wrote %d into %d-byte alloc\n",
           (void *)buf, WRITE_SIZE, ALLOC_SIZE);
    free(buf);
    return 0;
}
