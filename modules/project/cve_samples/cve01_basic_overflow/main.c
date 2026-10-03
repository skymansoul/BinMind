// cve01_basic_overflow — 基础堆溢出: malloc(128)→memset(256), 最直接的大小不匹配
// CVE参考: CVE-2012-2136, 模式: direct_size_mismatch
// 编译: gcc -Wall -O0 -fno-stack-protector -g -o cve01_basic_overflow main.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALLOC_SIZE 128
#define WRITE_SIZE 256

int main(int argc, char **argv) {
    char *buf = (char *)malloc(ALLOC_SIZE);
    if (!buf) return 1;

    // 漏洞: 分配128B但写入256B
    // 溢出128B
    memset(buf, 'A', WRITE_SIZE);

    printf("buf=%p, wrote %d into %d-byte alloc\n",
           (void *)buf, WRITE_SIZE, ALLOC_SIZE);
    free(buf);
    return 0;
}
