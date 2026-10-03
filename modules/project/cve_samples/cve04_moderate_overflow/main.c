// cve04_moderate_overflow — 中等溢出: malloc(64)→memset(96), IFD解析模式
// CVE参考: CVE-2016-10158, 模式: moderate_excess
// 编译: gcc -Wall -O0 -fno-stack-protector -g -o cve04_moderate_overflow main.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALLOC_SIZE 64
#define WRITE_SIZE 96

int main(int argc, char **argv) {
    char *buf = (char *)malloc(ALLOC_SIZE);
    if (!buf) return 1;

    // 漏洞: 分配64B但写入96B
    // 溢出32B
    memset(buf, 'A', WRITE_SIZE);

    printf("buf=%p, wrote %d into %d-byte alloc\n",
           (void *)buf, WRITE_SIZE, ALLOC_SIZE);
    free(buf);
    return 0;
}
