// cve00_safe_copy — 安全拷贝: malloc(256)→memset(128), 写入≤分配, 应无检出
// 阴性对照: 正确的边界检查, 应无检出
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALLOC_SIZE 256
#define WRITE_SIZE 128

int main(int argc, char **argv) {
    char *buf = (char *)malloc(ALLOC_SIZE);
    if (!buf) return 1;

    // 安全: 写入128 ≤ 分配256
    memset(buf, 'X', WRITE_SIZE);
    buf[WRITE_SIZE] = '\0';

    printf("buf=%p, wrote %d <= alloc %d, SAFE\n",
           (void *)buf, WRITE_SIZE, ALLOC_SIZE);
    free(buf);
    return 0;
}
