#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * CVE-57: SFOD字段偏移溢出 — 分配过小+字段写入越界
 *
 * 模式:
 *   typedef struct { char a[32]; char b[32]; } LargeHeader;
 *   buf = (LargeHeader*)malloc(16);  // 分配仅16字节
 *   memcpy(buf->b, src, 32);         // offset 32, write 32, end=64 > usable(16)=24 → OVERFLOW
 */
typedef struct {
    char a[32];
    char b[32];
} LargeHeader;

int main() {
    LargeHeader *buf = (LargeHeader *)malloc(16);
    if (!buf) return 1;

    char src[32];
    memset(src, 'X', 32);
    memcpy(buf->b, src, 32);

    printf("sfod_field_overflow\n");
    free(buf);
    return 0;
}
