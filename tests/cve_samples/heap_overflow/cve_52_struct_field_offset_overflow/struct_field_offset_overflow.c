#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * CVE-52: 结构体字段偏移溢出 — 字段写入超出分配大小
 *
 * 模式:
 *   typedef struct { char a[32]; char b[32]; } SmallHeader;  // sizeof=64
 *   buf = malloc(32);  // 分配过小
 *   memcpy(buf->b, src, 32);  // offset 32, write 32, end=64 > usable(32)=40 → OVERFLOW
 */
typedef struct {
    char a[32];
    char b[32];
} SmallHeader;

int main() {
    SmallHeader *buf = (SmallHeader *)malloc(32);
    if (!buf) return 1;

    char src[32];
    memset(src, 'I', 32);
    memcpy(buf->b, src, 32);

    printf("struct_field_offset_overflow\n");
    free(buf);
    return 0;
}
