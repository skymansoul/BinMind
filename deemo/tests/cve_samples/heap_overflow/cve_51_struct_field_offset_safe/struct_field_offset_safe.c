#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * CVE-51: 结构体字段偏移安全 — 固定偏移+固定写入
 *
 * 模式:
 *   typedef struct { char a[32]; char b[32]; int len; } Header;
 *   buf = malloc(sizeof(Header));  // sizeof=68, usable=72
 *   memcpy(buf->b, src, 32);      // offset 32, write 32, end=64 <= 72 → SAFE
 *   buf->len = 42;                 // offset 64, write 4, end=68 <= 72 → SAFE
 */
typedef struct {
    char a[32];
    char b[32];
    int len;
} Header;

int main() {
    Header *buf = (Header *)malloc(sizeof(Header));
    if (!buf) return 1;

    char src[32];
    memset(src, 'H', 32);
    memcpy(buf->b, src, 32);
    buf->len = 42;

    printf("struct_field_offset_safe: len=%d\n", buf->len);
    free(buf);
    return 0;
}
