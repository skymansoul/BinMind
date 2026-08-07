#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * CVE-56: SFOD字段偏移安全 — sizeof分配+字段写入在范围内
 *
 * 模式:
 *   typedef struct { char a[16]; char b[16]; int len; } Msg;
 *   buf = malloc(sizeof(Msg));  // sizeof=36, usable=40
 *   memcpy(buf->b, src, 16);    // offset 16, write 16, end=32 <= 40 → SAFE
 *   buf->len = 1;               // offset 32, write 4, end=36 <= 40 → SAFE
 */
typedef struct {
    char a[16];
    char b[16];
    int len;
} Msg;

int main() {
    Msg *buf = (Msg *)malloc(sizeof(Msg));
    if (!buf) return 1;

    char src[16];
    memset(src, 'A', 16);
    memcpy(buf->b, src, 16);
    buf->len = 1;

    printf("sfod_field_safe: len=%d\n", buf->len);
    free(buf);
    return 0;
}
