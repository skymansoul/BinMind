#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * CVE-60: SFOD嵌套字段安全 — 多字段结构体最后一个字段写入在范围内
 *
 * 模式:
 *   typedef struct { char a[64]; char b[64]; int count; long magic; } Wide;
 *   buf = malloc(sizeof(Wide));  // sizeof=136, usable=144
 *   buf->magic = 0xDEAD;        // offset 128, write 8, end=136 <= 144 → SAFE
 */
typedef struct {
    char a[64];
    char b[64];
    int count;
    long magic;
} Wide;

int main() {
    Wide *buf = (Wide *)malloc(sizeof(Wide));
    if (!buf) return 1;

    buf->count = 10;
    buf->magic = 0xDEAD;

    printf("sfod_nested_safe: magic=%ld\n", buf->magic);
    free(buf);
    return 0;
}
