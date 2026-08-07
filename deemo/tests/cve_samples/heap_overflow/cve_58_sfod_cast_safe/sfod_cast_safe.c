#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * CVE-58: SFOD cast类型推断安全 — (Small*)cast分配+字段写入安全
 *
 * 模式:
 *   typedef struct { char prefix[8]; char data[24]; } Small;
 *   buf = (Small*)malloc(sizeof(Small));  // sizeof=32, usable=40
 *   memcpy(buf->data, src, 24);           // offset 8, write 24, end=32 <= 40 → SAFE
 */
typedef struct {
    char prefix[8];
    char data[24];
} Small;

int main() {
    Small *buf = (Small *)malloc(sizeof(Small));
    if (!buf) return 1;

    char src[24];
    memset(src, 'K', 24);
    memcpy(buf->data, src, 24);

    printf("sfod_cast_safe\n");
    free(buf);
    return 0;
}
