#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * CVE-59: SFOD cast类型推断溢出 — (Tiny*)malloc(sizeof(Tiny))+memcpy越界
 *
 * 模式:
 *   typedef struct { char tag[4]; char body[12]; } Tiny;
 *   buf = (Tiny*)malloc(sizeof(Tiny));  // sizeof=16, usable=24
 *   memcpy(buf->body, src, 32);          // offset 4, write 32, end=36 > 24 → OVERFLOW
 */
typedef struct {
    char tag[4];
    char body[12];
} Tiny;

int main() {
    Tiny *buf = (Tiny *)malloc(sizeof(Tiny));
    if (!buf) return 1;

    char src[32];
    memset(src, 'O', 32);
    memcpy(buf->body, src, 32);

    printf("sfod_cast_overflow\n");
    free(buf);
    return 0;
}
