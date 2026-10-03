#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * CVE-46: cast别名溢出 — void*中间变量+cast后写入溢出
 *
 * 模式: void *raw = malloc(16); char *typed = (char*)raw;
 *       memcpy(typed, src, 64);  // 64 > usable(16)=24 → OVERFLOW
 */
int main() {
    void *raw = malloc(16);
    if (!raw) return 1;

    char *typed = (char *)raw;

    char src[64];
    memset(src, 'B', 64);
    memcpy(typed, src, 64);

    printf("cast_alias_overflow\n");
    free(raw);
    return 0;
}
