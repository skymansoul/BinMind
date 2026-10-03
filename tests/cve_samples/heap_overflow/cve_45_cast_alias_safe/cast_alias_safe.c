#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * CVE-45: cast别名安全 — void*中间变量+cast后写入
 *
 * 模式: void *raw = malloc(64); char *typed = (char*)raw;
 *       int *int_ptr = (int*)raw;
 *       memcpy(typed, src, 48);  // 48 <= usable(64)=72 → SAFE
 */
int main() {
    void *raw = malloc(64);
    if (!raw) return 1;

    char *typed = (char *)raw;
    int *int_ptr = (int *)raw;

    char src[64];
    memset(src, 'A', 64);
    memcpy(typed, src, 48);

    printf("cast_alias_safe\n");
    free(raw);
    return 0;
}
