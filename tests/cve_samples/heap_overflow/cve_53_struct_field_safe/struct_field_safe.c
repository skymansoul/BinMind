#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * CVE-53: 结构体字段安全 — 字段偏移在分配范围内
 *
 * 模式: struct S { char a[32]; char b[32]; }; malloc(sizeof(S)=64)
 * memcpy(s->b, src, 32);  ← offset=32, write_end=64 <= usable(64)=72 → SAFE
 */
typedef struct {
    char a[32];
    char b[32];
} S;

int main() {
    S *s = (S *)malloc(sizeof(S));
    if (!s) return 1;
    char src[32] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    memcpy(s->b, src, 32);
    free(s);
    return 0;
}
