#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * CVE-54: 结构体字段溢出 — 字段写入超出分配范围
 *
 * 模式: struct S { char a[16]; char b[16]; }; malloc(sizeof(S)=32)
 * memcpy(s->b, src, 48);  ← offset=16, write_end=64 > usable(32)=40 → OVERFLOW
 */
typedef struct {
    char a[16];
    char b[16];
} S;

int main() {
    S *s = (S *)malloc(sizeof(S));
    if (!s) return 1;
    char src[48];
    memset(src, 'A', 48);
    memcpy(s->b, src, 48);
    free(s);
    return 0;
}
