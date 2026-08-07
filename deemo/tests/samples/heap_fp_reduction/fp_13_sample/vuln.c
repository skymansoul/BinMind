/*
 * FP-13: 嵌套分配 —— 两个独立堆块, 互不干扰
 *
 * a = malloc(32); b = malloc(64);
 * 对 b 的合理写入不应被误关联到 a。
 * 检测器应正确区分不同的分配基址。
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *a = malloc(32);
    char *b = malloc(64);
    if (!a || !b) return 1;
    memset(a, 'A', 32);
    memset(b, 'B', 64);  // 对 b 的写入, 安全
    printf("nested: a=%c b=%c\n", a[0], b[63]);
    free(a);
    free(b);
    return 0;
}
