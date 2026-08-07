/*
 * fp_internal_copy packed variant — 仅剥离符号 (-s), 内部常量复制.
 * 双侧大小均为内部常量, 不可攻击者控制 → 应降权.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void format_output(void) {
    static const char banner[64] = "internal-constant-banner-data";
    char *buf = (char *)malloc(32);
    if (!buf) return;
    memcpy(buf, banner, 64);  /* 常量复制: malloc(32) < write(64) 但数据内部 */
    printf("%s\n", buf);
    free(buf);
}

int main(void) {
    format_output();
    return 0;
}
