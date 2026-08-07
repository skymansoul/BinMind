// uaf09_safe_no_free — 无free的正常使用
// CVE参考: SAFE-NO-UAF, 模式: safe_no_free
// 检测目标: 确保正常malloc→使用→free→不再使用的模式不产生误报
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *buf = (char *)malloc(256);
    if (!buf) return 1;
    memset(buf, 'Z', 256);
    printf("normal use: %p\n", (void *)buf);
    free(buf);
    // 之后不再使用buf → 无UAF
    return 0;
}
