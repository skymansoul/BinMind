// uaf03_alias_write — 别名传播UAF
// CVE参考: CVE-UAF-ALIAS, 模式: uaf_alias
// 检测目标: 指针别名传播后free, 别名是否被标记为悬挂
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *buf = (char *)malloc(128);
    if (!buf) return 1;
    char *alias = buf;  // 别名
    free(buf);
    // UAF: 通过别名写入
    memset(alias, 'Y', 32);
    printf("UAF via alias: %p\n", (void *)alias);
    return 0;
}
