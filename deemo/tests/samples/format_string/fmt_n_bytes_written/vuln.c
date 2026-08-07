#include <stdio.h>
#include <stdlib.h>
/* FMT-14: %n字节数写入 — 通过%n向栈变量写入累计字节数
 * 检测点: %n是格式字符串漏洞中最危险的说明符 */
int main(int argc, char **argv) {
    int count = 0;
    char buf[128];
    if (argc < 2) return 1;
    snprintf(buf, sizeof(buf), argv[1]);  /* VULNERABLE: %n可写入count地址 */
    printf("output: %s (n=%d)\n", buf, count);
    if (count != 0)
        printf("WARNING: %%n detected — count was modified!\n");
    return 0;
}
