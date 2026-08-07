#include <stdio.h>
#include <stdlib.h>
/* FMT-09: snprintf二次格式化 — 先snprintf构造格式字符串再传给printf
 * 检测点: 格式字符串的间接来源追踪 */
int main(int argc, char **argv) {
    char buf[128];
    if (argc < 2) return 1;
    snprintf(buf, sizeof(buf), argv[1]);     /* 将用户输入展开到buf */
    printf(buf);  /* VULNERABLE: buf包含用户控制的格式说明符 */
    return 0;
}
