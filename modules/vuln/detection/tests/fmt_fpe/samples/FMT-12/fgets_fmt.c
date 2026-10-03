
/* fgets 读取内容作为格式串. */
#include <stdio.h>

int main(void) {
    char buf[128];
    if (!fgets(buf, sizeof(buf), stdin)) return 0;
    printf(buf);             /* 格式串 = 用户输入 */
    return 0;
}
