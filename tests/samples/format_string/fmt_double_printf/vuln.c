#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* FMT-15: 双重printf — 先printf构造字符串再printf输出
 * 类似二次注入场景 */
int main(int argc, char **argv) {
    char temp[256];
    if (argc < 2) return 1;

    /* 第一层: 安全的snprintf展开字符串 */
    snprintf(temp, sizeof(temp), "input was: %s", argv[1]);

    /* 第二层: VULNERABLE — temp中包含用户输入且作为格式字符串 */
    printf(temp);
    printf("\n");
    return 0;
}
