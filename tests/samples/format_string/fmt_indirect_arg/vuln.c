#include <stdio.h>
#include <stdlib.h>
/* FMT-12: 间接参数格式字符串 — 用户输入不作为fmt而是作为参数
 * 安全写法对比: printf("%s", user) vs printf(user) */
int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: %s <msg>\n", argv[0]);  /* SAFE: 固定格式字符串 */
        return 0;
    }
    /* SAFE: 用户输入作为%s的参数, 不会被解释为格式字符串 */
    printf("message: %s\n", argv[1]);

    /* VULNERABLE: 用户输入作为格式字符串 */
    printf(argv[1]);
    printf("\n");
    return 0;
}
