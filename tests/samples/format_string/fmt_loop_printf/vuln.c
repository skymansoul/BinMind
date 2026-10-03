#include <stdio.h>
#include <stdlib.h>
/* FMT-07: 循环内的格式字符串 — 循环迭代中用户输入直接作为fmt
 * 检测点: 循环内的流不敏感分析可能遗漏迭代之间的fmt变化 */
int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        printf(argv[i]);  /* VULNERABLE: 循环内用户输入作为fmt */
        printf("\n");
    }
    return 0;
}
