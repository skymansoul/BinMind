#include <stdio.h>
#include <stdlib.h>
/* FMT-03: %n格式字符串栈写入 — 通过%n向任意地址写入
 * 最危险的格式字符串攻击向量, 可达任意写原语 */
int main(int argc, char **argv) {
    int written = 0;
    if (argc < 2) return 1;
    printf(argv[1]);           /* VULNERABLE: %n可修改栈上的变量 */
    printf("\nbytes written: %d\n", written);
    return 0;
}
