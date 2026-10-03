#include <stdio.h>
#include <stdlib.h>
/* FMT-05: 位置参数%n$ — 高级格式字符串攻击
 * 使用位置参数跳过栈上padding, 精确控制写入目标 */
int main(int argc, char **argv) {
    int a = 1, b = 2, c = 3, d = 4;
    if (argc < 2) return 1;
    printf(argv[1]);  /* VULNERABLE: %7$n直接跳转到第7个参数位置 */
    printf("\na=%d b=%d c=%d d=%d\n", a, b, c, d);
    return 0;
}
