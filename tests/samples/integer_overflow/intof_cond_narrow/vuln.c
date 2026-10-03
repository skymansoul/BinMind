#include <stdio.h>
#include <stdlib.h>
/* INTOF-07: 条件分支中的类型缩窄 — 大类型值赋给小类型变量
 * CWE-197: Numeric Truncation Error */
int main(int argc, char **argv) {
    long long big_val;
    if (argc < 2) big_val = 100;
    else big_val = atoll(argv[1]);

    /* VULNERABLE: long long→int截断, 大值截断后可能变负/变小 */
    int small_val = (int)big_val;
    if (small_val > 0) {
        char *buf = (char *)malloc(small_val);
        if (buf) {
            buf[0] = 'X';
            /* 如果small_val < big_val, 下面访问可能越界 */
            buf[big_val - 1] = 'Y';
            free(buf);
        }
    }
    return 0;
}
