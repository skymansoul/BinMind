#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* INTOF-02: 加法溢出 — size+offset可能回绕到小值
 * CWE-190: Integer Overflow from addition in allocation */
int main(int argc, char **argv) {
    int size = 100;
    int extra;
    if (argc < 2) extra = 20;
    else extra = atoi(argv[1]);

    /* VULNERABLE: INT_MAX + 1 回绕到负数 */
    int total = size + extra;
    if (total > 0) {
        char *buf = (char *)malloc(total);
        if (buf) {
            memset(buf, 'A', size + extra);  /* 如果total已回绕, 这里越界 */
            free(buf);
        }
    }
    return 0;
}
