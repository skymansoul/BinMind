#include <stdio.h>
#include <stdlib.h>
/* INTOF-12: 数组索引溢出 — 溢出的索引导致越界访问
 * CWE-129: Improper Validation of Array Index */
int main(int argc, char **argv) {
    int arr[100];
    unsigned int idx;
    if (argc < 2) idx = 50;
    else idx = (unsigned int)atoi(argv[1]);

    /* VULNERABLE: 如果idx+50溢出回绕, 检查通过但访问越界 */
    if (idx + 50 < 100) {
        arr[idx + 50] = 0xdead;  /* idx过大时加法溢出通过检查 */
    }
    return 0;
}
